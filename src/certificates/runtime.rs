use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::{ChallengeConfig, Source, Spec, acme, challenge, visit};
use crate::config::ValidatedConfigs;

#[derive(Default)]
pub(crate) struct Registry {
    workers: Vec<Arc<Worker>>,
    replacements: Mutex<Vec<Arc<Worker>>>,
}

struct Worker {
    source: Arc<Source>,
    lock: Option<Arc<File>>,
    listeners: Mutex<Vec<Arc<TcpListener>>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Worker {
    fn matches_source(&self, source: &Source) -> bool {
        // Implicit file-source names depend on discovery order, not identity.
        self.source.spec == source.spec
            && (self.source.name == source.name
                || (self.source.name.starts_with('@') && source.name.starts_with('@')))
    }

    async fn stop_task(&self) {
        let task = self.task.lock().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().take() {
            task.abort();
        }
    }
}

impl Registry {
    pub(crate) async fn prepare(
        validated: &mut ValidatedConfigs,
        previous: Option<&Self>,
    ) -> io::Result<Self> {
        let mut registry = Self::default();
        let mut claimed_storage = std::collections::HashSet::new();
        for source in &mut validated.certificates {
            let reused = previous.and_then(|previous| {
                previous
                    .workers
                    .iter()
                    .find(|worker| worker.matches_source(source))
            });
            let worker = if let Some(worker) = reused {
                worker.clone()
            } else {
                let mut listeners = Vec::new();
                let lock = if let Spec::Acme(config) = &source.spec {
                    let canonical = std::fs::canonicalize(&config.state_dir).ok();
                    let replacing = previous.and_then(|previous| {
                        previous.workers.iter().find(|worker| {
                            let Spec::Acme(old) = &worker.source.spec else {
                                return false;
                            };
                            old.state_dir == config.state_dir
                                || canonical.as_ref().is_some_and(|path| {
                                    std::fs::canonicalize(&old.state_dir).ok().as_ref()
                                        == Some(path)
                                })
                        })
                    });
                    let lock = if let Some(worker) = replacing {
                        registry.replacements.get_mut().push(worker.clone());
                        *source.material.write() = worker.source.material.read().clone();
                        worker.lock.as_ref().expect("ACME storage lease").clone()
                    } else {
                        Arc::new(acme::lock_state(config)?)
                    };
                    acme::load_cached(source, config)?;
                    if let ChallengeConfig::Http01 { listen } = &config.challenge {
                        for address in listen {
                            let existing = previous.and_then(|previous| {
                                previous.workers.iter().find_map(|worker| {
                                    let listener = worker
                                        .listeners
                                        .lock()
                                        .iter()
                                        .find(|listener| {
                                            listener.local_addr().ok().as_ref() == Some(address)
                                        })
                                        .cloned()?;
                                    Some((worker, listener))
                                })
                            });
                            listeners.push(match existing {
                                Some((owner, listener)) => {
                                    let replacements = registry.replacements.get_mut();
                                    if !replacements.iter().any(|worker| Arc::ptr_eq(worker, owner))
                                    {
                                        replacements.push(owner.clone());
                                    }
                                    listener
                                }
                                None => Arc::new(TcpListener::bind(address).await?),
                            });
                        }
                    }
                    Some(lock)
                } else {
                    None
                };
                Arc::new(Worker {
                    source: source.clone(),
                    lock,
                    listeners: Mutex::new(listeners),
                    task: Mutex::new(None),
                })
            };
            if let Spec::Acme(config) = &worker.source.spec
                && !claimed_storage.insert(std::fs::canonicalize(&config.state_dir)?)
            {
                return Err(super::invalid(
                    "ACME sources must not alias the same state_dir",
                ));
            }
            *source = worker.source.clone();
            registry.workers.push(worker);
        }
        visit(&mut validated.configs, &mut |binding, _, _, _, _| {
            if let Some(source) = binding {
                *source = registry
                    .workers
                    .iter()
                    .find(|worker| worker.matches_source(source))
                    .expect("validated certificate source")
                    .source
                    .clone();
            }
            Ok(())
        })?;
        Ok(registry)
    }

    pub(crate) async fn start(&self) {
        let replacements = std::mem::take(&mut *self.replacements.lock());
        for worker in replacements {
            worker.stop_task().await;
        }
        for worker in &self.workers {
            let mut task = worker.task.lock();
            if task.is_some() {
                continue;
            }
            let source = worker.source.clone();
            let listeners = worker.listeners.lock().clone();
            if let Spec::Acme(config) = &source.spec
                && acme::load_cached(&source, config).is_err()
            {
                log::warn!(
                    "Certificate source {} could not refresh durable state during activation; retaining prepared certificate",
                    source.name
                );
            }
            // Keep the storage lease until the aborted task has actually finished.
            let lock = worker.lock.clone();
            *task = Some(tokio::spawn(async move {
                let _lock = lock;
                match &source.spec {
                    Spec::Files { interval, .. } => {
                        let mut failures = 0u32;
                        loop {
                            tokio::time::sleep(Duration::from_secs(*interval)).await;
                            match source.refresh_files() {
                                Ok(changed) => {
                                    if changed {
                                        log::info!("Certificate source {} rotated", source.name);
                                    }
                                    failures = 0;
                                }
                                Err(_) => {
                                    if failures == 0 || failures.is_multiple_of(60) {
                                        log::warn!(
                                            "Certificate source {} update rejected; retaining last good pair (expired certificates are not served)",
                                            source.name
                                        );
                                    }
                                    failures = failures.saturating_add(1);
                                }
                            }
                        }
                    }
                    Spec::Acme(config) => {
                        let _cleanup = challenge::Cleanup(source.clone());
                        tokio::select! {
                            _ = acme::run(source.clone(), config) => {}
                            result = challenge::serve(listeners, source.clone()) => {
                                if result.is_err() {
                                    log::error!("Certificate source {} HTTP-01 listener failed", source.name);
                                }
                            }
                        }
                    }
                }
            }));
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        for worker in self.workers.drain(..) {
            if Arc::strong_count(&worker) == 1 {
                worker.stop_task().await;
            }
        }
    }

    pub(crate) async fn stop(&self) {
        for worker in &self.workers {
            worker.stop_task().await;
            worker.listeners.lock().clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> ValidatedConfigs {
        crate::config::create_server_configs(
            serde_yaml::from_str(&format!(
                r#"
- certificate_source: shared
  type: files
  cert: '{}'
  key: '{}'
  poll_interval_secs: 1
- address: 127.0.0.1:18443
  protocol:
    type: tls
    default_tls_target:
      certificate_source: shared
      protocol: {{ type: socks }}
- address: 127.0.0.1:18444
  protocol:
    type: tls
    default_tls_target:
      certificate_source: shared
      protocol: {{ type: socks }}
"#,
                dir.join("cert.pem").display(),
                dir.join("key.pem").display()
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn one_worker_is_reused_and_removal_cancels_it() {
        let dir = tempfile::tempdir().unwrap();
        let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), first.cert.pem()).unwrap();
        std::fs::write(
            dir.path().join("key.pem"),
            first.signing_key.serialize_pem(),
        )
        .unwrap();
        let mut validated = config(dir.path());
        let mut old = Registry::prepare(&mut validated, None).await.unwrap();
        assert_eq!(old.workers.len(), 1);
        old.start().await;
        tokio::task::yield_now().await;
        let mut replacement = config(dir.path());
        let mut next = Registry::prepare(&mut replacement, Some(&old))
            .await
            .unwrap();
        next.start().await;
        assert_eq!(next.workers.len(), 1);
        assert!(Arc::ptr_eq(&old.workers[0], &next.workers[0]));
        let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), second.cert.pem()).unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            validated.certificates[0].current().unwrap().cert[0],
            *first.cert.der()
        );
        std::fs::write(
            dir.path().join("key.pem"),
            second.signing_key.serialize_pem(),
        )
        .unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            validated.certificates[0].current().unwrap().cert[0],
            *second.cert.der()
        );
        old.shutdown().await;
        assert!(!next.workers[0].task.lock().as_ref().unwrap().is_finished());
        let task = next.workers[0].task.lock().as_ref().unwrap().abort_handle();
        next.shutdown().await;
        assert!(task.is_finished());
    }

    #[tokio::test]
    async fn acme_preparation_rollback_and_storage_handoff() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let directory = tempfile::tempdir().unwrap();
            let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reserved.local_addr().unwrap();
            drop(reserved);
            let make = |contacts: &str, state: &str| {
                crate::config::create_server_configs(
                    serde_yaml::from_str(&format!(
                        r#"
- certificate_source: managed
  type: acme
  domains: [proxy.test]
  directory_url: http://127.0.0.1:9/directory
  state_dir: '{}'
  contacts: [{contacts}]
  challenge: {{type: http01, listen: ['{address}']}}
"#,
                        directory.path().join(state).display()
                    ))
                    .unwrap(),
                )
                .unwrap()
            };
            let mut validated = make("", "state");
            let mut old = Registry::prepare(&mut validated, None).await.unwrap();
            assert!(TcpListener::bind(address).await.is_err());
            let source = old.workers[0].source.clone();
            source.challenges.write().push(challenge::Pending {
                domain: "proxy.test".into(),
                token: "test".into(),
                authorization: "test.authorization".into(),
                expires: std::time::Instant::now() + Duration::from_secs(60),
                tls: None,
            });
            let old_source = source.clone();
            *old.workers[0].task.lock() = Some(tokio::spawn(async move {
                let _cleanup = challenge::Cleanup(old_source);
                std::future::pending::<()>().await;
            }));
            tokio::task::yield_now().await;
            let mut other = make("", "state");
            assert!(Registry::prepare(&mut other, None).await.is_err());
            let mut replacement = make("mailto:changed@example.invalid", "state");
            let abandoned = Registry::prepare(&mut replacement, Some(&old))
                .await
                .unwrap();
            drop(abandoned);
            assert_eq!(source.challenges.read().len(), 1);
            assert!(!old.workers[0].task.lock().as_ref().unwrap().is_finished());
            let mut replacement = make("mailto:changed@example.invalid", "state");
            let mut next = Registry::prepare(&mut replacement, Some(&old))
                .await
                .unwrap();
            assert!(Arc::ptr_eq(
                old.workers[0].lock.as_ref().unwrap(),
                next.workers[0].lock.as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                &old.workers[0].listeners.lock()[0],
                &next.workers[0].listeners.lock()[0]
            ));
            next.start().await;
            assert!(source.challenges.read().is_empty());
            assert!(old.workers[0].task.lock().is_none());
            old.shutdown().await;
            let mut replacement = make("", "new-state");
            let abandoned = Registry::prepare(&mut replacement, Some(&next))
                .await
                .unwrap();
            assert!(!Arc::ptr_eq(
                next.workers[0].lock.as_ref().unwrap(),
                abandoned.workers[0].lock.as_ref().unwrap()
            ));
            drop(abandoned);
            assert!(!next.workers[0].task.lock().as_ref().unwrap().is_finished());
            let mut replacement = make("", "new-state");
            let mut migrated = Registry::prepare(&mut replacement, Some(&next))
                .await
                .unwrap();
            assert!(Arc::ptr_eq(
                &next.workers[0].listeners.lock()[0],
                &migrated.workers[0].listeners.lock()[0]
            ));
            migrated.start().await;
            assert!(next.workers[0].task.lock().is_none());
            next.shutdown().await;
            migrated.shutdown().await;
            assert!(TcpListener::bind(address).await.is_ok());
            let mut clean = make("", "state");
            Registry::prepare(&mut clean, None)
                .await
                .unwrap()
                .shutdown()
                .await;
        })
        .await
        .unwrap();
    }
}
