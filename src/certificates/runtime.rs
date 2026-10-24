use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::{ChallengeConfig, Input, Source, Spec, acme, challenge, visit};
use crate::config::{BindLocation, Config, Transport, ValidatedConfigs};

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
            && self.source.trust_digest == source.trust_digest
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
        Self::prepare_with_retiring(validated, previous, &[]).await
    }

    pub(crate) async fn prepare_with_retiring(
        validated: &mut ValidatedConfigs,
        previous: Option<&Self>,
        retiring: &[Config],
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
                        Arc::new(acme::lock_state(config).map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!(
                                    "certificate source {}: {}",
                                    source.name,
                                    acme::state_error(config, error)
                                ),
                            )
                        })?)
                    };
                    acme::load_cached(source, config).map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!(
                                "certificate source {}: {}",
                                source.name,
                                acme::state_error(config, error)
                            ),
                        )
                    })?;
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
                            match existing {
                                Some((owner, listener)) => {
                                    let replacements = registry.replacements.get_mut();
                                    if !replacements.iter().any(|worker| Arc::ptr_eq(worker, owner))
                                    {
                                        replacements.push(owner.clone());
                                    }
                                    listeners.push(listener);
                                }
                                None => match TcpListener::bind(address).await {
                                    Ok(listener) => listeners.push(Arc::new(listener)),
                                    Err(error)
                                        if error.kind() == io::ErrorKind::AddrInUse
                                            && retiring_proxy_covers(retiring, *address) => {}
                                    Err(error) => {
                                        return Err(http_bind_error(source, *address, error));
                                    }
                                },
                            }
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

    /// Finish binds deferred for ports still owned by the retiring proxy generation.
    pub(crate) async fn bind_pending(&self) -> io::Result<()> {
        for worker in &self.workers {
            let Spec::Acme(config) = &worker.source.spec else {
                continue;
            };
            let ChallengeConfig::Http01 { listen } = &config.challenge else {
                continue;
            };
            for address in listen {
                let bound = worker
                    .listeners
                    .lock()
                    .iter()
                    .any(|listener| listener.local_addr().ok().as_ref() == Some(address));
                if !bound {
                    let listener = TcpListener::bind(address)
                        .await
                        .map_err(|error| http_bind_error(&worker.source, *address, error))?;
                    worker.listeners.lock().push(Arc::new(listener));
                }
            }
        }
        Ok(())
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
                && let Err(error) = acme::load_cached(&source, config)
            {
                log::error!(
                    "Certificate source {} could not refresh durable state during activation: {}; retaining prepared certificate",
                    source.name,
                    acme::state_error(config, error)
                );
            }
            // Keep the storage lease until the aborted task has actually finished.
            let lock = worker.lock.clone();
            *task = Some(tokio::spawn(async move {
                let _lock = lock;
                match &source.spec {
                    Spec::Files { .. } => watch_files(&source).await,
                    Spec::Acme(config) => {
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

    pub(crate) async fn retire_unused(&self, next: &Self) {
        for worker in &self.workers {
            if !next
                .workers
                .iter()
                .any(|retained| Arc::ptr_eq(worker, retained))
            {
                worker.stop_task().await;
                worker.listeners.lock().clear();
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

fn http_bind_error(source: &Source, address: std::net::SocketAddr, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "certificate source {} HTTP-01 bind at {address}: {error}",
            source.name
        ),
    )
}

fn retiring_proxy_covers(configs: &[Config], address: std::net::SocketAddr) -> bool {
    configs.iter().any(|config| {
        let Config::Server(server) = config else {
            return false;
        };
        if server.transport != Transport::Tcp {
            return false;
        }
        let BindLocation::Address(addresses) = &server.bind_location else {
            return false;
        };
        addresses
            .iter()
            .filter_map(|bound| bound.literal_socket_addr())
            .any(|bound| {
                // Do not infer ownership across address families or by widening a binding.
                bound == address
                    || (bound.port() == address.port()
                        && bound.is_ipv4() == address.is_ipv4()
                        && bound.ip().is_unspecified())
            })
    })
}

async fn watch_files(source: &Source) {
    const DEBOUNCE: Duration = Duration::from_millis(250);
    const RETRY: Duration = Duration::from_secs(1);
    const RECONCILE: Duration = Duration::from_secs(60);
    let Spec::Files { cert, key } = &source.spec else {
        return;
    };
    let paths: Vec<_> = [cert, key]
        .into_iter()
        .filter_map(|input| match input {
            Input::File(path) => Some(path),
            Input::Inline(_) => None,
        })
        .collect();
    let (tx, mut changes) = tokio::sync::mpsc::channel(1);
    let mut _watcher = None;
    let mut refresh_watch = true;
    let mut watch_error = None;
    let mut next_warning = tokio::time::Instant::now();
    loop {
        // Build replacement watches before dropping the old ones, including symlink targets.
        if refresh_watch {
            watch_error = match crate::file_watcher::watch(&paths, tx.clone()) {
                Ok(next) => {
                    _watcher = Some(next);
                    None
                }
                Err(error) => Some(error),
            };
        }
        let result = source.refresh_files();
        if matches!(result, Ok(true)) {
            log::info!("Certificate source {} rotated", source.name);
        }
        if (watch_error.is_some() || result.is_err()) && tokio::time::Instant::now() >= next_warning
        {
            if let Some(error) = &watch_error {
                log::error!(
                    "Certificate source {} watch failed: {error}; using reconciliation",
                    source.name
                );
            }
            if let Err(error) = &result {
                log::error!(
                    "Certificate source {} update failed: {error}; retrying and retaining last good pair (expired certificates are not served)",
                    source.name
                );
            }
            next_warning = tokio::time::Instant::now() + RECONCILE;
        }
        // Retry separate writes promptly; reconcile missed events and watch failures periodically.
        let delay = if result.is_err() { RETRY } else { RECONCILE };
        tokio::select! {
            _ = changes.recv() => {
                crate::file_watcher::debounce(&mut changes, DEBOUNCE).await;
                refresh_watch = true;
            }
            _ = tokio::time::sleep(delay) => {
                refresh_watch = watch_error.is_some() || matches!(result, Ok(true));
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_binds_require_a_known_covering_proxy_binding() {
        for (bound, requested, covered) in [
            ("127.0.0.1:18443", "127.0.0.1:18443", true),
            ("0.0.0.0:18443", "127.0.0.1:18443", true),
            ("127.0.0.1:18443", "0.0.0.0:18443", false),
            ("0.0.0.0:18443", "[::1]:18443", false),
            ("[::]:18443", "127.0.0.1:18443", false),
            ("[::]:18443", "[::1]:18443", true),
            ("127.0.0.1:18443", "127.0.0.1:18444", false),
        ] {
            let configs: Vec<Config> = serde_yaml::from_str(&format!(
                "- address: '{bound}'\n  protocol: {{type: socks}}\n"
            ))
            .unwrap();
            assert_eq!(
                retiring_proxy_covers(&configs, requested.parse().unwrap()),
                covered
            );
        }
    }

    #[tokio::test]
    async fn http_bind_errors_identify_source_and_address_and_preserve_kind() {
        let directory = tempfile::tempdir().unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        let mut validated = crate::config::create_server_configs(serde_yaml::from_str(&format!(
            "- certificate_source: managed\n  type: acme\n  domains: [proxy.test]\n  directory_url: http://127.0.0.1:9/directory\n  state_dir: '{}'\n  challenge: {{type: http01, listen: ['{address}']}}\n", directory.path().join("state").display()
        )).unwrap()).unwrap();
        let error = Registry::prepare(&mut validated, None).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(
            error
                .to_string()
                .contains(&format!("managed HTTP-01 bind at {address}"))
        );

        let retiring: Vec<Config> = serde_yaml::from_str(&format!(
            "- address: '{address}'\n  protocol: {{type: socks}}\n"
        ))
        .unwrap();
        let mut registry = Registry::prepare_with_retiring(&mut validated, None, &retiring)
            .await
            .unwrap();
        let error = registry.bind_pending().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(
            error
                .to_string()
                .contains(&format!("managed HTTP-01 bind at {address}"))
        );
        drop(reserved);
        registry.bind_pending().await.unwrap();
        registry.shutdown().await;
    }

    fn config(dir: &std::path::Path) -> ValidatedConfigs {
        crate::config::create_server_configs(
            serde_yaml::from_str(&format!(
                r#"
- certificate_source: shared
  type: files
  cert: '{}'
  key: '{}'
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

    #[tokio::test]
    async fn http_shutdown_allows_immediate_rebind_and_restart() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        tokio::time::timeout(Duration::from_secs(10), async {
            let directory = tempfile::tempdir().unwrap();
            let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = reserved.local_addr().unwrap();
            drop(reserved);
            let configs = serde_json::json!([{
                "certificate_source": "managed", "type": "acme", "domains": ["proxy.test"],
                "directory_url": "http://127.0.0.1:9/directory", "state_dir": directory.path().join("state"),
                "challenge": {"type": "http01", "listen": [address.to_string()]}
            }]);
            for _ in 0..2 {
                let mut validated = crate::config::create_server_configs(
                    serde_yaml::from_value(serde_yaml::to_value(&configs).unwrap()).unwrap(),
                )
                .unwrap();
                let mut registry = Registry::prepare(&mut validated, None).await.unwrap();
                registry.start().await;
                let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
                stream.write_all(b"GET / HTTP/1.1\r\nHost: proxy.test\r\n\r\n").await.unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).await.unwrap();
                assert!(response.starts_with("HTTP/1.1 404 "));
                registry.shutdown().await;
                let socket = tokio::net::TcpSocket::new_v4().unwrap();
                socket.set_reuseaddr(true).unwrap();
                socket.bind(address).unwrap();
                let rebound = socket.listen(128).unwrap();
                let Spec::Acme(config) = &validated.certificates[0].spec else {
                    unreachable!()
                };
                let lock = acme::lock_state(config).unwrap();
                drop((rebound, lock));
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
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
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            validated.certificates[0].current().unwrap().cert[0],
            *first.cert.der()
        );
        std::fs::write(
            dir.path().join("key.pem"),
            second.signing_key.serialize_pem(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while validated.certificates[0].current().unwrap().cert[0] != *second.cert.der() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
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
    #[cfg(unix)]
    async fn file_watches_follow_symlink_replacement_and_release_on_stop() {
        use std::os::unix::fs::symlink;
        tokio::time::timeout(Duration::from_secs(10), async {
            let dir = tempfile::tempdir().unwrap();
            let a = dir.path().join("a");
            let b = dir.path().join("b");
            std::fs::create_dir(&a).unwrap();
            std::fs::create_dir(&b).unwrap();
            let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            for (directory, certificate) in [(&a, &first), (&b, &second)] {
                std::fs::write(directory.join("cert.pem"), certificate.cert.pem()).unwrap();
                std::fs::write(
                    directory.join("key.pem"),
                    certificate.signing_key.serialize_pem(),
                )
                .unwrap();
            }
            let current = dir.path().join("current");
            symlink(&a, &current).unwrap();
            let mut validated = config(&current);
            let mut registry = Registry::prepare(&mut validated, None).await.unwrap();
            registry.start().await;
            tokio::task::yield_now().await;
            symlink(&b, dir.path().join("next")).unwrap();
            std::fs::rename(dir.path().join("next"), &current).unwrap();
            let source = &validated.certificates[0];
            tokio::time::timeout(Duration::from_secs(3), async {
                while source.current().unwrap().cert[0] != *second.cert.der() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let unchanged = source.current().unwrap();
            std::fs::write(b.join("cert.pem"), second.cert.pem()).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(Arc::ptr_eq(&source.current().unwrap(), &unchanged));
            std::fs::remove_file(b.join("key.pem")).unwrap();
            std::fs::write(b.join("cert.pem"), first.cert.pem()).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(Arc::ptr_eq(&source.current().unwrap(), &unchanged));
            std::fs::write(b.join("new.key"), first.signing_key.serialize_pem()).unwrap();
            std::fs::rename(b.join("new.key"), b.join("key.pem")).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while source.current().unwrap().cert[0] != *first.cert.der() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            registry.shutdown().await;
            std::fs::write(b.join("cert.pem"), second.cert.pem()).unwrap();
            std::fs::write(b.join("key.pem"), second.signing_key.serialize_pem()).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(source.current().unwrap().cert[0], *first.cert.der());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn changed_acme_trust_replaces_worker_only_after_successful_preparation() {
        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("ca.crt");
        let first = rcgen::generate_simple_self_signed(vec!["ca.test".into()]).unwrap();
        std::fs::write(&ca_path, first.cert.pem()).unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let make = || {
            crate::config::create_server_configs(serde_yaml::from_value(serde_yaml::to_value(
                serde_json::json!([{
                    "certificate_source": "managed", "type": "acme", "domains": ["proxy.test"],
                    "directory_url": "http://127.0.0.1:9/directory", "state_dir": directory.path().join("state"),
                    "ca_cert": ca_path, "challenge": {"type": "http01", "listen": [address.to_string()]}
                }])
            ).unwrap()).unwrap())
        };
        let mut validated = make().unwrap();
        let mut old = Registry::prepare(&mut validated, None).await.unwrap();
        let mut unchanged = make().unwrap();
        let reused = Registry::prepare(&mut unchanged, Some(&old)).await.unwrap();
        assert!(Arc::ptr_eq(&old.workers[0], &reused.workers[0]));
        drop(reused);
        std::fs::write(&ca_path, "incomplete").unwrap();
        assert!(make().is_err());
        let digest = old.workers[0].source.trust_digest.clone();
        let second = rcgen::generate_simple_self_signed(vec!["ca.test".into()]).unwrap();
        std::fs::write(&ca_path, second.cert.pem()).unwrap();
        let mut validated = make().unwrap();
        let candidate = Registry::prepare(&mut validated, Some(&old)).await.unwrap();
        assert!(!Arc::ptr_eq(&old.workers[0], &candidate.workers[0]));
        assert!(Arc::ptr_eq(
            old.workers[0].lock.as_ref().unwrap(),
            candidate.workers[0].lock.as_ref().unwrap()
        ));
        assert_eq!(old.workers[0].source.trust_digest, digest);
        assert_ne!(candidate.workers[0].source.trust_digest, digest);
        drop(candidate);
        old.shutdown().await;
        assert!(TcpListener::bind(address).await.is_ok());
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
