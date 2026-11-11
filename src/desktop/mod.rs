#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) const MANAGED_STATE_DIRECTORY: &str = "/run/shoes";

use std::io;

#[cfg(test)]
tokio::task_local! {
    pub(crate) static TEST_NETWORK: std::cell::RefCell<Option<NetworkSession>>;
}

pub(crate) struct NetworkTopology {
    #[cfg(target_os = "linux")]
    spec: Option<linux::Spec>,
    #[cfg(target_os = "linux")]
    ingress: Option<std::sync::Arc<linux::Ingress>>,
}

impl NetworkTopology {
    pub(crate) fn validate(&self, configs: &[crate::config::ResolvedConfig]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if linux::Spec::from_resolved_configs(configs)? != self.spec {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                if self.spec.is_none() {
                    "enabling managed TUN requires a restart"
                } else {
                    "managed TUN topology changes require a restart"
                },
            ));
        }
        let _ = configs;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn ingress(&self) -> Option<std::sync::Arc<linux::Ingress>> {
        self.ingress.clone()
    }
}

#[derive(Default)]
pub(crate) struct NetworkSession {
    #[cfg(test)]
    test_changed: bool,
    #[cfg(test)]
    test_available: Option<bool>,
    #[cfg(target_os = "linux")]
    session: Option<linux::Session>,
    #[cfg(test)]
    test_events: Option<(
        tokio::sync::mpsc::Receiver<Option<bool>>,
        tokio::sync::mpsc::Sender<()>,
    )>,
}

impl NetworkSession {
    pub(crate) fn topology(&self) -> NetworkTopology {
        NetworkTopology {
            #[cfg(target_os = "linux")]
            spec: self.session.as_ref().map(|session| session.spec().clone()),
            #[cfg(target_os = "linux")]
            ingress: self.ingress(),
        }
    }
    pub(crate) async fn prepare(configs: &[crate::config::Config]) -> io::Result<Self> {
        #[cfg(test)]
        if let Ok(Some(network)) = TEST_NETWORK.try_with(|network| network.borrow_mut().take()) {
            return Ok(network);
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(spec) = linux::Spec::from_configs(configs)? {
                return Ok(Self {
                    session: Some(linux::Session::prepare(spec).await?),
                    #[cfg(test)]
                    test_events: None,
                    #[cfg(test)]
                    test_changed: false,
                    #[cfg(test)]
                    test_available: None,
                });
            }
        }
        let _ = configs;
        Ok(Self::default())
    }

    pub(crate) fn monitors_underlay(&self) -> bool {
        #[cfg(test)]
        if self.test_events.is_some() {
            return true;
        }
        #[cfg(target_os = "linux")]
        if self.session.is_some() {
            return true;
        }
        false
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn ingress(&self) -> Option<std::sync::Arc<linux::Ingress>> {
        self.session.as_ref().and_then(linux::Session::ingress)
    }

    pub(crate) async fn prepare_network(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            session.prepare_network().await?;
        }
        Ok(())
    }

    pub(crate) async fn activate(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            session.activate().await?;
        }
        Ok(())
    }

    pub(crate) async fn changed(&mut self) {
        #[cfg(test)]
        if let Some((changes, _)) = &mut self.test_events {
            let event = changes.recv().await.unwrap();
            self.test_changed = event.is_some();
            if let Some(available) = event {
                self.test_available = Some(available);
            }
            return;
        }
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            return session.changed().await;
        }
        std::future::pending().await
    }

    pub(crate) fn available(&self) -> bool {
        #[cfg(test)]
        if let Some(available) = self.test_available {
            return available;
        }
        #[cfg(target_os = "linux")]
        if let Some(session) = &self.session {
            return session.available();
        }
        true
    }

    pub(crate) fn refresh_bootstrap(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(session) = &self.session {
            session.refresh_bootstrap()?;
        }
        Ok(())
    }

    pub(crate) async fn reconcile(&mut self) -> io::Result<bool> {
        #[cfg(test)]
        if let Some((changes, reconciled)) = &mut self.test_events {
            // Reconciliation observes changes that arrived while worker startup was running.
            while let Ok(event) = changes.try_recv() {
                self.test_changed |= event.is_some();
                if let Some(available) = event {
                    self.test_available = Some(available);
                }
            }
            let _ = reconciled.try_send(());
            return Ok(std::mem::take(&mut self.test_changed));
        }
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            return session.reconcile().await;
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn with_test_events(
        changes: tokio::sync::mpsc::Receiver<Option<bool>>,
        reconciled: tokio::sync::mpsc::Sender<()>,
    ) -> Self {
        Self {
            test_events: Some((changes, reconciled)),
            ..Self::default()
        }
    }

    pub(crate) async fn deactivate(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            session.deactivate().await?;
        }
        Ok(())
    }

    pub(crate) async fn close(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            session.close().await?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{Ingress, cleanup};

pub(crate) fn validate_config(configs: &[crate::config::ResolvedConfig]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::Spec::from_resolved_configs(configs)?;
    }
    #[cfg(not(target_os = "linux"))]
    for config in configs {
        if let crate::config::ResolvedConfig::TunServer(tun) = config
            && tun.has_managed_options()
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "managed TUN is currently supported only on Linux",
            ));
        }
    }
    Ok(())
}
