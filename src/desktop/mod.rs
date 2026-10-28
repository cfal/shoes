#[cfg(target_os = "linux")]
mod linux;

use std::io;

#[derive(Default)]
pub(crate) struct NetworkSession {
    #[cfg(target_os = "linux")]
    session: Option<linux::Session>,
}

impl NetworkSession {
    pub(crate) async fn prepare(configs: &[crate::config::Config]) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            if let Some(spec) = linux::Spec::from_configs(configs)? {
                return Ok(Self {
                    session: Some(linux::Session::prepare(spec).await?),
                });
            }
        }
        let _ = configs;
        Ok(Self::default())
    }

    pub(crate) fn validate(&self, configs: &[crate::config::Config]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        match &self.session {
            Some(session) => return session.validate(configs),
            None if linux::Spec::from_configs(configs)?.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "enabling managed TUN requires a restart",
                ));
            }
            _ => {}
        }
        let _ = configs;
        Ok(())
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
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            return session.changed().await;
        }
        std::future::pending().await
    }

    pub(crate) async fn reconcile(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(session) = &mut self.session {
            session.reconcile().await?;
        }
        Ok(())
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

pub(crate) fn validate_config(configs: &[crate::config::Config]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::Spec::from_configs(configs)?;
    }
    #[cfg(not(target_os = "linux"))]
    for config in configs {
        if let crate::config::Config::TunServer(tun) = config
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
