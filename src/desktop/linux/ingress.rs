use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

use crate::client_proxy_selector::ClientProxySelector;
use crate::config::TunConfig;
use crate::resolver::Resolver;

use super::spec::Spec;

pub(crate) struct Ingress {
    device: Arc<crate::tun::RetainedDevice>,
    listeners: Vec<Arc<TcpListener>>,
}

impl Ingress {
    pub(super) fn new(spec: &Spec, device: crate::tun::RetainedDevice) -> io::Result<Self> {
        let mut listeners = Vec::new();
        if spec.redirect {
            for ipv6 in super::routes::families(spec) {
                let address = SocketAddr::new(
                    if ipv6 {
                        IpAddr::V6(Ipv6Addr::LOCALHOST)
                    } else {
                        IpAddr::V4(Ipv4Addr::LOCALHOST)
                    },
                    0,
                );
                listeners.push(Arc::new(crate::socket_util::new_tcp_listener(
                    address, 1024, None,
                )?));
            }
        }
        Ok(Self {
            device: Arc::new(device),
            listeners,
        })
    }

    pub(super) fn ports(&self) -> io::Result<[Option<u16>; 2]> {
        let mut ports = [None, None];
        for listener in &self.listeners {
            let address = listener.local_addr()?;
            ports[usize::from(address.is_ipv6())] = Some(address.port());
        }
        Ok(ports)
    }

    pub(crate) fn tcp_admission(config: &TunConfig) -> Option<Arc<Semaphore>> {
        config
            .resource_limits
            .tcp_connection_limit()
            .map(|limit| Arc::new(Semaphore::new(limit.min(Semaphore::MAX_PERMITS))))
    }

    pub(crate) async fn start(
        &self,
        config: &TunConfig,
        resolver: Arc<dyn Resolver>,
        admission: Option<Arc<Semaphore>>,
        tasks: &mut Vec<JoinHandle<io::Result<()>>>,
    ) -> io::Result<()> {
        let task = crate::tun::start_tun_server_retained(
            config.clone(),
            resolver.clone(),
            self.device.clone(),
            admission.clone(),
        )
        .await?;
        // Registers the TUN task for caller cleanup before fallible REDIRECT setup.
        tasks.push(task);
        tasks.extend(self.start_redirects(config, resolver, admission)?);
        Ok(())
    }

    pub(super) fn start_redirects(
        &self,
        config: &TunConfig,
        resolver: Arc<dyn Resolver>,
        admission: Option<Arc<Semaphore>>,
    ) -> io::Result<Vec<JoinHandle<io::Result<()>>>> {
        if self.listeners.is_empty() {
            return Ok(Vec::new());
        }
        let selector = crate::tun::proxy_selector(config, resolver.clone())?;
        Ok(self
            .listeners
            .iter()
            .map(|listener| {
                tokio::spawn(serve(
                    listener.clone(),
                    selector.clone(),
                    resolver.clone(),
                    admission.clone(),
                ))
            })
            .collect())
    }
}

async fn serve(
    listener: Arc<TcpListener>,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    admission: Option<Arc<Semaphore>>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (stream, source) = tokio::select! {
            result = accept(&listener) => result,
            _ = connections.join_next(), if !connections.is_empty() => continue,
        };
        let permit = match &admission {
            Some(admission) => match admission.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => continue,
            },
            None => None,
        };
        let target = match original_destination(&stream) {
            Ok(target) => target,
            Err(error) => {
                log::debug!("Rejected redirect connection: {error}");
                continue;
            }
        };
        let selector = selector.clone();
        let resolver = resolver.clone();
        connections.spawn(async move {
            let _permit = permit;
            let _ = crate::tun::handle_tcp_connection(
                stream,
                crate::address::NetLocation::from_ip_addr(target.ip(), target.port()),
                selector,
                resolver,
                Some(source),
            )
            .await;
        });
    }
}

async fn accept(listener: &TcpListener) -> (tokio::net::TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(connection) => return connection,
            Err(error) => {
                log::warn!("Redirect accept failed: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

fn original_destination(stream: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    let socket = socket2::SockRef::from(stream);
    let local = stream.local_addr()?;
    let original = if local.is_ipv6() {
        socket.original_dst_v6()?
    } else {
        socket.original_dst_v4()?
    };
    let target = original
        .as_socket()
        .ok_or_else(|| io::Error::other("invalid redirect address family"))?;
    if target == local
        || target.ip().is_loopback()
        || target.ip().is_unspecified()
        || target.ip().is_multicast()
        || target.port() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "connection was not redirected from an eligible destination",
        ));
    }
    crate::socket_policy::apply(socket, None)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redirect_accept_recovers_after_descriptor_exhaustion() -> io::Result<()> {
        const CHILD: &str = "SHOES_REDIRECT_EXHAUSTION";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "desktop::linux::ingress::tests::redirect_accept_recovers_after_descriptor_exhaustion", "--nocapture"])
                .env(CHILD, "1").output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("test result: ok. 1 passed;"),
                "redirect exhaustion test failed: {}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let limit = libc::rlimit {
            rlim_cur: 128,
            rlim_max: 128,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let mut files = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => files.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        let accept = accept(&listener);
        tokio::pin!(accept);
        assert!(futures::poll!(&mut accept).is_pending());
        drop(files);
        let (_, peer) = tokio::time::timeout(std::time::Duration::from_secs(2), accept).await?;
        assert_eq!(peer, client.local_addr()?);
        Ok(())
    }
}
