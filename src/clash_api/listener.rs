use std::io;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};

use super::ApiState;
use crate::config::{BindLocation, ClashApiConfig};

pub(super) enum Bound {
    Tcp(tokio::net::TcpListener, Arc<ClashApiConfig>),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, Arc<ClashApiConfig>, SocketOwner),
}

pub(super) async fn bind(configs: &[ClashApiConfig]) -> io::Result<Vec<Bound>> {
    let mut bound = Vec::new();
    for config in configs {
        println!("Starting Clash API controller at {}", config.bind);
        let config = Arc::new(config.clone());
        match &config.bind {
            BindLocation::Address(addresses) => {
                let addresses = addresses.clone();
                let sockets = tokio::task::spawn_blocking(move || {
                    let mut sockets = Vec::new();
                    for address in addresses.iter() {
                        sockets.extend(address.to_socket_addrs()?);
                    }
                    Ok::<_, io::Error>(sockets)
                })
                .await
                .map_err(io::Error::other)??;
                for socket in sockets {
                    if bound.len() >= 16 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Clash API exceeds 16 sockets",
                        ));
                    }
                    if !socket.ip().is_loopback() {
                        log::warn!(
                            "Clash API is exposed on plaintext TCP at {socket}; use a firewall and TLS termination"
                        );
                    }
                    bound.push(Bound::Tcp(
                        tokio::net::TcpListener::bind(socket).await?,
                        config.clone(),
                    ));
                }
            }
            #[cfg(unix)]
            BindLocation::Path(path) => {
                if bound.len() >= 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Clash API exceeds 16 sockets",
                    ));
                }
                let (listener, owner) = SocketOwner::bind(path).await?;
                bound.push(Bound::Unix(listener, config.clone(), owner));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported Clash API listener",
                ));
            }
        }
    }
    Ok(bound)
}

pub(super) async fn serve(bound: Bound, state: Arc<ApiState>) {
    match bound {
        Bound::Tcp(listener, config) => loop {
            let accepted = tokio::select! { _ = state.cancel.cancelled() => break, result = listener.accept() => result };
            admit(accepted.map(|(stream, _)| stream), "TCP", &config, &state).await;
        },
        #[cfg(unix)]
        Bound::Unix(listener, config, _owner) => loop {
            let accepted = tokio::select! { _ = state.cancel.cancelled() => break, result = listener.accept() => result };
            admit(accepted.map(|(stream, _)| stream), "Unix", &config, &state).await;
        },
    }
}

async fn admit<T>(
    accepted: io::Result<T>,
    transport: &str,
    config: &Arc<ClashApiConfig>,
    state: &Arc<ApiState>,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let stream = match accepted {
        Ok(stream) => stream,
        Err(error) => {
            log::warn!("Clash API {transport} accept failed: {error}");
            tokio::time::sleep(Duration::from_millis(100)).await;
            return;
        }
    };
    if let Ok(permit) = state.runtime.connections.clone().try_acquire_owned() {
        state
            .tasks
            .spawn(connection(stream, config.clone(), state.clone(), permit));
    }
}

async fn connection<T>(
    stream: T,
    config: Arc<ClashApiConfig>,
    state: Arc<ApiState>,
    permit: tokio::sync::OwnedSemaphorePermit,
) where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let cancelled = state.cancel.child_token();
    let permit = Arc::new(permit);
    let service = service_fn({
        let state = state.clone();
        let cancelled = cancelled.clone();
        move |request| {
            super::router::serve(
                request,
                config.clone(),
                state.clone(),
                cancelled.clone(),
                permit.clone(),
            )
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15))
        .max_buf_size(64 * 1024);
    tokio::select! { _ = cancelled.cancelled() => {}, _ = builder.serve_connection(TokioIo::new(stream),service).with_upgrades() => {} }
}

#[cfg(unix)]
pub(super) struct SocketOwner {
    path: std::path::PathBuf,
    lock: std::fs::File,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SocketOwner {
    async fn bind(path: &std::path::Path) -> io::Result<(tokio::net::UnixListener, Self)> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
        let path = crate::control::store::absolute_path(path)?;
        let parent = std::fs::metadata(path.parent().unwrap())?;
        let uid = unsafe { libc::geteuid() };
        if parent.uid() != uid || parent.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Clash Unix socket parent must be private and owned by the current user",
            ));
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(crate::control::store::lock_path(&path))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe Clash Unix socket ownership lock",
            ));
        }
        lock.try_lock().map_err(io::Error::other)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket() || metadata.uid() != uid {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "refusing to replace a non-owned socket path",
                    ));
                }
                match tokio::net::UnixStream::connect(&path).await {
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        let current = std::fs::symlink_metadata(&path)?;
                        if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "socket path changed during stale check",
                            ));
                        }
                        std::fs::remove_file(&path)?;
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "Clash Unix socket is active or cannot be proven stale",
                        ));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = tokio::net::UnixListener::bind(&path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        let owner = Self {
            path,
            lock,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(&owner.path, std::fs::Permissions::from_mode(0o600))?;
        Ok((listener, owner))
    }
}

#[cfg(unix)]
impl Drop for SocketOwner {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
        let _ = self.lock.unlock();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    #[tokio::test]
    async fn bind_enforces_socket_limit_for_unix_after_tcp() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("api.sock");
        let tcp: ClashApiConfig =
            serde_yaml::from_str("clash_api_address: '127.0.0.1:0'\nsecret: test").unwrap();
        let unix = ClashApiConfig {
            bind: BindLocation::Path(path.clone()),
            ..tcp.clone()
        };
        let mut configs = vec![tcp; 16];
        configs.push(unix);
        let error = bind(&configs)
            .await
            .err()
            .expect("17 sockets must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn unix_socket_ownership_preserves_files_and_reclaims_only_stale_sockets() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("api.sock");
        std::fs::write(&path, b"keep").unwrap();
        assert!(SocketOwner::bind(&path).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(directory.path().join("absent"), &path).unwrap();
        assert!(SocketOwner::bind(&path).await.is_err());
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        std::fs::remove_file(&path).unwrap();
        let active = tokio::net::UnixListener::bind(&path).unwrap();
        assert!(SocketOwner::bind(&path).await.is_err());
        drop(active);
        let (listener, mut owner) = SocketOwner::bind(&path).await.unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(SocketOwner::bind(&path).await.is_err());
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        // Models inode reuse without depending on the filesystem's allocation order.
        owner.inode = std::fs::symlink_metadata(&path).unwrap().ino();
        drop(owner);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    }

    #[tokio::test]
    async fn unix_socket_cleanup_preserves_replacement_sockets() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("api.sock");
        let (listener, owner) = SocketOwner::bind(&path).await.unwrap();
        // Keeps the original inode allocated while replacing its path.
        std::fs::rename(&path, directory.path().join("retired.sock")).unwrap();
        let replacement = tokio::net::UnixListener::bind(&path).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.dev(), owner.device);
        assert_ne!(metadata.ino(), owner.inode);
        drop(owner);
        let retained = std::fs::symlink_metadata(&path).unwrap();
        assert!(retained.file_type().is_socket());
        assert_eq!(retained.ino(), metadata.ino());
        drop(replacement);
        drop(listener);
    }
}
