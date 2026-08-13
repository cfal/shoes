//! Excluding sockets from the VPN route.
//!
//! When this process is the VPN on Android, the system routes every socket it
//! opens into the tunnel — including the ones the proxy uses to reach its
//! upstream server. Those loop back into the interface they are meant to feed.
//! `VpnService.protect(fd)` is Android's way out, and iOS has an equivalent;
//! the app supplies one through the FFI and it is installed here.
//!
//! Two things about this module are deliberate.
//!
//! It compiles everywhere, not only on mobile. The protector used to live
//! behind `cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))`
//! inside the TUN module, which meant that calling it from ordinary socket code
//! required repeating that gate at every site. Nobody did, so for a long time
//! exactly one socket in the whole program was protected. Unset, it costs one
//! read of an uncontended lock.
//!
//! And it is consulted inside the socket constructors rather than by their
//! callers, so a new outbound is protected because of where it was created
//! rather than because whoever added it remembered to.
//!
//! # Example (Android via JNI)
//!
//! ```ignore
//! // In Kotlin, implement a callback that calls VpnService.protect()
//! class SocketProtectorImpl(private val vpnService: VpnService) {
//!     fun protect(fd: Int): Boolean {
//!         return vpnService.protect(fd)
//!     }
//! }
//!
//! // Pass to Rust via FFI
//! shoesStartTun(config, tunFd, socketProtector)
//! ```

use std::io;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::{Arc, RwLock};

/// Socket protection callback for Android VPN.
///
/// On Android, this trait is implemented by the app to call `VpnService.protect(fd)`
/// on outbound sockets, preventing them from being routed through the VPN tunnel.
///
/// On other platforms, this can be a no-op implementation.
pub trait SocketProtector: Send + Sync {
    /// Protect a socket from VPN routing.
    ///
    /// # Arguments
    /// * `fd` - The raw file descriptor of the socket to protect.
    ///
    /// # Returns
    /// * `Ok(())` if protection succeeded.
    /// * `Err(...)` if protection failed (connection should be aborted).
    #[cfg(unix)]
    fn protect(&self, fd: RawFd) -> io::Result<()>;

    /// Protect a socket from VPN routing (non-Unix stub).
    #[cfg(not(unix))]
    fn protect(&self, fd: i32) -> io::Result<()>;
}

/// A no-op socket protector for platforms that don't need protection.
///
/// Used on Linux desktop and other non-VPN platforms.
#[derive(Debug, Clone, Default)]
pub struct NoOpSocketProtector;

impl SocketProtector for NoOpSocketProtector {
    #[cfg(unix)]
    fn protect(&self, _fd: RawFd) -> io::Result<()> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn protect(&self, _fd: i32) -> io::Result<()> {
        Ok(())
    }
}

/// A socket protector that calls a closure.
///
/// This is useful for creating protectors from FFI callbacks.
pub struct FnSocketProtector<F> {
    protect_fn: F,
}

impl<F> FnSocketProtector<F>
where
    F: Fn(i32) -> io::Result<()> + Send + Sync,
{
    /// Create a new function-based socket protector.
    pub fn new(f: F) -> Self {
        Self { protect_fn: f }
    }
}

impl<F> SocketProtector for FnSocketProtector<F>
where
    F: Fn(i32) -> io::Result<()> + Send + Sync,
{
    #[cfg(unix)]
    fn protect(&self, fd: RawFd) -> io::Result<()> {
        (self.protect_fn)(fd)
    }

    #[cfg(not(unix))]
    fn protect(&self, fd: i32) -> io::Result<()> {
        (self.protect_fn)(fd)
    }
}

// TODO: For a cleaner design, pass SocketProtector through the connection
// chain (similar to shadowsocks-rust's ConnectOpts). This global approach
// is simpler but less elegant.
static GLOBAL_SOCKET_PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

/// Set the global socket protector for Android VPN protection.
///
/// This should be called before starting the TUN service on Android.
/// Can be called multiple times (e.g., on VPN reconnect) - replaces the previous protector.
/// On other platforms, this can be left unset (no-op behavior).
pub fn set_global_socket_protector(protector: Arc<dyn SocketProtector>) {
    *GLOBAL_SOCKET_PROTECTOR.write().unwrap() = Some(protector);
}

/// Get the global socket protector, if one was installed.
pub fn get_global_socket_protector() -> Option<Arc<dyn SocketProtector>> {
    GLOBAL_SOCKET_PROTECTOR.read().unwrap().clone()
}

/// Protect a socket using the global protector.
///
/// Does nothing when no protector is installed, which is every platform that is
/// not acting as a VPN.
///
/// # Errors
/// Propagates the protector's failure. A socket the platform refused to protect
/// would be routed back into the tunnel, so the caller must not use it.
#[cfg(unix)]
pub fn protect_socket(fd: RawFd) -> io::Result<()> {
    match get_global_socket_protector() {
        Some(protector) => protector.protect(fd),
        None => Ok(()),
    }
}

/// Protect a socket using the global protector (non-Unix stub).
#[cfg(not(unix))]
pub fn protect_socket(fd: i32) -> io::Result<()> {
    match get_global_socket_protector() {
        Some(protector) => protector.protect(fd),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_protector() {
        let protector = NoOpSocketProtector;
        assert!(protector.protect(42).is_ok());
    }

    #[test]
    fn test_fn_protector() {
        let protector = FnSocketProtector::new(|fd| {
            assert_eq!(fd, 42);
            Ok(())
        });
        assert!(protector.protect(42).is_ok());
    }

    #[test]
    fn test_fn_protector_propagates_failure() {
        let protector = FnSocketProtector::new(|_fd| Err(io::Error::other("refused")));
        assert!(protector.protect(1).is_err());
    }
}
