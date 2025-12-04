//! Platform-specific interface for TUN operations.
//!
//! This module provides traits and types for platform-specific functionality
//! required by the TUN server, particularly for mobile platforms (Android/iOS).
//!
//! # Android Socket Protection
//!
//! On Android, when a VPN is active, all outbound connections are routed through
//! the VPN tunnel. This creates a problem: connections to the upstream proxy server
//! would also be routed through the VPN, creating an infinite loop.
//!
//! To prevent this, Android's `VpnService` provides a `protect(fd)` method that
//! excludes a socket from VPN routing. The [`SocketProtector`] trait allows the
//! Android app to provide this functionality to the Rust code.
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
use std::sync::Arc;

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

/// Platform callbacks for TUN operations.
///
/// This trait provides platform-specific callbacks that the TUN server uses
/// to communicate with the mobile app.
pub trait PlatformCallbacks: Send + Sync {
    /// Called when the TUN service has started successfully.
    fn on_started(&self);

    /// Called when the TUN service has stopped.
    ///
    /// # Arguments
    /// * `error` - If the service stopped due to an error, the error message.
    ///             `None` if the service stopped normally.
    fn on_stopped(&self, error: Option<String>);

    /// Called periodically with traffic statistics.
    ///
    /// # Arguments
    /// * `upload_bytes` - Total bytes uploaded since start.
    /// * `download_bytes` - Total bytes downloaded since start.
    fn on_traffic_update(&self, upload_bytes: u64, download_bytes: u64);
}

/// No-op platform callbacks for standalone/CLI usage.
#[derive(Debug, Clone, Default)]
pub struct NoOpPlatformCallbacks;

impl PlatformCallbacks for NoOpPlatformCallbacks {
    fn on_started(&self) {}
    fn on_stopped(&self, _error: Option<String>) {}
    fn on_traffic_update(&self, _upload_bytes: u64, _download_bytes: u64) {}
}

/// Combined platform interface for TUN operations.
///
/// This bundles socket protection and platform callbacks together.
pub struct PlatformInterface {
    /// Socket protector for Android VPN protection.
    pub socket_protector: Arc<dyn SocketProtector>,
    /// Platform callbacks for status updates.
    pub callbacks: Arc<dyn PlatformCallbacks>,
}

impl Default for PlatformInterface {
    fn default() -> Self {
        Self {
            socket_protector: Arc::new(NoOpSocketProtector),
            callbacks: Arc::new(NoOpPlatformCallbacks),
        }
    }
}

impl PlatformInterface {
    /// Create a new platform interface with custom protector and callbacks.
    pub fn new(
        socket_protector: Arc<dyn SocketProtector>,
        callbacks: Arc<dyn PlatformCallbacks>,
    ) -> Self {
        Self {
            socket_protector,
            callbacks,
        }
    }

    /// Create a platform interface with only socket protection.
    pub fn with_protector(socket_protector: Arc<dyn SocketProtector>) -> Self {
        Self {
            socket_protector,
            callbacks: Arc::new(NoOpPlatformCallbacks),
        }
    }
}

// On Android, sockets need protection from VPN routing. This global protector
// provides a callback for the connection infrastructure.
//
// TODO: For a cleaner design, pass SocketProtector through the connection
// chain (similar to shadowsocks-rust's ConnectOpts). This global approach
// is simpler but less elegant.

use std::sync::RwLock;

static GLOBAL_SOCKET_PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

/// Set the global socket protector for Android VPN protection.
///
/// This should be called before starting the TUN service on Android.
/// Can be called multiple times (e.g., on VPN reconnect) - replaces the previous protector.
/// On other platforms, this can be left unset (no-op behavior).
pub fn set_global_socket_protector(protector: Arc<dyn SocketProtector>) {
    *GLOBAL_SOCKET_PROTECTOR.write().unwrap() = Some(protector);
}

/// Get the global socket protector.
///
/// Returns the set protector, or a no-op protector if none was set.
pub fn get_global_socket_protector() -> Arc<dyn SocketProtector> {
    GLOBAL_SOCKET_PROTECTOR
        .read()
        .unwrap()
        .clone()
        .unwrap_or_else(|| Arc::new(NoOpSocketProtector))
}

/// Protect a socket using the global protector.
///
/// This is a convenience function for use in socket creation code.
///
/// # Arguments
/// * `fd` - The raw file descriptor to protect.
///
/// # Returns
/// * `Ok(())` if protection succeeded or no protector is set.
/// * `Err(...)` if protection failed.
#[cfg(unix)]
pub fn protect_socket(fd: RawFd) -> io::Result<()> {
    get_global_socket_protector().protect(fd)
}

/// Protect a socket using the global protector (non-Unix stub).
#[cfg(not(unix))]
pub fn protect_socket(fd: i32) -> io::Result<()> {
    get_global_socket_protector().protect(fd)
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
    fn test_fn_protector_error() {
        let protector = FnSocketProtector::new(|_fd| {
            Err(io::Error::new(io::ErrorKind::Other, "protection failed"))
        });
        assert!(protector.protect(42).is_err());
    }
}
