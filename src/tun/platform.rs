//! Platform-specific interface for TUN operations.
//!
//! This module provides traits and types for platform-specific functionality
//! required by the TUN server, particularly for mobile platforms (Android/iOS).
//!
//! Socket protection itself lives in [`crate::socket_protector`], which is not
//! gated to mobile targets so that the socket constructors can consult it. This
//! module re-exports it because the FFI reaches for it through `crate::tun`.

use std::sync::Arc;

pub use crate::socket_protector::{
    FnSocketProtector, NoOpSocketProtector, SocketProtector, get_global_socket_protector,
    protect_socket, set_global_socket_protector,
};

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
    ///   `None` if the service stopped normally.
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

// The protector's own tests moved with it, to crate::socket_protector.
