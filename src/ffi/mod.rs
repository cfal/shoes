//! FFI (Foreign Function Interface) for mobile platforms.
//!
//! This module provides C-compatible functions that can be called from
//! Android (via JNI) and iOS (via Swift/ObjC).
//!
//! # Android Usage
//!
//! Apps supply `com.shoesproxy.ShoesNative` declarations matching the JNI exports
//! in `android.rs`. The `start` method takes YAML containing the TUN `device_fd`
//! and a callback object exposing `protect(fd: Int): Boolean`.
//!
//! # iOS Usage
//!
//! ```swift
//! // Initialize
//! shoes_init("info")
//!
//! // Start VPN
//! let handle = shoes_start(configYaml, protectCallback)
//!
//! // Stop VPN
//! shoes_stop(handle)
//! ```
//!
//! # Thread Safety
//!
//! - `shoes_init` must be called once before any other function
//! - `shoes_start` / Android `start` starts a background runtime for the TUN service
//! - `shoes_stop` signals shutdown and waits for cleanup

// Common utilities shared between iOS and Android
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
#[cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]
mod common;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(any(target_os = "ios", all(test, unix, feature = "ffi")))]
mod ios;

#[cfg(target_os = "ios")]
pub use ios::*;

// Re-export for non-mobile platforms (stub implementations)
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod stub;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use stub::*;
