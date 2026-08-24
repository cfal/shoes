//! FFI (Foreign Function Interface) for mobile platforms.
//!
//! This module provides C-compatible functions that can be called from
//! Android (via JNI) and iOS (via Swift/ObjC).
//!
//! # Android Usage
//!
//! ```kotlin
//! // Load native library
//! System.loadLibrary("shoes")
//!
//! // Declare native methods
//! external fun shoesInit(logLevel: String): Int
//! external fun shoesStartTun(
//!     fd: Int,
//!     configYaml: String,
//!     protectCallback: (Int) -> Boolean
//! ): Long
//! external fun shoesStop(handle: Long)
//! ```
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
//! - `shoes_start` / `shoes_start_tun` starts a background thread for the TUN service
//! - `shoes_stop` signals shutdown and waits for cleanup

// Common utilities shared between the Apple and Android surfaces
#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos", test))]
mod common;

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::*;

// macOS as well as iOS. A Network Extension provider on macOS receives its
// descriptor from packetFlow exactly as on iOS, and the code that consumes it
// -- TunServerConfig::raw_fd, and the macos arm already present in
// src/tun/mod.rs -- is written and shipping. The desktop client's privileged
// host is that provider, and it is Swift, so it wants this C API rather than
// the Rust one in crate::control.
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod ios;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub use ios::*;

// Re-export for platforms with no packet-tunnel host (stub implementations)
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
mod stub;

#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "macos")))]
pub use stub::*;
