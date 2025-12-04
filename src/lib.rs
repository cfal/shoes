// This library shares code with the shoes binary. Server-side code appears "unused"
// in lib builds but is used by: (1) the binary for server mode, (2) FFI for mobile.
// The client/server code is intermingled within modules - a proper fix would require
// splitting into separate client/server modules or using feature flags.
#![allow(dead_code)]

//! shoes - A high-performance multi-protocol proxy server.
//!
//! This library provides the core functionality for shoes, enabling it to be
//! embedded in mobile applications (Android/iOS) as a VPN backend.
//!
//! # Features
//!
//! - **Multi-protocol support**: VLESS, VMess, Trojan, Shadowsocks, and more
//! - **TUN device support**: Virtual network interface for VPN mode
//! - **Proxy chaining**: Connect through multiple proxies
//! - **Flexible routing**: Rule-based traffic routing
//!
//! # Mobile Integration
//!
//! For Android, use the FFI module:
//!
//! ```kotlin
//! // Load native library
//! System.loadLibrary("shoes")
//!
//! // Initialize
//! ShoesNative.init("info")
//!
//! // Start VPN with TUN fd from VpnService
//! val handle = ShoesNative.startTun(tunFd, configYaml, protectCallback)
//!
//! // Stop VPN
//! ShoesNative.stop(handle)
//! ```
//!
//! For iOS, use the C FFI module from Swift:
//!
//! ```swift
//! // Initialize
//! shoes_init("info")
//!
//! // Start VPN with packet tunnel fd
//! let handle = shoes_start(configYaml, protectCallback)
//!
//! // Stop VPN
//! shoes_stop(handle)
//! ```
//!
//! # Platform Support
//!
//! - Linux (x86_64, aarch64)
//! - Android (arm64-v8a, armeabi-v7a, x86_64)
//! - iOS (arm64)

// Modules are declared here (mirroring main.rs) so the library crate can
// expose them for FFI/mobile integration.
mod address;
mod anytls;
mod async_stream;
mod buf_reader;
mod client_proxy_chain;
mod client_proxy_selector;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod http_handler;
mod hysteria2_server;
mod mixed_handler;
mod naiveproxy;
mod option_util;
mod port_forward_handler;
mod quic_server;
mod quic_stream;
mod reality;
mod reality_client_handler;
mod resolver;
mod routing;
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

/// Configuration types.
pub mod config;

/// TUN device support for VPN mode.
pub mod tun;

/// FFI bindings for mobile platforms.
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;
