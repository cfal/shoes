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
//! Android apps supply their own JNI declarations matching `src/ffi/android.rs`
//! and manage the VPN service and socket-protection callback. See the README's
//! Mobile Embedding section for the native build and integration contract.
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

// This module tree backs both the shoes binary, through `cli`, and FFI/mobile
// integration.
mod address;
mod anytls;
mod async_stream;
mod buf_reader;
mod certificates;
mod clash_api;
mod client_proxy_chain;
mod client_proxy_selector;
mod control;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod desktop;
pub mod dns;
mod file_watcher;
mod h2mux;
mod http2;
mod http_handler;
mod hysteria2_server;
mod listener_tasks;
mod mixed_handler;
mod naiveproxy;
mod option_util;
mod port_forward_handler;
mod prepend_stream;
mod process;
mod quic_endpoint;
mod quic_server;
mod quic_stream;
mod reality;
pub mod resolver;
pub mod resources;
mod routing;
pub mod rule_set;
pub mod rules;
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
mod sniff;
mod socket_policy;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
#[cfg(target_os = "linux")]
mod splice;
mod stream_reader;
mod sudoku_mask;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
mod udp_fragments;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

/// Command-line entry point of the `shoes` binary.
pub mod cli;

/// Configuration types.
pub mod config;

/// Multi-output logging infrastructure.
pub mod logging;

/// TUN device support for VPN mode.
#[cfg(unix)]
pub mod tun;

#[cfg(unix)]
pub(crate) mod ip_stack;
#[cfg(unix)]
pub(crate) mod wireguard;

/// FFI bindings for mobile platforms.
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;
mod xhttp;
