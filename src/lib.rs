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
//! # Library Embedding
//!
//! Applications that run their own userspace packet stack have no TUN file
//! descriptor to hand to [`tun`] or the FFI. They can drive a client proxy
//! chain directly, opening one proxied connection per flow:
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use shoes::config::{ClientChainHop, ClientConfig, ConfigSelection};
//! use shoes::resolver::{NativeResolver, Resolver};
//! use shoes::tcp::chain_builder::build_client_proxy_chain;
//! use shoes::{NetLocation, OneOrSome, ResolvedLocation};
//!
//! # async fn example(client_yaml: &str) -> std::io::Result<()> {
//! let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
//! let client: ClientConfig = serde_yaml::from_str(client_yaml).map_err(std::io::Error::other)?;
//! let chain = build_client_proxy_chain(
//!     OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(client))),
//!     resolver.clone(),
//! );
//! let target = NetLocation::from_str("example.com:443", None)?;
//! let setup = chain.connect_tcp(ResolvedLocation::from(target), &resolver).await?;
//! // `setup.client_stream` is an `AsyncRead + AsyncWrite` stream to the target.
//! # Ok(())
//! # }
//! ```
//!
//! UDP flows use `connect_udp_bidirectional` on the same chain. Servers can be
//! started inside the caller's tokio runtime with
//! [`tcp::tcp_server::start_servers`] from configs validated by
//! [`config::create_server_configs`].
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
pub mod async_stream;
mod buf_reader;
pub mod client_proxy_chain;
mod client_proxy_selector;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
pub mod dns;
mod h2mux;
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
pub mod resolver;
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
pub mod tcp;
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

/// Multi-output logging infrastructure.
pub mod logging;

/// TUN device support for VPN mode.
#[cfg(unix)]
pub mod tun;

/// FFI bindings for mobile platforms.
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub mod ffi;

// Types needed to build a client proxy chain and address its targets when
// embedding the library (see "Library Embedding" above).
pub use address::{Address, NetLocation, ResolvedLocation};
pub use option_util::OneOrSome;
