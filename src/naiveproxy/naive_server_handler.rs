//! NaiveProxy server handler
//!
//! This module provides the entry point for handling NaiveProxy connections
//! after TLS/Reality termination.

use std::io;
use std::sync::Arc;

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::crypto::CryptoTlsStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpServerSetupResult;
use crate::tls_server_handler::NaiveConfig;

use super::naive_hyper_service::run_naive_hyper_service;

/// Setup a NaiveProxy server stream after TLS/Reality termination
///
/// Determines HTTP version based on:
/// - Reality connections: always HTTP/2 (client already authenticated)
/// - TLS with ALPN "h2": HTTP/2 (NaiveProxy clients)
/// - TLS with other ALPN or None: HTTP/1.1 (fallback/static files only)
pub async fn setup_naive_server_stream<IO: AsyncStream + 'static>(
    tls_stream: CryptoTlsStream<IO>,
    naive_cfg: &NaiveConfig,
    effective_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<TcpServerSetupResult> {
    let use_h2 = tls_stream.is_reality() || tls_stream.alpn_protocol() == Some(b"h2");
    run_naive_hyper_service(tls_stream, naive_cfg, effective_selector, resolver, use_h2).await
}
