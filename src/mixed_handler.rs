//! Mixed HTTP+SOCKS5 server handler.
//!
//! This module provides a server handler that auto-detects whether the client
//! is speaking HTTP or SOCKS5 based on the first byte of the connection:
//! - 0x05 = SOCKS5 (RFC 1928 specifies version byte first)
//! - Anything else = HTTP
//!
//! This is similar to mihomo's mixed-port feature.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::http_handler::setup_http_server_stream_inner;
use crate::resolver::Resolver;
use crate::socks_handler::{VER_SOCKS5, setup_socks_server_stream_inner};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

/// Mixed HTTP+SOCKS5 server handler.
///
/// Auto-detects the protocol from the first byte and delegates to the
/// appropriate handler implementation.
#[derive(Debug)]
pub struct MixedTcpServerHandler {
    /// Authentication for both HTTP and SOCKS5
    auth_info: Option<(String, String)>,
    /// Pre-computed HTTP auth token (base64 encoded)
    http_auth_token: Option<String>,
    /// Enable UDP functionality for SOCKS5 (UDP ASSOCIATE and UDP-over-TCP)
    udp_enabled: bool,
    /// IP address to bind UDP sockets on (same as TCP server)
    bind_ip: IpAddr,
    /// Proxy selector for outbound connections
    proxy_selector: Arc<ClientProxySelector>,
    /// DNS resolver
    resolver: Arc<dyn Resolver>,
}

impl MixedTcpServerHandler {
    /// Create a new mixed HTTP+SOCKS5 server handler.
    ///
    /// # Arguments
    /// * `auth_info` - Optional username/password for authentication (used for both HTTP and SOCKS5)
    /// * `udp_enabled` - Enable UDP functionality for SOCKS5 (UDP ASSOCIATE and UDP-over-TCP)
    /// * `bind_ip` - IP address to bind UDP sockets on (should match TCP server)
    /// * `proxy_selector` - Proxy selector for outbound connections
    /// * `resolver` - DNS resolver
    pub fn new(
        auth_info: Option<(String, String)>,
        udp_enabled: bool,
        bind_ip: IpAddr,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let http_auth_token = auth_info
            .as_ref()
            .map(|(username, password)| BASE64.encode(format!("{username}:{password}")));

        Self {
            auth_info,
            http_auth_token,
            udp_enabled,
            bind_ip,
            proxy_selector,
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for MixedTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        // Peek at first byte to detect protocol
        let first_byte = stream_reader.peek_u8(&mut server_stream).await?;

        if first_byte == VER_SOCKS5 {
            // SOCKS5 protocol
            log::debug!("Mixed handler: detected SOCKS5 protocol");

            let udp_bind_ip = if self.udp_enabled {
                Some(self.bind_ip)
            } else {
                None
            };

            setup_socks_server_stream_inner(
                self.auth_info.as_ref(),
                udp_bind_ip,
                &self.proxy_selector,
                &self.resolver,
                server_stream,
                stream_reader,
            )
            .await
        } else {
            // HTTP protocol
            log::debug!(
                "Mixed handler: detected HTTP protocol (first byte: 0x{:02x})",
                first_byte
            );

            setup_http_server_stream_inner(
                self.http_auth_token.as_deref(),
                server_stream,
                stream_reader,
                self.proxy_selector.clone(),
            )
            .await
        }
    }
}
