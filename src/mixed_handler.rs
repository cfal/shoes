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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::resolver::NativeResolver;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn handler() -> MixedTcpServerHandler {
        MixedTcpServerHandler::new(
            Some(("user".into(), "password".into())),
            false,
            "0.0.0.0".parse().unwrap(),
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(NativeResolver::new()),
        )
    }

    fn socks_request(password: &[u8]) -> Vec<u8> {
        let mut request = b"\x05\x02\x00\x02\x01\x04user".to_vec();
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        request.extend_from_slice(b"\x05\x01\x00\x03\x0bexample.com\x01\xbbpayload");
        request
    }

    #[tokio::test]
    async fn coalesced_http_and_socks_preserve_destination_and_payload() {
        let token = BASE64.encode("user:password");
        let http_request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\npayload"
        )
        .into_bytes();
        for (request, auth_response) in [
            (http_request, &b""[..]),
            (socks_request(b"password"), &b"\x05\x02\x01\x00"[..]),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            let result = handler()
                .setup_server_stream(Box::new(server))
                .await
                .unwrap();
            let TcpServerSetupResult::TcpForward {
                remote_location,
                initial_remote_data,
                ..
            } = result
            else {
                panic!("expected TCP forwarding");
            };
            assert_eq!(
                remote_location,
                NetLocation::from_str("example.com:443", None).unwrap()
            );
            assert_eq!(initial_remote_data.as_deref(), Some(&b"payload"[..]));
            let mut response = vec![0; auth_response.len()];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, auth_response);
        }
    }

    #[tokio::test]
    async fn neither_protocol_can_bypass_configured_authentication() {
        for request in [
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n".to_vec(),
            socks_request(b"wrong"),
            b"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb".to_vec(),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            let error = handler().setup_server_stream(Box::new(server)).await.err().unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}
