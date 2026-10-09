use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksConfig;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::socks_handler::{CMD_CONNECT, CMD_UDP_ASSOCIATE, read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;

#[derive(Debug)]
struct ShadowsocksData {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    password_hash: Box<[u8]>,
    shadowsocks_data: Option<ShadowsocksData>,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    resolver: Option<Arc<dyn Resolver>>,
}

impl TrojanTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_inner(
            password,
            shadowsocks_config,
            Some(proxy_selector),
            Some(resolver),
        )
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        Self::new_inner(password, shadowsocks_config, None, None)
    }

    fn new_inner(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Option<Arc<ClientProxySelector>>,
        resolver: Option<Arc<dyn Resolver>>,
    ) -> Self {
        let password_hash = create_password_hash(password);
        let shadowsocks_data = shadowsocks_config.as_ref().map(|config| match config {
            ShadowsocksConfig::Legacy {
                cipher,
                password: shadowsocks_password,
            } => {
                let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                    shadowsocks_password,
                    cipher.algorithm().key_len(),
                )));
                ShadowsocksData {
                    cipher: *cipher,
                    key,
                }
            }
            ShadowsocksConfig::Aead2022 { .. } => {
                panic!("Trojan does not support shadowsocks 2022 ciphers (checked during config validation)")
            }
        });

        Self {
            password_hash,
            shadowsocks_data,
            proxy_selector,
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            server_stream = Box::new(ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        // read the entire line rather than exactly 56 bytes, so that we can masquerade as an HTTP server
        // and handle the request as if it were a HTTP request.
        // TODO: implement http response
        let received_hash = stream_reader.read_line_bytes(&mut server_stream).await?;
        if received_hash.len() != self.password_hash.len() {
            return Err(std::io::Error::other(format!(
                "Invalid password hash length, expected {}, got {}",
                self.password_hash.len(),
                received_hash.len()
            )));
        }

        // Use constant-time comparison to prevent timing attacks
        if self.password_hash.ct_eq(received_hash).unwrap_u8() == 0 {
            return Err(std::io::Error::other("Invalid password hash"));
        }

        let command_type = stream_reader.read_u8(&mut server_stream).await?;

        if command_type == CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP associate command is not supported",
            ));
        }

        if command_type != CMD_CONNECT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid command code: {command_type}"),
            ));
        }

        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        let request_suffix = stream_reader.read_u16_be(&mut server_stream).await?;
        if request_suffix != 0x0d0a {
            return Err(std::io::Error::other(format!(
                "Invalid request suffix bytes {request_suffix}"
            )));
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            let proxy_selector = self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler");
            let resolver = self.resolver.clone().expect("resolver required for h2mux");

            let initial_data = stream_reader.unparsed_data_owned();

            return Ok(TcpServerSetupResult::Session(Box::pin(async move {
                if let Err(e) = handle_h2mux_session(
                    server_stream,
                    initial_data,
                    false,
                    proxy_selector,
                    resolver,
                )
                .await
                {
                    debug!("Trojan h2mux session ended: {}", e);
                }
            })));
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

const CRLF_BYTES: [u8; 2] = [0x0d, 0x0a];

#[async_trait]
impl TcpClientHandler for TrojanTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        write_all(&mut client_stream, &self.password_hash).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        write_all(&mut client_stream, &[CMD_CONNECT]).await?;
        let location_bytes = write_location_to_vec(remote_location.location());
        write_all(&mut client_stream, &location_bytes).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        // TODO: Return true once setup_client_udp_bidirectional is implemented
        false
    }

    // TODO: Implement Trojan UDP-over-TCP
    // Trojan UDP uses a message-framed protocol where each packet has:
    // ATYPE + Address + Port + Length(2 bytes) + CRLF + Payload
    // async fn setup_client_udp_bidirectional(...)
}

fn create_password_hash(password: &str) -> Box<[u8]> {
    let digest = aws_lc_rs::digest::digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
    let mut hex_str = String::with_capacity(hash_bytes.len() * 2);
    for b in hash_bytes {
        hex_str.push_str(&format!("{b:02x}"));
    }
    let hex_bytes = hex_str.into_bytes().into_boxed_slice();
    if hex_bytes.len() != 56 {
        panic!(
            "Invalid password hash length, expected 56, got {}",
            hex_bytes.len()
        );
    }
    hex_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::resolver::NativeResolver;
    use std::io::ErrorKind;
    use tokio::io::AsyncReadExt;

    fn handler() -> TrojanTcpHandler {
        TrojanTcpHandler::new_server(
            "password",
            &None,
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(NativeResolver::new()),
        )
    }

    fn request(location: &NetLocation) -> Vec<u8> {
        // SHA-224("password"), independently fixed to verify client wire encoding too.
        let mut request =
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01".to_vec();
        request.extend_from_slice(&write_location_to_vec(location));
        request.extend_from_slice(b"\r\n");
        request
    }

    #[tokio::test]
    async fn ordinary_connect_preserves_coalesced_payload() {
        let location = NetLocation::from_str("example.com:443", None).unwrap();
        let mut request = request(&location);
        request.extend_from_slice(b"payload");
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
            connection_success_response,
            need_initial_flush,
            ..
        } = result
        else {
            panic!("expected TCP forwarding");
        };
        assert_eq!(remote_location, location);
        assert_eq!(initial_remote_data.as_deref(), Some(&b"payload"[..]));
        assert!(connection_success_response.is_none());
        assert!(!need_initial_flush);
    }

    #[tokio::test]
    async fn client_emits_hash_connect_address_and_suffix() {
        let location = NetLocation::from_str("example.com:443", None).unwrap();
        let (client, mut server) = tokio::io::duplex(1024);
        let result = TrojanTcpHandler::new_client("password", &None)
            .setup_client_tcp_stream(Box::new(client), location.clone().into())
            .await
            .unwrap();
        assert!(result.early_data.is_none());
        drop(result);
        let expected = request(&location);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn malformed_requests_never_produce_forwarding_work() {
        let valid = request(&NetLocation::from_str("example.com:443", None).unwrap());
        let mut cases = vec![(b"short\r\n".to_vec(), ErrorKind::Other)];
        let mut wrong_hash = valid.clone();
        wrong_hash[0] = b'0';
        cases.push((wrong_hash, ErrorKind::Other));
        for command in [CMD_UDP_ASSOCIATE, 0xff] {
            let mut request = valid.clone();
            request[58] = command;
            cases.push((request, ErrorKind::InvalidInput));
        }
        let mut bad_address = valid.clone();
        bad_address[59] = 0xff;
        cases.push((bad_address, ErrorKind::InvalidInput));
        cases.push((valid[..62].to_vec(), ErrorKind::ConnectionAborted));
        let mut bad_suffix = valid;
        *bad_suffix.last_mut().unwrap() = b'x';
        cases.push((bad_suffix, ErrorKind::Other));
        for (request, kind) in cases {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(
                handler()
                    .setup_server_stream(Box::new(server))
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                kind
            );
        }
    }

    #[tokio::test]
    async fn dropping_unpolled_mux_session_releases_transport() {
        let location = NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.into()),
            MUX_DESTINATION_PORT,
        );
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(&request(&location)).await.unwrap();
        client.shutdown().await.unwrap();
        let TcpServerSetupResult::Session(session) = handler()
            .setup_server_stream(Box::new(server))
            .await
            .unwrap()
        else {
            panic!("expected multiplexed session");
        };
        drop(session);
        let mut byte = [0];
        let read = std::pin::pin!(client.read(&mut byte));
        assert!(matches!(
            futures::poll!(read),
            std::task::Poll::Ready(Ok(0))
        ));
    }
}
