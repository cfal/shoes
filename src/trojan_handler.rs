use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksConfig;
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
}

impl TrojanTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
    ) -> Self {
        Self::new_inner(password, shadowsocks_config, Some(proxy_selector))
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        Self::new_inner(password, shadowsocks_config, None)
    }

    fn new_inner(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Option<Arc<ClientProxySelector>>,
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
