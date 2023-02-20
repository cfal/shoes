use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::config::ShadowsocksConfig;
use crate::option_util::NoneOrOne;
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::socks_handler::{read_location, write_location, CMD_CONNECT, CMD_UDP_ASSOCIATE};
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
struct ShadowsocksData {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

#[derive(Debug)]
pub struct TrojanTcpHandler {
    password_hash: Box<[u8]>,
    shadowsocks_data: Option<ShadowsocksData>,
}

impl TrojanTcpHandler {
    pub fn new(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        let password_hash = create_password_hash(&password);
        let shadowsocks_data = shadowsocks_config.as_ref().map(|config| {
            let ShadowsocksConfig {
                cipher,
                password: shadowsocks_password,
            } = config;
            let cipher: ShadowsocksCipher = cipher.as_str().into();
            let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                shadowsocks_password,
                cipher.algorithm().key_len(),
            )));
            ShadowsocksData { cipher, key }
        });

        Self {
            password_hash,
            shadowsocks_data,
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
                ShadowsocksStreamType::AEAD,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let mut received_hash = [0u8; 56];
        server_stream.read_exact(&mut received_hash).await?;
        for (b1, b2) in self.password_hash.iter().zip(received_hash.iter()) {
            if b1 != b2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid password hash",
                ));
            }
        }

        let mut request_prefix = [0u8; 3];
        server_stream.read_exact(&mut request_prefix).await?;

        if request_prefix[0] != 0x0d || request_prefix[1] != 0x0a {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Invalid request bytes (1) {} {}",
                    request_prefix[0], request_prefix[1]
                ),
            ));
        }

        if request_prefix[2] == CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "UDP associate command is not supported",
            ));
        }

        if request_prefix[2] != CMD_CONNECT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid command code: {}", request_prefix[2]),
            ));
        }

        let remote_location = read_location(&mut server_stream).await?;

        let mut request_suffix = [0u8; 2];
        server_stream.read_exact(&mut request_suffix).await?;

        if request_suffix[0] != 0x0d || request_suffix[1] != 0x0a {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid request bytes (2)",
            ));
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: None,
            override_proxy_provider: NoneOrOne::Unspecified,
        })
    }
}

const CRLF_BYTES: [u8; 2] = [0x0d, 0x0a];

#[async_trait]
impl TcpClientHandler for TrojanTcpHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::AEAD,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        client_stream.write_all(&self.password_hash).await?;
        client_stream.write_all(&CRLF_BYTES).await?;
        client_stream.write_all(&[CMD_CONNECT]).await?;
        write_location(&mut client_stream, &remote_location).await?;
        client_stream.write_all(&CRLF_BYTES).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult { client_stream })
    }
}

fn create_password_hash(password: &str) -> Box<[u8]> {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let hash_result = hasher.finalize();
    let hash_bytes = hash_result.as_slice();
    let mut hex_str = String::with_capacity(hash_bytes.len() * 2);
    for b in hash_bytes {
        hex_str.push_str(&format!("{:02x}", b));
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
