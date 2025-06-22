use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
use tokio::io::AsyncWriteExt;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::config::ShadowsocksConfig;
use crate::option_util::NoneOrOne;
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::socks_handler::{read_location, write_location_to_vec, CMD_CONNECT, CMD_UDP_ASSOCIATE};
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{
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
}

impl TrojanTcpHandler {
    pub fn new(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        let password_hash = create_password_hash(password);
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

        for (b1, b2) in self.password_hash.iter().zip(received_hash.iter()) {
            if b1 != b2 {
                return Err(std::io::Error::other("Invalid password hash"));
            }
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
                format!("Invalid command code: {}", command_type),
            ));
        }

        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;

        let request_suffix = stream_reader.read_u16_be(&mut server_stream).await?;
        if request_suffix != 0x0d0a {
            return Err(std::io::Error::other(format!(
                "Invalid request suffix bytes {}",
                request_suffix
            )));
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
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
        let location_bytes = write_location_to_vec(&remote_location);
        write_all(&mut client_stream, &location_bytes).await?;
        write_all(&mut client_stream, &CRLF_BYTES).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult { client_stream })
    }
}

fn create_password_hash(password: &str) -> Box<[u8]> {
    let digest = aws_lc_rs::digest::digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
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
