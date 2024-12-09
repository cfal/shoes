use std::sync::Arc;
use std::sync::OnceLock;

use argon2::Argon2;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::snell_udp_stream::SnellUdpStream;
use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::option_util::NoneOrOne;
use crate::shadowsocks::{
    ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::allocate_vec;

#[derive(Debug, Clone)]
struct SnellKey {
    password_bytes: Box<[u8]>,
    key_len: usize,
}

impl SnellKey {
    pub fn new(password: &str, key_len: usize) -> Self {
        Self {
            password_bytes: password.as_bytes().to_vec().into_boxed_slice(),
            key_len,
        }
    }
}

impl ShadowsocksKey for SnellKey {
    fn create_session_key(&self, salt: &[u8]) -> Box<[u8]> {
        static ARGON2: OnceLock<Argon2> = OnceLock::new();

        let instance = ARGON2.get_or_init(|| {
            // ref: https://github.com/icpz/open-snell/blob/master/components/aead/cipher.go#L48
            let params = argon2::Params::new(8, 3, 1, Some(32)).unwrap();
            Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        });

        let mut output = allocate_vec(32);
        instance
            .hash_password_into(&self.password_bytes, salt, &mut output)
            .unwrap();

        if self.key_len == 32 {
            output.into_boxed_slice()
        } else {
            output[0..self.key_len].to_vec().into_boxed_slice()
        }
    }
}

#[derive(Debug)]
pub struct SnellTcpHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

impl SnellTcpHandler {
    pub fn new(cipher_name: &str, password: &str) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.into();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self { cipher, key }
    }
}

const TCP_TUNNEL_RESPONSE: &[u8] = &[0x0];
const UDP_READY_RESPONSE: &[u8] = TCP_TUNNEL_RESPONSE;

#[async_trait]
impl TcpServerHandler for SnellTcpHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut server_stream = ShadowsocksStream::new(
            server_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            None,
        );

        let mut header = [0u8; 3];
        server_stream.read_exact(&mut header).await?;
        if header[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unexpected snell version: {}", header[0]),
            ));
        }

        let is_udp = match header[1] {
            0 => {
                // Ping command
                server_stream.write_all(&[0x01]).await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "responded to ping",
                ));
            }
            1 | 5 => {
                // 1 is Connect, used by Snell v3
                // 5 is Connect v2, used by Snell v2
                false
            }
            6 => {
                // UDP command
                true
            }
            unknown_command => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Got unknown command: {}", unknown_command),
                ));
            }
        };

        let mut buf = [0u8; 256];

        let client_id_len = header[2] as usize;
        if client_id_len > 0 {
            server_stream.read_exact(&mut buf[0..client_id_len]).await?;
        }

        if !is_udp {
            server_stream.read_exact(&mut header[0..1]).await?;

            let hostname_len = header[0] as usize;
            server_stream.read_exact(&mut buf[0..hostname_len]).await?;

            let hostname_str = match std::str::from_utf8(&buf[0..hostname_len]) {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode hostname: {}", e),
                    ));
                }
            };

            server_stream.read_exact(&mut header[0..2]).await?;
            let port = ((header[0] as u16) << 8) | (header[1] as u16);

            let remote_location = NetLocation::new(Address::from(hostname_str)?, port);

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),

                // flush the tunnel response
                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                initial_remote_data: None,
                override_proxy_provider: NoneOrOne::Unspecified,
            })
        } else {
            // write tunnel response.
            server_stream.write_all(UDP_READY_RESPONSE).await?;

            let udp_stream = SnellUdpStream::new(
                Box::new(server_stream),
                ShadowsocksStreamType::Aead.max_payload_len(),
            );

            Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(udp_stream),
                need_initial_flush: true,
                override_proxy_provider: NoneOrOne::Unspecified,
            })
        }
    }
}

#[async_trait]
impl TcpClientHandler for SnellTcpHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            self.cipher.salt_len(),
            self.key.clone(),
            None,
        ));

        let hostname_bytes = remote_location.address().to_string().into_bytes();

        if hostname_bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "hostname is too long",
            ));
        }

        client_stream
            .write_all(&[
                1, // snell version,
                1, // connect command,
                0, // client id length,
                hostname_bytes.len() as u8,
            ])
            .await?;

        client_stream.write_all(&hostname_bytes).await?;

        let port = remote_location.port();

        client_stream
            .write_all(&[(port >> 8) as u8, (port & 0xff) as u8])
            .await?;

        client_stream.flush().await?;

        let mut response = [0u8; 1];
        client_stream.read_exact(&mut response).await?;

        if response[0] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Got non-tunnel response ({})", response[0]),
            ));
        }

        Ok(TcpClientSetupResult { client_stream })
    }
}
