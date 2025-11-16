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
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::{allocate_vec, write_all};

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
pub struct SnellServerHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    udp_enabled: bool,
    udp_num_sockets: usize,
}

impl SnellServerHandler {
    pub fn new(
        cipher_name: &str,
        password: &str,
        udp_enabled: bool,
        udp_num_sockets: usize,
    ) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.try_into().unwrap();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            udp_enabled,
            udp_num_sockets,
        }
    }
}

const TCP_TUNNEL_RESPONSE: &[u8] = &[0x0];
const UDP_READY_RESPONSE: &[u8] = TCP_TUNNEL_RESPONSE;

#[async_trait]
impl TcpServerHandler for SnellServerHandler {
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

        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        let version = stream_reader.read_u8(&mut server_stream).await?;
        if version != 1 {
            return Err(std::io::Error::other(format!(
                "unexpected snell version: {version}"
            )));
        }

        let command_type = stream_reader.read_u8(&mut server_stream).await?;
        let is_udp = match command_type {
            0 => {
                // Ping command
                write_all(&mut server_stream, &[0x01]).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::other("responded to ping"));
            }
            1 | 5 => {
                // 1 is Connect, used by Snell v3
                // 5 is Connect v2, used by Snell v2
                false
            }
            6 => {
                // UDP command
                if !self.udp_enabled {
                    return Err(std::io::Error::other("snell UDP requested but not enabled"));
                }
                true
            }
            unknown_command => {
                return Err(std::io::Error::other(format!(
                    "Got unknown command: {unknown_command}"
                )));
            }
        };

        let client_id_len = stream_reader.read_u8(&mut server_stream).await?;
        if client_id_len > 0 {
            stream_reader
                .read_slice(&mut server_stream, client_id_len as usize)
                .await?;
        }

        if !is_udp {
            let hostname_len = stream_reader.read_u8(&mut server_stream).await? as usize;

            let hostname_and_port_bytes = stream_reader
                .read_slice(&mut server_stream, hostname_len + 2)
                .await?;

            let hostname_str = match std::str::from_utf8(&hostname_and_port_bytes[0..hostname_len])
            {
                Ok(s) => s,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode hostname: {e}"),
                    ));
                }
            };

            let port =
                u16::from_be_bytes(hostname_and_port_bytes[hostname_len..].try_into().unwrap());

            let remote_location = NetLocation::new(Address::from(hostname_str)?, port);

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),

                // flush the tunnel response
                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                initial_remote_data: stream_reader.unparsed_data_owned(),
                override_proxy_provider: NoneOrOne::Unspecified,
            })
        } else {
            // write tunnel response.
            write_all(&mut server_stream, UDP_READY_RESPONSE).await?;

            let udp_stream = SnellUdpStream::new(
                Box::new(server_stream),
                ShadowsocksStreamType::Aead.max_payload_len(),
            );

            Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(udp_stream),
                need_initial_flush: true,
                override_proxy_provider: NoneOrOne::Unspecified,
                num_sockets: self.udp_num_sockets,
            })
        }
    }
}

#[derive(Debug)]
pub struct SnellClientHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

impl SnellClientHandler {
    pub fn new(cipher_name: &str, password: &str) -> Self {
        let cipher: ShadowsocksCipher = cipher_name.try_into().unwrap();
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self { cipher, key }
    }
}

#[async_trait]
impl TcpClientHandler for SnellClientHandler {
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
            return Err(std::io::Error::other("hostname is too long"));
        }

        write_all(
            &mut client_stream,
            &[
                1, // snell version,
                1, // connect command,
                0, // client id length,
                hostname_bytes.len() as u8,
            ],
        )
        .await?;

        write_all(&mut client_stream, &hostname_bytes).await?;

        let port = remote_location.port();

        write_all(
            &mut client_stream,
            &[(port >> 8) as u8, (port & 0xff) as u8],
        )
        .await?;

        client_stream.flush().await?;

        let mut response = [0u8; 1];
        let n = client_stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF when reading tunnel response",
            ));
        }

        if response[0] != 0 {
            return Err(std::io::Error::other(format!(
                "Got non-tunnel response ({})",
                response[0]
            )));
        }

        Ok(TcpClientSetupResult { client_stream })
    }
}
