use std::sync::Arc;

use argon2::{Config as Argon2Config, ThreadMode, Variant, Version};
use async_trait::async_trait;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::snell_fixed_target_stream::SnellFixedTargetStream;
use super::snell_udp_stream::{SnellUdpClientStream, SnellUdpStream};
use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
use crate::resolver::Resolver;
use crate::shadowsocks::{
    ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::write_all;

// Snell protocol Argon2 parameters
// ref: https://github.com/icpz/open-snell/blob/master/components/aead/cipher.go#L48
const SNELL_ARGON2_CONFIG: Argon2Config<'static> = Argon2Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 8,  // 8 KB
    time_cost: 3, // 3 iterations
    lanes: 1,     // parallelism = 1
    thread_mode: ThreadMode::Sequential,
    secret: &[],
    ad: &[],
    hash_length: 32,
};

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
        let output = argon2::hash_raw(&self.password_bytes, salt, &SNELL_ARGON2_CONFIG).unwrap();

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
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl SnellServerHandler {
    pub fn new(
        cipher: ShadowsocksCipher,
        password: &str,
        udp_enabled: bool,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            udp_enabled,
            proxy_selector,
            resolver,
        }
    }
}

const TCP_TUNNEL_RESPONSE: &[u8] = &[0x0];
const UDP_READY_RESPONSE: &[u8] = TCP_TUNNEL_RESPONSE;

/// Snell uses a 16-byte AEAD salt for every cipher, unlike Shadowsocks where the
/// salt matches the key length. Reusing the Shadowsocks cipher's `salt_len()`
/// would read a 32-byte salt for chacha20-ietf-poly1305 - Snell's v1 default
/// cipher - so the handshake never decrypts against a real Snell peer. Both
/// open-snell and mihomo hardcode `SaltSize() == 16` regardless of cipher.
const SNELL_SALT_LEN: usize = 16;

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
            SNELL_SALT_LEN,
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

            // Checks for h2mux magic destination
            if let Address::Hostname(host) = remote_location.address()
                && host == MUX_DESTINATION_HOST
                && remote_location.port() == MUX_DESTINATION_PORT
            {
                // Send Snell success response before spawning h2mux session
                write_all(&mut server_stream, TCP_TUNNEL_RESPONSE).await?;
                server_stream.flush().await?;

                let proxy_selector = self.proxy_selector.clone();
                let resolver = self.resolver.clone();
                let udp_enabled = self.udp_enabled;

                let initial_data = stream_reader.unparsed_data_owned();

                tokio::spawn(async move {
                    if let Err(e) = handle_h2mux_session(
                        server_stream,
                        initial_data,
                        udp_enabled,
                        proxy_selector,
                        resolver,
                    )
                    .await
                    {
                        debug!("Snell h2mux session ended: {}", e);
                    }
                });

                return Ok(TcpServerSetupResult::AlreadyHandled);
            }

            Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: Box::new(server_stream),

                // flush the tunnel response
                need_initial_flush: true,
                connection_success_response: Some(TCP_TUNNEL_RESPONSE.to_vec().into_boxed_slice()),
                initial_remote_data: stream_reader.unparsed_data_owned(),
                proxy_selector: self.proxy_selector.clone(),
            })
        } else {
            write_all(&mut server_stream, UDP_READY_RESPONSE).await?;

            let udp_stream = SnellUdpStream::new(
                Box::new(server_stream),
                ShadowsocksStreamType::Aead.max_payload_len(),
            );

            Ok(TcpServerSetupResult::MultiDirectionalUdp {
                stream: Box::new(udp_stream),
                need_initial_flush: true,
                proxy_selector: self.proxy_selector.clone(),
            })
        }
    }
}

#[derive(Debug)]
pub struct SnellClientHandler {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
    udp_enabled: bool,
}

impl SnellClientHandler {
    pub fn new(cipher: ShadowsocksCipher, password: &str, udp_enabled: bool) -> Self {
        let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(SnellKey::new(
            password,
            cipher.algorithm().key_len(),
        )));
        Self {
            cipher,
            key,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpClientHandler for SnellClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let mut client_stream: Box<dyn AsyncStream> = Box::new(ShadowsocksStream::new(
            client_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            SNELL_SALT_LEN,
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

        let port = remote_location.location().port();

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

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let mut ss_stream = ShadowsocksStream::new(
            client_stream,
            ShadowsocksStreamType::Aead,
            self.cipher.algorithm(),
            SNELL_SALT_LEN,
            self.key.clone(),
            None,
        );

        write_all(
            &mut ss_stream,
            &[
                1, // snell version
                6, // UDP command
                0, // client id length
            ],
        )
        .await?;
        ss_stream.flush().await?;

        let mut response = [0u8; 1];
        let n = ss_stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF when reading UDP ready response",
            ));
        }

        if response[0] != 0 {
            return Err(std::io::Error::other(format!(
                "Got non-UDP-ready response ({})",
                response[0]
            )));
        }

        // Wraps multi-directional Snell UDP with a fixed target adapter for single-target mode.
        let max_payload_size = ShadowsocksStreamType::Aead.max_payload_len();
        let snell_udp_client_stream =
            SnellUdpClientStream::new(Box::new(ss_stream), max_payload_size);
        let fixed_target_stream =
            SnellFixedTargetStream::new(snell_udp_client_stream, target.into_location());

        Ok(Box::new(fixed_target_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::testing::{direct_selector, test_resolver};

    /// Drive shoes' own Snell client against its own server over loopback for the
    /// given cipher, and return the payload the server read back. This is the only
    /// end-to-end coverage of the Snell handshake; in particular it exercises the
    /// 16-byte salt against chacha20-ietf-poly1305 (whose key is 32 bytes), the
    /// combination the salt-length fix is about.
    async fn round_trip(cipher_name: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let target = NetLocation::from_str("1.2.3.4:80", None).unwrap();
        let sent = payload.to_vec();
        let cipher_name = cipher_name.to_string();
        let client_cipher_name = cipher_name.clone();
        let client = tokio::spawn(async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let cipher = ShadowsocksCipher::try_from(client_cipher_name.as_str()).unwrap();
            let handler = SnellClientHandler::new(cipher, "test-password", false);
            let mut stream = handler
                .setup_client_tcp_stream(Box::new(tcp), target.into())
                .await?
                .client_stream;
            stream.write_all(&sent).await?;
            stream.flush().await?;
            // Held open: a shutdown would race the server's read below.
            std::future::pending::<()>().await;
            Ok::<_, std::io::Error>(())
        });

        let (server_tcp, _) = listener.accept().await?;
        let resolver = test_resolver();
        let cipher = ShadowsocksCipher::try_from(cipher_name.as_str()).unwrap();
        let server = SnellServerHandler::new(
            cipher,
            "test-password",
            false,
            direct_selector(resolver.clone()),
            resolver,
        );

        let (mut server_stream, success_response, initial) =
            match server.setup_server_stream(Box::new(server_tcp)).await? {
                TcpServerSetupResult::TcpForward {
                    stream,
                    connection_success_response,
                    initial_remote_data,
                    ..
                } => (stream, connection_success_response, initial_remote_data),
                _ => return Err(std::io::Error::other("expected a TCP forward")),
            };

        // The caller is responsible for writing the tunnel-ready response; the
        // client's setup blocks reading it before it will send any payload.
        if let Some(response) = success_response {
            server_stream.write_all(&response).await?;
            server_stream.flush().await?;
        }

        let mut received = Vec::with_capacity(payload.len());
        if let Some(data) = initial {
            received.extend_from_slice(&data);
        }
        let mut buf = vec![0u8; 4096];
        while received.len() < payload.len() {
            let n = server_stream.read(&mut buf).await?;
            assert!(
                n > 0,
                "unexpected EOF at {} of {} bytes",
                received.len(),
                payload.len()
            );
            received.extend_from_slice(&buf[..n]);
        }

        client.abort();
        Ok(received)
    }

    #[tokio::test]
    async fn test_chacha20_round_trips_with_a_16_byte_salt() {
        let payload = b"snell over chacha20-ietf-poly1305 ".repeat(200);
        assert_eq!(
            round_trip("chacha20-ietf-poly1305", &payload)
                .await
                .unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn test_aes_128_gcm_round_trips() {
        let payload = b"snell over aes-128-gcm ".repeat(200);
        assert_eq!(round_trip("aes-128-gcm", &payload).await.unwrap(), payload);
    }
}
