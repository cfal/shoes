//! The Hysteria2 client outbound.

use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use rand::RngExt;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientQuicConfig;
use crate::quic_outbound::QuicOutboundSettings;
use crate::quic_outbound::connection::LiveConnection;
use crate::quic_stream::QuicStream;
use crate::quic_transport::obfs::Obfuscator;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

use super::auth::Hysteria2Authenticator;
use super::frame::{encode_tcp_request, parse_tcp_response, random_padding};

/// Largest TCP response we will buffer before giving up. Status, message and
/// padding together cannot legitimately approach this.
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

pub struct Hysteria2Connector {
    connection: LiveConnection,
    authenticator: Arc<Hysteria2Authenticator>,
    udp_enabled: bool,
}

impl std::fmt::Debug for Hysteria2Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Connector")
            .field("server", &self.connection.settings().server)
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl Hysteria2Connector {
    pub fn new(
        server: NetLocation,
        password: String,
        udp_enabled: bool,
        quic: ClientQuicConfig,
        bind_interface: Option<String>,
        obfs: Option<Arc<dyn Obfuscator>>,
    ) -> Self {
        let authenticator = Arc::new(Hysteria2Authenticator::new(password));
        let settings = QuicOutboundSettings {
            server,
            quic,
            bind_interface,
            obfs,
            default_alpn: "h3",
        };
        Self {
            connection: LiveConnection::new(settings, authenticator.clone()),
            authenticator,
            udp_enabled,
        }
    }

    /// Open a bidirectional stream and complete the TCP request exchange,
    /// retrying once if the connection turns out to have died in the window
    /// between being handed out and being used.
    ///
    /// That window is real and unavoidable: `get` can only report the
    /// connection was open when it looked, and a server that went away in the
    /// meantime should cost one reconnect, not a failed request.
    async fn open_tcp_stream(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &str,
    ) -> std::io::Result<(QuicStream, Vec<u8>)> {
        match self.open_tcp_stream_once(resolver, address).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                debug!("Hysteria2: connection died while opening a stream; retrying once");
                self.open_tcp_stream_once(resolver, address).await
            }
            other => other,
        }
    }

    /// Returns the stream and anything read past the response, which already
    /// belongs to the target's reply.
    ///
    /// A connection-level failure is reported as `ConnectionAborted` so the
    /// caller above can tell it apart from the server refusing the target.
    async fn open_tcp_stream_once(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &str,
    ) -> std::io::Result<(QuicStream, Vec<u8>)> {
        let connection = self.connection.get(resolver).await?;

        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to open a QUIC stream: {e}"),
            )
        })?;

        let request = encode_tcp_request(address, &random_padding())?;
        send.write_all(&request).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to write the TCP request: {e}"),
            )
        })?;

        let mut buffered = Vec::with_capacity(64);
        let mut chunk = [0u8; 1024];
        loop {
            match parse_tcp_response(&buffered)? {
                Some((Ok(()), consumed)) => {
                    let leftover = buffered.split_off(consumed);
                    return Ok((QuicStream::from(send, recv), leftover));
                }
                Some((Err(message), _)) => {
                    let _ = send.finish();
                    return Err(std::io::Error::other(if message.is_empty() {
                        format!("server refused to connect to {address}")
                    } else {
                        format!("server refused to connect to {address}: {message}")
                    }));
                }
                None => {}
            }

            if buffered.len() >= MAX_RESPONSE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TCP response never completed",
                ));
            }

            let read = recv.read(&mut chunk).await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("failed to read the TCP response: {e}"),
                )
            })?;
            match read {
                Some(0) | None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed before the TCP response arrived",
                    ));
                }
                Some(n) => buffered.extend_from_slice(&chunk[..n]),
            }
        }
    }

    #[cfg(test)]
    fn connection_count(&self) -> usize {
        self.connection.connections_raised()
    }

    #[cfg(test)]
    fn close_for_test(&self) {
        self.connection.close_for_test();
    }
}

#[async_trait]
impl TerminalConnector for Hysteria2Connector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let address = target.location().to_string();
        debug!("Hysteria2: TCP connect to {address}");

        let (stream, early_data) = self.open_tcp_stream(resolver, &address).await?;

        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream) as Box<dyn AsyncStream>,
            early_data: (!early_data.is_empty()).then_some(early_data),
        })
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP is disabled for this Hysteria2 outbound (udp_enabled: false)",
            ));
        }

        let connection = self.connection.get(resolver).await?;

        // Checked after connecting, because the answer arrives with the
        // authentication rather than being known up front.
        if !self.authenticator.server_udp_enabled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the Hysteria2 server refused UDP (Hysteria-UDP: false)",
            ));
        }

        let address = target.into_location().to_string();
        let session_id = rand::rng().random::<u32>();
        debug!("Hysteria2: UDP session {session_id} to {address}");

        Ok(Box::new(super::udp::Hysteria2UdpSession::new(
            connection, session_id, address,
        )))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::testing::*;
    use crate::quic_transport::obfs::Salamander;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SERVER_PASSWORD: &str = "test password";

    fn salamander(password: &[u8]) -> Arc<dyn Obfuscator> {
        Arc::new(Salamander::new(password).unwrap())
    }

    async fn spawn_server(obfs: Option<Arc<dyn Obfuscator>>) -> (SocketAddr, TestCertificate) {
        let cert = generate_certificate();
        let resolver = test_resolver();
        let bind_address = reserve_udp_port();

        crate::hysteria2::start_hysteria2_server(
            crate::quic_transport::QuicListenerSettings {
                bind_address,
                quic_server_config: quic_server_config(&cert, &["h3".to_string()]),
                num_endpoints: 1,
                obfs,
            },
            Box::leak(SERVER_PASSWORD.to_string().into_boxed_str()),
            direct_selector(resolver.clone()),
            resolver,
            true,
        )
        .await
        .unwrap();

        (bind_address, cert)
    }

    fn connector(
        server: SocketAddr,
        password: &str,
        obfs: Option<Arc<dyn Obfuscator>>,
    ) -> Hysteria2Connector {
        Hysteria2Connector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            password.to_string(),
            true,
            client_quic_config(),
            None,
            obfs,
        )
    }

    fn target(addr: SocketAddr) -> ResolvedLocation {
        NetLocation::from_str(&addr.to_string(), None)
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn test_tcp_round_trip() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();

        let connector = connector(server, SERVER_PASSWORD, None);
        let result = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap();

        let mut stream = result.client_stream;
        stream.write_all(b"hello through hysteria").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 22];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through hysteria");
    }

    #[tokio::test]
    async fn test_streams_share_one_authenticated_connection() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        for i in 0..3 {
            let mut stream = connector
                .connect_tcp(&resolver, target(echo))
                .await
                .unwrap()
                .client_stream;
            let payload = format!("stream {i}");
            stream.write_all(payload.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes());
        }

        assert_eq!(
            connector.connection_count(),
            1,
            "every stream must reuse the one authenticated connection"
        );
    }

    #[tokio::test]
    async fn test_wrong_password_is_a_clear_error() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, "the wrong password", None);

        let err = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect_tcp(&resolver, target(echo)),
        )
        .await
        .expect("must fail rather than hang")
        .err()
        .expect("a wrong password must not connect")
        .to_string();

        assert!(
            err.contains("233") || err.to_lowercase().contains("auth"),
            "error should say authentication failed, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_reconnects_after_the_connection_is_lost() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        let mut stream = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap()
            .client_stream;
        stream.write_all(b"one").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(connector.connection_count(), 1);

        connector.close_for_test();

        let mut stream = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap()
            .client_stream;
        stream.write_all(b"two").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"two");
        assert_eq!(
            connector.connection_count(),
            2,
            "a dead connection must be replaced, not reused"
        );
    }

    #[tokio::test]
    async fn test_tcp_round_trip_with_obfuscation() {
        let password = b"obfuscation password";
        let (server, _cert) = spawn_server(Some(salamander(password))).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();

        let connector = connector(server, SERVER_PASSWORD, Some(salamander(password)));
        let mut stream = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap()
            .client_stream;

        stream.write_all(b"obfuscated").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"obfuscated");
    }

    /// A mismatched obfuscation password cannot produce a diagnosis, and this
    /// test pins that rather than wishing otherwise. Neither side can decode
    /// the other's packets, so nothing comes back and the client waits out its
    /// handshake timeout. To a user it is indistinguishable from an
    /// unreachable server, which is worth saying in the documentation.
    #[tokio::test]
    async fn test_obfuscation_mismatch_never_connects() {
        let (server, _cert) = spawn_server(Some(salamander(b"server password"))).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(
            server,
            SERVER_PASSWORD,
            Some(salamander(b"client password")),
        );

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connector.connect_tcp(&resolver, target(echo)),
        )
        .await;

        match result {
            // Timed out, still trying: the expected shape of this failure.
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("mismatched obfuscation passwords must never connect"),
        }
    }

    /// Send one datagram through a session and read the reply back.
    async fn udp_exchange(
        stream: &mut Box<dyn AsyncMessageStream>,
        payload: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};

        std::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_write_message(cx, payload))
            .await?;

        let mut buf = vec![0u8; 65535];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        tokio::time::timeout(
            Duration::from_secs(10),
            std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut *stream).poll_read_message(cx, &mut read_buf)
            }),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no reply arrived"))??;

        Ok(read_buf.filled().to_vec())
    }

    #[tokio::test]
    async fn test_udp_round_trip() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let reply = udp_exchange(&mut stream, b"udp hello").await.unwrap();
        assert_eq!(reply, b"udp hello");
    }

    #[tokio::test]
    async fn test_udp_carries_several_packets_over_one_session() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        for i in 0..4u8 {
            let payload = vec![i; 32];
            let reply = udp_exchange(&mut stream, &payload).await.unwrap();
            assert_eq!(reply, payload, "packet {i}");
        }
    }

    /// Larger than a QUIC datagram, so the client has to fragment it and the
    /// server has to put it back together before forwarding.
    #[tokio::test]
    async fn test_large_udp_payload_is_fragmented_and_reassembled() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let payload: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let reply = udp_exchange(&mut stream, &payload).await.unwrap();
        assert_eq!(reply, payload);
    }

    #[tokio::test]
    async fn test_udp_round_trip_with_obfuscation() {
        let password = b"obfuscation password";
        let (server, _cert) = spawn_server(Some(salamander(password))).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, Some(salamander(password)));

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let reply = udp_exchange(&mut stream, b"obfuscated udp").await.unwrap();
        assert_eq!(reply, b"obfuscated udp");
    }

    #[tokio::test]
    async fn test_udp_is_refused_when_the_client_disabled_it() {
        let (server, _cert) = spawn_server(None).await;
        let resolver = test_resolver();
        let connector = Hysteria2Connector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            SERVER_PASSWORD.to_string(),
            false,
            client_quic_config(),
            None,
            None,
        );

        assert!(!connector.supports_udp());
        let err = connector
            .connect_udp_bidirectional(&resolver, target(server))
            .await
            .err()
            .expect("UDP must be refused when the client disabled it")
            .to_string();
        assert!(err.contains("udp_enabled"), "{err}");
    }
}
