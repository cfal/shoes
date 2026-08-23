//! The TUIC v5 client outbound.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::debug;
use rand::RngExt;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::{ClientQuicConfig, TuicUdpRelayMode};
use crate::quic_outbound::QuicOutboundSettings;
use crate::quic_outbound::connection::{ConnectionAuthenticator, LiveConnection};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

use super::frame::{encode_authenticate, encode_connect};

/// Derives the authentication token and sends the Authenticate command.
#[derive(Debug)]
struct TuicAuthenticator {
    uuid: [u8; 16],
    password: String,
}

#[async_trait]
impl ConnectionAuthenticator for TuicAuthenticator {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        // The token is exported from the live TLS session with the UUID as the
        // label and the raw password as the context, which is exactly what the
        // server computes to compare against.
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|e| {
                std::io::Error::other(format!("failed to export TUIC keying material: {e:?}"))
            })?;

        let mut stream = connection.open_uni().await.map_err(|e| {
            std::io::Error::other(format!("failed to open the TUIC auth stream: {e}"))
        })?;
        stream
            .write_all(&encode_authenticate(&self.uuid, &token))
            .await
            .map_err(|e| std::io::Error::other(format!("failed to send Authenticate: {e}")))?;
        stream
            .finish()
            .map_err(|e| std::io::Error::other(format!("failed to finish the auth stream: {e}")))?;

        // There is no response: the specification defines none. A wrong UUID or
        // token shows up later, as the server closing the connection.
        debug!("TUIC Authenticate sent");
        Ok(())
    }
}

pub struct TuicConnector {
    connection: LiveConnection,
    udp_enabled: bool,
    udp_relay_mode: TuicUdpRelayMode,
    heartbeat_interval: Duration,
}

impl std::fmt::Debug for TuicConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicConnector")
            .field("server", &self.connection.settings().server)
            .field("udp_relay_mode", &self.udp_relay_mode)
            .finish()
    }
}

impl TuicConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: NetLocation,
        uuid: &str,
        password: String,
        udp_enabled: bool,
        udp_relay_mode: TuicUdpRelayMode,
        heartbeat_interval: Duration,
        quic: ClientQuicConfig,
        bind_interface: Option<String>,
    ) -> std::io::Result<Self> {
        // parse_uuid hands back a Vec; the protocol field is exactly 16 bytes,
        // and pinning that in the type means the encoder cannot be handed
        // something of the wrong length.
        let uuid_bytes: [u8; 16] = crate::uuid_util::parse_uuid(uuid)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TUIC uuid is not a valid UUID: {e}"),
                )
            })?
            .try_into()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TUIC uuid did not decode to 16 bytes",
                )
            })?;

        let authenticator = Arc::new(TuicAuthenticator {
            uuid: uuid_bytes,
            password,
        });

        let settings = QuicOutboundSettings {
            server,
            quic,
            bind_interface,
            // TUIC has no obfuscation layer of its own.
            obfs: None,
            // TUIC has no port hopping in its protocol; offering the
            // setting would offer something no real server understands.
            port_hopping: None,
            default_alpn: "h3",
        };

        Ok(Self {
            connection: LiveConnection::new(settings, authenticator),
            udp_enabled,
            udp_relay_mode,
            heartbeat_interval,
        })
    }

    /// Open a stream and send Connect.
    ///
    /// Reported as `ConnectionAborted` when the connection itself failed, so
    /// the caller can tell that apart and retry once.
    async fn open_tcp_stream_once(
        &self,
        resolver: &Arc<dyn Resolver>,
        location: &NetLocation,
    ) -> std::io::Result<QuicStream> {
        let connection = self.connection.get(resolver).await?;

        let (mut send, recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to open a QUIC stream: {e}"),
            )
        })?;

        send.write_all(&encode_connect(location))
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    format!("failed to send Connect: {e}"),
                )
            })?;

        Ok(QuicStream::from(send, recv))
    }

    #[cfg(test)]
    fn connection_count(&self) -> usize {
        self.connection.connections_raised()
    }

    #[cfg(test)]
    pub(crate) fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    #[cfg(test)]
    pub(crate) fn udp_relay_mode(&self) -> TuicUdpRelayMode {
        self.udp_relay_mode
    }
}

#[async_trait]
impl TerminalConnector for TuicConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let location = target.into_location();
        debug!("TUIC: TCP connect to {location}");

        // One retry, for the window between the connection being handed out
        // and being used, in which the server can have gone away.
        let stream = match self.open_tcp_stream_once(resolver, &location).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                debug!("TUIC: connection died while opening a stream; retrying once");
                self.open_tcp_stream_once(resolver, &location).await?
            }
            other => other?,
        };

        // The server never answers a Connect. Payload follows the header
        // immediately, and a failure shows up as the stream being closed.
        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream) as Box<dyn AsyncStream>,
            early_data: None,
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
                "UDP is disabled for this TUIC outbound (udp_enabled: false)",
            ));
        }
        let connection = self.connection.get(resolver).await?;
        let location = target.into_location();
        let assoc_id: u16 = rand::rng().random();
        debug!("TUIC: UDP association {assoc_id} to {location}");

        Ok(Box::new(super::udp::TuicUdpSession::new(
            connection,
            assoc_id,
            location,
            self.udp_relay_mode,
            self.heartbeat_interval,
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
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_UUID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";
    const SERVER_PASSWORD: &str = "test password";

    async fn spawn_server() -> SocketAddr {
        let cert = generate_certificate();
        let resolver = test_resolver();
        let bind_address = reserve_udp_port();

        let uuid: &'static [u8] = Box::leak(
            crate::uuid_util::parse_uuid(TEST_UUID)
                .unwrap()
                .into_boxed_slice(),
        );

        crate::tuic::start_tuic_server(
            crate::quic_transport::QuicListenerSettings {
                bind_address,
                quic_server_config: quic_server_config(&cert, &["h3".to_string()]),
                num_endpoints: 1,
                obfs: None,
            },
            uuid,
            Box::leak(SERVER_PASSWORD.to_string().into_boxed_str()),
            direct_selector(resolver.clone()),
            resolver,
            false,
        )
        .await
        .unwrap();

        bind_address
    }

    fn connector(server: SocketAddr, uuid: &str, password: &str) -> TuicConnector {
        connector_with_mode(server, uuid, password, TuicUdpRelayMode::Native)
    }

    fn connector_with_mode(
        server: SocketAddr,
        uuid: &str,
        password: &str,
        mode: TuicUdpRelayMode,
    ) -> TuicConnector {
        TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            uuid,
            password.to_string(),
            true,
            mode,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
        )
        .unwrap()
    }

    fn target(addr: SocketAddr) -> ResolvedLocation {
        NetLocation::from_str(&addr.to_string(), None)
            .unwrap()
            .into()
    }

    #[test]
    fn test_rejects_a_malformed_uuid() {
        let err = TuicConnector::new(
            NetLocation::from_str("127.0.0.1:1", None).unwrap(),
            "not-a-uuid",
            "password".to_string(),
            true,
            TuicUdpRelayMode::Native,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
        )
        .expect_err("a malformed uuid must be refused at construction")
        .to_string();
        assert!(err.to_lowercase().contains("uuid"), "{err}");
    }

    #[test]
    fn test_keeps_its_configured_settings() {
        let connector = TuicConnector::new(
            NetLocation::from_str("127.0.0.1:1", None).unwrap(),
            TEST_UUID,
            "password".to_string(),
            true,
            TuicUdpRelayMode::Quic,
            Duration::from_millis(3000),
            client_quic_config(),
            None,
        )
        .unwrap();
        assert_eq!(connector.udp_relay_mode(), TuicUdpRelayMode::Quic);
        assert_eq!(connector.heartbeat_interval(), Duration::from_millis(3000));
    }

    #[tokio::test]
    async fn test_tcp_round_trip() {
        let server = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let result = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap();

        assert!(
            result.early_data.is_none(),
            "TUIC servers never answer Connect, so there is no early data"
        );

        let mut stream = result.client_stream;
        stream.write_all(b"hello through tuic").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through tuic");
    }

    #[tokio::test]
    async fn test_streams_share_one_authenticated_connection() {
        let server = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

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
        assert_eq!(connector.connection_count(), 1);
    }

    /// The protocol defines no response to Connect and no rejection for bad
    /// credentials, so a wrong password surfaces as the server closing the
    /// stream rather than as an error from connect_tcp.
    #[tokio::test]
    async fn test_wrong_password_cannot_relay() {
        let server = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, "the wrong password");

        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = connector
                .connect_tcp(&resolver, target(echo))
                .await?
                .client_stream;
            stream.write_all(b"ping").await?;
            stream.flush().await?;
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await
        })
        .await;

        match outcome {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("a wrong password must not relay traffic"),
            Err(_) => panic!("must fail rather than hang"),
        }
    }

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
    async fn test_udp_round_trip_in_native_mode() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let reply = udp_exchange(&mut stream, b"tuic udp").await.unwrap();
        assert_eq!(reply, b"tuic udp");
    }

    #[tokio::test]
    async fn test_udp_carries_several_packets_over_one_association() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        for i in 0..4u8 {
            let payload = vec![i; 48];
            let reply = udp_exchange(&mut stream, &payload).await.unwrap();
            assert_eq!(reply, payload, "packet {i}");
        }
    }

    #[tokio::test]
    async fn test_large_udp_payload_is_fragmented_and_reassembled() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, TEST_UUID, SERVER_PASSWORD);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let payload: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
        let reply = udp_exchange(&mut stream, &payload).await.unwrap();
        assert_eq!(reply, payload);
    }

    #[tokio::test]
    async fn test_udp_round_trip_in_quic_mode() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector =
            connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, TuicUdpRelayMode::Quic);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let reply = udp_exchange(&mut stream, b"tuic over streams")
            .await
            .unwrap();
        assert_eq!(reply, b"tuic over streams");
    }

    #[tokio::test]
    async fn test_quic_mode_carries_several_packets_over_one_association() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector =
            connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, TuicUdpRelayMode::Quic);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        for i in 0..4u8 {
            let payload = vec![i; 48];
            let reply = udp_exchange(&mut stream, &payload).await.unwrap();
            assert_eq!(reply, payload, "packet {i}");
        }
    }

    /// Larger than a QUIC datagram would carry. In this mode the packet still
    /// travels whole, because a stream has no datagram limit to fragment for.
    #[tokio::test]
    async fn test_quic_mode_carries_a_payload_past_the_datagram_limit() {
        let server = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector =
            connector_with_mode(server, TEST_UUID, SERVER_PASSWORD, TuicUdpRelayMode::Quic);

        let mut stream = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        let payload: Vec<u8> = (0..8000u32).map(|i| i as u8).collect();
        let reply = udp_exchange(&mut stream, &payload).await.unwrap();
        assert_eq!(reply, payload);
    }

    #[tokio::test]
    async fn test_udp_is_refused_when_the_client_disabled_it() {
        let server = spawn_server().await;
        let resolver = test_resolver();
        let connector = TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            TEST_UUID,
            SERVER_PASSWORD.to_string(),
            false,
            TuicUdpRelayMode::Native,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
        )
        .unwrap();

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
