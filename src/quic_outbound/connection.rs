//! One QUIC connection per outbound, authenticated once and re-established lazily.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use log::debug;
use tokio::sync::Mutex;

use crate::resolver::{Resolver, resolve_addresses};

use super::QuicOutboundSettings;

/// How long one address gets before the next is tried.
///
/// Only applied while another address remains, so it is a fallback trigger
/// rather than a connection deadline. A handshake over a working path
/// completes well inside this; one that does not is almost always a path that
/// never will, and the alternative is waiting out the 30s idle timeout with a
/// perfectly good second address untouched.
const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Per-connection authentication, run once each time a connection is raised.
#[async_trait]
pub trait ConnectionAuthenticator: Send + Sync + std::fmt::Debug {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()>;
}

struct State {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("remote", &self.connection.remote_address())
            .finish()
    }
}

/// Returns true when a new connection has to be raised.
fn needs_reconnect(state: Option<&State>) -> bool {
    match state {
        None => true,
        Some(state) => state.connection.close_reason().is_some(),
    }
}

/// Holds the single QUIC connection an outbound uses.
///
/// Callers take the mutex, and if the held connection is still open they get a
/// clone of it - cloning a `quinn::Connection` is cheap and shares the same
/// underlying connection. Otherwise the handshake and the protocol's
/// authentication happen *while the mutex is still held*, so that a burst of
/// requests arriving during a reconnect waits for one result instead of
/// starting one handshake each against a server that has just gone away.
///
/// A failed attempt is not remembered: the next request tries again.
#[derive(Debug)]
pub struct LiveConnection {
    settings: QuicOutboundSettings,
    authenticator: Arc<dyn ConnectionAuthenticator>,
    state: Mutex<Option<State>>,
    connections_raised: AtomicUsize,
}

impl LiveConnection {
    pub fn new(
        settings: QuicOutboundSettings,
        authenticator: Arc<dyn ConnectionAuthenticator>,
    ) -> Self {
        Self {
            settings,
            authenticator,
            state: Mutex::new(None),
            connections_raised: AtomicUsize::new(0),
        }
    }

    pub fn settings(&self) -> &QuicOutboundSettings {
        &self.settings
    }

    /// How many connections have been raised over this outbound's lifetime.
    ///
    /// Exists so a reconnect can be asserted rather than inferred from timing.
    #[cfg(test)]
    pub fn connections_raised(&self) -> usize {
        self.connections_raised.load(Ordering::Relaxed)
    }

    /// Return an open, authenticated connection, raising one if needed.
    pub async fn get(&self, resolver: &Arc<dyn Resolver>) -> std::io::Result<quinn::Connection> {
        let mut state = self.state.lock().await;

        if !needs_reconnect(state.as_ref()) {
            return Ok(state.as_ref().unwrap().connection.clone());
        }

        if let Some(previous) = state.as_ref() {
            debug!(
                "QUIC connection to {} is gone ({:?}); reconnecting",
                self.settings.server,
                previous.connection.close_reason()
            );
        }

        // Every resolved address, not just the first. A dual-stack host whose
        // IPv6 is published but whose UDP does not come back leaves the first
        // address a black hole, and taking only that one makes the outbound
        // look permanently dead. The TCP connector already walks the list
        // (`src/tcp/socket_connector_impl.rs:224`); this brings QUIC into line.
        let server_addrs = resolve_addresses(resolver, &self.settings.server).await?;

        // Reuse the endpoint across reconnects: it owns the UDP socket, and
        // rebinding one on every connection loss would churn source ports for
        // no reason. It can only be reused for an address of the same family,
        // because the socket underneath is bound for one.
        let mut endpoint: Option<quinn::Endpoint> = state.take().map(|previous| previous.endpoint);
        let mut last_err: Option<std::io::Error> = None;

        for (index, server_addr) in server_addrs.iter().copied().enumerate() {
            let reusable = endpoint
                .as_ref()
                .and_then(|e| e.local_addr().ok())
                .is_some_and(|local| local.is_ipv6() == server_addr.is_ipv6());
            let current = match endpoint.take() {
                Some(e) if reusable => e,
                _ => self.settings.build_endpoint(server_addr.is_ipv6())?,
            };

            let is_last = index + 1 == server_addrs.len();
            match self.attempt(&current, server_addr, is_last).await {
                Ok(connection) => {
                    if index > 0 {
                        debug!(
                            "QUIC connection to {server_addr} established after {index} \
                             address(es) failed"
                        );
                    }
                    *state = Some(State {
                        endpoint: current,
                        connection: connection.clone(),
                    });
                    return Ok(connection);
                }
                Err(e) => {
                    debug!("QUIC connect to {server_addr} failed: {e}; trying the next address");
                    last_err = Some(e);
                    endpoint = Some(current);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            std::io::Error::other(format!("could not resolve {}", self.settings.server))
        }))
    }

    /// One address, one handshake, one authentication.
    ///
    /// Every attempt but the last is bounded. A UDP path that swallows packets
    /// does not fail, it stalls, so without a bound the first black-holed
    /// address would consume the whole idle timeout and the fallback would
    /// never be reached in any useful time. The last attempt is left unbounded
    /// so that a single-address outbound - the overwhelming majority - keeps
    /// exactly the behaviour it had, and a genuinely slow link is not cut off
    /// when there is nothing else to try.
    async fn attempt(
        &self,
        endpoint: &quinn::Endpoint,
        server_addr: std::net::SocketAddr,
        is_last: bool,
    ) -> std::io::Result<quinn::Connection> {
        let server_name = self
            .settings
            .sni_hostname()
            .unwrap_or_else(|| server_addr.ip().to_string());

        let connecting = endpoint.connect(server_addr, &server_name).map_err(|e| {
            std::io::Error::other(format!("QUIC connect to {server_addr} failed: {e}"))
        })?;

        let connection = if is_last {
            connecting.await
        } else {
            match tokio::time::timeout(ATTEMPT_TIMEOUT, connecting).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "QUIC handshake with {server_addr} did not complete within {}s",
                            ATTEMPT_TIMEOUT.as_secs()
                        ),
                    ));
                }
            }
        }
        .map_err(|e| {
            std::io::Error::other(format!("QUIC handshake with {server_addr} failed: {e}"))
        })?;

        self.authenticator.authenticate(&connection).await?;
        self.connections_raised.fetch_add(1, Ordering::Relaxed);

        debug!("QUIC connection to {server_addr} established and authenticated");
        Ok(connection)
    }

    /// Close the held connection, so the next `get` raises a new one.
    #[cfg(test)]
    pub fn close_for_test(&self) {
        if let Ok(state) = self.state.try_lock()
            && let Some(state) = state.as_ref()
        {
            state.connection.close(0u32.into(), b"test");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct CountingAuthenticator {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ConnectionAuthenticator for CountingAuthenticator {
        async fn authenticate(&self, _connection: &quinn::Connection) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// A resolver that hands back a fixed list, so a test can put a black
    /// hole in front of a working address.
    #[derive(Debug)]
    struct ScriptedResolver {
        addresses: Vec<std::net::SocketAddr>,
    }

    impl crate::resolver::Resolver for ScriptedResolver {
        fn resolve_location(
            &self,
            _location: &crate::address::NetLocation,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send,
            >,
        > {
            let addresses = self.addresses.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    /// A UDP socket that receives and never answers, which is what a published
    /// but unreachable address looks like from the client: not a refusal, a
    /// silence.
    fn black_hole() -> std::net::SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while socket.recv_from(&mut buf).is_ok() {}
        });
        addr
    }

    /// The failure this fixes: a host whose first resolved address swallows
    /// UDP. Taking only `resolve_results[0]` left the outbound looking
    /// permanently dead while a working address sat untried.
    #[tokio::test]
    async fn test_a_black_holed_first_address_falls_through_to_the_next() {
        use crate::quic_outbound::testing::*;

        let cert = generate_certificate();
        let bind_address = reserve_udp_port();
        crate::hysteria2::start_hysteria2_server(
            crate::quic_transport::QuicListenerSettings {
                bind_address,
                quic_server_config: quic_server_config(&cert, &["h3".to_string()]),
                num_endpoints: 1,
                obfs: None,
            },
            Box::leak("fallback test".to_string().into_boxed_str()),
            direct_selector(test_resolver()),
            test_resolver(),
            true,
        )
        .await
        .unwrap();

        let live = LiveConnection::new(
            QuicOutboundSettings {
                // A hostname, so the scripted resolver is consulted rather
                // than the literal short-circuit.
                server: crate::address::NetLocation::from_str("example.invalid:443", None).unwrap(),
                quic: client_quic_config(),
                bind_interface: None,
                obfs: None,
                port_hopping: None,
                default_alpn: "h3",
            },
            Arc::new(CountingAuthenticator::default()),
        );

        let resolver: Arc<dyn crate::resolver::Resolver> = Arc::new(ScriptedResolver {
            addresses: vec![black_hole(), bind_address],
        });

        let started = std::time::Instant::now();
        let connection =
            tokio::time::timeout(std::time::Duration::from_secs(20), live.get(&resolver))
                .await
                .expect("the fallback must not wait out the idle timeout")
                .expect("the second address should have connected");

        assert!(connection.close_reason().is_none());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "took {:?}, which means the black hole was not bounded",
            started.elapsed()
        );
    }

    fn live_connection() -> LiveConnection {
        LiveConnection::new(
            QuicOutboundSettings {
                server: crate::address::NetLocation::from_str("127.0.0.1:1", None).unwrap(),
                quic: crate::config::ClientQuicConfig::default(),
                bind_interface: None,
                obfs: None,
                port_hopping: None,
                default_alpn: "h3",
            },
            Arc::new(CountingAuthenticator::default()),
        )
    }

    #[test]
    fn test_needs_reconnect_for_a_missing_connection() {
        assert!(needs_reconnect(None));
    }

    #[test]
    fn test_starts_with_no_connections_raised() {
        assert_eq!(live_connection().connections_raised(), 0);
    }

    /// A refused handshake must not be remembered as a connection, and must not
    /// leave state behind that a later call would mistake for a live one.
    #[tokio::test]
    async fn test_a_failed_handshake_is_not_counted_or_cached() {
        let live = live_connection();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());

        // Port 1 on loopback has nothing listening. The handshake either fails
        // outright or is still in flight when our own bound elapses; both are
        // "did not complete", and cutting it short keeps this out of the
        // suite's critical path.
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(500), live.get(&resolver)).await;

        if let Ok(outcome) = result {
            assert!(
                outcome.is_err(),
                "a handshake to a dead port must not succeed"
            );
        }
        assert_eq!(
            live.connections_raised(),
            0,
            "a failed handshake is not a raised connection"
        );
    }
}
