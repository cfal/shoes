//! One QUIC connection per outbound, authenticated once and re-established lazily.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use log::debug;
use tokio::sync::Mutex;

use crate::resolver::{Resolver, resolve_single_address};

use super::QuicOutboundSettings;

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

        let server_addr = resolve_single_address(resolver, &self.settings.server).await?;

        // Reuse the endpoint across reconnects: it owns the UDP socket, and
        // rebinding one on every connection loss would churn source ports for
        // no reason.
        let endpoint = match state.take() {
            Some(previous) => previous.endpoint,
            None => self.settings.build_endpoint(server_addr.is_ipv6())?,
        };

        let server_name = self
            .settings
            .sni_hostname()
            .unwrap_or_else(|| server_addr.ip().to_string());

        let connecting = endpoint.connect(server_addr, &server_name).map_err(|e| {
            std::io::Error::other(format!("QUIC connect to {server_addr} failed: {e}"))
        })?;

        let connection = connecting.await.map_err(|e| {
            std::io::Error::other(format!("QUIC handshake with {server_addr} failed: {e}"))
        })?;

        self.authenticator.authenticate(&connection).await?;
        self.connections_raised.fetch_add(1, Ordering::Relaxed);

        debug!("QUIC connection to {server_addr} established and authenticated");

        *state = Some(State {
            endpoint,
            connection: connection.clone(),
        });

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

    fn live_connection() -> LiveConnection {
        LiveConnection::new(
            QuicOutboundSettings {
                server: crate::address::NetLocation::from_str("127.0.0.1:1", None).unwrap(),
                quic: crate::config::ClientQuicConfig::default(),
                bind_interface: None,
                obfs: None,
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
