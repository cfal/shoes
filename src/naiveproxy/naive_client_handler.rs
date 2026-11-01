//! NaiveProxy client handler with HTTP/2 multiplexing support.
//!
//! A bounded cache retains H2 sessions by selected prefix. Eviction leaves
//! existing tunnels alive through their session owners.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use log::debug;
use parking_lot::Mutex;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncStream;
use crate::tcp::carrier_dialer::CarrierDialer;
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};

use super::naive_client_session::NaiveClientSession;

const MAX_CACHED_SESSIONS: usize = 16;

struct CachedSession {
    session: NaiveClientSession,
    // Retains connector identities so pointer-based route keys cannot be recycled.
    route: Arc<dyn CarrierDialer>,
}

/// NaiveProxy client handler with HTTP/2 multiplexing.
///
/// Establishes HTTP/2 CONNECT tunnels with padding support, reusing H2 sessions
/// across multiple connections for efficient multiplexing.
pub struct NaiveProxyTcpClientHandler {
    /// Base64-encoded credentials for Basic Auth
    auth_header: String,
    /// Enable padding
    padding_enabled: bool,
    /// Least recently used first; sessions are cheap to clone.
    sessions: Arc<Mutex<Vec<CachedSession>>>,
}

impl std::fmt::Debug for NaiveProxyTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NaiveProxyTcpClientHandler")
            .field("padding_enabled", &self.padding_enabled)
            .finish()
    }
}

impl Clone for NaiveProxyTcpClientHandler {
    fn clone(&self) -> Self {
        Self {
            auth_header: self.auth_header.clone(),
            padding_enabled: self.padding_enabled,
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl NaiveProxyTcpClientHandler {
    pub fn new(username: &str, password: &str, padding_enabled: bool) -> Self {
        let credentials = format!("{}:{}", username, password);
        let auth_header = format!("Basic {}", BASE64.encode(&credentials));

        Self {
            auth_header,
            padding_enabled,
            sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl TcpClientHandler for NaiveProxyTcpClientHandler {
    fn has_session_pool(&self) -> bool {
        true
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let session = self.session_for(transport).await?;
        self.open_stream(session, &target).await
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        // A supplied stream has no route identity and must never enter the cache.
        let session = NaiveClientSession::new(client_stream).await?;
        self.open_stream(session, &remote_location).await
    }
}

impl NaiveProxyTcpClientHandler {
    async fn open_stream(
        &self,
        mut session: NaiveClientSession,
        target: &ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let result = session
            .open_stream(target.location(), &self.auth_header, self.padding_enabled)
            .await;
        let stream = match result {
            Ok(stream) => stream,
            Err(e) => {
                let retired = {
                    let mut sessions = self.sessions.lock();
                    sessions
                        .iter()
                        .position(|current| current.session.same_generation(&session))
                        .map(|index| sessions.remove(index))
                };
                drop(retired);
                return Err(e);
            }
        };

        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
    async fn session_for(&self, transport: ClientTransport<'_>) -> io::Result<NaiveClientSession> {
        let cached = {
            let mut sessions = self.sessions.lock();
            let index = sessions.iter().position(|cached| {
                cached.route.route_key() == transport.route.route_key() && cached.session.is_ready()
            });
            index.map(|index| {
                let cached = sessions.remove(index);
                let session = cached.session.clone();
                sessions.push(cached);
                session
            })
        };
        if let Some(session) = cached {
            debug!("NaiveProxy: reusing session for selected prefix");
            return Ok(session);
        }

        // Dialing stays outside the lock so a stalled prefix cannot block others.
        // Each cold flow uses its own transport, even if another flow publishes first.
        let session = NaiveClientSession::new(transport.open.await?).await?;
        let mut retired = Vec::new();
        {
            let mut sessions = self.sessions.lock();
            let mut index = 0;
            while index < sessions.len() {
                let cached = &sessions[index];
                if !cached.session.is_ready()
                    || cached.route.route_key() == transport.route.route_key()
                {
                    retired.push(sessions.remove(index));
                } else {
                    index += 1;
                }
            }
            if sessions.len() == MAX_CACHED_SESSIONS {
                retired.push(sessions.remove(0));
            }
            sessions.push(CachedSession {
                session: session.clone(),
                route: transport.route,
            });
        }
        drop(retired);

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::carrier_dialer::RouteKey;
    use std::time::Duration;

    #[derive(Debug)]
    struct Route(RouteKey);

    #[async_trait]
    impl CarrierDialer for Route {
        fn route_key(&self) -> &RouteKey {
            &self.0
        }

        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            panic!("test supplies the transport separately")
        }
    }

    fn transport(id: usize, stream: Option<tokio::io::DuplexStream>) -> ClientTransport<'static> {
        ClientTransport {
            route: Arc::new(Route(RouteKey(vec![id]))),
            open: Box::pin(async move {
                Ok(Box::new(stream.expect("warm acquisition must not dial"))
                    as Box<dyn AsyncStream>)
            }),
        }
    }

    fn target() -> ResolvedLocation {
        crate::address::NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn cache_retains_sixteen_paths_and_evicts_the_least_recently_used() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let mut peers = Vec::new();
        let mut sessions = Vec::new();
        let mut routes = Vec::new();
        for id in 0..16 {
            let (client, peer) = tokio::io::duplex(8192);
            peers.push(peer);
            let transport = transport(id, Some(client));
            routes.push(Arc::downgrade(&transport.route));
            sessions.push(handler.session_for(transport).await.unwrap());
        }
        assert_eq!(handler.sessions.lock().len(), 16);
        assert!(
            sessions[0].same_generation(&handler.session_for(transport(0, None)).await.unwrap())
        );
        let (client, peer) = tokio::io::duplex(8192);
        peers.push(peer);
        sessions.push(
            handler
                .session_for(transport(16, Some(client)))
                .await
                .unwrap(),
        );
        assert_eq!(handler.sessions.lock().len(), 16);
        assert!(routes[1].upgrade().is_none());
        assert!(
            sessions[1].is_ready(),
            "eviction must not close a retained session"
        );
        for id in (0..=16).filter(|id| *id != 1) {
            let warm = handler.session_for(transport(id, None)).await.unwrap();
            assert!(sessions[id].same_generation(&warm));
        }
        drop(handler);
        assert!(routes.iter().all(|route| route.upgrade().is_none()));
    }

    #[tokio::test]
    async fn insertion_prunes_all_closed_sessions_before_evicting_a_live_path() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let mut peers = Vec::new();
        let mut sessions = Vec::new();
        let mut routes = Vec::new();
        for id in 0..16 {
            let (client, peer) = tokio::io::duplex(8192);
            peers.push(Some(peer));
            let transport = transport(id, Some(client));
            routes.push(Arc::downgrade(&transport.route));
            sessions.push(handler.session_for(transport).await.unwrap());
        }
        drop(peers[4].take());
        drop(peers[15].take());
        tokio::time::timeout(Duration::from_secs(1), async {
            while sessions[4].is_ready() || sessions[15].is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (client, peer) = tokio::io::duplex(8192);
        peers.push(Some(peer));
        handler
            .session_for(transport(16, Some(client)))
            .await
            .unwrap();
        assert_eq!(handler.sessions.lock().len(), 15);
        for id in 0..16 {
            if id == 4 || id == 15 {
                assert!(routes[id].upgrade().is_none());
            } else {
                let warm = handler.session_for(transport(id, None)).await.unwrap();
                assert!(sessions[id].same_generation(&warm));
            }
        }
    }

    #[tokio::test]
    async fn eviction_keeps_an_active_tunnel_working() {
        use bytes::Bytes;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, peer) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut receive = request.into_body();
            let exchange = async {
                let mut received = Vec::new();
                while let Some(data) = receive.data().await {
                    let data = data.unwrap();
                    receive.flow_control().release_capacity(data.len()).unwrap();
                    received.extend_from_slice(&data);
                }
                assert_eq!(received, b"after eviction");
                send.send_data(Bytes::from(received), true).unwrap();
            };
            tokio::pin!(exchange);
            tokio::select! {
                _ = &mut exchange => {},
                _ = connection.accept() => panic!("unexpected connection end"),
            }
            while connection.accept().await.is_some() {}
        });
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let route = transport(0, Some(client));
        let weak = Arc::downgrade(&route.route);
        let mut stream = handler
            .connect_client_tcp(route, target())
            .await
            .unwrap()
            .client_stream;
        let mut peers = Vec::new();
        for id in 1..=16 {
            let (client, peer) = tokio::io::duplex(8192);
            peers.push(peer);
            handler
                .session_for(transport(id, Some(client)))
                .await
                .unwrap();
        }
        assert!(weak.upgrade().is_none());
        tokio::time::timeout(Duration::from_secs(1), async {
            stream.write_all(b"after eviction").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, b"after eviction");
            drop(stream);
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stalled_prefix_does_not_block_other_routes_or_change_the_cache() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let (a, _peer_a) = tokio::io::duplex(8192);
        let first = handler.session_for(transport(1, Some(a))).await.unwrap();
        let (started, starting) = tokio::sync::oneshot::channel();
        let b = ClientTransport {
            route: transport(2, None).route,
            open: Box::pin(async move {
                started.send(()).unwrap();
                std::future::pending().await
            }),
        };
        let opening = handler.session_for(b);
        tokio::pin!(opening);
        tokio::select! {
            _ = starting => {},
            _ = &mut opening => panic!("B should remain pending"),
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            let warm = handler.session_for(transport(1, None)).await.unwrap();
            assert!(first.same_generation(&warm));
            let (c, _peer_c) = tokio::io::duplex(8192);
            let third = handler.session_for(transport(3, Some(c))).await.unwrap();
            assert!(!first.same_generation(&third));
            assert!(
                handler
                    .try_reuse_tcp_stream(&target())
                    .await
                    .unwrap()
                    .is_none()
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_warm_open_cannot_retire_a_replacement_session() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let (client, peer) = tokio::io::duplex(8192);
        handler
            .session_for(transport(1, Some(client)))
            .await
            .unwrap();
        let (arrived, arrival) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            arrived.send(()).unwrap();
            released.await.unwrap();
            respond
                .send_response(
                    http::Response::builder().status(503).body(()).unwrap(),
                    true,
                )
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let opener = handler.clone();
        let opening = tokio::spawn(async move {
            let target = crate::address::NetLocation::from_str("example.com:443", None)
                .unwrap()
                .into();
            opener.connect_client_tcp(transport(1, None), target).await
        });
        arrival.await.unwrap();
        assert!(handler.sessions.try_lock().is_some());
        let (replacement_stream, _peer) = tokio::io::duplex(8192);
        let replacement = NaiveClientSession::new(Box::new(replacement_stream))
            .await
            .unwrap();
        let retired = std::mem::replace(
            &mut handler.sessions.lock()[0],
            CachedSession {
                session: replacement.clone(),
                route: Arc::new(Route(RouteKey(vec![1]))),
            },
        );
        drop(retired);
        let (other, _other_peer) = tokio::io::duplex(8192);
        let other = handler
            .session_for(transport(2, Some(other)))
            .await
            .unwrap();
        release.send(()).unwrap();
        assert!(opening.await.unwrap().is_err());
        assert!(
            handler
                .sessions
                .lock()
                .first()
                .unwrap()
                .session
                .same_generation(&replacement)
        );
        assert_eq!(handler.sessions.lock().len(), 2);
        assert!(other.same_generation(&handler.session_for(transport(2, None)).await.unwrap()));
        peer.abort();
        let _ = peer.await;
    }

    #[tokio::test]
    async fn rejected_connect_does_not_discard_retired_tunnels_tail() {
        use bytes::Bytes;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, peer) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut receive = request.into_body();
            let read = async {
                let warmup = receive.data().await.unwrap().unwrap();
                assert_eq!(warmup, b"warmup"[..]);
                receive
                    .flow_control()
                    .release_capacity(warmup.len())
                    .unwrap();
                send.send_data(Bytes::new(), true).unwrap();
                let mut tail = Vec::new();
                while let Some(data) = receive.data().await {
                    let data = data.unwrap();
                    receive.flow_control().release_capacity(data.len()).unwrap();
                    tail.extend_from_slice(&data);
                }
                tail
            };
            tokio::pin!(read);
            loop {
                tokio::select! {
                    tail = &mut read => break tail,
                    accepted = connection.accept() => match accepted {
                        Some(Ok((_, mut respond))) => {
                            let response = http::Response::builder().status(503).body(()).unwrap();
                            respond.send_response(response, true).unwrap();
                        }
                        _ => break read.await,
                    }
                }
            }
        });
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let target = crate::address::NetLocation::from_str("example.com:443", None).unwrap();
        let mut stream = handler
            .connect_client_tcp(transport(1, Some(client)), target.clone().into())
            .await
            .unwrap()
            .client_stream;
        stream.write_all(b"warmup").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        let result = handler
            .connect_client_tcp(transport(1, None), target.into())
            .await;
        assert!(result.is_err());
        assert!(handler.sessions.lock().is_empty());
        stream.write_all(b"FINAL-TAIL").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let tail = tokio::time::timeout(std::time::Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(tail, b"FINAL-TAIL");
    }

    #[tokio::test]
    async fn replaces_closed_session_with_supplied_transport() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let (client, peer) = tokio::io::duplex(8192);
        let first = handler
            .session_for(transport(1, Some(client)))
            .await
            .unwrap();
        drop(peer);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while first.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let target = crate::address::NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        assert!(
            handler
                .try_reuse_tcp_stream(&target)
                .await
                .unwrap()
                .is_none()
        );
        let (client, _peer) = tokio::io::duplex(8192);
        let second = handler
            .session_for(transport(1, Some(client)))
            .await
            .unwrap();
        assert!(second.is_ready());
        assert!(!first.same_generation(&second));
    }

    #[tokio::test]
    async fn failed_and_cancelled_replacements_leave_the_cached_route_intact() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let (client, _peer) = tokio::io::duplex(8192);
        let first = handler
            .session_for(transport(1, Some(client)))
            .await
            .unwrap();
        let failed = ClientTransport {
            route: transport(2, None).route,
            open: Box::pin(async { Err(io::Error::other("dial failed")) }),
        };
        assert!(handler.session_for(failed).await.is_err());
        let stalled = ClientTransport {
            route: transport(2, None).route,
            open: Box::pin(std::future::pending()),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), handler.session_for(stalled))
                .await
                .is_err()
        );
        // The H2 preface cannot fit; cancellation during handshake must also preserve A.
        let (client, _peer) = tokio::io::duplex(1);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                handler.session_for(transport(2, Some(client)))
            )
            .await
            .is_err()
        );
        let warm = handler.session_for(transport(1, None)).await.unwrap();
        assert!(first.same_generation(&warm));
        assert_eq!(handler.sessions.lock().len(), 1);
        assert!(handler.sessions.try_lock().is_some());
    }

    #[tokio::test]
    async fn cold_race_uses_each_opened_transport_and_retains_only_the_cached_route() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let mut slow = transport(1, None);
        let route = Arc::downgrade(&slow.route);
        let (started, starting) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (client, _peer) = tokio::io::duplex(8192);
        slow.open = Box::pin(async move {
            started.send(()).unwrap();
            released.await.unwrap();
            Ok(Box::new(client) as Box<dyn AsyncStream>)
        });
        let opener = handler.clone();
        let opening = tokio::spawn(async move { opener.session_for(slow).await.unwrap() });
        starting.await.unwrap();
        let (client, _peer) = tokio::io::duplex(8192);
        let fast = handler
            .session_for(transport(1, Some(client)))
            .await
            .unwrap();
        release.send(()).unwrap();
        let slow = opening.await.unwrap();
        assert_eq!(handler.sessions.lock().len(), 1);
        assert!(
            !slow.same_generation(&fast),
            "opened transports must not be discarded"
        );
        assert!(fast.is_ready());
        assert!(route.upgrade().is_some());
        assert!(
            handler
                .session_for(transport(1, None))
                .await
                .unwrap()
                .same_generation(&slow)
        );
        let (client, _peer) = tokio::io::duplex(8192);
        let next = transport(2, Some(client));
        let next_route = Arc::downgrade(&next.route);
        handler.session_for(next).await.unwrap();
        assert_eq!(handler.sessions.lock().len(), 2);
        assert!(route.upgrade().is_some());
        drop(handler);
        assert!(route.upgrade().is_none());
        assert!(next_route.upgrade().is_none());
    }

    #[tokio::test]
    async fn context_free_setup_uses_supplied_transport_without_touching_the_cache() {
        for warm in [false, true] {
            let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
            let (a, _peer_a) = tokio::io::duplex(8192);
            let cached = if warm {
                Some(handler.session_for(transport(1, Some(a))).await.unwrap())
            } else {
                None
            };
            assert!(
                handler
                    .try_reuse_tcp_stream(&target())
                    .await
                    .unwrap()
                    .is_none()
            );
            let (b, peer_b) = tokio::io::duplex(8192);
            let peer = tokio::spawn(async move {
                let mut connection = h2::server::handshake(peer_b).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    "example.com:443"
                );
                respond
                    .send_response(http::Response::new(()), true)
                    .unwrap();
                while connection.accept().await.is_some() {}
            });
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                handler.setup_client_tcp_stream(Box::new(b), target()),
            )
            .await
            .unwrap()
            .unwrap();
            if let Some(cached) = cached {
                assert!(
                    handler
                        .session_for(transport(1, None))
                        .await
                        .unwrap()
                        .same_generation(&cached)
                );
            } else {
                assert!(handler.sessions.lock().is_empty());
            }
            drop(result);
            peer.abort();
            let _ = peer.await;
        }
    }

    #[test]
    fn test_handler_new_encodes_credentials() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", true);
        // Base64 of "user:pass" is "dXNlcjpwYXNz"
        assert_eq!(handler.auth_header, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_handler_new_special_chars_in_credentials() {
        let handler = NaiveProxyTcpClientHandler::new("user@domain", "p@ss:word!", false);
        // Verify it encodes without panicking
        assert!(handler.auth_header.starts_with("Basic "));
    }

    #[test]
    fn test_handler_clone_shares_session_cache() {
        let handler1 = NaiveProxyTcpClientHandler::new("user", "pass", true);
        let handler2 = handler1.clone();

        assert!(Arc::ptr_eq(&handler1.sessions, &handler2.sessions));
    }

    #[test]
    fn test_handler_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<NaiveProxyTcpClientHandler>();
        assert_sync::<NaiveProxyTcpClientHandler>();
    }
}
