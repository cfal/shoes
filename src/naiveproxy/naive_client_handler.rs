//! NaiveProxy client handler with HTTP/2 multiplexing support.
//!
//! This handler maintains a persistent H2 session and multiplexes all outgoing
//! connections over the same underlying TLS connection, matching the behavior
//! of the reference NaiveProxy client.
//!
//! ## Multiplexing Design
//!
//! Following the h2 crate's pattern (see their benchmarks), `NaiveClientSession`
//! is cheaply cloneable because h2's `SendRequest` internally uses `Arc<Mutex<...>>`.
//!
//! The handler maintains `Arc<Mutex<Option<NaiveClientSession>>>` only for:
//! - Lazy initialization (session created on first request)
//! - Reconnection (recreate session if connection dies)
//!
//! Once obtained, the session is cloned and used directly without holding locks,
//! enabling concurrent stream creation.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use log::debug;
use tokio::sync::Mutex;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

use super::naive_client_session::NaiveClientSession;

/// NaiveProxy client handler with HTTP/2 multiplexing.
///
/// Establishes HTTP/2 CONNECT tunnels with padding support, reusing H2 sessions
/// across multiple connections for efficient multiplexing.
pub struct NaiveProxyTcpClientHandler {
    /// Base64-encoded credentials for Basic Auth
    auth_header: String,
    /// Enable padding
    padding_enabled: bool,
    /// Session slot for lazy init and reconnection (session itself is cheap to clone)
    session: Arc<Mutex<Option<NaiveClientSession>>>,
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
            // Share the same session slot across clones for multiplexing
            session: Arc::clone(&self.session),
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
            session: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl TcpClientHandler for NaiveProxyTcpClientHandler {
    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> io::Result<Option<TcpClientSetupResult>> {
        let session = {
            // A cold handshake holds this lock; preflight must not wait behind it.
            let Ok(slot) = self.session.try_lock() else {
                return Ok(None);
            };
            slot.as_ref().filter(|session| session.is_ready()).cloned()
        };
        match session {
            Some(session) => self.open_stream(session, target).await.map(Some),
            None => Ok(None),
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let session = self.get_or_create_session(client_stream).await?;
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
                let mut slot = self.session.lock().await;
                if slot
                    .as_ref()
                    .is_some_and(|current| current.same_generation(&session))
                {
                    *slot = None;
                }
                return Err(e);
            }
        };

        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
    /// Get an existing session or create a new one, returning a clone.
    ///
    /// The session is cloned so we can release the lock before calling open_stream.
    /// Cloning is cheap because h2's SendRequest uses internal Arc.
    async fn get_or_create_session(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> io::Result<NaiveClientSession> {
        let mut guard = self.session.lock().await;

        if let Some(ref session) = *guard {
            if session.is_ready() {
                debug!("NaiveProxy: reusing existing session");
                return Ok(session.clone());
            }
            debug!("NaiveProxy: existing session not ready, creating new session");
        }

        debug!("NaiveProxy: creating new H2 session for multiplexing");
        let session = NaiveClientSession::new(client_stream).await?;
        *guard = Some(session.clone());

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reuse_miss_does_not_wait_for_a_cold_handshake() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
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
        let _guard = handler.session.lock().await;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handler.try_reuse_tcp_stream(&target),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn failed_warm_open_cannot_retire_a_replacement_session() {
        let handler = NaiveProxyTcpClientHandler::new("user", "pass", false);
        let (client, peer) = tokio::io::duplex(8192);
        handler
            .get_or_create_session(Box::new(client))
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
            opener.try_reuse_tcp_stream(&target).await
        });
        arrival.await.unwrap();
        assert!(handler.session.try_lock().is_ok());
        let (transport, _peer) = tokio::io::duplex(8192);
        let replacement = NaiveClientSession::new(Box::new(transport)).await.unwrap();
        *handler.session.lock().await = Some(replacement.clone());
        release.send(()).unwrap();
        assert!(opening.await.unwrap().is_err());
        assert!(
            handler
                .session
                .lock()
                .await
                .as_ref()
                .unwrap()
                .same_generation(&replacement)
        );
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
            .setup_client_tcp_stream(Box::new(client), target.clone().into())
            .await
            .unwrap()
            .client_stream;
        stream.write_all(b"warmup").await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        let result = handler.try_reuse_tcp_stream(&target.into()).await;
        assert!(result.is_err());
        assert!(handler.session.lock().await.is_none());
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
            .get_or_create_session(Box::new(client))
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
            .get_or_create_session(Box::new(client))
            .await
            .unwrap();
        assert!(second.is_ready());
        assert!(!first.same_generation(&second));
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
    fn test_handler_clone_shares_session_slot() {
        let handler1 = NaiveProxyTcpClientHandler::new("user", "pass", true);
        let handler2 = handler1.clone();

        // Both handlers should share the same session slot
        assert!(Arc::ptr_eq(&handler1.session, &handler2.session));
    }

    #[test]
    fn test_handler_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<NaiveProxyTcpClientHandler>();
        assert_sync::<NaiveProxyTcpClientHandler>();
    }
}
