//! AnyTLS Server Handler
//!
//! Implements TcpServerHandler for AnyTLS protocol.
//! This handler:
//! 1. Authenticates clients via SHA256(password)
//! 2. Creates an AnyTlsSession with all routing dependencies
//! 3. Runs the session which handles streams internally

use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use crate::address::NetLocation;
use crate::anytls::anytls_padding::PaddingFactory;
use crate::anytls::anytls_server_session::AnyTlsSession;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};
use crate::util::write_all;
use aws_lc_rs::digest::{SHA256, digest};

/// AnyTLS server handler implementing TcpServerHandler
///
/// This handler receives a post-TLS stream and handles AnyTLS protocol.
/// It authenticates the client, creates a session with routing dependencies,
/// and runs the session which handles all streams internally.
#[derive(Debug)]
pub struct AnyTlsServerHandler {
    /// Authenticated users (password_hash -> user name)
    users: HashMap<[u8; 32], String>,
    /// 8-byte prefixes of all user password hashes for quick fallback.
    /// If incoming data doesn't match any prefix, we can fallback immediately
    /// without waiting for the full 32-byte hash.
    hash_prefixes: HashSet<[u8; 8]>,
    /// Padding factory for traffic obfuscation
    padding: Arc<PaddingFactory>,
    /// Resolver for destination addresses
    resolver: Arc<dyn Resolver>,
    /// Proxy provider for routing decisions
    proxy_provider: Arc<ClientProxySelector>,
    /// UDP enabled for UoT support
    udp_enabled: bool,
    /// Fallback destination for failed authentication
    fallback: Option<NetLocation>,
}

impl AnyTlsServerHandler {
    /// Create a new AnyTLS server handler.
    ///
    /// # Arguments
    /// * `users` - Vec of (name, password) tuples for authentication
    /// * `padding` - Padding factory for traffic obfuscation
    /// * `resolver` - DNS resolver for destination addresses
    /// * `proxy_provider` - Proxy selector for routing decisions
    /// * `udp_enabled` - Whether UDP-over-TCP is enabled
    /// * `fallback` - Optional fallback destination for failed auth
    pub fn new(
        users: Vec<(String, String)>,
        padding: Arc<PaddingFactory>,
        resolver: Arc<dyn Resolver>,
        proxy_provider: Arc<ClientProxySelector>,
        udp_enabled: bool,
        fallback: Option<NetLocation>,
    ) -> Self {
        // Build hash -> name map and collect prefixes
        let mut user_map = HashMap::with_capacity(users.len());
        let mut hash_prefixes = HashSet::with_capacity(users.len());

        for (name, password) in users {
            let hash_result = digest(&SHA256, password.as_bytes());
            let mut password_hash = [0u8; 32];
            password_hash.copy_from_slice(hash_result.as_ref());

            // Extract 8-byte prefix for quick fallback lookup
            let prefix: [u8; 8] = password_hash[..8].try_into().unwrap();
            hash_prefixes.insert(prefix);

            user_map.insert(password_hash, name);
        }

        Self {
            users: user_map,
            hash_prefixes,
            padding,
            resolver,
            proxy_provider,
            udp_enabled,
            fallback,
        }
    }
}

#[async_trait]
impl TcpServerHandler for AnyTlsServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        // Use StreamReader to peek at auth header without consuming
        let mut reader = StreamReader::new();

        // First, peek at the 8-byte prefix for quick fallback.
        // This allows us to reject non-AnyTLS traffic (e.g., small HTTP requests)
        // without hanging waiting for the full 32-byte hash.
        //
        // Timing side-channel note: This creates a timing difference between prefix
        // match and mismatch, but is not exploitable since enumerating 2^64 prefixes
        // is infeasible, and discovering a valid prefix doesn't help recover the
        // password or the remaining 24 bytes of the SHA256 hash.
        let prefix_data = reader.peek_slice(&mut server_stream, 8).await?;

        if !self.hash_prefixes.contains(prefix_data) {
            log::debug!("AnyTLS quick fallback: 8-byte prefix doesn't match any user");
            if let Some(ref fallback) = self.fallback {
                return self.fallback_to_dest(server_stream, reader, fallback).await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication failed (prefix mismatch)",
            ));
        }

        // Prefix matches - now read the full 32-byte hash
        let auth_data = reader.peek_slice(&mut server_stream, 32).await?;

        let user_name = match self.users.get(auth_data) {
            Some(name) => {
                log::debug!("AnyTLS user authenticated: {}", name);
                // Auth succeeded - consume the header bytes
                reader.consume(32);
                name.clone()
            }
            None => {
                log::debug!("AnyTLS authentication failed: unknown password");
                // If fallback is configured, forward the connection there
                if let Some(ref fallback) = self.fallback {
                    return self.fallback_to_dest(server_stream, reader, fallback).await;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authentication failed",
                ));
            }
        };

        let padding_len = reader.read_u16_be(&mut server_stream).await?;

        // Skip padding bytes (consume them from the reader)
        if padding_len > 0 {
            let _ = reader
                .read_slice(&mut *server_stream, padding_len as usize)
                .await?;
        }

        // Get any remaining unparsed data that may have been buffered
        let initial_data = reader.unparsed_data_owned();

        // Create session with all dependencies for internal stream handling
        let session = AnyTlsSession::new_server_with_initial_data(
            server_stream,
            Arc::clone(&self.padding),
            Arc::clone(&self.resolver),
            Arc::clone(&self.proxy_provider),
            self.udp_enabled,
            user_name,
            initial_data,
        );

        // Keep the session outside the handshake timeout, but owned by the caller.
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            if let Err(e) = session.run().await {
                log::debug!("AnyTLS session ended: {}", e);
            }
        })))
    }
}

impl AnyTlsServerHandler {
    /// Forward the connection to a fallback destination when authentication fails.
    ///
    /// This makes the server indistinguishable from a legitimate server by transparently
    /// proxying failed auth attempts to the configured fallback destination.
    async fn fallback_to_dest(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        reader: StreamReader,
        fallback: &NetLocation,
    ) -> std::io::Result<TcpServerSetupResult> {
        log::debug!("AnyTLS FALLBACK: Connecting to fallback: {}", fallback);

        // Get the unconsumed data from the reader (includes auth header)
        let unconsumed_data = reader.unparsed_data();

        // Resolve and connect to the fallback destination
        let dest_addr = crate::resolver::resolve_single_address(&self.resolver, fallback).await?;

        log::debug!("AnyTLS FALLBACK: Resolved {} to {}", fallback, dest_addr);

        let socket = crate::socket_util::new_tcp_socket(None, dest_addr.is_ipv6())?;
        let mut dest_stream: Box<dyn AsyncStream> = Box::new(socket.connect(dest_addr).await?);

        log::debug!(
            "AnyTLS FALLBACK: Connected to fallback, forwarding {} bytes",
            unconsumed_data.len()
        );

        // Forward the unconsumed data (auth header that the client sent)
        if !unconsumed_data.is_empty() {
            write_all(&mut dest_stream, unconsumed_data).await?;
            dest_stream.flush().await?;
        }

        log::debug!("AnyTLS FALLBACK: Spawning bidirectional copy");

        // Return the transfer to the caller so cancellation owns the entire connection.
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let result = copy_bidirectional(
                &mut *client_stream,
                &mut *dest_stream,
                false, // client doesn't need initial flush
                false, // dest doesn't need initial flush
            )
            .await;

            futures::join!(
                crate::util::shutdown_stream(&mut client_stream),
                crate::util::shutdown_stream(&mut dest_stream),
            );

            if let Err(e) = result {
                log::debug!("AnyTLS FALLBACK: Connection ended: {}", e);
            } else {
                log::debug!("AnyTLS FALLBACK: Connection completed");
            }
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::resolver::NativeResolver;
    use std::io::ErrorKind;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    fn compute_password_hash(password: &str) -> [u8; 32] {
        let hash_result = digest(&SHA256, password.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_result.as_ref());
        hash
    }

    fn handler(fallback: Option<NetLocation>) -> AnyTlsServerHandler {
        AnyTlsServerHandler::new(
            vec![("alice".into(), "secret123".into())],
            PaddingFactory::default_factory(),
            Arc::new(NativeResolver::new()),
            Arc::new(ClientProxySelector::new(Vec::new())),
            false,
            fallback,
        )
    }

    #[tokio::test]
    async fn invalid_credentials_are_rejected_at_both_authentication_stages() {
        for corrupt_index in [0, 8] {
            let mut auth = compute_password_hash("secret123");
            auth[corrupt_index] ^= 1;
            let (io, mut peer) = tokio::io::duplex(1024);
            let offered = if corrupt_index == 0 { 8 } else { 32 };
            peer.write_all(&auth[..offered]).await.unwrap();
            let error = tokio::time::timeout(
                Duration::from_secs(2),
                handler(None).setup_server_stream(Box::new(io)),
            )
            .await
            .expect("authentication waited for more bytes")
            .err()
            .expect("invalid credentials created a session");
            assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        }
    }

    #[tokio::test]
    async fn complete_authentication_and_padding_are_required_for_a_session() {
        let mut auth = compute_password_hash("secret123").to_vec();
        auth.extend_from_slice(&[0, 3, 1, 2, 3]);
        for len in 0..auth.len() {
            let (io, mut peer) = tokio::io::duplex(1024);
            peer.write_all(&auth[..len]).await.unwrap();
            peer.shutdown().await.unwrap();
            let error = handler(None)
                .setup_server_stream(Box::new(io))
                .await
                .err()
                .expect("truncated authentication created a session");
            assert_eq!(error.kind(), ErrorKind::ConnectionAborted, "len={len}");
        }

        let (io, mut peer) = tokio::io::duplex(1024);
        peer.write_all(&auth).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            handler(None).setup_server_stream(Box::new(io)),
        )
        .await
        .expect("complete authentication stalled")
        .unwrap();
        let TcpServerSetupResult::Session(session) = result else {
            panic!("valid credentials did not create a session");
        };
        drop(session);
        let read = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut [0; 1]))
            .await
            .expect("unpolled session retained the stream");
        assert_eq!(read.unwrap(), 0);
    }

    #[tokio::test]
    async fn fallback_preserves_bytes_and_session_owns_both_connections() {
        for corrupt_index in [0, 8] {
            for start_session in [false, true] {
                tokio::time::timeout(Duration::from_secs(2), async {
                    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
                    let fallback = NetLocation::new(
                        Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        listener.local_addr().unwrap().port(),
                    );
                    let mut flight = compute_password_hash("secret123").to_vec();
                    flight[corrupt_index] ^= 1;
                    flight.extend_from_slice(b"buffered");
                    let (io, mut peer) = tokio::io::duplex(1024);
                    peer.write_all(&flight).await.unwrap();
                    let result = handler(Some(fallback))
                        .setup_server_stream(Box::new(io))
                        .await
                        .unwrap();
                    let TcpServerSetupResult::Session(mut session) = result else {
                        panic!("expected fallback session");
                    };
                    let (mut remote, _) = listener.accept().await.unwrap();
                    let mut received = vec![0; flight.len()];
                    remote.read_exact(&mut received).await.unwrap();
                    assert_eq!(received, flight);

                    if start_session {
                        let exchange = async {
                            peer.write_all(b"live").await.unwrap();
                            let mut received = [0; 4];
                            remote.read_exact(&mut received).await.unwrap();
                            assert_eq!(&received, b"live");
                            remote.write_all(b"back").await.unwrap();
                            peer.read_exact(&mut received).await.unwrap();
                            assert_eq!(&received, b"back");
                        };
                        tokio::select! {
                            () = &mut session => panic!("fallback ended before the exchange"),
                            () = exchange => {},
                        }
                    }
                    drop(session);
                    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
                    assert_eq!(remote.read(&mut [0; 1]).await.unwrap(), 0);
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("corrupt_index={corrupt_index}, running={start_session}")
                });
            }
        }
    }
}
