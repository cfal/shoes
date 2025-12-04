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
use tokio::net::TcpStream;

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

        // Run the session in a background task
        tokio::spawn(async move {
            if let Err(e) = session.run().await {
                log::debug!("AnyTLS session ended: {}", e);
            }
        });

        Ok(TcpServerSetupResult::AlreadyHandled)
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

        let mut dest_stream: Box<dyn AsyncStream> = Box::new(TcpStream::connect(dest_addr).await?);

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

        // Spawn the long-running bidirectional copy as a background task.
        // This allows the setup to complete within the timeout while the actual
        // data transfer runs indefinitely.
        tokio::spawn(async move {
            let result = copy_bidirectional(
                &mut *client_stream,
                &mut *dest_stream,
                false, // client doesn't need initial flush
                false, // dest doesn't need initial flush
            )
            .await;

            let _ = client_stream.shutdown().await;
            let _ = dest_stream.shutdown().await;

            if let Err(e) = result {
                log::debug!("AnyTLS FALLBACK: Connection ended: {}", e);
            } else {
                log::debug!("AnyTLS FALLBACK: Connection completed");
            }
        });

        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to compute password hash the same way the handler does
    fn compute_password_hash(password: &str) -> [u8; 32] {
        let hash_result = digest(&SHA256, password.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hash_result.as_ref());
        hash
    }

    #[test]
    fn test_password_hashing() {
        let hash = compute_password_hash("secret123");

        let expected = digest(&SHA256, b"secret123");
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_ref());

        assert_eq!(hash, expected_bytes);
    }

    #[test]
    fn test_different_passwords_different_hashes() {
        let hash1 = compute_password_hash("pass1");
        let hash2 = compute_password_hash("pass2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_map_and_prefix_construction() {
        // Test that the handler correctly builds user map and prefix set
        let users = vec![
            ("alice".to_string(), "password1".to_string()),
            ("bob".to_string(), "password2".to_string()),
        ];

        // Compute expected hashes
        let hash1 = compute_password_hash("password1");
        let hash2 = compute_password_hash("password2");

        // Build the maps the same way the handler does
        let mut user_map = HashMap::with_capacity(users.len());
        let mut hash_prefixes = HashSet::with_capacity(users.len());

        for (name, password) in users {
            let hash = compute_password_hash(&password);
            let prefix: [u8; 8] = hash[..8].try_into().unwrap();
            hash_prefixes.insert(prefix);
            user_map.insert(hash, name);
        }

        assert_eq!(user_map.len(), 2);
        assert_eq!(hash_prefixes.len(), 2);

        // Verify slice lookups work via Borrow<[u8]>
        let prefix1_slice: &[u8] = &hash1[..8];
        let prefix2_slice: &[u8] = &hash2[..8];
        assert!(hash_prefixes.contains(prefix1_slice));
        assert!(hash_prefixes.contains(prefix2_slice));

        // Verify a random prefix is NOT in the set
        let random_prefix: &[u8] = &[0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54]; // "GET / HT"
        assert!(!hash_prefixes.contains(random_prefix));

        // Verify full hash lookup returns correct name
        let hash1_slice: &[u8] = &hash1[..];
        assert!(user_map.get(hash1_slice).is_some());
        assert_eq!(user_map.get(hash1_slice).unwrap(), "alice");

        let hash2_slice: &[u8] = &hash2[..];
        assert_eq!(user_map.get(hash2_slice).unwrap(), "bob");
    }
}
