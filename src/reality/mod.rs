// REALITY Protocol Implementation
//
// This module implements the REALITY obfuscation protocol for TLS connections.
// REALITY disguises proxy traffic as legitimate HTTPS connections using:
// - X25519 ECDH key exchange
// - HKDF-SHA256 key derivation
// - AES-256-GCM encryption
// - HMAC-SHA512 authentication

mod common;
mod reality_aead;
mod reality_auth;
mod reality_certificate;
mod reality_cipher_suite;
mod reality_client_connection;
mod reality_client_verify;
mod reality_io_state;
mod reality_reader_writer;
mod reality_records;
mod reality_server_connection;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;

pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub use reality_util::{decode_private_key, decode_public_key, decode_short_id, generate_keypair};

// Re-export connection types for crypto_connection module
pub use reality_client_connection::{
    RealityClientConfig, RealityClientConnection, feed_reality_client_connection,
};
pub use reality_reader_writer::{RealityReader, RealityWriter};
pub use reality_server_connection::{
    RealityServerConfig, RealityServerConnection, feed_reality_server_connection,
};
