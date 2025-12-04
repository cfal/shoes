// Server parts not used by library's public API

// REALITY protocol: TLS obfuscation using X25519, HKDF-SHA256, AES-256-GCM, HMAC-SHA512

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
mod reality_server_handler;
mod reality_tls13_keys;
mod reality_tls13_messages;
mod reality_util;

pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
// generate_keypair is used by binary, not by library's public API
#[allow(unused_imports)]
pub use reality_util::{decode_private_key, decode_public_key, decode_short_id, generate_keypair};

// Re-exports for crypto_connection module
pub use reality_client_connection::{
    RealityClientConfig, RealityClientConnection, feed_reality_client_connection,
};
pub use reality_reader_writer::{RealityReader, RealityWriter};
pub use reality_server_connection::{
    RealityServerConfig, RealityServerConnection, feed_reality_server_connection,
};
pub use reality_server_handler::{RealityServerTarget, setup_reality_server_stream};
