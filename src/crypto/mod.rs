// Unified cryptographic connection abstraction
//
// This module provides a common interface for different TLS-like protocols,
// allowing rustls and REALITY to be used interchangeably throughout the codebase.

mod crypto_connection;
mod crypto_reader_writer;
mod crypto_tls_stream;

// Re-export core types
pub use crypto_connection::{feed_crypto_connection, CryptoConnection};
pub use crypto_tls_stream::CryptoTlsStream;
// CryptoReader, CryptoWriter, and IoState are used internally within this module
