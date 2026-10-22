//! Shared rustls transport, including record-preserving Vision transitions.

mod crypto_handshake;
mod crypto_tls_stream;
mod tls_connection;
pub mod tls_deframer;
mod tls_reader_writer;

pub use crypto_tls_stream::{CryptoTlsStream, TlsReadMode};
pub use tls_connection::TlsConnection;
pub(crate) use tls_connection::tls_error;
