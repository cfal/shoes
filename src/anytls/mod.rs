//! AnyTLS protocol implementation for shoes
//!
//! AnyTLS is a TLS-based proxy protocol with:
//! - Session multiplexing: Multiple proxy streams over a single TLS connection
//! - Configurable padding: First N packets are padded to obscure fingerprints
//! - Password authentication: SHA256-based user authentication

mod anytls_client_handler;
mod anytls_client_session;
mod anytls_padding;
mod anytls_server_handler;
mod anytls_server_session;
mod anytls_stream;
mod anytls_types;

pub use anytls_client_handler::AnyTlsClientHandler;
pub use anytls_padding::PaddingFactory;
pub use anytls_server_handler::AnyTlsServerHandler;
