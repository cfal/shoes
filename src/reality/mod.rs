//! REALITY authentication, certificate policy, and target mirroring over rustls.

mod reality_auth;
mod reality_certificate;
mod reality_certificate_verify;
mod reality_cipher_suite;
mod reality_client;
mod reality_client_handler;
mod reality_config;
mod reality_hello;
mod reality_mldsa;
mod reality_rustls_adapter;
mod reality_server;
mod reality_server_handler;
mod reality_target_flight;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::reality_fixtures::{default_target_records, established_pair};

pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
pub(crate) use reality_config::parse_server_name;
#[allow(unused_imports)]
pub use reality_mldsa::{
    VerifyKey as Mldsa65VerifyKey, decode_mldsa65_seed, decode_mldsa65_verify,
    generate_mldsa65_keypair, mldsa65_signing_key,
};
// generate_keypair is used by binary, not by library's public API
#[allow(unused_imports)]
pub use reality_config::{
    decode_private_key, decode_public_key, decode_short_id, generate_keypair,
};

pub use reality_client::RealityClientConfig;
pub use reality_client_handler::RealityClientHandler;
pub use reality_server::RealityServerConfig;
pub use reality_server_handler::{RealityServerTarget, setup_reality_server_stream};
