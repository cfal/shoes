use std::io;
use std::sync::Arc;

use super::CipherSuite;
use super::reality_connection::{RealityTransport, delegate_tls};
use super::reality_rustls::{client_authentication, io_error, provider};

#[derive(Clone)]
pub struct RealityClientConfig {
    pub mldsa65_verify: Option<super::reality_mldsa::VerifyKey>,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: String,
    pub cipher_suites: Vec<CipherSuite>,
}

pub struct RealityClientConnection {
    pub(super) transport: RealityTransport,
}

impl RealityClientConnection {
    pub fn new(config: RealityClientConfig) -> io::Result<Self> {
        let crypto = provider(&config.cipher_suites);
        let schemes = crypto.signature_verification_algorithms.supported_schemes();
        Self::with_options(config, crypto, schemes, Arc::new(rustls::NoKeyLog {}))
    }

    pub(super) fn with_options(
        config: RealityClientConfig,
        crypto: rustls::crypto::CryptoProvider,
        schemes: Vec<rustls::SignatureScheme>,
        key_log: Arc<dyn rustls::KeyLog>,
    ) -> io::Result<Self> {
        let (hooks, verifier) = client_authentication(&config, schemes);
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(crypto))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io_error)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tls.cert_decompressors.clear();
        tls.key_log = key_log;
        let name = config.server_name.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid REALITY server name")
        })?;
        let connection =
            rustls::ClientConnection::new_reality(Arc::new(tls), name, Box::new(hooks))
                .map_err(io_error)?;
        Ok(Self {
            transport: RealityTransport::new(connection.into()),
        })
    }

    delegate_tls!();
}

pub fn feed_reality_client_connection(
    connection: &mut RealityClientConnection,
    data: &[u8],
) -> io::Result<()> {
    connection.transport.feed(data)
}
