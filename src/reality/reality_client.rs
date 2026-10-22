use std::io;
use std::sync::Arc;

use rustls::pki_types::ServerName;

use super::CipherSuite;
use super::reality_rustls_adapter::{client_authentication, provider};
use crate::crypto::{TlsConnection, tls_error};

#[derive(Clone)]
pub struct RealityClientConfig {
    pub mldsa65_verify: Option<super::reality_mldsa::VerifyKey>,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: ServerName<'static>,
    pub cipher_suites: Vec<CipherSuite>,
}

impl RealityClientConfig {
    pub fn create_connection(self) -> io::Result<TlsConnection> {
        let crypto = provider(&self.cipher_suites);
        let schemes = crypto.signature_verification_algorithms.supported_schemes();
        self.create_connection_with_options(crypto, schemes, Arc::new(rustls::NoKeyLog {}))
    }

    pub(super) fn create_connection_with_options(
        self,
        crypto: rustls::crypto::CryptoProvider,
        schemes: Vec<rustls::SignatureScheme>,
        key_log: Arc<dyn rustls::KeyLog>,
    ) -> io::Result<TlsConnection> {
        let (hooks, verifier) = client_authentication(&self, schemes);
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(crypto))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_error)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tls.cert_decompressors.clear();
        tls.key_log = key_log;
        let connection =
            rustls::ClientConnection::new_reality(Arc::new(tls), self.server_name, Box::new(hooks))
                .map_err(tls_error)?;
        Ok(TlsConnection::new_reality(connection))
    }
}
