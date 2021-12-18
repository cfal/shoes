use crate::async_stream::AsyncStream;
use crate::async_tls::{AsyncTlsAcceptor, AsyncTlsConnector, AsyncTlsFactory};

use std::lazy::SyncOnceCell;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

#[async_trait]
impl AsyncStream for tokio_rustls::client::TlsStream<TcpStream> {}

#[async_trait]
impl AsyncStream for tokio_rustls::server::TlsStream<TcpStream> {}

#[async_trait]
impl AsyncTlsAcceptor for tokio_rustls::TlsAcceptor {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<Box<dyn AsyncStream>> {
        tokio_rustls::TlsAcceptor::accept(&self, stream)
            .await
            .map(|mut s| {
                s.get_mut().1.set_buffer_limit(Some(32768));
                Box::new(s) as Box<dyn AsyncStream>
            })
    }
}

fn get_dummy_server_name() -> rustls::ServerName {
    static INSTANCE: SyncOnceCell<rustls::ServerName> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| rustls::ServerName::try_from("example.com").unwrap())
        .clone()
}

#[async_trait]
impl AsyncTlsConnector for tokio_rustls::TlsConnector {
    async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let server_name = match rustls::ServerName::try_from(domain) {
            Ok(s) => s,
            Err(_) => get_dummy_server_name(),
        };

        tokio_rustls::TlsConnector::connect(&self, server_name, stream)
            .await
            .map(|mut s| {
                s.get_mut().1.set_buffer_limit(Some(32768));
                Box::new(s) as Box<dyn AsyncStream>
            })
    }
}

pub struct RustlsFactory;

impl RustlsFactory {
    pub fn new() -> Self {
        Self
    }
}

fn create_client_config(verify: bool) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder().with_safe_defaults();

    let mut config = if !verify {
        builder
            .with_custom_certificate_verifier(get_disabled_verifier())
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // TODO: make SNI configurable
    config.enable_sni = true;
    config
}

fn get_client_config(verify: bool) -> Arc<rustls::ClientConfig> {
    static VERIFIED_INSTANCE: SyncOnceCell<Arc<rustls::ClientConfig>> = SyncOnceCell::new();
    static UNVERIFIED_INSTANCE: SyncOnceCell<Arc<rustls::ClientConfig>> = SyncOnceCell::new();
    if verify {
        VERIFIED_INSTANCE
            .get_or_init(|| Arc::new(create_client_config(true)))
            .clone()
    } else {
        UNVERIFIED_INSTANCE
            .get_or_init(|| Arc::new(create_client_config(false)))
            .clone()
    }
}

impl AsyncTlsFactory for RustlsFactory {
    fn create_acceptor(&self, cert_bytes: &[u8], key_bytes: &[u8]) -> Box<dyn AsyncTlsAcceptor> {
        let acceptor: tokio_rustls::TlsAcceptor =
            Arc::new(create_config(cert_bytes, key_bytes)).into();
        Box::new(acceptor)
    }

    fn create_connector(&self, verify: bool) -> Box<dyn AsyncTlsConnector> {
        let connector: tokio_rustls::TlsConnector = get_client_config(verify).into();
        Box::new(connector)
    }
}

pub struct DisabledVerifier;
impl rustls::client::ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::client::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: SyncOnceCell<Arc<DisabledVerifier>> = SyncOnceCell::new();
    INSTANCE
        .get_or_init(|| Arc::new(DisabledVerifier {}))
        .clone()
}

fn load_certs(cert_bytes: &[u8]) -> Vec<rustls::Certificate> {
    let mut reader = std::io::Cursor::new(cert_bytes);
    let mut certs = vec![];
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::X509Certificate(cert) => {
                certs.push(rustls::Certificate(cert));
            }
            _ => (),
        }
    }
    certs
}

fn load_private_key(key_bytes: &[u8]) -> rustls::PrivateKey {
    let mut reader = std::io::Cursor::new(key_bytes);
    for item in std::iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
        match item.unwrap() {
            rustls_pemfile::Item::PKCS8Key(key) => {
                return rustls::PrivateKey(key);
            }
            _ => (),
        }
    }
    panic!("No private key found");
}

fn create_config(cert_bytes: &[u8], key_bytes: &[u8]) -> rustls::ServerConfig {
    let certs = load_certs(cert_bytes);
    let privkey = load_private_key(key_bytes);
    rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)
        .expect("bad certificate/key")
}
