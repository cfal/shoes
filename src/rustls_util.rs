use std::sync::Arc;
use std::sync::OnceLock;

pub fn create_client_config(
    verify: bool,
    alpn_protocols: &[String],
    enable_sni: bool,
) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder().with_safe_defaults();

    let mut config = if !verify {
        builder
            .with_custom_certificate_verifier(get_disabled_verifier())
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
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

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.enable_sni = enable_sni;
    config
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
    static INSTANCE: OnceLock<Arc<DisabledVerifier>> = OnceLock::new();
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
            rustls_pemfile::Item::RSAKey(key) => {
                return rustls::PrivateKey(key);
            }
            _ => (),
        }
    }
    panic!("No private key found");
}

pub fn create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
) -> rustls::ServerConfig {
    let certs = load_certs(cert_bytes);
    let privkey = load_private_key(key_bytes);
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)
        .expect("bad certificate/key");

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.max_early_data_size = u32::MAX;

    config
}
