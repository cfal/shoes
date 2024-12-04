use log::error;
use std::collections::BTreeSet;
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
        if let rustls_pemfile::Item::X509Certificate(cert) = item.unwrap() {
            certs.push(rustls::Certificate(cert));
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
    client_fingerprints: &[String],
) -> rustls::ServerConfig {
    let certs = load_certs(cert_bytes);
    let privkey = load_private_key(key_bytes);

    let builder = rustls::ServerConfig::builder().with_safe_defaults();
    let builder = if client_fingerprints.len() == 0 {
        builder.with_no_client_auth()
    } else {
        builder.with_client_cert_verifier(Arc::new(KnownPublicKeysVerifier {
            public_keys: process_client_fingerprints(client_fingerprints),
        }))
    };
    let mut config = builder
        .with_single_cert(certs, privkey)
        .expect("bad certificate/key");

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.max_early_data_size = u32::MAX;

    config
}

fn process_client_fingerprints(client_fingerprints: &[String]) -> BTreeSet<Vec<u8>> {
    let mut result = BTreeSet::new();

    for fingerprint in client_fingerprints {
        // Remove any colons and whitespace
        let clean_fp = fingerprint.replace(":", "").replace(" ", "");

        if clean_fp.len() % 2 != 0 {
            panic!("Invalid client fingerprint, odd number of hex chars");
        }

        if let Ok(bytes) = (0..clean_fp.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_fp[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
        {
            result.insert(bytes);
        }
    }

    result
}

pub struct KnownPublicKeysVerifier {
    public_keys: BTreeSet<Vec<u8>>,
}

impl rustls::server::ClientCertVerifier for KnownPublicKeysVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        // Calculate SHA-256 fingerprint of the entire certificate
        let fingerprint = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref().to_vec();

        if self.public_keys.contains(&fingerprint_bytes) {
            Ok(rustls::server::ClientCertVerified::assertion())
        } else {
            // Format fingerprint as hex string for error message
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join(":");

            error!(
                "Unknown client certificate with public key fingerprint: {}",
                hex_fingerprint
            );
            Err(rustls::Error::General("Unknown client public key".into()))
        }
    }
}
