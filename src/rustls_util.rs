use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::pki_types::pem::PemObject;

pub fn create_client_config(
    verify: bool,
    alpn_protocols: &[String],
    enable_sni: bool,
) -> rustls::ClientConfig {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap();

    let mut config = if !verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(get_disabled_verifier())
            .with_no_client_auth()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
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

#[derive(Debug)]
pub struct DisabledVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: OnceLock<Arc<DisabledVerifier>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let default_provider = rustls::crypto::ring::default_provider();
            let supported_algs = default_provider.signature_verification_algorithms;
            Arc::new(DisabledVerifier { supported_algs })
        })
        .clone()
}

pub fn create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> rustls::ServerConfig {
    let certs = vec![
        rustls::pki_types::CertificateDer::from_pem_slice(cert_bytes)
            .unwrap()
            .into_owned(),
    ];

    // there's no into_owned for PrivateKeyDer.
    let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes).unwrap();

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap();
    let builder =
        if client_fingerprints.is_empty() || client_fingerprints.iter().any(|fp| fp == "any") {
            builder.with_no_client_auth()
        } else {
            let default_provider = rustls::crypto::ring::default_provider();
            let supported_algs = default_provider.signature_verification_algorithms;
            builder.with_client_cert_verifier(Arc::new(KnownPublicKeysVerifier {
                supported_algs,
                public_keys: process_client_fingerprints(client_fingerprints).unwrap(),
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

pub fn process_client_fingerprints(
    client_fingerprints: &[String],
) -> std::io::Result<BTreeSet<Vec<u8>>> {
    let mut result = BTreeSet::new();

    for fingerprint in client_fingerprints {
        // Remove any colons and whitespace
        let clean_fp = fingerprint.replace(":", "").replace(" ", "");

        if clean_fp.len() % 2 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid client fingerprint, odd number of hex chars: {}",
                    fingerprint
                ),
            ));
        }

        let bytes = (0..clean_fp.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean_fp[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Invalid client fingerprint, could not convert to hex: {}",
                        fingerprint
                    ),
                )
            })?;

        result.insert(bytes);
    }

    Ok(result)
}

#[derive(Debug)]
pub struct KnownPublicKeysVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    public_keys: BTreeSet<Vec<u8>>,
}

impl rustls::server::danger::ClientCertVerifier for KnownPublicKeysVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Calculate SHA-256 fingerprint of the entire certificate
        let fingerprint = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.public_keys.contains(fingerprint_bytes) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            // Format fingerprint as hex string for error message
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(
                format!("unknown client certificate: {}", hex_fingerprint).into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
