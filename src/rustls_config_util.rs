use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::pki_types::pem::PemObject;

pub fn try_create_client_config(
    verify_webpki: bool,
    server_fingerprints: Vec<String>,
    alpn_protocols: Vec<String>,
    enable_sni: bool,
    client_key_and_cert: Option<(Vec<u8>, Vec<u8>)>,
    tls13_only: bool,
) -> std::io::Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(get_crypto_provider());
    let builder = if tls13_only {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
    } else {
        builder.with_safe_default_protocol_versions().unwrap()
    };

    let builder = if verify_webpki {
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            get_root_cert_store(),
            get_crypto_provider(),
        )
        .build()
        .unwrap();
        if !server_fingerprints.is_empty() {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                    supported_algs: get_supported_algorithms(),
                    server_fingerprints: process_fingerprints(&server_fingerprints)?,
                    webpki_verifier: Some(Arc::into_inner(webpki_verifier).unwrap()),
                }))
        } else {
            builder.with_webpki_verifier(webpki_verifier)
        }
    } else if !server_fingerprints.is_empty() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerFingerprintVerifier {
                supported_algs: get_supported_algorithms(),
                server_fingerprints: process_fingerprints(&server_fingerprints)?,
                webpki_verifier: None,
            }))
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(get_disabled_verifier())
    };

    let mut config = match client_key_and_cert {
        Some((key_bytes, cert_bytes)) => {
            // Parse all certificates from the PEM file (client cert + intermediates if any)
            let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(std::io::Error::other)?;

            let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_bytes)
                .map_err(std::io::Error::other)?;
            builder
                .with_client_auth_cert(certs, privkey)
                .map_err(std::io::Error::other)?
        }
        None => builder.with_no_client_auth(),
    };

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.enable_sni = enable_sni;
    Ok(config)
}

#[derive(Debug)]
pub struct ServerFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    server_fingerprints: BTreeSet<Vec<u8>>,
    webpki_verifier: Option<rustls::client::WebPkiServerVerifier>,
}

impl rustls::client::danger::ServerCertVerifier for ServerFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            let _ = webpki_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.server_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown server fingerprint: {hex_fingerprint}"
            )))
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

fn get_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTANCE: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .clone()
}

fn get_supported_algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    get_crypto_provider().signature_verification_algorithms
}

fn get_disabled_verifier() -> Arc<DisabledVerifier> {
    static INSTANCE: OnceLock<Arc<DisabledVerifier>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            Arc::new(DisabledVerifier {
                supported_algs: get_supported_algorithms(),
            })
        })
        .clone()
}

fn get_root_cert_store() -> Arc<rustls::RootCertStore> {
    static INSTANCE: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(root_store)
        })
        .clone()
}

/// Creates a simple TLS ClientConfig with root CA verification.
/// Used by hickory-resolver for DoT/DoH connections.
pub fn create_dns_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates((*get_root_cert_store()).clone())
        .with_no_client_auth()
}

pub fn try_create_server_config(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    ca_cert_bytes: Vec<Vec<u8>>,
    alpn_protocols: &[String],
    client_fingerprints: &[String],
) -> std::io::Result<rustls::ServerConfig> {
    // Parse all certificates from the PEM file (server cert + intermediates)
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)?;

    log::debug!(
        "TLS server config: loaded {} certificate(s) in chain",
        certs.len()
    );

    let privkey = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_bytes)
        .map_err(std::io::Error::other)?;

    let webpki_verifier = if ca_cert_bytes.is_empty() {
        None
    } else {
        let mut store = rustls::RootCertStore::empty();
        for ca_cert in ca_cert_bytes.into_iter() {
            let ca_cert = rustls::pki_types::CertificateDer::from_pem_slice(&ca_cert)
                .map_err(std::io::Error::other)?
                .into_owned();
            store.add(ca_cert).map_err(std::io::Error::other)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(store),
            get_crypto_provider(),
        )
        .build()
        .map_err(std::io::Error::other)?;
        Some(verifier)
    };

    let builder = rustls::ServerConfig::builder_with_provider(get_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap();
    // Always wraps in ClientFingerprintVerifier even for CA-only auth, because
    // WebPkiClientVerifier's root_hint_subjects() leaks CA names to unauthenticated clients.
    let builder = if client_fingerprints.is_empty() && webpki_verifier.is_none() {
        builder.with_no_client_auth()
    } else {
        builder.with_client_cert_verifier(Arc::new(ClientFingerprintVerifier {
            supported_algs: get_supported_algorithms(),
            webpki_verifier,
            client_fingerprints: process_fingerprints(client_fingerprints)?,
        }))
    };
    let mut config = builder
        .with_single_cert(certs, privkey)
        .map_err(std::io::Error::other)?;

    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();

    config.max_fragment_size = None;
    config.max_early_data_size = u32::MAX;
    config.ignore_client_order = true;

    Ok(config)
}

pub fn process_fingerprints(client_fingerprints: &[String]) -> std::io::Result<BTreeSet<Vec<u8>>> {
    let mut result = BTreeSet::new();

    for fingerprint in client_fingerprints {
        // Remove any colons and whitespace
        let clean_fp = fingerprint.replace(":", "").replace(" ", "");

        if !clean_fp.is_ascii() || clean_fp.len() % 2 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid client fingerprint, expected pairs of ASCII hex digits: {fingerprint}"
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
                    format!("Invalid client fingerprint, could not convert to hex: {fingerprint}"),
                )
            })?;

        result.insert(bytes);
    }

    Ok(result)
}

#[cfg(test)]
mod material_tests {
    use super::*;

    #[test]
    fn certificate_errors_are_fallible_for_both_roles() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let key = cert.signing_key.serialize_pem();
        let wrong_key = other.signing_key.serialize_pem();
        for (cert, key, valid) in [
            (pem.as_str(), key.as_str(), true),
            ("invalid", key.as_str(), false),
            (pem.as_str(), "invalid", false),
            (pem.as_str(), wrong_key.as_str(), false),
        ] {
            assert_eq!(
                try_create_server_config(cert.as_bytes(), key.as_bytes(), vec![], &[], &[]).is_ok(),
                valid
            );
            assert_eq!(
                try_create_client_config(
                    false,
                    vec![],
                    vec![],
                    true,
                    Some((key.as_bytes().to_vec(), cert.as_bytes().to_vec())),
                    false
                )
                .is_ok(),
                valid
            );
        }
        assert!(
            try_create_server_config(
                pem.as_bytes(),
                key.as_bytes(),
                vec![b"invalid".to_vec()],
                &[],
                &[]
            )
            .is_err()
        );
        assert!(process_fingerprints(&["\u{e9}ab".into()]).is_err());
    }
}

#[derive(Debug)]
pub struct ClientFingerprintVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
    webpki_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    client_fingerprints: BTreeSet<Vec<u8>>,
}

impl rustls::server::danger::ClientCertVerifier for ClientFingerprintVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        // Avoids leaking trusted CA names to unauthenticated clients.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if let Some(ref webpki_verifier) = self.webpki_verifier {
            let result = webpki_verifier.verify_client_cert(end_entity, intermediates, now);
            if result.is_ok() {
                return Ok(rustls::server::danger::ClientCertVerified::assertion());
            }
        }

        let fingerprint =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, end_entity.as_ref());
        let fingerprint_bytes = fingerprint.as_ref();

        if self.client_fingerprints.contains(fingerprint_bytes) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            let hex_fingerprint = fingerprint_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join(":");

            Err(rustls::Error::General(format!(
                "unknown client fingerprint: {hex_fingerprint}"
            )))
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
