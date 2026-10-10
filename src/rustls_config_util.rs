use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::pki_types::pem::PemObject;

use crate::config::TlsKeyExchangeGroups;

#[cfg(test)]
mod hybrid_tests;

pub fn try_create_client_config(
    verify_webpki: bool,
    server_fingerprints: Vec<String>,
    alpn_protocols: Vec<String>,
    enable_sni: bool,
    client_key_and_cert: Option<(Vec<u8>, Vec<u8>)>,
    tls13_only: bool,
    key_exchange_groups: &TlsKeyExchangeGroups,
) -> std::io::Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(crypto_provider_with_groups(
        key_exchange_groups,
    ));
    let builder = if tls13_only || key_exchange_groups.requires_hybrid() {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(std::io::Error::other)?;

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
    if key_exchange_groups.requires_hybrid() {
        config.enable_early_data = false;
    }
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

fn crypto_provider_with_groups(
    groups: &TlsKeyExchangeGroups,
) -> Arc<rustls::crypto::CryptoProvider> {
    let Some(groups) = groups.groups() else {
        return get_crypto_provider();
    };
    let mut provider = (*get_crypto_provider()).clone();
    provider.kx_groups = groups.iter().map(|group| group.rustls_group()).collect();
    Arc::new(provider)
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
    key_exchange_groups: &TlsKeyExchangeGroups,
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

    let builder = rustls::ServerConfig::builder_with_provider(crypto_provider_with_groups(
        key_exchange_groups,
    ));
    let builder = if key_exchange_groups.requires_hybrid() {
        builder.with_protocol_versions(&[&rustls::version::TLS13])
    } else {
        builder.with_safe_default_protocol_versions()
    }
    .map_err(std::io::Error::other)?;
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
    if key_exchange_groups.requires_hybrid() {
        config.max_early_data_size = 0;
        config.send_half_rtt_data = false;
    }
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
    use std::io::{Read, Write};

    fn resumption_configs() -> (Arc<rustls::ClientConfig>, rustls::ServerConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = try_create_server_config(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
            vec![],
            &[],
            &[],
            &Default::default(),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(get_crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.enable_early_data = true;
        (Arc::new(client), server)
    }

    fn transfer_tls(
        from: &mut rustls::Connection,
        to: &mut rustls::Connection,
    ) -> Result<(), rustls::Error> {
        let mut wire = Vec::new();
        from.write_tls(&mut wire).unwrap();
        let mut wire = std::io::Cursor::new(wire);
        while wire.position() < wire.get_ref().len() as u64 {
            assert!(to.read_tls(&mut wire).unwrap() > 0);
            to.process_new_packets()?;
        }
        Ok(())
    }

    fn finish_handshake(client: &mut rustls::Connection, server: &mut rustls::Connection) {
        for _ in 0..8 {
            transfer_tls(client, server).unwrap();
            transfer_tls(server, client).unwrap();
            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                return;
            }
        }
        panic!("TLS handshake did not complete");
    }

    #[test]
    fn tcp_tls_disables_early_data_without_disabling_resumption() {
        let (client_config, server_config) = resumption_configs();
        assert_eq!(server_config.max_early_data_size, 0);
        let server_config = Arc::new(server_config);
        for expected in [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed] {
            let mut client = rustls::ClientConnection::new(
                client_config.clone(),
                "localhost".try_into().unwrap(),
            )
            .unwrap();
            assert!(client.early_data().is_none());
            let mut client = rustls::Connection::Client(client);
            let mut server = rustls::Connection::Server(
                rustls::ServerConnection::new(server_config.clone()).unwrap(),
            );
            finish_handshake(&mut client, &mut server);
            assert_eq!(client.handshake_kind(), Some(expected));
            assert_eq!(server.handshake_kind(), Some(expected));
            client.writer().write_all(b"proxy request").unwrap();
            transfer_tls(&mut client, &mut server).unwrap();
            let mut request = [0; 13];
            server.reader().read_exact(&mut request).unwrap();
            assert_eq!(&request, b"proxy request");
        }
    }

    #[test]
    fn tcp_tls_rejects_stale_early_data_and_bounds_discarded_bytes() {
        for early_len in [1024, 32 * 1024] {
            let (client_config, mut previous_config) = resumption_configs();
            previous_config.max_early_data_size = u32::MAX;
            let mut current_config = previous_config.clone();
            current_config.max_early_data_size = 0;
            let mut client = rustls::Connection::Client(
                rustls::ClientConnection::new(
                    client_config.clone(),
                    "localhost".try_into().unwrap(),
                )
                .unwrap(),
            );
            let mut server = rustls::Connection::Server(
                rustls::ServerConnection::new(Arc::new(previous_config)).unwrap(),
            );
            finish_handshake(&mut client, &mut server);

            let mut resumed =
                rustls::ClientConnection::new(client_config, "localhost".try_into().unwrap())
                    .unwrap();
            resumed.set_buffer_limit(None);
            resumed
                .early_data()
                .unwrap()
                .write_all(&vec![b'x'; early_len])
                .unwrap();
            let mut client = rustls::Connection::Client(resumed);
            let mut server = rustls::Connection::Server(
                rustls::ServerConnection::new(Arc::new(current_config)).unwrap(),
            );
            let result = transfer_tls(&mut client, &mut server);
            if early_len > 16 * 1024 {
                assert!(
                    result.is_err(),
                    "stale early data must not be discarded without a bound"
                );
                continue;
            }
            result.unwrap();
            finish_handshake(&mut client, &mut server);
            let rustls::Connection::Client(ref client_conn) = client else {
                unreachable!()
            };
            assert!(!client_conn.is_early_data_accepted());
            assert_eq!(
                client.handshake_kind(),
                Some(rustls::HandshakeKind::Resumed)
            );
            let rustls::Connection::Server(ref mut server_conn) = server else {
                unreachable!()
            };
            assert!(server_conn.early_data().is_none());
            assert_eq!(
                server.reader().read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            client.writer().write_all(b"retried").unwrap();
            transfer_tls(&mut client, &mut server).unwrap();
            let mut request = [0; 7];
            server.reader().read_exact(&mut request).unwrap();
            assert_eq!(&request, b"retried");
        }
    }

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
                try_create_server_config(
                    cert.as_bytes(),
                    key.as_bytes(),
                    vec![],
                    &[],
                    &[],
                    &Default::default()
                )
                .is_ok(),
                valid
            );
            assert_eq!(
                try_create_client_config(
                    false,
                    vec![],
                    vec![],
                    true,
                    Some((key.as_bytes().to_vec(), cert.as_bytes().to_vec())),
                    false,
                    &Default::default(),
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
                &[],
                &Default::default(),
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
