//! Certificate generation helpers for tests

use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

/// Struct to hold CA state
struct CaState {
    key_pair: rcgen::KeyPair,
    params: rcgen::CertificateParams,
}

static CA_STATE: OnceLock<CaState> = OnceLock::new();

/// Path where we store our test CA cert for system trust
pub const TEST_CA_SYSTEM_PATH: &str = "/usr/local/share/ca-certificates/shoes-test-ca.crt";

/// Initialize the test CA and install it to the system trust store.
/// This only runs once per test run.
pub fn init_test_ca() -> io::Result<()> {
    // Use get_or_init with a wrapper that stores Result
    static INIT_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

    let result = INIT_RESULT.get_or_init(|| {
        match do_init_test_ca() {
            Ok(state) => {
                // Store the state
                let _ = CA_STATE.set(state);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    });

    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(io::Error::other(e.clone())),
    }
}

fn do_init_test_ca() -> io::Result<CaState> {
    eprintln!("[CA] Initializing test CA and installing to system trust store...");

    let (state, ca_cert_pem) = generate_test_ca()?;

    // Write CA cert to system location
    std::fs::write(TEST_CA_SYSTEM_PATH, &ca_cert_pem).map_err(|e| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Failed to write CA cert to {}. Run with sudo: {}",
                TEST_CA_SYSTEM_PATH, e
            ),
        )
    })?;

    // Update CA certificates
    let output = Command::new("update-ca-certificates").output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "update-ca-certificates failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    eprintln!("[CA] Test CA installed successfully");
    Ok(state)
}

fn generate_test_ca() -> io::Result<(CaState, String)> {
    // Generate CA key pair
    let ca_key_pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;

    // Create CA certificate parameters with proper CN
    let mut ca_params = rcgen::CertificateParams::new(vec!["Shoes Test CA".to_string()])
        .map_err(io::Error::other)?;

    // Set a proper distinguished name for the CA
    let mut ca_dn = rcgen::DistinguishedName::new();
    ca_dn.push(rcgen::DnType::CommonName, "Shoes Test CA");
    ca_params.distinguished_name = ca_dn;

    // Make it a CA certificate
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    // IMPORTANT: Chromium/libcronet enforces a maximum certificate validity of 398 days.
    // The default rcgen validity (1975-4096) will be rejected with "cert validity too long".
    // This affects sing-box naive outbound which uses libcronet for TLS.
    // See: https://chromium.googlesource.com/chromium/src/+/master/net/cert/cert_verify_proc.cc
    let now = SystemTime::now();
    ca_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
    ca_params.not_after = (now + Duration::from_secs(397 * 24 * 60 * 60)).into();

    // Generate self-signed CA certificate
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .map_err(io::Error::other)?;

    Ok((
        CaState {
            key_pair: ca_key_pair,
            params: ca_params,
        },
        ca_cert.pem(),
    ))
}

/// Remove the test CA from the system trust store (cleanup)
pub fn cleanup_test_ca() -> io::Result<()> {
    if Path::new(TEST_CA_SYSTEM_PATH).exists() {
        eprintln!("[CA] Removing test CA from system trust store...");
        std::fs::remove_file(TEST_CA_SYSTEM_PATH)?;
        Command::new("update-ca-certificates")
            .arg("--fresh")
            .output()?;
        eprintln!("[CA] Test CA removed");
    }
    Ok(())
}

/// Generate a certificate signed by the test CA for a given hostname.
/// The CA must be initialized first with init_test_ca().
///
/// Returns (cert_pem, key_pem) as byte vectors
pub fn generate_ca_signed_cert(hostname: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
    // Ensure CA is initialized
    init_test_ca()?;

    let ca_state = CA_STATE
        .get()
        .ok_or_else(|| io::Error::other("CA not initialized"))?;

    generate_ca_signed_cert_with(hostname, ca_state)
}

fn generate_ca_signed_cert_with(
    hostname: &str,
    ca_state: &CaState,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    // Create issuer from CA params and key
    let issuer = rcgen::Issuer::from_params(&ca_state.params, &ca_state.key_pair);

    // Generate server key pair
    let server_key_pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    let server_key_pem = server_key_pair.serialize_pem();

    // Create server certificate parameters with proper CN
    let mut server_params =
        rcgen::CertificateParams::new(vec![hostname.to_string()]).map_err(io::Error::other)?;

    // Set a proper distinguished name for the server cert
    let mut server_dn = rcgen::DistinguishedName::new();
    server_dn.push(rcgen::DnType::CommonName, hostname);
    server_params.distinguished_name = server_dn;

    // IMPORTANT: Chromium/libcronet enforces a maximum certificate validity of 398 days.
    // See comment in do_init_test_ca() for details.
    let now = SystemTime::now();
    server_params.not_before = (now - Duration::from_secs(24 * 60 * 60)).into();
    server_params.not_after = (now + Duration::from_secs(365 * 24 * 60 * 60)).into();

    // Sign with CA
    let server_cert = server_params
        .signed_by(&server_key_pair, &issuer)
        .map_err(io::Error::other)?;

    let server_cert_pem = server_cert.pem();

    Ok((server_cert_pem.into_bytes(), server_key_pem.into_bytes()))
}

/// Generate a CA-signed certificate and write it to temporary files
///
/// Returns (cert_path, key_path) as tempfile::TempPath objects
pub fn generate_ca_signed_cert_files(
    hostname: &str,
) -> io::Result<(tempfile::TempPath, tempfile::TempPath)> {
    use std::io::Write;

    let (cert_pem, key_pem) = generate_ca_signed_cert(hostname)?;

    let mut cert_file = tempfile::NamedTempFile::new()?;
    let mut key_file = tempfile::NamedTempFile::new()?;

    cert_file.write_all(&cert_pem)?;
    key_file.write_all(&key_pem)?;

    cert_file.flush()?;
    key_file.flush()?;

    Ok((cert_file.into_temp_path(), key_file.into_temp_path()))
}

/// Generates a CA and leaf certificate in fixture-owned temporary files.
pub fn generate_ca_signed_cert_bundle_files(
    hostname: &str,
) -> io::Result<(tempfile::TempPath, tempfile::TempPath, tempfile::TempPath)> {
    use std::io::Write;

    let (ca_state, ca_pem) = generate_test_ca()?;
    let (cert_pem, key_pem) = generate_ca_signed_cert_with(hostname, &ca_state)?;

    let mut cert_file = tempfile::NamedTempFile::new()?;
    let mut key_file = tempfile::NamedTempFile::new()?;
    let mut ca_file = tempfile::Builder::new().suffix(".crt").tempfile()?;

    cert_file.write_all(&cert_pem)?;
    key_file.write_all(&key_pem)?;
    ca_file.write_all(ca_pem.as_bytes())?;
    cert_file.flush()?;
    key_file.flush()?;
    ca_file.flush()?;

    Ok((
        cert_file.into_temp_path(),
        key_file.into_temp_path(),
        ca_file.into_temp_path(),
    ))
}

/// Generate a self-signed certificate and private key for testing
///
/// Returns (cert_pem, key_pem) as byte vectors
pub fn generate_test_cert() -> io::Result<(Vec<u8>, Vec<u8>)> {
    // Generate key pair
    let key_pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;

    // Serialize key before using it
    let key_pem = key_pair.serialize_pem();

    // Create certificate parameters
    let params =
        rcgen::CertificateParams::new(vec!["test.local".to_string()]).map_err(io::Error::other)?;

    // Generate self-signed certificate
    let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;

    let cert_pem = cert.pem();

    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

/// An insecure certificate verifier that accepts any certificate.
/// Only for use in tests.
#[derive(Debug)]
pub struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Generate a self-signed certificate and write it to temporary files
///
/// Returns (cert_path, key_path) as tempfile::TempPath objects
pub fn generate_test_cert_files() -> io::Result<(tempfile::TempPath, tempfile::TempPath)> {
    use std::io::Write;

    let (cert_pem, key_pem) = generate_test_cert()?;

    // Create temp files
    let mut cert_file = tempfile::NamedTempFile::new()?;
    let mut key_file = tempfile::NamedTempFile::new()?;

    // Write the PEM data
    cert_file.write_all(&cert_pem)?;
    key_file.write_all(&key_pem)?;

    // Flush to ensure data is written
    cert_file.flush()?;
    key_file.flush()?;

    // Convert to TempPath (closes file handles but keeps paths alive for deletion on drop)
    let cert_temp_path = cert_file.into_temp_path();
    let key_temp_path = key_file.into_temp_path();

    Ok((cert_temp_path, key_temp_path))
}
