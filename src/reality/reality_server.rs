use std::io;
use std::sync::Arc;

use bytes::Bytes;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::CipherSuite;
use super::reality_auth::{decrypt_session_id, derive_auth_key, perform_ecdh};
use super::reality_certificate::generate_hmac_certificate;
use super::reality_key_exchange::extract_client_key_shares;
use super::reality_rustls::{RealitySigningKey, provider};
use super::reality_target_template::{flight_plan, verify_staged_flight};
use super::reality_util::{extract_client_random, extract_session_id_slice};
use crate::address::{Address, NetLocation};
use crate::crypto::{TlsConnection, tls_error};

#[derive(Clone)]
pub struct RealityServerConfig {
    pub mldsa65_key: Option<Arc<aws_lc_rs::signature::PqdsaKeyPair>>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub dest: NetLocation,
    pub max_time_diff: Option<u64>,
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    pub cipher_suites: Vec<CipherSuite>,
}

pub struct AuthenticatedClientHello {
    config: RealityServerConfig,
    record: Vec<u8>,
    auth_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for AuthenticatedClientHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedClientHello")
            .finish_non_exhaustive()
    }
}

impl RealityServerConfig {
    pub fn authenticate_client_hello(self, hello: &[u8]) -> io::Result<AuthenticatedClientHello> {
        let random = extract_client_random(hello)?;
        let session = extract_session_id_slice(hello)?;
        let shares = extract_client_key_shares(hello)?;
        let peer = shares.authentication_public_key()?;
        let shared = Zeroizing::new(perform_ecdh(&self.private_key, peer)?);
        let auth_key = Zeroizing::new(derive_auth_key(&shared, &random[..20], b"REALITY")?);
        let session: &[u8; 32] = session.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid REALITY session ID")
        })?;
        let mut aad = hello[5..].to_vec();
        aad[39..71].fill(0);
        let metadata = Zeroizing::new(
            decrypt_session_id(session, &auth_key, &random[20..], &aad)
                .map_err(|_| denied("REALITY session authentication failed"))?,
        );
        let version: [u8; 3] = metadata[..3].try_into().unwrap();
        let short_id: [u8; 8] = metadata[8..16].try_into().unwrap();
        if !self
            .short_ids
            .iter()
            .fold(false, |found, id| found | bool::from(short_id.ct_eq(id)))
        {
            return Err(denied("Invalid REALITY short ID"));
        }
        if self.min_client_version.is_some_and(|min| version < min)
            || self.max_client_version.is_some_and(|max| version > max)
        {
            return Err(denied("Unsupported REALITY client version"));
        }
        if let Some(max_ms) = self.max_time_diff {
            let timestamp = u32::from_be_bytes(metadata[4..8].try_into().unwrap()) as u64;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| io::Error::other("System time error"))?
                .as_secs();
            if now.abs_diff(timestamp) > max_ms / 1000 {
                return Err(denied("REALITY timestamp outside allowed window"));
            }
        }
        Ok(AuthenticatedClientHello {
            config: self,
            record: hello.to_vec(),
            auth_key,
        })
    }
}

impl AuthenticatedClientHello {
    pub fn into_connection(self, records: &[Bytes]) -> io::Result<TlsConnection> {
        let plan = flight_plan(records)?;
        let crypto = provider(&self.config.cipher_suites);
        let hello = &self.record[5..];
        let prepared = rustls::reality::PreparedServerHello::new(hello, &records[0][5..], &crypto)
            .map_err(|error| match error {
                rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare) => {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "Unsupported REALITY peer key share",
                    )
                }
                error => tls_error(error),
            })?
            .with_flight_plan(plan);
        let hostname = match self.config.dest.address() {
            Address::Hostname(hostname) => hostname,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY requires a hostname destination",
                ));
            }
        };
        let mldsa = self
            .config
            .mldsa65_key
            .as_deref()
            .map(|key| (key, hello, prepared.server_hello()));
        let (certificate, key) = generate_hmac_certificate(&self.auth_key, hostname, mldsa)?;
        let key = rustls::sign::CertifiedKey::new(
            vec![certificate.der().clone()],
            Arc::new(RealitySigningKey::new(key)),
        );
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(crypto))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_error)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
        let expected_hello = prepared.server_hello().to_vec();
        let server =
            rustls::ServerConnection::new_reality(Arc::new(config), prepared).map_err(tls_error)?;
        // Stage the complete flight without socket access. On failure even queued alerts are discarded.
        let mut staged = TlsConnection::new_reality(server);
        staged.feed(&self.record).map_err(|error| {
            if error.kind() == io::ErrorKind::Unsupported {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unsupported REALITY target or insufficient capacity",
                )
            } else {
                error
            }
        })?;
        let mut wire = Vec::new();
        while staged.wants_write() {
            if staged.write_tls(&mut wire)? == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
        }
        verify_staged_flight(&wire, records, &expected_hello)?;
        staged.set_staged_output(wire.into());
        Ok(staged)
    }
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
