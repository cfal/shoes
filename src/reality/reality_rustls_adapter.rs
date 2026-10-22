use std::fmt;
use std::sync::Arc;

use aws_lc_rs::{agreement, kem, signature};
use parking_lot::Mutex;
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, NamedGroup, SignatureScheme};
use zeroize::Zeroizing;

use super::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
use super::reality_certificate_verify::{
    extract_ed25519_public_key, verify_certificate_hmac, verify_certificate_mldsa,
};
use super::reality_hello::MLKEM_CIPHERTEXT_LEN;
use super::{CipherSuite, DEFAULT_CIPHER_SUITES, RealityClientConfig};

pub(super) fn provider(suites: &[CipherSuite]) -> CryptoProvider {
    let suites = if suites.is_empty() {
        DEFAULT_CIPHER_SUITES
    } else {
        suites
    };
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = suites
        .iter()
        .filter_map(|suite| {
            provider
                .cipher_suites
                .iter()
                .find(|supported| u16::from(supported.suite()) == suite.id())
                .copied()
        })
        .collect();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        rustls::crypto::aws_lc_rs::kx_group::X25519,
    ];
    provider
}

fn crypto_error() -> Error {
    Error::General("REALITY key exchange failed".into())
}

fn verification_error() -> Error {
    Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

#[derive(Default)]
struct VerificationContext {
    auth: Option<Zeroizing<[u8; 32]>>,
    hellos: Vec<u8>,
    public_key: Option<[u8; 32]>,
}

pub(super) struct ClientAuthentication {
    server_key: [u8; 32],
    short_id: [u8; 8],
    shared: Option<Zeroizing<[u8; 32]>>,
    context: Arc<Mutex<VerificationContext>>,
}

impl fmt::Debug for ClientAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientAuthentication")
            .finish_non_exhaustive()
    }
}

pub(super) struct RealityVerifier {
    context: Arc<Mutex<VerificationContext>>,
    mldsa: Option<super::reality_mldsa::VerifyKey>,
    schemes: Vec<SignatureScheme>,
}

impl fmt::Debug for RealityVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityVerifier").finish_non_exhaustive()
    }
}

pub(super) fn client_authentication(
    config: &RealityClientConfig,
    schemes: Vec<SignatureScheme>,
) -> (ClientAuthentication, RealityVerifier) {
    let context = Arc::new(Mutex::new(VerificationContext::default()));
    (
        ClientAuthentication {
            server_key: config.public_key,
            short_id: config.short_id,
            shared: None,
            context: context.clone(),
        },
        RealityVerifier {
            context,
            mldsa: config.mldsa65_verify.clone(),
            schemes,
        },
    )
}

struct ClientExchange {
    private: Zeroizing<[u8; 32]>,
    mlkem: Option<kem::DecapsulationKey>,
    public: Vec<u8>,
    group: NamedGroup,
}

impl ActiveKeyExchange for ClientExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let offset = if self.group == NamedGroup::X25519MLKEM768 {
            MLKEM_CIPHERTEXT_LEN
        } else {
            0
        };
        let x25519_peer =
            peer.get(offset..)
                .and_then(|p| p.try_into().ok())
                .ok_or(Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::InvalidKeyShare,
                ))?;
        let x25519 =
            Zeroizing::new(perform_ecdh(&self.private, x25519_peer).map_err(|_| crypto_error())?);
        let mut shared = Zeroizing::new(Vec::with_capacity(64));
        if offset != 0 {
            let kem = self.mlkem.as_ref().ok_or_else(crypto_error)?;
            let secret = kem
                .decapsulate(kem::Ciphertext::from(&peer[..offset]))
                .map_err(|_| crypto_error())?;
            shared.extend_from_slice(secret.as_ref());
        }
        shared.extend_from_slice(x25519.as_ref());
        Ok(SharedSecret::from(shared.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        self.group
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        (self.group == NamedGroup::X25519MLKEM768)
            .then(|| (NamedGroup::X25519, &self.public[self.public.len() - 32..]))
    }

    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer = peer.try_into().map_err(|_| crypto_error())?;
        let shared = Zeroizing::new(perform_ecdh(&self.private, peer).map_err(|_| crypto_error())?);
        Ok(SharedSecret::from(shared.as_ref()))
    }
}

impl rustls::reality::ClientHooks for ClientAuthentication {
    fn start_key_exchange(
        &mut self,
        kx: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        if !matches!(kx.name(), NamedGroup::X25519 | NamedGroup::X25519MLKEM768) {
            return Err(crypto_error());
        }
        let mut private = Zeroizing::new([0; 32]);
        rand::rng().fill_bytes(private.as_mut());
        let key = agreement::PrivateKey::from_private_key(&agreement::X25519, private.as_ref())
            .map_err(|_| crypto_error())?;
        let public = key.compute_public_key().map_err(|_| crypto_error())?;
        self.shared = Some(Zeroizing::new(
            perform_ecdh(&private, &self.server_key).map_err(|_| crypto_error())?,
        ));
        let (mlkem, mut share) = if kx.name() == NamedGroup::X25519MLKEM768 {
            let key =
                kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| crypto_error())?;
            let public = key
                .encapsulation_key()
                .and_then(|key| key.key_bytes())
                .map_err(|_| crypto_error())?;
            (Some(key), public.as_ref().to_vec())
        } else {
            (None, Vec::new())
        };
        share.extend_from_slice(public.as_ref());
        Ok(Box::new(ClientExchange {
            private,
            mlkem,
            public: share,
            group: kx.name(),
        }))
    }

    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error> {
        let shared = self.shared.take().ok_or_else(crypto_error)?;
        let random = hello.get(6..38).ok_or_else(crypto_error)?;
        let auth = Zeroizing::new(
            derive_auth_key(&shared, &random[..20], b"REALITY").map_err(|_| crypto_error())?,
        );
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::FailedToGetCurrentTime)?
            .as_secs() as u32;
        let mut plaintext = Zeroizing::new([0; 16]);
        plaintext[..3].copy_from_slice(&[1, 8, 0]);
        plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
        plaintext[8..].copy_from_slice(&self.short_id);
        let mut aad = hello.to_vec();
        aad.get_mut(39..71).ok_or_else(crypto_error)?.fill(0);
        let id = encrypt_session_id(&plaintext, &auth, &random[20..], &aad)
            .map_err(|_| crypto_error())?;
        self.context.lock().auth = Some(auth);
        Ok(id)
    }

    fn server_hello(&mut self, client: &[u8], server: &[u8]) -> Result<(), Error> {
        let mut context = self.context.lock();
        context.hellos.extend_from_slice(client);
        context.hellos.extend_from_slice(server);
        Ok(())
    }
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut context = self.context.lock();
        let auth = context.auth.take().ok_or_else(verification_error)?;
        if !intermediates.is_empty() || context.hellos.is_empty() {
            return Err(verification_error());
        }
        let public =
            verify_certificate_hmac(end_entity, &auth).map_err(|_| verification_error())?;
        if let Some(key) = &self.mldsa {
            verify_certificate_mldsa(end_entity, &auth, &context.hellos, key)
                .map_err(|_| verification_error())?;
        }
        context.public_key = Some(public);
        context.hellos.clear();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(verification_error())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let context = self.context.lock();
        let public = context.public_key.ok_or_else(verification_error)?;
        if signature.scheme != SignatureScheme::ED25519
            || extract_ed25519_public_key(cert).map_err(|_| verification_error())? != public
        {
            return Err(verification_error());
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(message, signature.signature())
            .map_err(|_| verification_error())?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

pub(super) struct RealitySigningKey(Arc<signature::Ed25519KeyPair>);

impl RealitySigningKey {
    pub(super) fn new(key: signature::Ed25519KeyPair) -> Self {
        Self(Arc::new(key))
    }
}

impl fmt::Debug for RealitySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RealitySigningKey")
    }
}

impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        Some(Box::new(Self(self.0.clone())))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

impl rustls::sign::Signer for RealitySigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.sign(message).as_ref().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
