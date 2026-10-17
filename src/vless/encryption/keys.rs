use std::{fmt, io};

use aws_lc_rs::{agreement, kem};
use ml_kem::{
    DecapsulationKey, MlKem768, Seed,
    kem::{KeyExport, TryKeyInit},
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MLKEM_PUBLIC_LEN: usize = 1184;
pub(crate) const MLKEM_CIPHERTEXT_LEN: usize = 1088;
pub(crate) type Secret = Zeroizing<[u8; 32]>;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid VLESS encryption key exchange",
    )
}

#[allow(deprecated, reason = "AWS-LC imports expanded ML-KEM keys, not seeds")]
fn import_mlkem_seed(
    seed: &[u8; 64],
) -> io::Result<(kem::DecapsulationKey, kem::EncapsulationKey)> {
    use ml_kem::ExpandedKeyEncoding;

    let expanded = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
    let public = expanded.encapsulation_key().to_bytes();
    let mut private = expanded.to_expanded_bytes();
    let imported = kem::DecapsulationKey::new(&kem::ML_KEM_768, private.as_slice());
    private.zeroize();
    let private = imported.map_err(|_| invalid())?;
    let public =
        kem::EncapsulationKey::new(&kem::ML_KEM_768, public.as_slice()).map_err(|_| invalid())?;
    Ok((private, public))
}

pub(crate) fn x25519_agree(private: &agreement::PrivateKey, public: &[u8]) -> io::Result<Secret> {
    let public = agreement::UnparsedPublicKey::new(&agreement::X25519, public);
    agreement::agree(private, public, invalid(), |secret| {
        Ok(Zeroizing::new(secret.try_into().map_err(|_| invalid())?))
    })
}

pub(crate) fn generate_x25519() -> io::Result<agreement::PrivateKey> {
    agreement::PrivateKey::generate(&agreement::X25519).map_err(|_| invalid())
}

pub(crate) fn import_mlkem_public(raw: &[u8]) -> io::Result<kem::EncapsulationKey> {
    // AWS-LC import checks size but defers the modulus check until encapsulation.
    ml_kem::EncapsulationKey::<MlKem768>::new_from_slice(raw).map_err(|_| invalid())?;
    kem::EncapsulationKey::new(&kem::ML_KEM_768, raw).map_err(|_| invalid())
}

enum PublicKey {
    X25519,
    Mlkem(kem::EncapsulationKey),
}

pub(crate) struct ClientKey {
    key: PublicKey,
    pub(crate) public: Vec<u8>,
    pub(crate) hash: [u8; 32],
}

impl ClientKey {
    pub(crate) fn new(raw: &[u8]) -> io::Result<Self> {
        let key = match raw.len() {
            32 => {
                // A fixed private key suffices to reject noncontributory public keys.
                let probe = agreement::PrivateKey::from_private_key(&agreement::X25519, &[9; 32])
                    .map_err(|_| invalid())?;
                x25519_agree(&probe, raw)?;
                PublicKey::X25519
            }
            MLKEM_PUBLIC_LEN => PublicKey::Mlkem(import_mlkem_public(raw)?),
            _ => return Err(invalid()),
        };
        Ok(Self {
            key,
            public: raw.to_vec(),
            hash: *blake3::hash(raw).as_bytes(),
        })
    }

    pub(crate) fn exchange(&self) -> io::Result<(Vec<u8>, Secret)> {
        match &self.key {
            PublicKey::X25519 => {
                let private = generate_x25519()?;
                let public = private.compute_public_key().map_err(|_| invalid())?;
                Ok((
                    public.as_ref().to_vec(),
                    x25519_agree(&private, &self.public)?,
                ))
            }
            PublicKey::Mlkem(key) => {
                let (ciphertext, secret) = key.encapsulate().map_err(|_| invalid())?;
                Ok((
                    ciphertext.as_ref().to_vec(),
                    Zeroizing::new(secret.as_ref().try_into().map_err(|_| invalid())?),
                ))
            }
        }
    }
}

enum PrivateKey {
    X25519(agreement::PrivateKey),
    Mlkem(kem::DecapsulationKey),
}

pub(crate) struct ServerKey {
    key: PrivateKey,
    pub(crate) public: Vec<u8>,
    pub(crate) hash: [u8; 32],
}

impl ServerKey {
    pub(crate) fn new(raw: &[u8]) -> io::Result<Self> {
        let (key, public) = match raw.len() {
            32 => {
                let key = agreement::PrivateKey::from_private_key(&agreement::X25519, raw)
                    .map_err(|_| invalid())?;
                let public = key
                    .compute_public_key()
                    .map_err(|_| invalid())?
                    .as_ref()
                    .to_vec();
                (PrivateKey::X25519(key), public)
            }
            64 => {
                let (key, public) = import_mlkem_seed(raw.try_into().map_err(|_| invalid())?)?;
                let public = public.key_bytes().map_err(|_| invalid())?.as_ref().to_vec();
                (PrivateKey::Mlkem(key), public)
            }
            _ => return Err(invalid()),
        };
        let hash = *blake3::hash(&public).as_bytes();
        Ok(Self { key, public, hash })
    }

    pub(crate) fn relay_len(&self) -> usize {
        match &self.key {
            PrivateKey::X25519(_) => 32,
            PrivateKey::Mlkem(_) => MLKEM_CIPHERTEXT_LEN,
        }
    }

    pub(crate) fn exchange(&self, relay: &[u8]) -> io::Result<Secret> {
        match &self.key {
            PrivateKey::X25519(key) => {
                if relay.len() != 32 || relay[31] & 0x80 != 0 {
                    return Err(invalid());
                }
                x25519_agree(key, relay)
            }
            PrivateKey::Mlkem(key) => {
                let secret = key
                    .decapsulate(kem::Ciphertext::from(relay))
                    .map_err(|_| invalid())?;
                Ok(Zeroizing::new(
                    secret.as_ref().try_into().map_err(|_| invalid())?,
                ))
            }
        }
    }
}

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientKey([REDACTED])")
    }
}

impl fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_public_keys_match_go() {
        use aws_lc_rs::digest;
        let seeds = [[0; 64], [1; 64], std::array::from_fn(|i| i as u8)];
        let hashes = [
            "f95c185fe5b2335d2fc938dd889c6425944acd74376b6952bf1130f720f6ba99",
            "e68d60857f9cb41f88c278ca430e472c6df5679fd5bac3ce872334293c5d0c42",
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9",
        ];
        for (seed, expected) in seeds.iter().zip(hashes) {
            let server = ServerKey::new(seed).unwrap();
            let hash = digest::digest(&digest::SHA256, &server.public);
            let actual: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(actual, expected);
            let client = ClientKey::new(&server.public).unwrap();
            let (ciphertext, expected_secret) = client.exchange().unwrap();
            assert_eq!(server.exchange(&ciphertext).unwrap(), expected_secret);
        }
    }

    #[test]
    fn x25519_rejects_noncontributory_and_noncanonical_relay() {
        let server = ServerKey::new(&[1; 32]).unwrap();
        let client = ClientKey::new(&server.public).unwrap();
        let (mut relay, secret) = client.exchange().unwrap();
        assert_eq!(server.exchange(&relay).unwrap(), secret);
        relay[31] |= 0x80;
        assert!(server.exchange(&relay).is_err());
        assert!(server.exchange(&[0; 32]).is_err());
        assert!(ClientKey::new(&[0; 32]).is_err());
    }

    #[test]
    fn malformed_keys_are_rejected() {
        assert!(ClientKey::new(&[0xff; MLKEM_PUBLIC_LEN]).is_err());
        assert!(ClientKey::new(&[0; 31]).is_err());
        assert!(ServerKey::new(&[0; 63]).is_err());
    }
}
