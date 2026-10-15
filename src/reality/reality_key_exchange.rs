use std::io;

use aws_lc_rs::{agreement, kem};
use rand::Rng;

use super::reality_auth::perform_ecdh;
use crate::buf_reader::BufReader;

const MLKEM_PUBLIC_LEN: usize = 1184;
const MLKEM_CIPHERTEXT_LEN: usize = 1088;
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RealityGroup {
    X25519 = 0x001d,
    X25519MlKem768 = 0x11ec,
}

impl RealityGroup {
    pub fn name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X25519MlKem768 => "X25519MLKEM768",
        }
    }

    pub fn secret_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::X25519MlKem768 => 64,
        }
    }

    pub fn share_len(self, client: bool) -> usize {
        match self {
            Self::X25519 => 32,
            Self::X25519MlKem768 if client => MLKEM_PUBLIC_LEN + 32,
            Self::X25519MlKem768 => MLKEM_CIPHERTEXT_LEN + 32,
        }
    }

    fn from_id(id: u16) -> Option<Self> {
        match id {
            0x001d => Some(Self::X25519),
            0x11ec => Some(Self::X25519MlKem768),
            _ => None,
        }
    }
}

pub struct KeyShareRef<'a> {
    pub group: RealityGroup,
    pub data: &'a [u8],
}

#[derive(Clone, Default)]
pub struct ClientKeyShares {
    pub x25519: Option<[u8; 32]>,
    pub hybrid: Option<Box<[u8; 1216]>>,
}

impl ClientKeyShares {
    pub fn authentication_public_key(&self) -> io::Result<&[u8; 32]> {
        if let Some(key) = &self.x25519 {
            return Ok(key);
        }
        self.hybrid
            .as_ref()
            .map(|key| key[MLKEM_PUBLIC_LEN..].try_into().unwrap())
            .ok_or_else(|| invalid("Missing REALITY authentication key share"))
    }

    pub fn get(&self, group: RealityGroup) -> io::Result<&[u8]> {
        match group {
            RealityGroup::X25519 => self.x25519.as_ref().map(|k| k.as_slice()),
            RealityGroup::X25519MlKem768 => self.hybrid.as_ref().map(|k| k.as_slice()),
        }
        .ok_or_else(|| invalid("Server selected a key share absent from ClientHello"))
    }
}

fn key_share_extension(record: &[u8], client: bool) -> io::Result<&[u8]> {
    let mut record_reader = BufReader::new(record);
    if record_reader.read_u8()? != 22 {
        return Err(invalid("Expected TLS handshake record"));
    }
    record_reader.skip(2)?;
    let record_len = record_reader.read_u16_be()? as usize;
    let mut hello = BufReader::new(record_reader.read_slice(record_len)?);
    let expected_message_type = if client { 1 } else { 2 };
    if !record_reader.is_consumed() || hello.read_u8()? != expected_message_type {
        return Err(invalid("Invalid TLS hello framing"));
    }
    let length = hello.read_u24_be()? as usize;
    if length != hello.remaining() || hello.read_u16_be()? != 0x0303 {
        return Err(invalid("Invalid TLS hello length or version"));
    }
    let random = hello.read_slice(32)?;
    if !client && random == HELLO_RETRY_RANDOM {
        return Err(invalid("REALITY does not synthesize HelloRetryRequest"));
    }
    let session_len = hello.read_u8()? as usize;
    if session_len > 32 {
        return Err(invalid("Invalid TLS session ID length"));
    }
    hello.skip(session_len)?;
    if client {
        let cipher_len = hello.read_u16_be()? as usize;
        if cipher_len == 0 || !cipher_len.is_multiple_of(2) {
            return Err(invalid("Invalid cipher suite vector"));
        }
        hello.skip(cipher_len)?;
        let compression_len = hello.read_u8()? as usize;
        hello.skip(compression_len)?;
    } else {
        hello.skip(2)?;
        if hello.read_u8()? != 0 {
            return Err(invalid("Invalid ServerHello compression"));
        }
    }
    let extensions_len = hello.read_u16_be()? as usize;
    let mut extensions = BufReader::new(hello.read_slice(extensions_len)?);
    if !hello.is_consumed() {
        return Err(invalid("Trailing TLS hello bytes"));
    }
    let mut share = None;
    let mut tls13 = false;
    while !extensions.is_consumed() {
        let id = extensions.read_u16_be()?;
        let len = extensions.read_u16_be()? as usize;
        let data = extensions.read_slice(len)?;
        match id {
            51 => {
                if share.replace(data).is_some() {
                    return Err(invalid("Duplicate key_share extension"));
                }
            }
            43 if !client => {
                if tls13 || data != [3, 4] {
                    return Err(invalid("Invalid ServerHello supported_versions"));
                }
                tls13 = true;
            }
            _ => {}
        }
    }
    if !client && !tls13 {
        return Err(invalid("REALITY requires TLS 1.3"));
    }
    share.ok_or_else(|| invalid("Missing key_share extension"))
}

pub fn extract_client_key_shares(record: &[u8]) -> io::Result<ClientKeyShares> {
    parse_client_shares(key_share_extension(record, true)?)
}

fn parse_client_shares(data: &[u8]) -> io::Result<ClientKeyShares> {
    let mut reader = BufReader::new(data);
    let length = reader.read_u16_be()? as usize;
    if length != reader.remaining() {
        return Err(invalid("Invalid client key_share vector length"));
    }
    let mut shares = ClientKeyShares::default();
    while !reader.is_consumed() {
        let id = reader.read_u16_be()?;
        let len = reader.read_u16_be()? as usize;
        let data = reader.read_slice(len)?;
        let Some(group) = RealityGroup::from_id(id) else {
            continue;
        };
        if len != group.share_len(true) {
            return Err(invalid("Invalid client key share length"));
        }
        let duplicate = match group {
            RealityGroup::X25519 => shares.x25519.replace(data.try_into().unwrap()).is_some(),
            RealityGroup::X25519MlKem768 => shares
                .hybrid
                .replace(Box::new(data.try_into().unwrap()))
                .is_some(),
        };
        if duplicate {
            return Err(invalid("Duplicate client key share"));
        }
    }
    shares.authentication_public_key()?;
    Ok(shares)
}

pub fn extract_server_key_share(record: &[u8]) -> io::Result<KeyShareRef<'_>> {
    let mut reader = BufReader::new(key_share_extension(record, false)?);
    let group = RealityGroup::from_id(reader.read_u16_be()?)
        .ok_or_else(|| invalid("Unsupported REALITY server key share"))?;
    let len = reader.read_u16_be()? as usize;
    let data = reader.read_slice(len)?;
    if !reader.is_consumed() || len != group.share_len(false) {
        return Err(invalid("Invalid server key share length"));
    }
    Ok(KeyShareRef { group, data })
}

pub fn generate_mlkem() -> io::Result<(kem::DecapsulationKey, Vec<u8>)> {
    let private = kem::DecapsulationKey::generate(&kem::ML_KEM_768)
        .map_err(|_| io::Error::other("ML-KEM key generation failed"))?;
    let public = private
        .encapsulation_key()
        .and_then(|key| key.key_bytes())
        .map_err(|_| io::Error::other("ML-KEM public key encoding failed"))?;
    Ok((private, public.as_ref().to_vec()))
}

pub fn complete_client_exchange(
    private: &[u8; 32],
    mlkem: &kem::DecapsulationKey,
    share: &KeyShareRef<'_>,
) -> io::Result<Vec<u8>> {
    let kem_ciphertext_len = if share.group == RealityGroup::X25519MlKem768 {
        MLKEM_CIPHERTEXT_LEN
    } else {
        0
    };
    let peer = share
        .data
        .get(kem_ciphertext_len..)
        .and_then(|p| p.try_into().ok())
        .ok_or_else(|| invalid("Invalid server X25519 share"))?;
    let x25519 = perform_ecdh(private, peer).map_err(|_| invalid("Invalid server X25519 key"))?;
    let mut secret = Vec::with_capacity(share.group.secret_len());
    if share.group == RealityGroup::X25519MlKem768 {
        let kem_secret = mlkem
            .decapsulate(kem::Ciphertext::from(&share.data[..kem_ciphertext_len]))
            .map_err(|_| invalid("ML-KEM decapsulation failed"))?;
        secret.extend_from_slice(kem_secret.as_ref());
    }
    secret.extend_from_slice(&x25519);
    Ok(secret)
}

pub fn server_exchange(
    group: RealityGroup,
    shares: &ClientKeyShares,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let client = shares
        .get(group)
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;
    let mut private_bytes = [0; 32];
    rand::rng().fill_bytes(&mut private_bytes);
    let private = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_bytes)
        .map_err(|_| io::Error::other("X25519 key generation failed"))?;
    let x25519_public = private
        .compute_public_key()
        .map_err(|_| io::Error::other("X25519 public key failed"))?;
    let kem_public_len = if group == RealityGroup::X25519MlKem768 {
        MLKEM_PUBLIC_LEN
    } else {
        0
    };
    let peer = client[kem_public_len..].try_into().unwrap();
    let x25519 = perform_ecdh(&private_bytes, peer)
        .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid client X25519 key"))?;
    let mut response = Vec::with_capacity(group.share_len(false));
    let mut secret = Vec::with_capacity(group.secret_len());
    if group == RealityGroup::X25519MlKem768 {
        let kem_public = kem::EncapsulationKey::new(&kem::ML_KEM_768, &client[..kem_public_len])
            .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "Invalid ML-KEM public key"))?;
        let (ciphertext, kem_secret) = kem_public
            .encapsulate()
            .map_err(|_| io::Error::other("ML-KEM encapsulation failed"))?;
        response.extend_from_slice(ciphertext.as_ref());
        secret.extend_from_slice(kem_secret.as_ref());
    }
    response.extend_from_slice(x25519_public.as_ref());
    secret.extend_from_slice(&x25519);
    Ok((response, secret))
}

#[cfg(test)]
mod tests {
    use super::super::reality_tls13_messages::{
        construct_client_hello, construct_server_hello, write_record_header,
    };
    use super::*;

    fn public(private: &[u8; 32]) -> [u8; 32] {
        agreement::PrivateKey::from_private_key(&agreement::X25519, private)
            .unwrap()
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap()
    }

    fn share_vector(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut data = vec![0, 0];
        for (group, key) in entries {
            data.extend_from_slice(&group.to_be_bytes());
            data.extend_from_slice(&(key.len() as u16).to_be_bytes());
            data.extend_from_slice(key);
        }
        let len = (data.len() - 2) as u16;
        data[..2].copy_from_slice(&len.to_be_bytes());
        data
    }

    #[test]
    fn hybrid_keys_and_authentication_are_independent() {
        let (kem, mut hybrid) = generate_mlkem().unwrap();
        let hybrid_private = [7; 32];
        hybrid.extend_from_slice(&public(&hybrid_private));
        let classic = public(&[8; 32]);
        for standalone in [false, true] {
            let mut entries = vec![(0x11ec, hybrid.as_slice())];
            if standalone {
                entries.push((0x001d, &classic));
            }
            let shares = parse_client_shares(&share_vector(&entries)).unwrap();
            assert_eq!(
                shares.authentication_public_key().unwrap(),
                if standalone {
                    &classic
                } else {
                    hybrid[1184..].try_into().unwrap()
                }
            );
            let (response, server_secret) =
                server_exchange(RealityGroup::X25519MlKem768, &shares).unwrap();
            let client_secret = complete_client_exchange(
                &hybrid_private,
                &kem,
                &KeyShareRef {
                    group: RealityGroup::X25519MlKem768,
                    data: &response,
                },
            )
            .unwrap();
            assert_eq!(server_secret, client_secret);
            assert_eq!(server_secret.len(), 64);
            let mut corrupted = response;
            corrupted[0] ^= 1;
            let corrupt_secret = complete_client_exchange(
                &hybrid_private,
                &kem,
                &KeyShareRef {
                    group: RealityGroup::X25519MlKem768,
                    data: &corrupted,
                },
            )
            .unwrap();
            assert_ne!(server_secret, corrupt_secret);
        }
    }

    #[test]
    fn malformed_share_vectors_fail_without_panics() {
        let valid = share_vector(&[(0x0a0a, &[0]), (0x001d, &[1; 32])]);
        assert!(parse_client_shares(&valid).is_ok());
        for end in 0..valid.len() {
            assert!(parse_client_shares(&valid[..end]).is_err());
        }
        for entries in [
            vec![(0x001d, vec![1; 31])],
            vec![(0x11ec, vec![1; 1215])],
            vec![(0x001d, vec![1; 32]), (0x001d, vec![2; 32])],
            vec![(0x11ec, vec![1; 1216]), (0x11ec, vec![2; 1216])],
        ] {
            let refs: Vec<_> = entries.iter().map(|(g, d)| (*g, d.as_slice())).collect();
            assert!(parse_client_shares(&share_vector(&refs)).is_err());
        }
        let zero = ClientKeyShares {
            x25519: Some([0; 32]),
            hybrid: None,
        };
        assert_eq!(
            server_exchange(RealityGroup::X25519, &zero)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            server_exchange(RealityGroup::X25519MlKem768, &zero)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let bad_kem = ClientKeyShares {
            x25519: None,
            hybrid: Some(Box::new([255; 1216])),
        };
        assert!(server_exchange(RealityGroup::X25519MlKem768, &bad_kem).is_err());
    }

    #[test]
    fn hello_parsers_check_framing_and_retry() {
        let hello = construct_client_hello(
            &[0; 32],
            &[0; 32],
            &[KeyShareRef {
                group: RealityGroup::X25519,
                data: &[1; 32],
            }],
            "cover.test",
            &[0x1301],
            &[],
        )
        .unwrap();
        let mut record = write_record_header(22, hello.len() as u16);
        record.extend_from_slice(&hello);
        assert!(extract_client_key_shares(&record).is_ok());
        for end in 0..record.len() {
            assert!(extract_client_key_shares(&record[..end]).is_err());
        }
        record.push(0);
        assert!(extract_client_key_shares(&record).is_err());
        let hello = construct_server_hello(
            &HELLO_RETRY_RANDOM,
            &[0; 32],
            0x1301,
            RealityGroup::X25519,
            &[1; 32],
        )
        .unwrap();
        let mut retry = write_record_header(22, hello.len() as u16);
        retry.extend_from_slice(&hello);
        assert!(extract_server_key_share(&retry).is_err());
    }
}
