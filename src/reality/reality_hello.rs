use std::io;

use crate::buf_reader::BufReader;

const MLKEM_PUBLIC_LEN: usize = 1184;
pub(super) const MLKEM_CIPHERTEXT_LEN: usize = 1088;
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

#[derive(Default)]
pub struct ClientKeyShares<'a> {
    pub x25519: Option<&'a [u8; 32]>,
    pub hybrid: Option<&'a [u8; 1216]>,
}

impl<'a> ClientKeyShares<'a> {
    pub fn authentication_public_key(&self) -> io::Result<&'a [u8; 32]> {
        if let Some(key) = self.x25519 {
            return Ok(key);
        }
        self.hybrid
            .map(|key| key[MLKEM_PUBLIC_LEN..].try_into().unwrap())
            .ok_or_else(|| invalid("Missing REALITY authentication key share"))
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

pub fn extract_client_key_shares(record: &[u8]) -> io::Result<ClientKeyShares<'_>> {
    parse_client_shares(key_share_extension(record, true)?)
}

fn parse_client_shares(data: &[u8]) -> io::Result<ClientKeyShares<'_>> {
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
            RealityGroup::X25519MlKem768 => {
                shares.hybrid.replace(data.try_into().unwrap()).is_some()
            }
        };
        if duplicate {
            return Err(invalid("Duplicate client key share"));
        }
    }
    shares.authentication_public_key()?;
    Ok(shares)
}

pub fn validate_server_key_share(record: &[u8]) -> io::Result<()> {
    let mut reader = BufReader::new(key_share_extension(record, false)?);
    let group = RealityGroup::from_id(reader.read_u16_be()?)
        .ok_or_else(|| invalid("Unsupported REALITY server key share"))?;
    let len = reader.read_u16_be()? as usize;
    reader.skip(len)?;
    if !reader.is_consumed() || len != group.share_len(false) {
        return Err(invalid("Invalid server key share length"));
    }
    Ok(())
}

/// Extracts ClientRandom from ClientHello
///
/// ClientHello structure (simplified):
/// - TLS Header: 5 bytes
/// - Handshake Type: 1 byte
/// - Length: 3 bytes
/// - Protocol Version: 2 bytes
/// - ClientRandom: 32 bytes (starts at offset 11)
pub fn extract_client_random(client_hello: &[u8]) -> io::Result<[u8; 32]> {
    const TLS_HEADER_LEN: usize = 5;
    const HANDSHAKE_HEADER_LEN: usize = 4; // type(1) + length(3)
    const PROTOCOL_VERSION_LEN: usize = 2;
    const RANDOM_OFFSET: usize = TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN + PROTOCOL_VERSION_LEN;

    if client_hello.len() < RANDOM_OFFSET + 32 {
        return Err(invalid("ClientHello too short to extract random"));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[RANDOM_OFFSET..RANDOM_OFFSET + 32]);
    Ok(random)
}

/// Extracts SessionId slice from ClientHello without allocation
///
/// SessionId comes after ClientRandom and has a 1-byte length prefix.
/// Returns a slice pointing into the original buffer.
pub fn extract_session_id_slice(client_hello: &[u8]) -> io::Result<&[u8]> {
    const TLS_HEADER_LEN: usize = 5;
    const HANDSHAKE_HEADER_LEN: usize = 4;
    const PROTOCOL_VERSION_LEN: usize = 2;
    const RANDOM_LEN: usize = 32;
    const SESSION_ID_LEN_OFFSET: usize =
        TLS_HEADER_LEN + HANDSHAKE_HEADER_LEN + PROTOCOL_VERSION_LEN + RANDOM_LEN;

    if client_hello.len() < SESSION_ID_LEN_OFFSET + 1 {
        return Err(invalid("ClientHello too short to extract session ID"));
    }

    let session_id_len = client_hello[SESSION_ID_LEN_OFFSET] as usize;

    if client_hello.len() < SESSION_ID_LEN_OFFSET + 1 + session_id_len {
        return Err(invalid("ClientHello session ID extends past end"));
    }

    Ok(&client_hello[SESSION_ID_LEN_OFFSET + 1..SESSION_ID_LEN_OFFSET + 1 + session_id_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::tests::reality_fixtures::{
        configs, construct_server_hello, write_record_header,
    };

    #[test]
    fn test_extract_client_random() {
        // Create a minimal ClientHello with random
        let mut client_hello = vec![0u8; 100];

        // TLS Header
        client_hello[0] = 0x16; // Handshake
        client_hello[1] = 0x03; // Version major
        client_hello[2] = 0x03; // Version minor (TLS 1.2)

        // Handshake header
        client_hello[5] = 0x01; // ClientHello type

        // Protocol version in handshake
        client_hello[9] = 0x03; // Major
        client_hello[10] = 0x03; // Minor

        // ClientRandom starts at offset 11
        for i in 0..32 {
            client_hello[11 + i] = (i + 1) as u8;
        }

        let random = extract_client_random(&client_hello).unwrap();
        for (i, byte) in random.iter().enumerate() {
            assert_eq!(*byte, (i + 1) as u8);
        }
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
    fn standalone_share_takes_precedence_for_authentication() {
        let hybrid = [7; 1216];
        let classic = [8; 32];
        for standalone in [false, true] {
            let mut entries = vec![(0x11ec, hybrid.as_slice())];
            if standalone {
                entries.push((0x001d, &classic));
            }
            let data = share_vector(&entries);
            let shares = parse_client_shares(&data).unwrap();
            assert_eq!(shares.hybrid.unwrap().as_ptr(), data[6..].as_ptr());
            if standalone {
                assert_eq!(
                    shares.x25519.unwrap().as_ptr(),
                    data[data.len() - 32..].as_ptr()
                );
            }
            assert_eq!(
                shares.authentication_public_key().unwrap(),
                if standalone {
                    &classic
                } else {
                    hybrid[1184..].try_into().unwrap()
                }
            );
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
    }

    #[test]
    fn hello_parsers_check_framing_and_retry() {
        let (config, _) = configs(super::super::CipherSuite::AES_128_GCM_SHA256);
        let mut client = config.create_connection().unwrap();
        let mut record = Vec::new();
        client.write_tls(&mut record).unwrap();
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
        assert!(validate_server_key_share(&retry).is_err());
    }
}
