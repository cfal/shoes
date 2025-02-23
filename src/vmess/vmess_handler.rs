use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyIvInit};
use aes::Aes128;
use async_trait::async_trait;
use aws_lc_rs::aead::{
    Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, CHACHA20_POLY1305,
};
use cfb_mode::cipher::AsyncStreamCipher;
use digest::KeyInit;
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;
use tokio::io::AsyncWriteExt;

use super::fnv1a::Fnv1aHasher;
use super::md5::{compute_hmac_md5, compute_md5, compute_md5_repeating, create_chacha_key};
use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::typed::{Aes128CfbDec, Aes128CfbEnc};
use super::vmess_stream::{ReadHeaderInfo, VmessStream};
use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::line_reader::LineReader;
use crate::option_util::NoneOrOne;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::util::{allocate_vec, parse_uuid, write_all};

const TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DataCipher {
    Any,
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

impl From<&str> for DataCipher {
    fn from(name: &str) -> Self {
        match name {
            "" | "any" => DataCipher::Any,
            "aes-128-gcm" => DataCipher::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => DataCipher::ChaCha20Poly1305,
            "none" => DataCipher::None,
            _ => {
                panic!("Unknown cipher: {}", name);
            }
        }
    }
}

type UserHash = [u8; 16];

#[derive(Debug)]
struct CertHashProvider {
    user_key: [u8; 16],
    hashes: HashMap<UserHash, u64>,
    last_hash_time_secs: u64,
}

impl CertHashProvider {
    pub fn new(user_id_bytes: &[u8]) -> Self {
        if user_id_bytes.len() != 16 {
            panic!("invalid user id bytes length ({})", user_id_bytes.len());
        }
        let mut user_key = [0u8; 16];
        user_key.copy_from_slice(user_id_bytes);
        Self {
            user_key,
            hashes: HashMap::with_capacity(64),
            last_hash_time_secs: 0,
        }
    }

    pub fn check(&mut self, hash: &UserHash) -> Option<u64> {
        if let Some(time_secs) = self.hashes.get(hash) {
            return Some(*time_secs);
        }
        self.update_hashes();
        self.hashes.get(hash).copied()
    }

    fn update_hashes(&mut self) {
        let current_time_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();

        let to_time_secs = current_time_secs + 32;
        if self.last_hash_time_secs >= to_time_secs {
            return;
        }

        let from_time_secs = current_time_secs - 32;

        self.hashes
            .retain(|_, hash_time_secs| *hash_time_secs >= from_time_secs);

        let mut create_time_secs = std::cmp::max(from_time_secs, self.last_hash_time_secs);
        while create_time_secs <= to_time_secs {
            let hash_bytes: [u8; 16] =
                compute_hmac_md5(&self.user_key, &create_time_secs.to_be_bytes());
            self.hashes.insert(hash_bytes, create_time_secs);
            create_time_secs += 1;
        }

        self.last_hash_time_secs = to_time_secs;
    }
}

#[derive(Debug)]
pub struct VmessTcpServerHandler {
    data_cipher: DataCipher,
    instruction_key: [u8; 16],
    aead_cipher: Aes128,
    cert_hash_provider: Option<Mutex<CertHashProvider>>,
    udp_enabled: bool,
}

impl VmessTcpServerHandler {
    pub fn new(cipher_name: &str, user_id: &str, force_aead: bool, udp_enabled: bool) -> Self {
        let mut user_id_bytes = parse_uuid(user_id).unwrap();
        let cert_hash_provider = if force_aead {
            None
        } else {
            Some(Mutex::new(CertHashProvider::new(&user_id_bytes)))
        };

        user_id_bytes.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key: [u8; 16] = compute_md5(&user_id_bytes);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let aead_cipher = Aes128::new((&derived_key[0..16]).into());

        Self {
            data_cipher: cipher_name.into(),
            aead_cipher,
            instruction_key,
            cert_hash_provider,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpServerHandler for VmessTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let mut line_reader = LineReader::new_with_buffer_size(8192);

        let mut cert_hash = [0u8; 16];
        line_reader
            .read_slice_into(&mut server_stream, &mut cert_hash)
            .await?;

        // we need to copy it over because if this is an aead request, we need the original
        // bytes for decrypting the header.
        let mut aead_bytes = [0u8; 16];
        aead_bytes.copy_from_slice(&cert_hash);

        self.aead_cipher.decrypt_block((&mut aead_bytes).into());
        let checksum = super::crc32::crc32c(&aead_bytes[0..12]);
        let expected_checksum = u32::from_be_bytes(aead_bytes[12..16].try_into().unwrap());
        let is_aead_request = checksum == expected_checksum;

        let mut header_reader = if is_aead_request {
            let time_secs = u64::from_be_bytes(aead_bytes[0..8].try_into().unwrap());
            let current_time_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
            let time_delta = if time_secs > current_time_secs {
                time_secs - current_time_secs
            } else {
                current_time_secs - time_secs
            };
            if time_delta > 120 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Hash timestamp is too old ({} is {} seconds old)",
                        time_secs, time_delta
                    ),
                ));
            }

            let mut encrypted_payload_length = [0u8; 18];
            line_reader
                .read_slice_into(&mut server_stream, &mut encrypted_payload_length)
                .await?;

            let mut nonce = [0u8; 8];
            line_reader
                .read_slice_into(&mut server_stream, &mut nonce)
                .await?;

            let header_length_aead_key = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
            );

            let header_length_nonce = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
            );

            // TODO: don't unwrap
            let unbound_key =
                UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

            let mut opening_key = OpeningKey::new(
                unbound_key,
                SingleUseNonce::new(&header_length_nonce[0..12]),
            );

            if opening_key
                .open_in_place(Aad::from(&cert_hash), &mut encrypted_payload_length)
                .is_err()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to open encrypted header length",
                ));
            }

            let payload_length =
                u16::from_be_bytes(encrypted_payload_length[0..2].try_into().unwrap());

            let header_aead_key = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Key", &cert_hash, &nonce],
            );

            let header_nonce = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
            );

            let mut encrypted_header =
                allocate_vec(payload_length as usize + TAG_LEN).into_boxed_slice();

            line_reader
                .read_slice_into(&mut server_stream, &mut encrypted_header)
                .await?;

            // TODO: don't unwrap
            let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();

            let mut opening_key =
                OpeningKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));

            if opening_key
                .open_in_place(Aad::from(&cert_hash), &mut encrypted_header)
                .is_err()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "failed to open encrypted header",
                ));
            }

            HeaderReader::Aead(AeadHeaderReader {
                server_stream,
                decrypted_header: encrypted_header,
                cursor: 0,
            })
        } else {
            let hash_time_secs = match self.cert_hash_provider {
                Some(ref provider) => match provider.lock().check(&cert_hash) {
                    Some(t) => t,
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "unauthorized request, unknown hash",
                        ));
                    }
                },
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unauthorized request, unknown aead hash",
                    ));
                }
            };

            let instruction_iv: [u8; 16] = {
                let time_bytes = hash_time_secs.to_be_bytes();
                compute_md5_repeating(&time_bytes, 4)
            };

            let request_cipher =
                Aes128CfbDec::new(&self.instruction_key.into(), &instruction_iv.into());

            HeaderReader::AesCfb(AesCfbHeaderReader {
                server_stream,
                request_cipher,
            })
        };

        let mut fnv_hasher = Fnv1aHasher::new();

        let mut instructions_to_addr_type = [0u8; 41];
        header_reader
            .read_slice_into(&mut line_reader, &mut instructions_to_addr_type)
            .await?;
        fnv_hasher.write(&instructions_to_addr_type);

        if instructions_to_addr_type[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid version {}", instructions_to_addr_type[0]),
            ));
        }

        let port = u16::from_be_bytes(instructions_to_addr_type[38..40].try_into().unwrap());

        let remote_location = match instructions_to_addr_type[40] {
            1 => {
                // 4 byte ipv4 address
                let mut address_bytes = [0u8; 4];
                header_reader
                    .read_slice_into(&mut line_reader, &mut address_bytes)
                    .await?;
                fnv_hasher.write(&address_bytes);

                let v4addr = Ipv4Addr::new(
                    address_bytes[0],
                    address_bytes[1],
                    address_bytes[2],
                    address_bytes[3],
                );
                NetLocation::new(Address::Ipv4(v4addr), port)
            }
            2 => {
                // domain name
                let mut domain_name_len = [0u8; 1];
                header_reader
                    .read_slice_into(&mut line_reader, &mut domain_name_len)
                    .await?;
                fnv_hasher.write(&domain_name_len);

                let mut domain_name_bytes = allocate_vec(domain_name_len[0] as usize);
                header_reader
                    .read_slice_into(&mut line_reader, &mut domain_name_bytes)
                    .await?;
                fnv_hasher.write(&domain_name_bytes);

                let address_str = match std::str::from_utf8(&domain_name_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Failed to decode address: {}", e),
                        ));
                    }
                };

                // Although this is supposed to be a hostname, some clients will pass
                // ipv4 and ipv6 addresses as well, so parse it rather than directly
                // using Address:Hostname enum.
                NetLocation::new(Address::from(address_str)?, port)
            }
            3 => {
                // 16 byte ipv6 address
                let mut address_bytes = [0u8; 16];
                header_reader
                    .read_slice_into(&mut line_reader, &mut address_bytes)
                    .await?;
                fnv_hasher.write(&address_bytes);

                let v6addr = Ipv6Addr::new(
                    u16::from_be_bytes(address_bytes[0..2].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[2..4].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[4..6].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[6..8].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[8..10].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[10..12].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[12..14].try_into().unwrap()),
                    u16::from_be_bytes(address_bytes[14..16].try_into().unwrap()),
                );

                NetLocation::new(Address::Ipv6(v6addr), port)
            }
            invalid_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid address type: {}", invalid_type),
                ));
            }
        };

        let margin_len: u8 = instructions_to_addr_type[35] >> 4;
        if margin_len > 0 {
            let mut margin_bytes = allocate_vec(margin_len as usize).into_boxed_slice();
            header_reader
                .read_slice_into(&mut line_reader, &mut margin_bytes)
                .await?;
            fnv_hasher.write(&margin_bytes);
        }

        let mut check_bytes = [0u8; 4];
        header_reader
            .read_slice_into(&mut line_reader, &mut check_bytes)
            .await?;

        let expected_check_value = u32::from_be_bytes(check_bytes[0..4].try_into().unwrap());
        let actual_check_value = fnv_hasher.finish();
        if expected_check_value != actual_check_value {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Bad fnv1a checksum, expected {}, got {}",
                    expected_check_value, actual_check_value
                ),
            ));
        }

        let server_stream = header_reader.into_stream();

        let data_encryption_iv: &[u8] = &instructions_to_addr_type[1..17];
        let data_encryption_key: &[u8] = &instructions_to_addr_type[17..33];
        let response_authentication_v = instructions_to_addr_type[33];
        let option = instructions_to_addr_type[34];

        if option & 0x01 != 0x01 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Standard format data stream was not requested",
            ));
        }

        if option & 0x10 == 0x10 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Auth length option is not supported",
            ));
        }

        let enable_chunk_masking = option & 0x04 == 0x04;
        let enable_global_padding = option & 0x08 == 0x08;

        if enable_global_padding && !enable_chunk_masking {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Global padding cannot be enabled without chunk masking",
            ));
        }

        // the developer docs have incorrect values for the data type,
        // see headers.pb.go in v2ray-core for the correct values.
        let requested_data_cipher = match instructions_to_addr_type[35] & 0b1111 {
            1 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Unsupported aes-128-cfb data cipher requested",
                ));
            }
            3 => DataCipher::Aes128Gcm,
            4 => DataCipher::ChaCha20Poly1305,
            5 => DataCipher::None,
            unknown_cipher_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested cipher: {}", unknown_cipher_type),
                ));
            }
        };

        if self.data_cipher != DataCipher::Any && requested_data_cipher != self.data_cipher {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Server only allows {:?} but client requested {:?}",
                    self.data_cipher, requested_data_cipher
                ),
            ));
        }

        let is_udp = match instructions_to_addr_type[37] {
            1 => false,
            2 => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "UDP not enabled",
                    ));
                }
                true
            }
            unknown_protocol_type => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown requested protocol: {}", unknown_protocol_type),
                ));
            }
        };

        let mut response_header: [u8; 4] = [
            response_authentication_v,
            0, // option
            0, // command
            0, // command length
        ];

        let (response_header_iv, response_header_key): ([u8; 16], [u8; 16]) = if is_aead_request {
            let mut truncated_iv = [0u8; 16];
            let mut truncated_key = [0u8; 16];
            truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
            truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);

            (truncated_iv, truncated_key)
        } else {
            (
                compute_md5(data_encryption_iv),
                compute_md5(data_encryption_key),
            )
        };

        let unbound_keys = match requested_data_cipher {
            // TODO: stop unwrapping
            DataCipher::Aes128Gcm => {
                // key is 16 bytes
                Some((
                    UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                    UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                ))
            }
            DataCipher::ChaCha20Poly1305 => {
                // key is 32 bytes
                Some((
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(data_encryption_key))
                        .unwrap(),
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&response_header_key))
                        .unwrap(),
                ))
            }
            DataCipher::None => None,
            DataCipher::Any => unreachable!(),
        };

        let data_keys = if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
            let opening_key = OpeningKey::new(
                unbound_opening_key,
                VmessNonceSequence::new(data_encryption_iv),
            );
            let sealing_key = SealingKey::new(
                unbound_sealing_key,
                VmessNonceSequence::new(&response_header_iv),
            );
            Some((opening_key, sealing_key))
        } else {
            None
        };

        let (read_length_shake_reader, write_length_shake_reader) = if enable_chunk_masking {
            let mut request_hasher = Shake128::default();
            request_hasher.update(data_encryption_iv);
            let request_reader = request_hasher.finalize_xof();

            let mut response_hasher = Shake128::default();
            response_hasher.update(&response_header_iv);
            let response_reader = response_hasher.finalize_xof();

            (Some(request_reader), Some(response_reader))
        } else {
            (None, None)
        };

        // store the response header as prefix bytes to read when we are streaming.
        // writing the response header immediately without reading causes Surge to fail with
        // "Got short header" error.
        let prefix_bytes: Box<[u8]> = if is_aead_request {
            let response_header_length_aead_key =
                super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Len Key"]);
            let response_header_length_nonce =
                super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header Len IV"]);

            let mut encrypted_response_header = [0u8; 2 + TAG_LEN + 4 + TAG_LEN];

            // we know the size of response_header already.
            encrypted_response_header[1] = 4;

            // TODO: don't unwrap
            let unbound_key =
                UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16]).unwrap();
            let mut sealing_key = SealingKey::new(
                unbound_key,
                SingleUseNonce::new(&response_header_length_nonce[0..12]),
            );
            let tag = sealing_key
                .seal_in_place_separate_tag(Aad::empty(), &mut encrypted_response_header[0..2])
                .unwrap();
            encrypted_response_header[2..2 + TAG_LEN].copy_from_slice(tag.as_ref());

            let response_header_aead_key =
                super::sha2::kdf(&response_header_key, &[b"AEAD Resp Header Key"]);
            let response_header_nonce =
                super::sha2::kdf(&response_header_iv, &[b"AEAD Resp Header IV"]);
            let unbound_key =
                UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
            let mut sealing_key = SealingKey::new(
                unbound_key,
                SingleUseNonce::new(&response_header_nonce[0..12]),
            );

            encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4]
                .copy_from_slice(&response_header);

            let tag = sealing_key
                .seal_in_place_separate_tag(
                    Aad::empty(),
                    &mut encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4],
                )
                .unwrap();
            encrypted_response_header[2 + TAG_LEN + 4..].copy_from_slice(tag.as_ref());

            Box::new(encrypted_response_header)
        } else {
            let response_cipher =
                Aes128CfbEnc::new(&response_header_key.into(), &response_header_iv.into());
            response_cipher.encrypt(&mut response_header);
            Box::new(response_header)
        };

        let mut vmess_stream = VmessStream::new(
            server_stream,
            is_udp,
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            enable_global_padding,
            Some(prefix_bytes),
            None,
        );

        let unparsed_data = line_reader.unparsed_data();
        if !unparsed_data.is_empty() {
            vmess_stream.feed_initial_read_data(unparsed_data)?;
        }

        let server_stream = Box::new(vmess_stream);

        match is_udp {
            false => Ok(TcpServerSetupResult::TcpForward {
                remote_location,
                stream: server_stream,
                // Wait until there is data to send the response header.
                need_initial_flush: false,
                connection_success_response: None,
                initial_remote_data: None,
                override_proxy_provider: NoneOrOne::Unspecified,
            }),
            true => Ok(TcpServerSetupResult::BidirectionalUdp {
                remote_location,
                stream: server_stream,
                need_initial_flush: false,
                override_proxy_provider: NoneOrOne::Unspecified,
            }),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum HeaderReader {
    AesCfb(AesCfbHeaderReader),
    Aead(AeadHeaderReader),
}

impl HeaderReader {
    async fn read_slice_into(
        &mut self,
        line_reader: &mut LineReader,
        data: &mut [u8],
    ) -> std::io::Result<()> {
        match self {
            HeaderReader::AesCfb(ref mut reader) => reader.read_slice_into(line_reader, data).await,
            HeaderReader::Aead(ref mut reader) => reader.read_slice_into(data),
        }
    }

    fn into_stream(self) -> Box<dyn AsyncStream> {
        match self {
            HeaderReader::AesCfb(reader) => reader.into_stream(),
            HeaderReader::Aead(reader) => reader.into_stream(),
        }
    }
}

struct AesCfbHeaderReader {
    server_stream: Box<dyn AsyncStream>,
    request_cipher: Aes128CfbDec,
}

impl AesCfbHeaderReader {
    async fn read_slice_into(
        &mut self,
        line_reader: &mut LineReader,
        data: &mut [u8],
    ) -> std::io::Result<()> {
        line_reader
            .read_slice_into(&mut self.server_stream, data)
            .await?;
        self.request_cipher.clone().decrypt(data);
        Ok(())
    }

    fn into_stream(self) -> Box<dyn AsyncStream> {
        self.server_stream
    }
}

struct AeadHeaderReader {
    server_stream: Box<dyn AsyncStream>,
    decrypted_header: Box<[u8]>,
    cursor: usize,
}

impl AeadHeaderReader {
    fn read_slice_into(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let len = data.len();
        data.copy_from_slice(&self.decrypted_header[self.cursor..self.cursor + len]);
        self.cursor += len;
        Ok(())
    }

    fn into_stream(self) -> Box<dyn AsyncStream> {
        self.server_stream
    }
}

#[derive(Debug)]
pub struct VmessTcpClientHandler {
    data_cipher: DataCipher,
    user_key: [u8; 16],
    instruction_key: [u8; 16],
    aead_cipher: Aes128,
    is_aead: bool,
}

impl VmessTcpClientHandler {
    pub fn new(cipher_name: &str, user_id: &str, is_aead: bool) -> Self {
        let mut user_id_bytes = parse_uuid(user_id).unwrap();
        let mut user_key = [0u8; 16];
        user_key.copy_from_slice(&user_id_bytes);

        user_id_bytes.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key: [u8; 16] = compute_md5(&user_id_bytes);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let aead_cipher = Aes128::new((&derived_key[0..16]).into());

        Self {
            data_cipher: cipher_name.into(),
            aead_cipher,
            user_key,
            instruction_key,
            is_aead,
        }
    }
}

#[async_trait]
impl TcpClientHandler for VmessTcpClientHandler {
    async fn setup_client_stream(
        &self,
        _server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let (cert_hash, time_bytes): ([u8; 16], [u8; 8]) = if self.is_aead {
            // AEAD allows 120 second delta from the current time.
            // See authid.go in v2ray-core.
            let random_delta: u64 = rand::thread_rng().gen_range(0..241);
            let time_secs: u64 =
                SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 120u64 + random_delta;

            let mut aead_bytes = [0u8; 16];
            let time_bytes = time_secs.to_be_bytes();
            aead_bytes[0..8].copy_from_slice(&time_bytes);

            rand::thread_rng().fill_bytes(&mut aead_bytes[8..12]);

            let checksum = super::crc32::crc32c(&aead_bytes[0..12]).to_be_bytes();
            aead_bytes[12..16].copy_from_slice(&checksum);

            self.aead_cipher.encrypt_block((&mut aead_bytes).into());
            (aead_bytes, time_bytes)
        } else {
            // non-AEAD only allows 30 second delta.
            let random_delta: u64 = rand::thread_rng().gen_range(0..61);
            let time_secs: u64 =
                SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 30u64 + random_delta;
            let time_bytes = time_secs.to_be_bytes();
            let hash_bytes = compute_hmac_md5(&self.user_key, &time_bytes);
            (hash_bytes, time_bytes)
        };

        write_all(&mut client_stream, &cert_hash).await?;

        // max length of encrypted header:
        // 41 (instructions up to addr type) + 256 (max domain name length 255 + 1 length byte) +
        // 15 (max margin length, 4 bits) + 4 (fnv1a hash) = 316 + TAG_LEN
        let mut header_bytes = [0u8; 316 + TAG_LEN];

        header_bytes[0] = 1;

        // this fills:
        // - data encryption iv (16 bytes)
        // - data encryption key (16 bytes)
        // - response authentication v (1 byte)
        rand::thread_rng().fill_bytes(&mut header_bytes[1..34]);

        let data_encryption_iv: &[u8] = &header_bytes[1..17];
        let data_encryption_key: &[u8] = &header_bytes[17..33];
        let response_authentication_v = header_bytes[33];

        // construct everything where we need data_encryption_iv and data_encryption_key now,
        // because instructions_to_addr_type will be encrypted once it's filled.
        let (response_header_iv, response_header_key): ([u8; 16], [u8; 16]) = if self.is_aead {
            let mut truncated_iv = [0u8; 16];
            let mut truncated_key = [0u8; 16];
            truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
            truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);

            (truncated_iv, truncated_key)
        } else {
            (
                compute_md5(data_encryption_iv),
                compute_md5(data_encryption_key),
            )
        };

        let (read_length_shake_reader, write_length_shake_reader) = {
            let mut request_hasher = Shake128::default();
            request_hasher.update(data_encryption_iv);
            let request_reader = request_hasher.finalize_xof();

            let mut response_hasher = Shake128::default();
            response_hasher.update(&response_header_iv);
            let response_reader = response_hasher.finalize_xof();

            (Some(response_reader), Some(request_reader))
        };

        let (encryption_method, unbound_keys) = match self.data_cipher {
            DataCipher::Aes128Gcm => {
                // key is 16 bytes
                (
                    3u8,
                    Some((
                        UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                        UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                    )),
                )
            }
            DataCipher::ChaCha20Poly1305 | DataCipher::Any => {
                // default to chacha.
                // key is 32 bytes
                (
                    4u8,
                    Some((
                        UnboundKey::new(
                            &CHACHA20_POLY1305,
                            &create_chacha_key(&response_header_key),
                        )
                        .unwrap(),
                        UnboundKey::new(
                            &CHACHA20_POLY1305,
                            &create_chacha_key(data_encryption_key),
                        )
                        .unwrap(),
                    )),
                )
            }
            DataCipher::None => (5u8, None),
        };

        let data_keys = if let Some((unbound_opening_key, unbound_sealing_key)) = unbound_keys {
            let opening_key = OpeningKey::new(
                unbound_opening_key,
                VmessNonceSequence::new(&response_header_iv),
            );
            let sealing_key = SealingKey::new(
                unbound_sealing_key,
                VmessNonceSequence::new(data_encryption_iv),
            );
            Some((opening_key, sealing_key))
        } else {
            None
        };

        // continue filling out other parts of instructions_to_addr_type.

        // set options, standard format data stream and metadata obfuscation
        header_bytes[34] = 0x01 | 0x04;

        // only 4 bits, generate this now before our first await.
        let margin_len: u8 = rand::random::<u8>() & 0xf;
        header_bytes[35] = (margin_len << 4) | encryption_method;

        // specify tcp protocol
        header_bytes[37] = 1;

        let (remote_address, remote_port) = remote_location.unwrap_components();

        header_bytes[38] = (remote_port >> 8) as u8;
        header_bytes[39] = (remote_port & 0xff) as u8;

        let mut cursor = match remote_address {
            Address::Ipv4(v4addr) => {
                header_bytes[40] = 1;
                header_bytes[41..45].copy_from_slice(&v4addr.octets());
                45
            }
            Address::Ipv6(v6addr) => {
                header_bytes[40] = 3;
                header_bytes[41..57].copy_from_slice(&v6addr.octets());
                57
            }
            Address::Hostname(hostname) => {
                if hostname.len() > 255 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Hostname is too long: {}", hostname),
                    ));
                }
                header_bytes[40] = 2;
                header_bytes[41] = hostname.len() as u8;
                header_bytes[42..42 + hostname.len()].copy_from_slice(hostname.as_bytes());
                42 + hostname.len()
            }
        };

        if margin_len > 0 {
            rand::thread_rng().fill_bytes(&mut header_bytes[cursor..cursor + margin_len as usize]);
            cursor += margin_len as usize;
        }

        let mut fnv_hasher = Fnv1aHasher::new();
        fnv_hasher.write(&header_bytes[0..cursor]);
        let check_bytes = fnv_hasher.finish().to_be_bytes();
        header_bytes[cursor..cursor + 4].copy_from_slice(&check_bytes);
        cursor += 4;

        if self.is_aead {
            let mut encrypted_payload_length = [0u8; 18];
            let mut nonce = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut nonce);

            let header_length_aead_key = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
            );

            let header_length_nonce = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
            );

            let unbound_key =
                UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

            let mut sealing_key = SealingKey::new(
                unbound_key,
                SingleUseNonce::new(&header_length_nonce[0..12]),
            );

            encrypted_payload_length[0] = (cursor >> 8) as u8;
            encrypted_payload_length[1] = (cursor & 0xff) as u8;

            let tag = sealing_key
                .seal_in_place_separate_tag(
                    Aad::from(&cert_hash),
                    &mut encrypted_payload_length[0..2],
                )
                .unwrap();

            encrypted_payload_length[2..].copy_from_slice(tag.as_ref());

            write_all(&mut client_stream, &encrypted_payload_length).await?;
            write_all(&mut client_stream, &nonce).await?;

            let header_aead_key = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Key", &cert_hash, &nonce],
            );

            let header_nonce = super::sha2::kdf(
                &self.instruction_key,
                &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
            );

            // TODO: don't unwrap
            let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
            let mut sealing_key =
                SealingKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));
            let tag = sealing_key
                .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut header_bytes[0..cursor])
                .unwrap();

            header_bytes[cursor..cursor + TAG_LEN].copy_from_slice(tag.as_ref());
            cursor += TAG_LEN;
            write_all(&mut client_stream, &header_bytes[0..cursor]).await?;
        } else {
            let instruction_iv: [u8; 16] = compute_md5_repeating(&time_bytes, 4);
            let cipher = Aes128CfbEnc::new(&self.instruction_key.into(), &instruction_iv.into());
            let sized_header_bytes = &mut header_bytes[0..cursor];
            cipher.encrypt(sized_header_bytes);
            write_all(&mut client_stream, sized_header_bytes).await?;
        }

        // Flush the entire request.
        client_stream.flush().await?;

        // Info for reading the server response, which arrives along with the initial data.
        let read_header_info = ReadHeaderInfo {
            is_aead: self.is_aead,
            response_header_key,
            response_header_iv,
            response_authentication_v,
        };

        let client_stream = Box::new(VmessStream::new(
            client_stream,
            false,
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            false,
            None,
            Some(read_header_info),
        ));

        Ok(TcpClientSetupResult { client_stream })
    }
}
