use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use async_trait::async_trait;
use aws_lc_rs::aead::{
    AES_128_GCM, Aad, BoundKey, CHACHA20_POLY1305, OpeningKey, SealingKey, UnboundKey,
};
use bytes::BytesMut;
use digest::KeyInit;
use rand::{Rng, RngCore};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update};
use tokio::io::AsyncWriteExt;

use super::fnv1a::Fnv1aHasher;
use super::md5::{compute_md5, create_chacha_key};
use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::vmess_stream::{ReadHeaderInfo, VmessStream};
use crate::address::{Address, NetLocation};
use crate::async_stream::{AsyncMessageStream, AsyncSessionMessageStream, AsyncStream};
use crate::option_util::NoneOrOne;
use crate::stream_reader::StreamReader;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpClientUdpSetupResult, TcpServerHandler,
    TcpServerSetupResult, UdpStreamRequest,
};
use crate::util::{allocate_vec, parse_uuid, write_all};
use crate::xudp::XudpMessageStream;

const TAG_LEN: usize = 16;

// VMess protocol command types
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const COMMAND_MUX: u8 = 3; // MUX/XUDP mode

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
                panic!("Unknown cipher: {name}");
            }
        }
    }
}

#[derive(Debug)]
pub struct VmessTcpServerHandler {
    data_cipher: DataCipher,
    instruction_key: [u8; 16],
    aead_cipher: Aes128,
    udp_enabled: bool,
}

impl VmessTcpServerHandler {
    pub fn new(cipher_name: &str, user_id: &str, udp_enabled: bool) -> Self {
        let mut user_id_bytes = parse_uuid(user_id).unwrap();
        user_id_bytes.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key: [u8; 16] = compute_md5(&user_id_bytes);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let aead_cipher = Aes128::new((&derived_key[0..16]).into());

        Self {
            data_cipher: cipher_name.into(),
            aead_cipher,
            instruction_key,
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
        let mut stream_reader = StreamReader::new_with_buffer_size(8192);

        let mut cert_hash = [0u8; 16];
        stream_reader
            .read_slice_into(&mut server_stream, &mut cert_hash)
            .await?;

        // we need to copy it over because if this is an aead request, we need the original
        // bytes for decrypting the header.
        let mut aead_bytes = [0u8; 16];
        aead_bytes.copy_from_slice(&cert_hash);

        self.aead_cipher.decrypt_block((&mut aead_bytes).into());
        let checksum = super::crc32::crc32c(&aead_bytes[0..12]);
        let expected_checksum = u32::from_be_bytes(aead_bytes[12..16].try_into().unwrap());

        if checksum != expected_checksum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AEAD authentication failed: checksum mismatch",
            ));
        }

        let time_secs = u64::from_be_bytes(aead_bytes[0..8].try_into().unwrap());
        let current_time_secs = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let time_delta = time_secs.abs_diff(current_time_secs);
        if time_delta > 120 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Hash timestamp is too old ({time_secs} is {time_delta} seconds old)"),
            ));
        }

        let mut encrypted_payload_length = [0u8; 18];
        stream_reader
            .read_slice_into(&mut server_stream, &mut encrypted_payload_length)
            .await?;

        let mut nonce = [0u8; 8];
        stream_reader
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
        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::from(&cert_hash), &mut encrypted_payload_length)
            .is_err()
        {
            return Err(std::io::Error::other(
                "failed to open encrypted header length",
            ));
        }

        let payload_length = u16::from_be_bytes(encrypted_payload_length[0..2].try_into().unwrap());

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

        stream_reader
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
            return Err(std::io::Error::other("failed to open encrypted header"));
        }

        let mut header_reader = AeadHeaderReader {
            server_stream,
            decrypted_header: encrypted_header,
            cursor: 0,
        };

        let mut fnv_hasher = Fnv1aHasher::new();

        // Read fixed 38-byte header first
        let mut fixed_header = [0u8; 38];
        header_reader.read_slice_into(&mut fixed_header)?;
        fnv_hasher.write(&fixed_header);

        if fixed_header[0] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid version {}", fixed_header[0]),
            ));
        }

        let command = fixed_header[37];

        log::info!("VMess command: {}", command);

        // For MUX/XUDP command (0x03), there is NO destination in the VMess header
        // Destinations come in XUDP frames themselves
        let remote_location = if command == COMMAND_MUX {
            // Use a placeholder address for XUDP - actual destinations come from XUDP frames
            log::info!(
                "VMess MUX/XUDP: No destination in VMess header (destinations come in XUDP frames)"
            );
            NetLocation::new(Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0)), 0)
        } else {
            // For TCP/UDP commands, read port (2 bytes) and address
            let mut port_and_addr_type = [0u8; 3];
            header_reader.read_slice_into(&mut port_and_addr_type)?;
            fnv_hasher.write(&port_and_addr_type);

            let port = u16::from_be_bytes(port_and_addr_type[0..2].try_into().unwrap());

            match port_and_addr_type[2] {
                1 => {
                    // 4 byte ipv4 address
                    let mut address_bytes = [0u8; 4];
                    header_reader.read_slice_into(&mut address_bytes)?;
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
                    header_reader.read_slice_into(&mut domain_name_len)?;
                    fnv_hasher.write(&domain_name_len);

                    let mut domain_name_bytes = allocate_vec(domain_name_len[0] as usize);
                    header_reader.read_slice_into(&mut domain_name_bytes)?;
                    fnv_hasher.write(&domain_name_bytes);

                    let address_str = match std::str::from_utf8(&domain_name_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Failed to decode address: {e}"),
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
                    header_reader.read_slice_into(&mut address_bytes)?;
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
                        format!("Invalid address type: {invalid_type}"),
                    ));
                }
            }
        };

        let margin_len: u8 = fixed_header[35] >> 4;
        log::info!("VMess margin_len: {}, command: {}", margin_len, command);
        if margin_len > 0 {
            let mut margin_bytes = allocate_vec(margin_len as usize).into_boxed_slice();
            header_reader.read_slice_into(&mut margin_bytes)?;
            log::info!("VMess margin_bytes: {:?}", &margin_bytes[..]);
            fnv_hasher.write(&margin_bytes);
        }

        let mut check_bytes = [0u8; 4];
        header_reader.read_slice_into(&mut check_bytes)?;
        log::info!("VMess check_bytes: {:?}", &check_bytes);

        let expected_check_value = u32::from_be_bytes(check_bytes[0..4].try_into().unwrap());
        let actual_check_value = fnv_hasher.finish();
        log::info!(
            "VMess FNV1a: expected={}, actual={}",
            expected_check_value,
            actual_check_value
        );
        if expected_check_value != actual_check_value {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Bad fnv1a checksum, expected {expected_check_value}, got {actual_check_value}"
                ),
            ));
        }

        let server_stream = header_reader.into_stream();

        let data_encryption_iv: &[u8] = &fixed_header[1..17];
        let data_encryption_key: &[u8] = &fixed_header[17..33];
        let response_authentication_v = fixed_header[33];
        let option = fixed_header[34];

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
        let requested_data_cipher = match fixed_header[35] & 0b1111 {
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
                    format!("Unknown requested cipher: {unknown_cipher_type}"),
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

        let response_header: [u8; 4] = [
            response_authentication_v,
            0, // option
            0, // command
            0, // command length
        ];

        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

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
        // AEAD mode only
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
        let unbound_key = UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4].copy_from_slice(&response_header);

        let tag = sealing_key
            .seal_in_place_separate_tag(
                Aad::empty(),
                &mut encrypted_response_header[2 + TAG_LEN..2 + TAG_LEN + 4],
            )
            .unwrap();
        encrypted_response_header[2 + TAG_LEN + 4..].copy_from_slice(tag.as_ref());

        let prefix_bytes = BytesMut::from(&encrypted_response_header[..]);

        match command {
            COMMAND_TCP => {
                let mut vmess_stream = VmessStream::new(
                    server_stream,
                    false, // is_udp = false
                    data_keys,
                    read_length_shake_reader,
                    write_length_shake_reader,
                    enable_global_padding,
                    Some(prefix_bytes),
                    None,
                );

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    vmess_stream.feed_initial_read_data(unparsed_data)?;
                }

                let server_stream = Box::new(vmess_stream);

                Ok(TcpServerSetupResult::TcpForward {
                    remote_location,
                    stream: server_stream,
                    // Wait until there is data to send the response header.
                    need_initial_flush: false,
                    connection_success_response: None,
                    initial_remote_data: None,
                    override_proxy_provider: NoneOrOne::Unspecified,
                })
            }
            COMMAND_UDP => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "UDP not enabled",
                    ));
                }

                let mut vmess_stream = VmessStream::new(
                    server_stream,
                    true, // is_udp = true
                    data_keys,
                    read_length_shake_reader,
                    write_length_shake_reader,
                    enable_global_padding,
                    Some(prefix_bytes),
                    None,
                );

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    vmess_stream.feed_initial_read_data(unparsed_data)?;
                }

                let server_stream = Box::new(vmess_stream);

                Ok(TcpServerSetupResult::BidirectionalUdp {
                    remote_location,
                    stream: server_stream,
                    need_initial_flush: false,
                    override_proxy_provider: NoneOrOne::Unspecified,
                })
            }
            COMMAND_MUX => {
                if !self.udp_enabled {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "MUX/XUDP requires UDP to be enabled",
                    ));
                }

                // For XUDP mode, use is_udp=false since XUDP wraps the stream
                let mut vmess_stream = VmessStream::new(
                    server_stream,
                    false, // XUDP handles UDP multiplexing, VmessStream sees it as TCP-like
                    data_keys,
                    read_length_shake_reader,
                    write_length_shake_reader,
                    enable_global_padding,
                    Some(prefix_bytes),
                    None,
                );

                let unparsed_data = stream_reader.unparsed_data();
                if !unparsed_data.is_empty() {
                    vmess_stream.feed_initial_read_data(unparsed_data)?;
                }

                // Wrap VmessStream with XudpMessageStream for session multiplexing
                let xudp_stream = XudpMessageStream::new(Box::new(vmess_stream));

                // No unparsed data to feed since VmessStream already consumed it
                // (XUDP framing starts after VMess header)

                Ok(TcpServerSetupResult::SessionBasedUdp {
                    stream: Box::new(xudp_stream),
                    need_initial_flush: false,
                    override_proxy_provider: NoneOrOne::Unspecified,
                })
            }
            unknown_protocol_type => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown requested protocol: {unknown_protocol_type}"),
            )),
        }
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
    instruction_key: [u8; 16],
    aead_cipher: Aes128,
    udp_enabled: bool,
}

impl VmessTcpClientHandler {
    pub fn new(cipher_name: &str, user_id: &str, udp_enabled: bool) -> Self {
        let mut user_id_bytes = parse_uuid(user_id).unwrap();
        user_id_bytes.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let instruction_key: [u8; 16] = compute_md5(&user_id_bytes);

        let derived_key = super::sha2::kdf(&instruction_key, &[b"AES Auth ID Encryption"]);
        let aead_cipher = Aes128::new((&derived_key[0..16]).into());

        Self {
            data_cipher: cipher_name.into(),
            aead_cipher,
            instruction_key,
            udp_enabled,
        }
    }
}

#[async_trait]
impl TcpClientHandler for VmessTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // AEAD allows 120 second delta from the current time.
        // See authid.go in v2ray-core.
        let random_delta: u64 = rand::rng().random_range(0..241);
        let time_secs: u64 =
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 120u64 + random_delta;

        let mut aead_bytes = [0u8; 16];
        let time_bytes = time_secs.to_be_bytes();
        aead_bytes[0..8].copy_from_slice(&time_bytes);

        rand::rng().fill_bytes(&mut aead_bytes[8..12]);

        let checksum_value = super::crc32::crc32c(&aead_bytes[0..12]);
        let checksum = checksum_value.to_be_bytes();
        aead_bytes[12..16].copy_from_slice(&checksum);

        self.aead_cipher.encrypt_block((&mut aead_bytes).into());

        let cert_hash = aead_bytes;

        // max length of encrypted header:
        // 41 (instructions up to addr type) + 256 (max domain name length 255 + 1 length byte) +
        // 15 (max margin length, 4 bits) + 4 (fnv1a hash) = 316 + TAG_LEN
        let mut header_bytes = [0u8; 316 + TAG_LEN];

        header_bytes[0] = 1;

        // this fills:
        // - data encryption iv (16 bytes)
        // - data encryption key (16 bytes)
        // - response authentication v (1 byte)
        rand::rng().fill_bytes(&mut header_bytes[1..34]);

        let data_encryption_iv: &[u8] = &header_bytes[1..17];
        let data_encryption_key: &[u8] = &header_bytes[17..33];
        let response_authentication_v = header_bytes[33];

        // construct everything where we need data_encryption_iv and data_encryption_key now,
        // because instructions_to_addr_type will be encrypted once it's filled.
        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

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
                        format!("Hostname is too long: {hostname}"),
                    ));
                }
                header_bytes[40] = 2;
                header_bytes[41] = hostname.len() as u8;
                header_bytes[42..42 + hostname.len()].copy_from_slice(hostname.as_bytes());
                42 + hostname.len()
            }
        };

        if margin_len > 0 {
            rand::rng().fill_bytes(&mut header_bytes[cursor..cursor + margin_len as usize]);
            cursor += margin_len as usize;
        }

        let mut fnv_hasher = Fnv1aHasher::new();
        fnv_hasher.write(&header_bytes[0..cursor]);
        let check_bytes = fnv_hasher.finish().to_be_bytes();
        header_bytes[cursor..cursor + 4].copy_from_slice(&check_bytes);
        cursor += 4;

        // AEAD mode only
        let mut encrypted_payload_length = [0u8; 18];
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let header_length_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );

        let header_length_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        encrypted_payload_length[0] = (cursor >> 8) as u8;
        encrypted_payload_length[1] = (cursor & 0xff) as u8;

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut encrypted_payload_length[0..2])
            .unwrap();

        encrypted_payload_length[2..].copy_from_slice(tag.as_ref());

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

        // Build complete AEAD request in a single buffer to avoid multiple writes as some
        // servers expect to read the entire header in one shot
        let total_len = 16 + 18 + 8 + cursor;
        let mut complete_request = Vec::with_capacity(total_len);
        complete_request.extend_from_slice(&cert_hash);
        complete_request.extend_from_slice(&encrypted_payload_length);
        complete_request.extend_from_slice(&nonce);
        complete_request.extend_from_slice(&header_bytes[0..cursor]);

        write_all(&mut client_stream, &complete_request).await?;

        // Flush the entire request.
        client_stream.flush().await?;

        // Info for reading the server response, which arrives along with the initial data.
        // Always AEAD mode
        let read_header_info = ReadHeaderInfo {
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

        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled // VMess supports UDP-over-TCP tunneling when enabled
    }

    async fn setup_client_udp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        request: UdpStreamRequest,
    ) -> std::io::Result<TcpClientUdpSetupResult> {
        match request {
            UdpStreamRequest::SessionBased { server_stream } => {
                // VMess XUDP/MUX mode: Send VMess header with COMMAND_MUX (3), no destination.
                // Destinations come in XUDP frames.
                self.setup_udp_stream_session_based(client_stream, server_stream)
                    .await
            }
            UdpStreamRequest::Bidirectional {
                server_stream,
                target,
            } => {
                // VMess single-target UDP mode: Send VMess header with COMMAND_UDP (2)
                // and destination address. Uses VmessStream with is_udp=true.
                self.setup_udp_stream_bidirectional(client_stream, target, server_stream)
                    .await
            }
            UdpStreamRequest::MultiDirectional { .. } => {
                // VMess doesn't have native MultiDirectional support
                // Use SessionBased (XUDP) instead
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "VMess does not support MultiDirectional UDP. Use SessionBased instead.",
                ))
            }
        }
    }
}

impl VmessTcpClientHandler {
    async fn setup_udp_stream_session_based(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        server_stream: Box<dyn AsyncSessionMessageStream>,
    ) -> std::io::Result<TcpClientUdpSetupResult> {
        // VMess XUDP/MUX mode: Send VMess header with COMMAND_MUX (3), no destination.
        // Destinations come in XUDP frames.

        // AEAD allows 120 second delta from the current time.
        let random_delta: u64 = rand::rng().random_range(0..241);
        let time_secs: u64 =
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 120u64 + random_delta;

        let mut aead_bytes = [0u8; 16];
        let time_bytes = time_secs.to_be_bytes();
        aead_bytes[0..8].copy_from_slice(&time_bytes);

        rand::rng().fill_bytes(&mut aead_bytes[8..12]);

        let checksum_value = super::crc32::crc32c(&aead_bytes[0..12]);
        let checksum = checksum_value.to_be_bytes();
        aead_bytes[12..16].copy_from_slice(&checksum);

        self.aead_cipher.encrypt_block((&mut aead_bytes).into());

        let cert_hash = aead_bytes;

        // MUX header is shorter - no port/address: 38 (instructions without addr) + margin + fnv
        // 38 = version(1) + keys(33) + opts(1) + padding|method(1) + reserved(1) + command(1)
        let mut header_bytes = [0u8; 128 + TAG_LEN];

        header_bytes[0] = 1; // version

        // this fills:
        // - data encryption iv (16 bytes)
        // - data encryption key (16 bytes)
        // - response authentication v (1 byte)
        rand::rng().fill_bytes(&mut header_bytes[1..34]);

        let data_encryption_iv: &[u8] = &header_bytes[1..17];
        let data_encryption_key: &[u8] = &header_bytes[17..33];
        let response_authentication_v = header_bytes[33];

        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

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
            DataCipher::Aes128Gcm => (
                3u8,
                Some((
                    UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                    UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                )),
            ),
            DataCipher::ChaCha20Poly1305 | DataCipher::Any => (
                4u8,
                Some((
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&response_header_key))
                        .unwrap(),
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(data_encryption_key))
                        .unwrap(),
                )),
            ),
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

        // set options, standard format data stream and metadata obfuscation
        header_bytes[34] = 0x01 | 0x04;

        // only 4 bits for margin, generate this now before our first await.
        let margin_len: u8 = rand::random::<u8>() & 0xf;
        header_bytes[35] = (margin_len << 4) | encryption_method;

        // reserved byte
        header_bytes[36] = 0;

        // MUX command (3) - no port/address follows
        header_bytes[37] = COMMAND_MUX;

        // cursor after command byte - MUX has no port/address
        let mut cursor = 38;

        if margin_len > 0 {
            rand::rng().fill_bytes(&mut header_bytes[cursor..cursor + margin_len as usize]);
            cursor += margin_len as usize;
        }

        let mut fnv_hasher = Fnv1aHasher::new();
        fnv_hasher.write(&header_bytes[0..cursor]);
        let check_bytes = fnv_hasher.finish().to_be_bytes();
        header_bytes[cursor..cursor + 4].copy_from_slice(&check_bytes);
        cursor += 4;

        // AEAD mode only
        let mut encrypted_payload_length = [0u8; 18];
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let header_length_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );

        let header_length_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        encrypted_payload_length[0] = (cursor >> 8) as u8;
        encrypted_payload_length[1] = (cursor & 0xff) as u8;

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut encrypted_payload_length[0..2])
            .unwrap();

        encrypted_payload_length[2..].copy_from_slice(tag.as_ref());

        let header_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );

        let header_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
        let mut sealing_key =
            SealingKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut header_bytes[0..cursor])
            .unwrap();

        header_bytes[cursor..cursor + TAG_LEN].copy_from_slice(tag.as_ref());
        cursor += TAG_LEN;

        // Build complete AEAD request in a single buffer
        let total_len = 16 + 18 + 8 + cursor;
        let mut complete_request = Vec::with_capacity(total_len);
        complete_request.extend_from_slice(&cert_hash);
        complete_request.extend_from_slice(&encrypted_payload_length);
        complete_request.extend_from_slice(&nonce);
        complete_request.extend_from_slice(&header_bytes[0..cursor]);

        write_all(&mut client_stream, &complete_request).await?;
        client_stream.flush().await?;

        // Info for reading the server response
        let read_header_info = ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            response_authentication_v,
        };

        // Create VmessStream with is_udp=false since XUDP handles UDP multiplexing
        let vmess_stream = VmessStream::new(
            client_stream,
            false, // XUDP handles UDP, VmessStream sees TCP-like stream
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            false,
            None,
            Some(read_header_info),
        );

        // Wrap with XUDP message stream for session-based multiplexing
        let xudp_stream = XudpMessageStream::new(Box::new(vmess_stream));

        Ok(TcpClientUdpSetupResult::SessionBased {
            server_stream,
            client_stream: Box::new(xudp_stream),
        })
    }

    async fn setup_udp_stream_bidirectional(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
        server_stream: Box<dyn AsyncMessageStream>,
    ) -> std::io::Result<TcpClientUdpSetupResult> {
        // VMess single-target UDP mode: Send VMess header with COMMAND_UDP (2).
        // Same as TCP setup but with command=2 and is_udp=true for VmessStream.

        // AEAD allows 120 second delta from the current time.
        let random_delta: u64 = rand::rng().random_range(0..241);
        let time_secs: u64 =
            SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs() - 120u64 + random_delta;

        let mut aead_bytes = [0u8; 16];
        let time_bytes = time_secs.to_be_bytes();
        aead_bytes[0..8].copy_from_slice(&time_bytes);

        rand::rng().fill_bytes(&mut aead_bytes[8..12]);

        let checksum_value = super::crc32::crc32c(&aead_bytes[0..12]);
        let checksum = checksum_value.to_be_bytes();
        aead_bytes[12..16].copy_from_slice(&checksum);

        self.aead_cipher.encrypt_block((&mut aead_bytes).into());

        let cert_hash = aead_bytes;

        // max length of encrypted header (same as TCP):
        // 41 (instructions up to addr type) + 256 (max domain name length) +
        // 15 (max margin length) + 4 (fnv1a hash) = 316 + TAG_LEN
        let mut header_bytes = [0u8; 316 + TAG_LEN];

        header_bytes[0] = 1; // version

        // Fill encryption keys and response auth:
        // - data encryption iv (16 bytes)
        // - data encryption key (16 bytes)
        // - response authentication v (1 byte)
        rand::rng().fill_bytes(&mut header_bytes[1..34]);

        let data_encryption_iv: &[u8] = &header_bytes[1..17];
        let data_encryption_key: &[u8] = &header_bytes[17..33];
        let response_authentication_v = header_bytes[33];

        // AEAD mode only - use SHA256 for response header keys
        let mut truncated_iv = [0u8; 16];
        let mut truncated_key = [0u8; 16];
        truncated_iv.copy_from_slice(&super::sha2::compute_sha256(data_encryption_iv)[0..16]);
        truncated_key.copy_from_slice(&super::sha2::compute_sha256(data_encryption_key)[0..16]);
        let response_header_iv = truncated_iv;
        let response_header_key = truncated_key;

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
            DataCipher::Aes128Gcm => (
                3u8,
                Some((
                    UnboundKey::new(&AES_128_GCM, &response_header_key).unwrap(),
                    UnboundKey::new(&AES_128_GCM, data_encryption_key).unwrap(),
                )),
            ),
            DataCipher::ChaCha20Poly1305 | DataCipher::Any => (
                4u8,
                Some((
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(&response_header_key))
                        .unwrap(),
                    UnboundKey::new(&CHACHA20_POLY1305, &create_chacha_key(data_encryption_key))
                        .unwrap(),
                )),
            ),
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

        // Set options: standard format data stream and metadata obfuscation
        header_bytes[34] = 0x01 | 0x04;

        // Margin length (4 bits) + encryption method
        let margin_len: u8 = rand::random::<u8>() & 0xf;
        header_bytes[35] = (margin_len << 4) | encryption_method;

        // Reserved byte
        header_bytes[36] = 0;

        // Command = UDP (2) instead of TCP (1)
        header_bytes[37] = COMMAND_UDP;

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
                        format!("Hostname is too long: {hostname}"),
                    ));
                }
                header_bytes[40] = 2;
                header_bytes[41] = hostname.len() as u8;
                header_bytes[42..42 + hostname.len()].copy_from_slice(hostname.as_bytes());
                42 + hostname.len()
            }
        };

        if margin_len > 0 {
            rand::rng().fill_bytes(&mut header_bytes[cursor..cursor + margin_len as usize]);
            cursor += margin_len as usize;
        }

        let mut fnv_hasher = Fnv1aHasher::new();
        fnv_hasher.write(&header_bytes[0..cursor]);
        let check_bytes = fnv_hasher.finish().to_be_bytes();
        header_bytes[cursor..cursor + 4].copy_from_slice(&check_bytes);
        cursor += 4;

        // AEAD encryption of header
        let mut encrypted_payload_length = [0u8; 18];
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let header_length_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key_Length", &cert_hash, &nonce],
        );

        let header_length_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce_Length", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_length_aead_key[0..16]).unwrap();

        let mut sealing_key = SealingKey::new(
            unbound_key,
            SingleUseNonce::new(&header_length_nonce[0..12]),
        );

        encrypted_payload_length[0] = (cursor >> 8) as u8;
        encrypted_payload_length[1] = (cursor & 0xff) as u8;

        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut encrypted_payload_length[0..2])
            .unwrap();

        encrypted_payload_length[2..].copy_from_slice(tag.as_ref());

        let header_aead_key = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Key", &cert_hash, &nonce],
        );

        let header_nonce = super::sha2::kdf(
            &self.instruction_key,
            &[b"VMess Header AEAD Nonce", &cert_hash, &nonce],
        );

        let unbound_key = UnboundKey::new(&AES_128_GCM, &header_aead_key[0..16]).unwrap();
        let mut sealing_key =
            SealingKey::new(unbound_key, SingleUseNonce::new(&header_nonce[0..12]));
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::from(&cert_hash), &mut header_bytes[0..cursor])
            .unwrap();

        header_bytes[cursor..cursor + TAG_LEN].copy_from_slice(tag.as_ref());
        cursor += TAG_LEN;

        // Build complete AEAD request in a single buffer
        let total_len = 16 + 18 + 8 + cursor;
        let mut complete_request = Vec::with_capacity(total_len);
        complete_request.extend_from_slice(&cert_hash);
        complete_request.extend_from_slice(&encrypted_payload_length);
        complete_request.extend_from_slice(&nonce);
        complete_request.extend_from_slice(&header_bytes[0..cursor]);

        write_all(&mut client_stream, &complete_request).await?;
        client_stream.flush().await?;

        // Info for reading the server response
        let read_header_info = ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            response_authentication_v,
        };

        // Create VmessStream with is_udp=true for bidirectional UDP
        let vmess_stream = VmessStream::new(
            client_stream,
            true, // is_udp = true for bidirectional UDP mode
            data_keys,
            read_length_shake_reader,
            write_length_shake_reader,
            false,
            None,
            Some(read_header_info),
        );

        Ok(TcpClientUdpSetupResult::Bidirectional {
            server_stream,
            client_stream: Box::new(vmess_stream),
        })
    }
}
