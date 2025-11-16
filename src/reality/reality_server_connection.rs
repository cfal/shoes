// REALITY server-side connection
//
// This implements a rustls-compatible API for REALITY protocol server connections,
// allowing REALITY to be used as a drop-in replacement for rustls.

use std::io::{self, Read, Write};

use crate::address::{Address, NetLocation};
use crate::slide_buffer::SlideBuffer;

use super::common::{
    self, CIPHERTEXT_READ_BUF_CAPACITY, CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_FINISHED,
    PLAINTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE, TLS_RECORD_HEADER_SIZE,
};
use super::reality_aead::{decrypt_handshake_message, decrypt_tls13_record};
use super::reality_auth::{decrypt_session_id, derive_auth_key, perform_ecdh};
use super::reality_certificate::generate_hmac_certificate;
use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::{encrypt_handshake_to_records, encrypt_plaintext_to_records};
use super::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use super::reality_tls13_messages::*;
use super::reality_util::{
    extract_client_public_key, extract_client_random, extract_session_id_slice,
};
use aws_lc_rs::{
    agreement, digest,
    rand::{SecureRandom, SystemRandom},
};
use subtle::ConstantTimeEq;

/// Configuration for REALITY server connections
#[derive(Clone)]
pub struct RealityServerConfig {
    /// Server's X25519 private key (32 bytes)
    pub private_key: [u8; 32],
    /// List of valid short IDs for authentication (8 bytes each)
    pub short_ids: Vec<[u8; 8]>,
    /// Destination server for certificate generation
    pub dest: NetLocation,
    /// Maximum allowed time difference in milliseconds (None = no check)
    pub max_time_diff: Option<u64>,
    /// Minimum accepted client version (3 bytes: major.minor.patch)
    pub min_client_version: Option<[u8; 3]>,
    /// Maximum accepted client version (3 bytes: major.minor.patch)
    pub max_client_version: Option<[u8; 3]>,
}

/// Handshake state machine for REALITY server
enum HandshakeState {
    /// Initial state, waiting for ClientHello
    Initial,
    /// ServerHello and encrypted handshake messages sent, waiting for client Finished
    ServerHelloSent {
        handshake_hash: [u8; 32],                      // Hash before server Finished
        handshake_hash_with_server_finished: [u8; 32], // Hash including server Finished (for verifying client Finished)
        client_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: u16,
    },
    /// Handshake complete, ready for application data
    Complete,
}

/// REALITY server-side connection implementing rustls-compatible API
pub struct RealityServerConnection {
    // Configuration
    config: RealityServerConfig,

    // Handshake state
    handshake_state: HandshakeState,

    // TLS 1.3 application traffic encryption (post-handshake)
    app_read_key: Option<Vec<u8>>,
    app_read_iv: Option<Vec<u8>>,
    app_write_key: Option<Vec<u8>>,
    app_write_iv: Option<Vec<u8>>,
    read_seq: u64,
    write_seq: u64,
    cipher_suite: u16,

    // Pre-allocated buffer for TLS read operations (reused across calls)
    tls_read_buffer: Box<[u8; TLS_MAX_RECORD_SIZE]>,

    // Buffers for I/O - using SlideBuffer for efficient zero-alloc operations
    ciphertext_read_buf: SlideBuffer, // Incoming encrypted TLS records
    ciphertext_write_buf: Vec<u8>,    // Outgoing encrypted TLS records
    plaintext_read_buf: SlideBuffer,  // Decrypted application data
    plaintext_write_buf: Vec<u8>,     // Application data to encrypt
}

impl RealityServerConnection {
    /// Create a new REALITY server connection
    pub fn new(config: RealityServerConfig) -> io::Result<Self> {
        Ok(RealityServerConnection {
            config,
            handshake_state: HandshakeState::Initial,
            app_read_key: None,
            app_read_iv: None,
            app_write_key: None,
            app_write_iv: None,
            read_seq: 0,
            write_seq: 0,
            cipher_suite: 0,
            tls_read_buffer: Box::new([0u8; TLS_MAX_RECORD_SIZE]),
            ciphertext_read_buf: SlideBuffer::new(CIPHERTEXT_READ_BUF_CAPACITY),
            ciphertext_write_buf: Vec::with_capacity(CIPHERTEXT_READ_BUF_CAPACITY),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::with_capacity(TLS_MAX_RECORD_SIZE),
        })
    }

    /// Read TLS messages from the provided reader into internal buffer
    ///
    /// This does NOT decrypt - call process_new_packets() for that.
    /// Uses pre-allocated buffer to avoid allocation on every call.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        // Compact if remaining capacity is insufficient for a full TLS record
        if self.ciphertext_read_buf.remaining_capacity() < TLS_MAX_RECORD_SIZE {
            self.ciphertext_read_buf.compact();
        }

        // Read into pre-allocated buffer
        let n = rd.read(&mut self.tls_read_buffer[..])?;
        if n > 0 {
            self.ciphertext_read_buf
                .extend_from_slice(&self.tls_read_buffer[..n]);
        }
        Ok(n)
    }

    /// Process buffered TLS messages and advance handshake/decrypt data
    ///
    /// Returns I/O state with available plaintext bytes and write status.
    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        match &self.handshake_state {
            HandshakeState::Initial => {
                self.process_client_hello()?;
            }
            HandshakeState::ServerHelloSent { .. } => {
                self.process_client_finished()?;
            }
            HandshakeState::Complete => {
                self.process_application_data()?;
            }
        }

        Ok(RealityIoState::new(self.plaintext_read_buf.len()))
    }

    /// Process ClientHello message and send ServerHello
    fn process_client_hello(&mut self) -> io::Result<()> {
        // Need at least TLS record header (5 bytes)
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(()); // Need more data
        }

        // Parse TLS record length
        let record_len = self
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;

        // Check if we have the complete record
        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(()); // Need more data
        }

        // Copy the ClientHello record to a Vec for processing
        // (We need to keep it around for transcript hashing and AAD modification)
        let client_hello: Vec<u8> = self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);

        // Step 1: Extract fields from ClientHello (using slice for session_id to avoid allocation)
        let client_random = extract_client_random(&client_hello)?;
        let session_id = extract_session_id_slice(&client_hello)?;
        let client_public_key = extract_client_public_key(&client_hello)?;

        log::debug!(
            "REALITY: ClientHello received, client_random: {:?}",
            &client_random[..8]
        );

        // Step 2: Perform ECDH to derive auth key
        let shared_secret = perform_ecdh(&self.config.private_key, &client_public_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Use slices directly from client_random to avoid copying
        let salt = &client_random[0..20];
        let auth_key = derive_auth_key(&shared_secret, salt, b"REALITY")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Step 3: Validate session ID (contains encrypted metadata)
        if session_id.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid session ID length",
            ));
        }

        let nonce = &client_random[20..32];
        let mut encrypted_session_id_arr = [0u8; 32];
        encrypted_session_id_arr.copy_from_slice(session_id);

        // CRITICAL: Reconstruct AAD with zeros at SessionId location
        // The AAD during encryption had zeros where the session ID would go
        // SessionId is at offset 39 in ClientHello handshake (after type(1) + length(3) + version(2) + random(32) + sessionid_length(1))
        let client_hello_handshake = &client_hello[TLS_RECORD_HEADER_SIZE..];
        let mut aad_for_decryption = client_hello_handshake.to_vec();
        if aad_for_decryption.len() >= 39 + 32 {
            // Replace encrypted SessionId with zeros
            aad_for_decryption[39..39 + 32].fill(0);
        }

        let decrypted_session_id = decrypt_session_id(
            &encrypted_session_id_arr,
            &auth_key,
            nonce,
            &aad_for_decryption,
        )
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Session ID decrypt failed: {:?}", e),
            )
        })?;

        // Validate session ID contents
        // Bytes 0-2: Version
        // Byte 3: Padding
        // Bytes 4-7: Timestamp (uint32)
        // Bytes 8-15: ShortId
        let client_version = &decrypted_session_id[0..3];
        let client_timestamp = u32::from_be_bytes([
            decrypted_session_id[4],
            decrypted_session_id[5],
            decrypted_session_id[6],
            decrypted_session_id[7],
        ]) as u64;
        let client_short_id = &decrypted_session_id[8..16];

        log::debug!("REALITY: Client version: {:?}", client_version);
        log::debug!("REALITY: Client timestamp: {}", client_timestamp);
        log::debug!("REALITY: Client short_id: {:02x?}", client_short_id);

        // Validate short ID - check if client's short_id is in the configured list
        let mut client_short_id_arr = [0u8; 8];
        client_short_id_arr.copy_from_slice(client_short_id);
        let short_id_ok = self.config.short_ids.contains(&client_short_id_arr);

        if !short_id_ok {
            log::warn!(
                "REALITY: Client short_id {:02x?} not in configured list",
                client_short_id
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Invalid short_id: {:02x?}", client_short_id),
            ));
        }

        // Validate timestamp if max_time_diff is configured
        if let Some(max_diff_ms) = self.config.max_time_diff {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| io::Error::other("System time error"))?
                .as_secs();

            let time_diff_secs = now.abs_diff(client_timestamp);
            let max_diff_secs = max_diff_ms / 1000;

            if time_diff_secs > max_diff_secs {
                log::warn!(
                    "REALITY: Client timestamp {} differs from server {} by {} seconds (max: {} seconds)",
                    client_timestamp, now, time_diff_secs, max_diff_secs
                );
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Timestamp difference {} seconds exceeds maximum {} seconds",
                        time_diff_secs, max_diff_secs
                    ),
                ));
            }
        }

        // Validate client version (min)
        if let Some(min_ver) = &self.config.min_client_version {
            if client_version < &min_ver[..] {
                log::warn!(
                    "REALITY: Client version {:?} is below minimum {:?}",
                    client_version,
                    min_ver
                );
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Client version {:?} is below minimum {:?}",
                        client_version, min_ver
                    ),
                ));
            }
        }

        // Validate client version (max)
        if let Some(max_ver) = &self.config.max_client_version {
            if client_version > &max_ver[..] {
                log::warn!(
                    "REALITY: Client version {:?} is above maximum {:?}",
                    client_version,
                    max_ver
                );
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Client version {:?} is above maximum {:?}",
                        client_version, max_ver
                    ),
                ));
            }
        }

        log::info!("REALITY: Client authentication successful - short_id: {:02x?}, version: {:?}, timestamp: {}",
                   client_short_id, client_version, client_timestamp);

        // Step 4: Generate our server X25519 keypair
        let rng = SystemRandom::new();
        let mut our_private_bytes = [0u8; 32];
        rng.fill(&mut our_private_bytes)
            .map_err(|_| io::Error::other("RNG failed"))?;

        let our_private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &our_private_bytes)
                .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
        let our_public_key_bytes = our_private_key
            .compute_public_key()
            .map_err(|_| io::Error::other("Failed to compute public key"))?;

        // Step 5: Generate server random
        let mut server_random = [0u8; 32];
        rng.fill(&mut server_random)
            .map_err(|_| io::Error::other("RNG failed"))?;

        // Step 6: Use standard cipher suite (TLS_AES_128_GCM_SHA256)
        const CIPHER_SUITE: u16 = 0x1301;

        // Step 7: Build ServerHello
        let server_hello = construct_server_hello(
            &server_random,
            session_id,
            CIPHER_SUITE,
            our_public_key_bytes.as_ref(),
        )?;

        // Step 8: Compute transcript hashes
        let client_hello_handshake = &client_hello[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header

        let mut ch_transcript = digest::Context::new(&digest::SHA256);
        ch_transcript.update(client_hello_handshake);
        let client_hello_hash = ch_transcript.finish();

        let mut ch_sh_transcript = digest::Context::new(&digest::SHA256);
        ch_sh_transcript.update(client_hello_handshake);
        ch_sh_transcript.update(&server_hello);

        // Clone before finalizing
        let mut handshake_transcript = ch_sh_transcript.clone();
        let server_hello_hash = ch_sh_transcript.finish();

        // Step 9: Perform ECDH for TLS 1.3 key derivation
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, &client_public_key);
        let mut tls_shared_secret = [0u8; 32];
        agreement::agree(
            &our_private_key,
            peer_public_key,
            io::Error::other("ECDH failed"),
            |key_material| {
                tls_shared_secret.copy_from_slice(key_material);
                Ok(())
            },
        )?;

        // Step 10: Derive TLS 1.3 keys
        let mut client_hello_hash_arr = [0u8; 32];
        client_hello_hash_arr.copy_from_slice(client_hello_hash.as_ref());
        let mut server_hello_hash_arr = [0u8; 32];
        server_hello_hash_arr.copy_from_slice(server_hello_hash.as_ref());

        let hs_keys = derive_handshake_keys(
            &tls_shared_secret,
            &client_hello_hash_arr,
            &server_hello_hash_arr,
        )?;

        // Get destination hostname for certificate
        let dest_hostname = match self.config.dest.address() {
            Address::Hostname(h) => h.as_str(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY requires a hostname destination",
                ))
            }
        };

        // Step 11: Generate HMAC-signed certificate
        let (cert_der, signing_key) = generate_hmac_certificate(&auth_key, dest_hostname)?;

        // Step 12: Build encrypted handshake messages
        let encrypted_extensions = construct_encrypted_extensions()?;
        handshake_transcript.update(&encrypted_extensions);

        let certificate = construct_certificate(&cert_der)?;
        handshake_transcript.update(&certificate);

        let cert_verify_hash = handshake_transcript.clone().finish();
        let mut cert_verify_hash_arr = [0u8; 32];
        cert_verify_hash_arr.copy_from_slice(cert_verify_hash.as_ref());
        let certificate_verify = construct_certificate_verify(&signing_key, &cert_verify_hash_arr)?;
        handshake_transcript.update(&certificate_verify);

        let handshake_hash_before_finished = handshake_transcript.clone().finish();
        let mut handshake_hash_arr = [0u8; 32];
        handshake_hash_arr.copy_from_slice(handshake_hash_before_finished.as_ref());

        // Step 13: Derive server handshake traffic keys for encryption
        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(&hs_keys.server_handshake_traffic_secret, CIPHER_SUITE)?;

        // Step 14: Build server Finished message first (before encryption)
        let server_verify_data = compute_finished_verify_data(
            &hs_keys.server_handshake_traffic_secret,
            &handshake_hash_arr,
        )?;
        let server_finished = construct_finished(&server_verify_data)?;

        // Step 15: Combine all 4 handshake messages into one plaintext buffer
        // This is required by REALITY protocol - all 4 messages in one encrypted record
        let mut combined_plaintext = Vec::new();
        combined_plaintext.extend_from_slice(&encrypted_extensions);
        combined_plaintext.extend_from_slice(&certificate);
        combined_plaintext.extend_from_slice(&certificate_verify);
        combined_plaintext.extend_from_slice(&server_finished);

        log::debug!("REALITY SERVER: Combining 4 handshake messages: EE={}, Cert={}, CV={}, Fin={}, Total={}",
                   encrypted_extensions.len(), certificate.len(), certificate_verify.len(),
                   server_finished.len(), combined_plaintext.len());

        // Step 16: Encrypt the combined handshake messages, fragmenting into multiple records if needed
        // TLS 1.3 limits records to 16,640 bytes ciphertext (16,623 bytes plaintext).
        // Large certificates can exceed this, so we fragment like uTLS does.
        let mut handshake_ciphertext = Vec::new();
        let mut handshake_seq = 0u64;
        encrypt_handshake_to_records(
            &combined_plaintext,
            &server_hs_key,
            &server_hs_iv,
            &mut handshake_seq,
            &mut handshake_ciphertext,
        )?;

        // Update transcript with server Finished (needed for client Finished verification)
        handshake_transcript.update(&server_finished);
        let handshake_hash_with_server_finished = handshake_transcript.finish();
        let mut handshake_hash_with_finished_arr = [0u8; 32];
        handshake_hash_with_finished_arr
            .copy_from_slice(handshake_hash_with_server_finished.as_ref());

        // Step 16: Buffer all handshake messages to write buffer
        // ServerHello (plaintext)
        self.ciphertext_write_buf
            .extend_from_slice(&write_record_header(
                CONTENT_TYPE_HANDSHAKE,
                server_hello.len() as u16,
            ));
        self.ciphertext_write_buf.extend_from_slice(&server_hello);

        // ChangeCipherSpec (for compatibility)
        self.ciphertext_write_buf
            .extend_from_slice(&write_record_header(CONTENT_TYPE_CHANGE_CIPHER_SPEC, 1));
        self.ciphertext_write_buf.push(0x01);

        // Encrypted handshake record(s) - may be fragmented into multiple records
        self.ciphertext_write_buf
            .extend_from_slice(&handshake_ciphertext);

        log::info!(
            "REALITY: ServerHello and encrypted handshake messages buffered ({} bytes)",
            self.ciphertext_write_buf.len()
        );

        // Step 17: Update handshake state
        self.handshake_state = HandshakeState::ServerHelloSent {
            handshake_hash: handshake_hash_arr,
            handshake_hash_with_server_finished: handshake_hash_with_finished_arr,
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret.clone(),
            master_secret: hs_keys.master_secret,
            cipher_suite: CIPHER_SUITE,
        };

        Ok(())
    }

    /// Process client's Finished message and complete handshake
    fn process_client_finished(&mut self) -> io::Result<()> {
        // Check if we have enough data for a TLS record header BEFORE extracting state
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(()); // Need more data
        }

        // Check for ChangeCipherSpec (TLS 1.3 compatibility message)
        if self.ciphertext_read_buf[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            // ChangeCipherSpec record
            let ccs_len = self
                .ciphertext_read_buf
                .get_u16_be(3)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
                as usize;

            // Need complete ChangeCipherSpec record
            if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE + ccs_len {
                return Ok(()); // Need more data
            }

            // Skip ChangeCipherSpec (compatibility message)
            log::debug!("REALITY: Skipping ChangeCipherSpec (compatibility message)");
            self.ciphertext_read_buf
                .consume(TLS_RECORD_HEADER_SIZE + ccs_len);

            // Check if we have the next record header
            if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
                return Ok(()); // Need more data
            }
        }

        // Parse TLS record length
        let record_len = self
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;

        // Check if we have the complete record
        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(()); // Need more data
        }

        // Verify it's ApplicationData (encrypted Finished)
        if self.ciphertext_read_buf[0] != CONTENT_TYPE_APPLICATION_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected ApplicationData (0x17), got 0x{:02x}",
                    self.ciphertext_read_buf[0]
                ),
            ));
        }

        // NOW we're committed to processing - take ownership of handshake state
        // This avoids cloning Vec<u8> fields
        let old_state = std::mem::replace(&mut self.handshake_state, HandshakeState::Complete);
        let (
            client_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            _handshake_hash,
            handshake_hash_with_server_finished,
        ) = match old_state {
            HandshakeState::ServerHelloSent {
                client_handshake_traffic_secret,
                master_secret,
                cipher_suite,
                handshake_hash,
                handshake_hash_with_server_finished,
            } => (
                client_handshake_traffic_secret, // moved, not cloned
                master_secret,                   // moved, not cloned
                cipher_suite,
                handshake_hash,
                handshake_hash_with_server_finished,
            ),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid state for process_client_finished",
                ))
            }
        };

        // Extract the encrypted Finished record (copy to Vec for decryption)
        let record: Vec<u8> = self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);
        let ciphertext = &record[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header

        // Derive client handshake traffic keys for decryption
        let (client_hs_key, client_hs_iv) =
            derive_traffic_keys(&client_handshake_traffic_secret, cipher_suite)?;

        // Decrypt the Finished message (sequence number = 0 for client's first encrypted record)
        let plaintext = decrypt_handshake_message(
            &client_hs_key,
            &client_hs_iv,
            0, // Client's first encrypted record
            ciphertext,
            record_len as u16,
        )?;

        // Verify it's a Finished message (type 0x14)
        if plaintext.is_empty() || plaintext[0] != HANDSHAKE_TYPE_FINISHED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected Finished message",
            ));
        }

        // Extract verify_data (skip type(1) + length(3) = 4 bytes)
        if plaintext.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Finished message too short",
            ));
        }
        let client_verify_data = &plaintext[4..];

        // Compute expected client Finished verify_data
        // IMPORTANT: Use hash that includes server Finished (per TLS 1.3 RFC 8446)
        let expected_verify_data = compute_finished_verify_data(
            &client_handshake_traffic_secret,
            &handshake_hash_with_server_finished,
        )?;

        // Verify it matches using constant-time comparison to prevent timing attacks
        if client_verify_data
            .ct_eq(expected_verify_data.as_slice())
            .unwrap_u8()
            == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Client Finished verify_data mismatch",
            ));
        }

        log::debug!("REALITY: Client Finished verified successfully");

        // Derive application secrets
        // IMPORTANT: Use hash that includes server Finished (per TLS 1.3 RFC 8446)
        let (client_app_secret, server_app_secret) =
            derive_application_secrets(&master_secret, &handshake_hash_with_server_finished)?;

        // Derive application traffic keys
        let (client_app_key, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        // Store application traffic keys
        self.app_read_key = Some(client_app_key);
        self.app_read_iv = Some(client_app_iv);
        self.app_write_key = Some(server_app_key);
        self.app_write_iv = Some(server_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = cipher_suite;

        // Handshake state already set to Complete above

        log::debug!("REALITY: Handshake complete, application keys derived");

        Ok(())
    }

    /// Decrypt application data using TLS 1.3 keys
    fn process_application_data(&mut self) -> io::Result<()> {
        // Check if we have application keys
        let (app_read_key, app_read_iv) = match (&self.app_read_key, &self.app_read_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => return Ok(()), // Keys not ready yet
        };

        // Process all complete TLS records in the buffer
        while self.ciphertext_read_buf.len() >= 5 {
            // Parse TLS record header
            let record_len = self
                .ciphertext_read_buf
                .get_u16_be(3)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
                as usize;

            // Check if we have the complete record
            let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
            if self.ciphertext_read_buf.len() < total_record_len {
                break; // Need more data
            }

            // Copy record header for decryption AAD
            let tls_header: [u8; TLS_RECORD_HEADER_SIZE] = [
                self.ciphertext_read_buf[0],
                self.ciphertext_read_buf[1],
                self.ciphertext_read_buf[2],
                self.ciphertext_read_buf[3],
                self.ciphertext_read_buf[4],
            ];
            let ciphertext: Vec<u8> =
                self.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
            self.ciphertext_read_buf.consume(total_record_len);

            // Decrypt the application data
            let mut plaintext = decrypt_tls13_record(
                app_read_key,
                app_read_iv,
                self.read_seq,
                &ciphertext,
                &tls_header,
            )?;

            self.read_seq += 1;

            // TLS 1.3: Remove ContentType trailer byte
            // The last byte of the plaintext is the actual ContentType
            if !plaintext.is_empty() {
                let content_type = plaintext.pop().unwrap();

                // For now, we only handle ApplicationData (0x17) and Alert (0x15)
                // Alerts should be handled separately, but for now just pass through
                if content_type != CONTENT_TYPE_APPLICATION_DATA
                    && content_type != CONTENT_TYPE_ALERT
                {
                    log::warn!("REALITY: Unexpected ContentType: 0x{:02x}", content_type);
                }
            }

            // Compact plaintext buffer if needed before extending
            self.plaintext_read_buf.maybe_compact(4096);

            // Append to plaintext buffer (without ContentType)
            self.plaintext_read_buf.extend_from_slice(&plaintext);
        }

        Ok(())
    }

    /// Get a reader for accessing decrypted plaintext
    pub fn reader(&mut self) -> RealityReader<'_> {
        // SlideBuffer handles compaction internally via maybe_compact()
        // Compact before returning reader if we've consumed significant data
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf)
    }

    /// Get a writer for buffering plaintext to be encrypted
    pub fn writer(&mut self) -> RealityWriter<'_> {
        RealityWriter::new(&mut self.plaintext_write_buf)
    }

    /// Write buffered TLS messages to the provided writer
    ///
    /// This encrypts any pending plaintext and writes ciphertext.
    /// Large plaintext is automatically fragmented into multiple TLS records
    /// to comply with the TLS 1.3 record size limit.
    pub fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        // If handshake not complete, just write buffered handshake data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            let n = wr.write(&self.ciphertext_write_buf)?;
            self.ciphertext_write_buf.drain(..n);
            return Ok(n);
        }

        // Encrypt any pending plaintext (with automatic fragmentation for large data)
        if !self.plaintext_write_buf.is_empty() {
            let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
                (Some(key), Some(iv)) => (key, iv),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Application keys not available",
                    ))
                }
            };

            encrypt_plaintext_to_records(
                &mut self.plaintext_write_buf,
                app_write_key,
                app_write_iv,
                &mut self.write_seq,
                &mut self.ciphertext_write_buf,
            )?;
        }

        // Write buffered ciphertext
        let n = wr.write(&self.ciphertext_write_buf)?;
        self.ciphertext_write_buf.drain(..n);
        Ok(n)
    }

    /// Check if the connection wants to write data
    pub fn wants_write(&self) -> bool {
        !self.ciphertext_write_buf.is_empty() || !self.plaintext_write_buf.is_empty()
    }

    /// Check if handshake is still in progress
    pub fn is_handshaking(&self) -> bool {
        !matches!(self.handshake_state, HandshakeState::Complete)
    }

    /// Queue a close notification alert
    pub fn send_close_notify(&mut self) {
        // In TLS 1.3, alerts must be encrypted like application data
        if !matches!(self.handshake_state, HandshakeState::Complete) {
            log::debug!("REALITY: Cannot send close_notify - handshake not complete");
            return;
        }

        // Get application keys
        let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => {
                log::debug!("REALITY: Cannot send close_notify - application keys not available");
                return;
            }
        };

        // Use common helper to build encrypted close_notify alert
        match common::build_close_notify_alert(app_write_key, app_write_iv, self.write_seq) {
            Ok(record) => {
                self.write_seq += 1;
                self.ciphertext_write_buf.extend_from_slice(&record);
                log::debug!("REALITY: Encrypted close_notify alert queued");
            }
            Err(e) => {
                log::error!("REALITY: Failed to encrypt close_notify: {}", e);
            }
        }
    }
}

#[inline(always)]
pub fn feed_reality_server_connection(
    server_connection: &mut RealityServerConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = server_connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed TLS connection: {e}"),
            )
        })?;
        i += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_server_connection_creation() {
        let config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            max_time_diff: Some(60000),
            min_client_version: None,
            max_client_version: None,
        };

        let conn = RealityServerConnection::new(config).unwrap();
        assert!(conn.is_handshaking());
        assert!(!conn.wants_write());
    }

    #[test]
    fn test_io_state() {
        let config = RealityServerConfig {
            private_key: [0u8; 32],
            short_ids: vec![[0u8; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
        };

        let mut conn = RealityServerConnection::new(config).unwrap();
        let state = conn.process_new_packets().unwrap();

        assert_eq!(state.plaintext_bytes_to_read(), 0);
        assert!(!conn.wants_write());
    }
}
