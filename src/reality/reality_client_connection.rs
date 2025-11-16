// REALITY client-side connection
//
// This implements a rustls-compatible API for REALITY protocol client connections,
// allowing REALITY to be used as a drop-in replacement for rustls.

use std::io::{self, Read, Write};

use crate::slide_buffer::SlideBuffer;

use aws_lc_rs::{
    agreement, digest,
    rand::{SecureRandom, SystemRandom},
};

use super::common::{
    self, CIPHERTEXT_READ_BUF_CAPACITY, CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CERTIFICATE,
    HANDSHAKE_TYPE_CERTIFICATE_VERIFY, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_TYPE_FINISHED, PLAINTEXT_READ_BUF_CAPACITY, TLS_MAX_RECORD_SIZE,
    TLS_RECORD_HEADER_SIZE,
};
use super::reality_aead::{decrypt_handshake_message, decrypt_tls13_record};
use super::reality_auth::{derive_auth_key, encrypt_session_id, perform_ecdh};
use super::reality_client_verify::{extract_certificate_der, verify_certificate_hmac};
use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::{encrypt_handshake_to_records, encrypt_plaintext_to_records};
use super::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use super::reality_tls13_messages::*;
use super::reality_util::extract_server_public_key;

/// Configuration for REALITY client connections
#[derive(Clone)]
pub struct RealityClientConfig {
    /// Server's X25519 public key (32 bytes)
    pub public_key: [u8; 32],
    /// Short ID for authentication (8 bytes)
    pub short_id: [u8; 8],
    /// Server name for SNI
    pub server_name: String,
}

/// Handshake state machine for REALITY client
enum HandshakeState {
    /// ClientHello sent, waiting for ServerHello
    AwaitingServerHello {
        client_hello_hash: [u8; 32],
        client_hello_bytes: Vec<u8>, // Full ClientHello handshake message
        client_private_key: [u8; 32],
        auth_key: [u8; 32], // REALITY authentication key for HMAC verification
    },
    /// ServerHello received, processing encrypted handshake messages
    ProcessingHandshake {
        client_handshake_traffic_secret: Vec<u8>,
        server_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: u16,
        handshake_transcript_bytes: Vec<u8>, // Accumulated transcript for hash computation
        auth_key: [u8; 32],                  // REALITY authentication key for HMAC verification
    },
    /// Handshake complete, ready for application data
    Complete,
}

/// REALITY client-side connection implementing rustls-compatible API
pub struct RealityClientConnection {
    // Configuration
    config: RealityClientConfig,

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

impl RealityClientConnection {
    /// Create a new REALITY client connection and generate ClientHello
    pub fn new(config: RealityClientConfig) -> io::Result<Self> {
        let mut conn = RealityClientConnection {
            config,
            handshake_state: HandshakeState::AwaitingServerHello {
                client_hello_hash: [0u8; 32],
                client_hello_bytes: Vec::new(),
                client_private_key: [0u8; 32],
                auth_key: [0u8; 32],
            },
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
        };

        // Generate ClientHello immediately
        conn.generate_client_hello()?;

        Ok(conn)
    }

    /// Generate and buffer ClientHello
    fn generate_client_hello(&mut self) -> io::Result<()> {
        let rng = SystemRandom::new();

        // Generate our X25519 keypair
        let mut our_private_bytes = [0u8; 32];
        rng.fill(&mut our_private_bytes)
            .map_err(|_| io::Error::other("RNG failed"))?;

        let our_private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &our_private_bytes)
                .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
        let our_public_key_bytes = our_private_key
            .compute_public_key()
            .map_err(|_| io::Error::other("Failed to compute public key"))?;

        // Generate client random
        let mut client_random = [0u8; 32];
        rng.fill(&mut client_random)
            .map_err(|_| io::Error::other("RNG failed"))?;

        // Perform ECDH with server's public key to derive auth key
        let shared_secret = perform_ecdh(&our_private_bytes, &self.config.public_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Use slice directly from client_random to avoid copying
        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], b"REALITY")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Create session ID with REALITY metadata
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::other("System time error"))?
            .as_secs();

        let mut session_id_plaintext = [0u8; 16];
        session_id_plaintext[0] = 1; // Protocol version major
        session_id_plaintext[1] = 8; // Protocol version minor
        session_id_plaintext[2] = 0; // Protocol version patch
        session_id_plaintext[3] = 0; // Padding byte
                                     // Timestamp (4 bytes as uint32, in seconds)
        session_id_plaintext[4..8].copy_from_slice(&(timestamp as u32).to_be_bytes());
        // Short ID (8 bytes)
        session_id_plaintext[8..16].copy_from_slice(&self.config.short_id);

        // Create a 32-byte SessionId (16 bytes plaintext + 16 bytes zeros for padding)
        let mut session_id_for_hello = [0u8; 32];
        session_id_for_hello[0..16].copy_from_slice(&session_id_plaintext);

        // Build ClientHello with plaintext SessionId first
        let mut client_hello = construct_client_hello(
            &client_random,
            &session_id_for_hello,
            our_public_key_bytes.as_ref(),
            &self.config.server_name,
        )?;

        // Now encrypt the SessionId using the ClientHello with zeroed SessionId as AAD
        // Use slice directly from client_random to avoid copying
        let nonce = &client_random[20..32];

        // Zero out the SessionId in ClientHello to create AAD (matches what server will use)
        // SessionId is at offset 39 in ClientHello handshake
        client_hello[39..71].fill(0);

        log::debug!("REALITY CLIENT: Encrypting SessionId");
        log::debug!("  auth_key={:02x?}", &auth_key);
        log::debug!("  nonce={:02x?}", nonce);
        log::debug!("  plaintext={:02x?}", &session_id_plaintext);
        log::debug!(
            "  aad_len={} (ClientHello with zero SessionId)",
            client_hello.len()
        );
        log::debug!("  aad[0..4]={:02x?}", &client_hello[0..4]);

        let encrypted_session_id =
            encrypt_session_id(&session_id_plaintext, &auth_key, nonce, &client_hello)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        log::debug!(
            "REALITY CLIENT: Encrypted SessionId={:02x?}",
            &encrypted_session_id
        );

        // Replace the zeros with the encrypted SessionId
        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        // Compute ClientHello hash
        let mut ch_transcript = digest::Context::new(&digest::SHA256);
        ch_transcript.update(&client_hello);
        let client_hello_hash = ch_transcript.finish();
        let mut client_hello_hash_arr = [0u8; 32];
        client_hello_hash_arr.copy_from_slice(client_hello_hash.as_ref());

        // Wrap in TLS record
        let mut record = write_record_header(CONTENT_TYPE_HANDSHAKE, client_hello.len() as u16);
        record.extend_from_slice(&client_hello);

        // Buffer for sending
        self.ciphertext_write_buf.extend_from_slice(&record);

        // Update state
        self.handshake_state = HandshakeState::AwaitingServerHello {
            client_hello_hash: client_hello_hash_arr,
            client_hello_bytes: client_hello.clone(), // Save the actual ClientHello bytes
            client_private_key: our_private_bytes,
            auth_key, // Save auth_key for HMAC certificate verification
        };

        log::debug!(
            "REALITY: ClientHello generated and buffered ({} bytes)",
            record.len()
        );

        Ok(())
    }

    /// Read TLS messages from the provided reader into internal buffer
    ///
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

    /// Process buffered packets and advance state machine
    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        match &self.handshake_state {
            HandshakeState::AwaitingServerHello { .. } => {
                self.process_server_hello()?;
            }
            HandshakeState::ProcessingHandshake { .. } => {
                self.process_encrypted_handshake()?;
            }
            HandshakeState::Complete => {
                self.process_application_data()?;
            }
        }

        Ok(RealityIoState::new(self.plaintext_read_buf.len()))
    }

    /// Process ServerHello
    fn process_server_hello(&mut self) -> io::Result<()> {
        // Extract state
        let (client_hello_hash, client_private_key, auth_key) = match &self.handshake_state {
            HandshakeState::AwaitingServerHello {
                client_hello_hash,
                client_hello_bytes: _,
                client_private_key,
                auth_key,
            } => (*client_hello_hash, *client_private_key, *auth_key),
            _ => return Ok(()), // Wrong state
        };

        // Check if we have enough data for a TLS record header
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

        // Copy ServerHello record to Vec for processing
        let record: Vec<u8> = self.ciphertext_read_buf[..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);
        let server_hello = &record[TLS_RECORD_HEADER_SIZE..]; // Skip TLS record header (includes handshake header)

        log::debug!(
            "REALITY CLIENT: ServerHello for transcript: len={}, bytes={:02x?}",
            server_hello.len(),
            server_hello
        );

        // Extract server public key from ServerHello
        let server_public_key = extract_server_public_key(&record)?;

        // Compute transcript hash including ClientHello and ServerHello
        // NOTE: We need to update with the actual ClientHello bytes, not its hash!
        // We need to preserve the ClientHello bytes to include them in the transcript
        // For now, we'll need to get them from the state

        // Get the actual ClientHello bytes from our saved state
        let client_hello_bytes = match &self.handshake_state {
            HandshakeState::AwaitingServerHello {
                client_hello_bytes, ..
            } => client_hello_bytes.clone(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid handshake state",
                ))
            }
        };

        let mut full_transcript = digest::Context::new(&digest::SHA256);
        log::debug!(
            "REALITY CLIENT: Transcript includes ClientHello ({} bytes), first bytes: {:02x?}",
            client_hello_bytes.len(),
            &client_hello_bytes[..client_hello_bytes.len().min(20)]
        );
        log::debug!(
            "REALITY CLIENT: Transcript includes ServerHello ({} bytes), first bytes: {:02x?}",
            server_hello.len(),
            &server_hello[..server_hello.len().min(20)]
        );
        full_transcript.update(&client_hello_bytes); // Use actual ClientHello bytes, not hash!
        full_transcript.update(server_hello); // ServerHello already includes handshake header
        let server_hello_hash = full_transcript.finish();
        let mut server_hello_hash_arr = [0u8; 32];
        server_hello_hash_arr.copy_from_slice(server_hello_hash.as_ref());

        // Perform ECDH for TLS 1.3 key derivation
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, &server_public_key);
        let my_private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &client_private_key)
                .map_err(|_| io::Error::other("Failed to create private key"))?;

        let mut tls_shared_secret = [0u8; 32];
        agreement::agree(
            &my_private_key,
            peer_public_key,
            io::Error::other("ECDH failed"),
            |key_material| {
                tls_shared_secret.copy_from_slice(key_material);
                Ok(())
            },
        )?;

        // Derive handshake keys
        // Removed verbose secret logging for security
        let hs_keys = derive_handshake_keys(
            &tls_shared_secret,
            &client_hello_hash,
            &server_hello_hash_arr,
        )?;

        // Use standard cipher suite
        const CIPHER_SUITE: u16 = 0x1301; // TLS_AES_128_GCM_SHA256

        log::debug!("REALITY: ServerHello processed, handshake keys derived");

        // Initialize transcript with actual ClientHello and ServerHello bytes (not hashes!)
        let mut transcript_bytes = Vec::new();
        transcript_bytes.extend_from_slice(&client_hello_bytes); // Actual ClientHello bytes
        transcript_bytes.extend_from_slice(server_hello); // Actual ServerHello bytes

        // Update state
        self.handshake_state = HandshakeState::ProcessingHandshake {
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret.clone(),
            server_handshake_traffic_secret: hs_keys.server_handshake_traffic_secret.clone(),
            master_secret: hs_keys.master_secret.clone(),
            cipher_suite: CIPHER_SUITE,
            handshake_transcript_bytes: transcript_bytes,
            auth_key, // Pass auth_key for certificate HMAC verification
        };

        Ok(())
    }

    /// Process encrypted handshake messages (EncryptedExtensions, Certificate, CertificateVerify, Finished)
    fn process_encrypted_handshake(&mut self) -> io::Result<()> {
        // Extract state - we need to preserve it across multiple calls
        let (
            client_hs_secret,
            server_hs_secret,
            master_secret,
            cipher_suite,
            transcript_bytes,
            auth_key,
        ) = match &self.handshake_state {
            HandshakeState::ProcessingHandshake {
                client_handshake_traffic_secret,
                server_handshake_traffic_secret,
                master_secret,
                cipher_suite,
                handshake_transcript_bytes,
                auth_key,
            } => (
                client_handshake_traffic_secret.clone(),
                server_handshake_traffic_secret.clone(),
                master_secret.clone(),
                *cipher_suite,
                handshake_transcript_bytes.clone(),
                *auth_key,
            ),
            _ => return Ok(()),
        };

        // Derive server handshake traffic keys for decryption
        let (server_hs_key, server_hs_iv) = derive_traffic_keys(&server_hs_secret, cipher_suite)?;

        log::debug!(
            "REALITY CLIENT: Server HS key={:02x?}, iv={:02x?}",
            &server_hs_key[..16],
            &server_hs_iv
        );

        // Check if we have enough data for a TLS record header
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(()); // Need more data
        }

        // Check record type
        let record_type = self.ciphertext_read_buf[0];
        let tls_version = self
            .ciphertext_read_buf
            .get_u16_be(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?;
        let record_len = self
            .ciphertext_read_buf
            .get_u16_be(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
            as usize;

        log::debug!(
            "REALITY CLIENT: TLS record header: type=0x{:02x}, version=0x{:04x}, len={}",
            record_type,
            tls_version,
            record_len
        );

        // Check if we have the complete record
        let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
        if self.ciphertext_read_buf.len() < total_record_len {
            return Ok(()); // Need more data
        }

        // Skip ChangeCipherSpec records - these are dummy in TLS 1.3
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            log::debug!(
                "REALITY CLIENT: Skipping ChangeCipherSpec record ({} bytes)",
                record_len
            );
            self.ciphertext_read_buf.consume(total_record_len);
            // Process next record recursively
            return self.process_encrypted_handshake();
        }

        // If it's not Application Data, we have a problem
        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Expected Application Data record, got 0x{:02x}",
                    record_type
                ),
            ));
        }

        // Copy and extract the combined handshake record
        let ciphertext: Vec<u8> =
            self.ciphertext_read_buf[TLS_RECORD_HEADER_SIZE..total_record_len].to_vec();
        self.ciphertext_read_buf.consume(total_record_len);

        log::debug!("REALITY CLIENT: Decrypting combined handshake record - record_type=0x{:02x}, record_len={}, seq=0",
                  record_type, record_len);

        // Try different sequence numbers - sing-box might count differently
        let mut combined_plaintext = None;
        for seq in 0..3 {
            match decrypt_handshake_message(
                &server_hs_key,
                &server_hs_iv,
                seq,
                &ciphertext,
                record_len as u16,
            ) {
                Ok(plaintext) => {
                    combined_plaintext = Some(plaintext);
                    break;
                }
                Err(_) if seq < 2 => {
                    log::debug!(
                        "REALITY CLIENT: Decryption failed with seq={}, trying next",
                        seq
                    );
                    continue;
                }
                Err(e) => {
                    log::error!("REALITY CLIENT: Failed to decrypt combined handshake with all sequence numbers: {}", e);
                    return Err(e);
                }
            }
        }

        let combined_plaintext = combined_plaintext.unwrap();

        log::info!(
            "REALITY CLIENT: Successfully decrypted combined handshake record ({} bytes plaintext)",
            combined_plaintext.len()
        );

        // Now parse the individual handshake messages from the combined plaintext
        let mut offset = 0;
        let mut messages_found = 0;
        let mut certificate_verified = false;

        while offset < combined_plaintext.len() && messages_found < 4 {
            // Each handshake message has: type (1 byte) + length (3 bytes) + data
            if offset + 4 > combined_plaintext.len() {
                break;
            }

            let msg_type = combined_plaintext[offset];
            let msg_len = u32::from_be_bytes([
                0,
                combined_plaintext[offset + 1],
                combined_plaintext[offset + 2],
                combined_plaintext[offset + 3],
            ]) as usize;

            if offset + 4 + msg_len > combined_plaintext.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid handshake message length: {} at offset {}",
                        msg_len, offset
                    ),
                ));
            }

            let msg_name = match msg_type {
                HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
                HANDSHAKE_TYPE_CERTIFICATE => "Certificate",
                HANDSHAKE_TYPE_CERTIFICATE_VERIFY => "CertificateVerify",
                HANDSHAKE_TYPE_FINISHED => "Finished",
                _ => "Unknown",
            };

            log::info!(
                "REALITY CLIENT: Found {} message (type={}, len={})",
                msg_name,
                msg_type,
                msg_len
            );

            // Verify HMAC signature when we encounter the Certificate message
            if msg_type == HANDSHAKE_TYPE_CERTIFICATE {
                let cert_der =
                    extract_certificate_der(&combined_plaintext[offset..offset + 4 + msg_len])?;
                verify_certificate_hmac(cert_der, &auth_key)?;
                certificate_verified = true;
            }

            messages_found += 1;
            offset += 4 + msg_len;
        }

        // Check if we got all 4 messages AND the certificate was verified
        if messages_found != 4 {
            // Not all messages received yet - this shouldn't happen with combined record
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected 4 handshake messages, found {}", messages_found),
            ));
        }

        // Ensure the Certificate message was present and HMAC verified
        if !certificate_verified {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY handshake failed: Certificate message not received or not verified",
            ));
        }

        // Build handshake transcript
        // We need the actual handshake message bytes, not their hashes!
        // The transcript_bytes already contains the actual ClientHello and ServerHello bytes
        let mut handshake_transcript = digest::Context::new(&digest::SHA256);
        handshake_transcript.update(&transcript_bytes); // Contains actual ClientHello + ServerHello bytes
        handshake_transcript.update(&combined_plaintext); // EncryptedExtensions + Certificate + CertificateVerify + Finished

        let handshake_hash = handshake_transcript.finish();
        let mut handshake_hash_arr = [0u8; 32];
        handshake_hash_arr.copy_from_slice(handshake_hash.as_ref());

        log::info!(
            "REALITY CLIENT: Handshake hash for client Finished: {:02x?}",
            handshake_hash_arr
        );
        log::info!(
            "REALITY CLIENT: Transcript bytes len={}, combined_plaintext len={}",
            transcript_bytes.len(),
            combined_plaintext.len()
        );

        // Generate client Finished message
        let client_verify_data =
            compute_finished_verify_data(&client_hs_secret, &handshake_hash_arr)?;
        log::info!(
            "REALITY CLIENT: Client verify data: {:02x?}",
            client_verify_data
        );
        let client_finished = construct_finished(&client_verify_data)?;

        // Derive client handshake traffic keys for encryption
        let (client_hs_key, client_hs_iv) = derive_traffic_keys(&client_hs_secret, cipher_suite)?;

        // Encrypt Finished message
        let mut client_hs_seq = 0u64;
        let buf_len_before = self.ciphertext_write_buf.len();
        encrypt_handshake_to_records(
            &client_finished,
            &client_hs_key,
            &client_hs_iv,
            &mut client_hs_seq,
            &mut self.ciphertext_write_buf,
        )?;

        log::info!(
            "REALITY CLIENT: Client Finished message generated and buffered ({} bytes)",
            self.ciphertext_write_buf.len() - buf_len_before
        );

        // Derive application secrets
        let (client_app_secret, server_app_secret) =
            derive_application_secrets(&master_secret, &handshake_hash_arr)?;

        // Derive application traffic keys
        let (client_app_key, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        // Store application keys
        self.app_read_key = Some(server_app_key);
        self.app_read_iv = Some(server_app_iv);
        self.app_write_key = Some(client_app_key);
        self.app_write_iv = Some(client_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = cipher_suite;

        // Mark handshake complete
        self.handshake_state = HandshakeState::Complete;
        log::info!("REALITY CLIENT: Handshake complete, application keys derived");

        Ok(())
    }

    /// Decrypt application data using TLS 1.3 keys
    fn process_application_data(&mut self) -> io::Result<()> {
        let (app_read_key, app_read_iv) = match (&self.app_read_key, &self.app_read_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => return Ok(()),
        };

        while self.ciphertext_read_buf.len() >= TLS_RECORD_HEADER_SIZE {
            let record_len = self
                .ciphertext_read_buf
                .get_u16_be(3)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too short"))?
                as usize;

            let total_record_len = TLS_RECORD_HEADER_SIZE + record_len;
            if self.ciphertext_read_buf.len() < total_record_len {
                break;
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

                // For now, we only handle ApplicationData and Alert
                // Alerts should be handled separately, but for now just pass through
                if content_type != CONTENT_TYPE_APPLICATION_DATA
                    && content_type != CONTENT_TYPE_ALERT
                {
                    log::warn!(
                        "REALITY CLIENT: Unexpected ContentType: 0x{:02x}",
                        content_type
                    );
                }
            }

            // Compact plaintext buffer if needed before extending
            self.plaintext_read_buf.maybe_compact(4096);
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
            log::debug!("REALITY CLIENT: Cannot send close_notify - handshake not complete");
            return;
        }

        // Get application keys
        let (app_write_key, app_write_iv) = match (&self.app_write_key, &self.app_write_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => {
                log::debug!(
                    "REALITY CLIENT: Cannot send close_notify - application keys not available"
                );
                return;
            }
        };

        // Use common helper to build encrypted close_notify alert
        match common::build_close_notify_alert(app_write_key, app_write_iv, self.write_seq) {
            Ok(record) => {
                self.write_seq += 1;
                self.ciphertext_write_buf.extend_from_slice(&record);
                log::debug!("REALITY CLIENT: Encrypted close_notify alert queued");
            }
            Err(e) => {
                log::error!("REALITY CLIENT: Failed to encrypt close_notify: {}", e);
            }
        }
    }
}

#[inline(always)]
pub fn feed_reality_client_connection(
    client_connection: &mut RealityClientConnection,
    data: &[u8],
) -> std::io::Result<()> {
    let mut cursor = std::io::Cursor::new(data);
    let mut i = 0;
    while i < data.len() {
        let n = client_connection.read_tls(&mut cursor).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to feed TLS connection: {e}"),
            )
        })?;
        i += n;
    }
    Ok(())
}
