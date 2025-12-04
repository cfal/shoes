// REALITY server-side connection
//
// This implements a rustls-compatible API for REALITY protocol server connections,
// allowing REALITY to be used as a drop-in replacement for rustls.

use aws_lc_rs::{agreement, digest};
use rand::RngCore;
use std::io::{self, Read, Write};
use subtle::ConstantTimeEq;

use super::common::{
    ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, CIPHERTEXT_READ_BUF_CAPACITY, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_FINISHED, OUTGOING_BUFFER_LIMIT, PLAINTEXT_READ_BUF_CAPACITY,
    TLS_MAX_RECORD_SIZE, TLS_RECORD_HEADER_SIZE,
};
use super::reality_aead::{AeadKey, decrypt_handshake_message};
use super::reality_auth::{decrypt_session_id, derive_auth_key, perform_ecdh};
use super::reality_certificate::generate_hmac_certificate;
use super::reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
use super::reality_io_state::RealityIoState;
use super::reality_reader_writer::{RealityReader, RealityWriter};
use super::reality_records::{RecordDecryptor, RecordEncryptor};
use super::reality_tls13_keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys,
};
use super::reality_tls13_messages::{
    construct_certificate, construct_certificate_verify, construct_encrypted_extensions,
    construct_finished, construct_server_hello, write_record_header,
};
use super::reality_util::{
    extract_client_cipher_suites, extract_client_public_key, extract_client_random,
    extract_session_id_slice, negotiate_cipher_suite,
};
use crate::address::{Address, NetLocation};
use crate::slide_buffer::SlideBuffer;
use crate::util::allocate_vec;

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
    /// Supported TLS 1.3 cipher suites (empty = use defaults)
    pub cipher_suites: Vec<CipherSuite>,
}

/// Handshake state machine for REALITY server
enum HandshakeState {
    /// Initial state, waiting for ClientHello
    Initial,
    /// ClientHello validated, waiting to build response with dest structure
    ClientHelloValidated { info: ClientHelloInfo },
    /// ServerHello and encrypted handshake messages sent, waiting for client Finished
    ServerHelloSent {
        handshake_hash_with_server_finished: Vec<u8>, // Hash including server Finished (for verifying client Finished)
        client_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        cipher_suite: CipherSuite,
    },
    /// Handshake complete, ready for application data
    Complete,
}

/// Information extracted from ClientHello during validation phase
/// This is passed to build_server_response() to construct the reply
#[derive(Clone)]
pub struct ClientHelloInfo {
    /// Session ID from ClientHello (echoed back in ServerHello)
    pub session_id: Vec<u8>,
    /// Client's X25519 public key from key_share extension
    pub client_public_key: [u8; 32],
    /// Derived auth key for HMAC certificate
    pub auth_key: [u8; 32],
    /// Negotiated cipher suite
    pub cipher_suite: CipherSuite,
    /// Raw ClientHello handshake bytes (for transcript hash)
    pub client_hello_handshake: Vec<u8>,
}

/// REALITY server-side connection implementing rustls-compatible API
pub struct RealityServerConnection {
    // Configuration
    config: RealityServerConfig,

    // Handshake state
    handshake_state: HandshakeState,

    // TLS 1.3 application traffic encryption (post-handshake)
    // Keys are cached as AeadKey to avoid per-record key setup overhead
    app_read_key: Option<AeadKey>,
    app_read_iv: Option<Vec<u8>>,
    app_write_key: Option<AeadKey>,
    app_write_iv: Option<Vec<u8>>,
    read_seq: u64,
    write_seq: u64,
    cipher_suite: Option<CipherSuite>,

    // Pre-allocated buffer for TLS read operations (reused across calls)
    tls_read_buffer: Box<[u8]>,

    // Buffers for I/O - using SlideBuffer for efficient zero-alloc operations
    ciphertext_read_buf: SlideBuffer, // Incoming encrypted TLS records
    ciphertext_write_buf: Vec<u8>,    // Outgoing encrypted TLS records
    plaintext_read_buf: SlideBuffer,  // Decrypted application data
    plaintext_write_buf: Vec<u8>,     // Application data to encrypt

    // Connection state flags (mirrors rustls patterns)
    received_close_notify: bool,        // Peer sent close_notify alert
    fatal_error: Option<io::ErrorKind>, // Fatal error occurred, connection unusable
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
            cipher_suite: None,
            tls_read_buffer: allocate_vec(TLS_MAX_RECORD_SIZE).into_boxed_slice(),
            ciphertext_read_buf: SlideBuffer::new(CIPHERTEXT_READ_BUF_CAPACITY),
            ciphertext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            plaintext_read_buf: SlideBuffer::new(PLAINTEXT_READ_BUF_CAPACITY),
            plaintext_write_buf: Vec::with_capacity(OUTGOING_BUFFER_LIMIT),
            received_close_notify: false,
            fatal_error: None,
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
    /// Like rustls, this loops until no more progress can be made, ensuring
    /// that piggybacked application data (e.g., VLESS request sent with TLS Finished)
    /// is processed in the same call.
    pub fn process_new_packets(&mut self) -> io::Result<RealityIoState> {
        // Return persisted error if connection is in fatal error state (rustls pattern)
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        // Don't process more data after receiving close_notify (RFC 8446)
        if self.received_close_notify {
            return Ok(RealityIoState::new(self.plaintext_read_buf.len()));
        }

        let result = self.process_new_packets_inner();

        // Persist fatal errors
        if let Err(ref e) = result {
            // Persist error for certain error kinds that indicate fatal connection failure
            match e.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(e.kind());
                }
                _ => {}
            }
        }

        result
    }

    /// Inner implementation of process_new_packets
    fn process_new_packets_inner(&mut self) -> io::Result<RealityIoState> {
        loop {
            match &self.handshake_state {
                HandshakeState::Initial | HandshakeState::ClientHelloValidated { .. } => {
                    // Initial: ClientHello must be passed via validate_client_hello()
                    // ClientHelloValidated: Response must be built via build_server_response()
                    // Neither should be reached during process_new_packets
                    break;
                }
                HandshakeState::ServerHelloSent { .. } => {
                    if !self.process_client_finished()? {
                        break;
                    }
                }
                HandshakeState::Complete => {
                    self.process_application_data()?;
                    break;
                }
            }
        }

        Ok(RealityIoState::new(self.plaintext_read_buf.len()))
    }

    /// Public API: Validate ClientHello
    ///
    /// This performs authentication (ECDH, decrypt session_id, validate short_id/timestamp/version)
    /// but does NOT build the server response. Call build_server_response() after to complete.
    ///
    /// Returns Ok(()) on success, Err(PermissionDenied) on auth failure.
    pub fn validate_client_hello(&mut self, client_hello: &[u8]) -> io::Result<()> {
        // Return persisted error if connection is in fatal error state
        if let Some(error_kind) = self.fatal_error {
            return Err(io::Error::new(error_kind, "connection previously failed"));
        }

        // Must be in Initial state
        if !matches!(self.handshake_state, HandshakeState::Initial) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "validate_client_hello called in wrong state",
            ));
        }

        // Process ClientHello validation
        let result = self.process_client_hello_validation(client_hello);

        // Persist fatal errors
        if let Err(ref e) = result {
            match e.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::ConnectionAborted => {
                    self.fatal_error = Some(e.kind());
                }
                _ => {}
            }
        }

        result
    }

    /// Public API: Build server response using dest's record structure as template
    ///
    /// Call this after validate_client_hello() succeeds. Pass the TLS records
    /// received from the destination server to match their structure.
    ///
    /// dest_records should contain: [ServerHello, CCS, encrypted_handshake..., NewSessionTicket...]
    pub fn build_server_response(&mut self, dest_records: Vec<bytes::Bytes>) -> io::Result<()> {
        // Must be in ClientHelloValidated state
        if !matches!(
            self.handshake_state,
            HandshakeState::ClientHelloValidated { .. }
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "build_server_response called in wrong state",
            ));
        }

        self.build_server_response_internal(&dest_records)
    }

    /// Phase 1: Validate ClientHello and extract info for later response building
    #[inline]
    fn process_client_hello_validation(&mut self, client_hello: &[u8]) -> io::Result<()> {
        // Validate minimum length (TLS record header + some content)
        if client_hello.len() < TLS_RECORD_HEADER_SIZE + 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too short",
            ));
        }

        // Extract fields from ClientHello
        let client_random = extract_client_random(client_hello)?;
        let session_id = extract_session_id_slice(client_hello)?;
        let client_public_key = extract_client_public_key(client_hello)?;

        log::debug!(
            "REALITY: ClientHello received, client_random: {:?}",
            &client_random[..8]
        );

        // Perform ECDH to derive auth key
        let shared_secret = perform_ecdh(&self.config.private_key, &client_public_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let salt = &client_random[0..20];
        let auth_key = derive_auth_key(&shared_secret, salt, b"REALITY")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Validate session ID (contains encrypted metadata)
        if session_id.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid session ID length",
            ));
        }

        let nonce = &client_random[20..32];
        let mut encrypted_session_id_arr = [0u8; 32];
        encrypted_session_id_arr.copy_from_slice(session_id);

        // Reconstruct AAD with zeros at SessionId location
        let client_hello_handshake = &client_hello[TLS_RECORD_HEADER_SIZE..];
        let mut aad_for_decryption = client_hello_handshake.to_vec();
        if aad_for_decryption.len() >= 39 + 32 {
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

        // Validate short ID using constant-time comparison
        let mut client_short_id_arr = [0u8; 8];
        client_short_id_arr.copy_from_slice(client_short_id);
        let short_id_ok = self.config.short_ids.iter().fold(false, |acc, valid_id| {
            acc | (client_short_id_arr.ct_eq(valid_id).unwrap_u8() == 1)
        });

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
                    client_timestamp,
                    now,
                    time_diff_secs,
                    max_diff_secs
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
        if let Some(min_ver) = &self.config.min_client_version
            && client_version < &min_ver[..]
        {
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

        // Validate client version (max)
        if let Some(max_ver) = &self.config.max_client_version
            && client_version > &max_ver[..]
        {
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

        log::debug!(
            "REALITY: Client authentication successful - short_id: {:02x?}, version: {:?}, timestamp: {}",
            client_short_id,
            client_version,
            client_timestamp
        );

        // Negotiate cipher suite with client
        let client_cipher_suites = extract_client_cipher_suites(client_hello)?;
        let server_cipher_suites = if self.config.cipher_suites.is_empty() {
            DEFAULT_CIPHER_SUITES.to_vec()
        } else {
            self.config.cipher_suites.clone()
        };
        let cipher_suite = negotiate_cipher_suite(&server_cipher_suites, &client_cipher_suites)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No common TLS 1.3 cipher suite found",
                )
            })?;
        log::debug!(
            "REALITY: Negotiated cipher suite {:?} (client offered: {:04x?})",
            cipher_suite,
            client_cipher_suites
        );

        // Store validated info for response building
        self.handshake_state = HandshakeState::ClientHelloValidated {
            info: ClientHelloInfo {
                session_id: session_id.to_vec(),
                client_public_key,
                auth_key,
                cipher_suite,
                client_hello_handshake: client_hello_handshake.to_vec(),
            },
        };

        Ok(())
    }

    /// Phase 2: Build server response using dest's record structure as template
    fn build_server_response_internal(&mut self, dest_records: &[bytes::Bytes]) -> io::Result<()> {
        // Take ownership of info from state (state already validated by caller)
        let HandshakeState::ClientHelloValidated { info } =
            std::mem::replace(&mut self.handshake_state, HandshakeState::Initial)
        else {
            unreachable!()
        };

        let cipher_suite = info.cipher_suite;

        // Generate our server X25519 keypair
        let mut rng = rand::rng();
        let mut our_private_bytes = [0u8; 32];
        rng.fill_bytes(&mut our_private_bytes);

        let our_private_key =
            agreement::PrivateKey::from_private_key(&agreement::X25519, &our_private_bytes)
                .map_err(|_| io::Error::other("Failed to create X25519 key"))?;
        let our_public_key_bytes = our_private_key
            .compute_public_key()
            .map_err(|_| io::Error::other("Failed to compute public key"))?;

        // Generate server random
        let mut server_random = [0u8; 32];
        rng.fill_bytes(&mut server_random);

        // Build ServerHello
        let server_hello = construct_server_hello(
            &server_random,
            &info.session_id,
            cipher_suite.id(),
            our_public_key_bytes.as_ref(),
        )?;

        // Compute transcript hashes using cipher suite's digest algorithm
        let digest_alg = cipher_suite.digest_algorithm();

        let mut ch_transcript = digest::Context::new(digest_alg);
        ch_transcript.update(&info.client_hello_handshake);
        let client_hello_hash = ch_transcript.finish();

        let mut ch_sh_transcript = digest::Context::new(digest_alg);
        ch_sh_transcript.update(&info.client_hello_handshake);
        ch_sh_transcript.update(&server_hello);

        let mut handshake_transcript = ch_sh_transcript.clone();
        let server_hello_hash = ch_sh_transcript.finish();

        // Perform ECDH for TLS 1.3 key derivation
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::X25519, &info.client_public_key);
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

        // Derive TLS 1.3 keys
        let hs_keys = derive_handshake_keys(
            cipher_suite,
            &tls_shared_secret,
            client_hello_hash.as_ref(),
            server_hello_hash.as_ref(),
        )?;

        // Get destination hostname for certificate
        let dest_hostname = match self.config.dest.address() {
            Address::Hostname(h) => h.as_str(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "REALITY requires a hostname destination",
                ));
            }
        };

        // Generate HMAC-signed certificate
        let (cert, signing_key) = generate_hmac_certificate(&info.auth_key, dest_hostname)?;

        // Build encrypted handshake messages
        let encrypted_extensions = construct_encrypted_extensions()?;
        handshake_transcript.update(&encrypted_extensions);

        let certificate = construct_certificate(cert)?;
        handshake_transcript.update(&certificate);

        let cert_verify_hash = handshake_transcript.clone().finish();
        let certificate_verify =
            construct_certificate_verify(&signing_key, cert_verify_hash.as_ref())?;
        handshake_transcript.update(&certificate_verify);

        let handshake_hash_before_finished = handshake_transcript.clone().finish();

        // Derive server handshake traffic keys for encryption
        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(&hs_keys.server_handshake_traffic_secret, cipher_suite)?;

        // Build server Finished message
        let server_verify_data = compute_finished_verify_data(
            cipher_suite,
            &hs_keys.server_handshake_traffic_secret,
            handshake_hash_before_finished.as_ref(),
        )?;
        let server_finished = construct_finished(&server_verify_data)?;

        // Analyze dest's record structure to determine how to encrypt
        // dest_records: [0]=ServerHello, [1]=CCS, [2..]=encrypted handshake, possibly NewSessionTicket
        let dest_encrypted_records: Vec<&bytes::Bytes> = if dest_records.len() > 2 {
            dest_records[2..].iter().collect()
        } else {
            vec![]
        };

        // Build handshake messages array
        let messages: [&[u8]; 4] = [
            &encrypted_extensions,
            &certificate,
            &certificate_verify,
            &server_finished,
        ];

        // Encrypt handshake messages, matching dest's structure exactly
        let mut handshake_ciphertext = Vec::new();
        let mut handshake_seq = 0u64;
        let hs_aead_key = AeadKey::new(cipher_suite, &server_hs_key)?;

        // Determine if dest uses combined mode or separate mode using 512-byte heuristic
        // Like XTLS/REALITY: if first encrypted record > 512 bytes, it's combined mode
        let is_combined_mode = match dest_encrypted_records.first() {
            Some(first_record) => first_record.len() > 512,
            None => true, // No encrypted records = default to combined mode
        };

        if is_combined_mode {
            // Combined mode: all messages in one record (with optional padding)
            let mut combined_plaintext = Vec::new();
            for msg in &messages {
                combined_plaintext.extend_from_slice(msg);
            }

            let target_size = dest_encrypted_records.first().map(|r| r.len()).unwrap_or(0);

            log::debug!(
                "REALITY SERVER: Combined mode - EE={}, Cert={}, CV={}, Fin={}, Total={}, target={}",
                encrypted_extensions.len(),
                certificate.len(),
                certificate_verify.len(),
                server_finished.len(),
                combined_plaintext.len(),
                target_size
            );

            let mut encryptor =
                RecordEncryptor::new(&hs_aead_key, &server_hs_iv, &mut handshake_seq);
            encryptor.encrypt_handshake_with_padding(
                &combined_plaintext,
                &mut handshake_ciphertext,
                target_size,
            )?;
        } else {
            // Separate mode: encrypt each message as its own record, matching dest's sizes
            log::debug!(
                "REALITY SERVER: Separate mode - {} dest records, encrypting {} messages separately",
                dest_encrypted_records.len(),
                messages.len()
            );

            let mut encryptor =
                RecordEncryptor::new(&hs_aead_key, &server_hs_iv, &mut handshake_seq);

            for (i, msg) in messages.iter().enumerate() {
                let target_size = dest_encrypted_records.get(i).map(|r| r.len()).unwrap_or(0);
                encryptor.encrypt_handshake_with_padding(
                    msg,
                    &mut handshake_ciphertext,
                    target_size,
                )?;
            }
        }

        // Update transcript with server Finished
        handshake_transcript.update(&server_finished);
        let handshake_hash_with_server_finished = handshake_transcript.finish();

        // Buffer all handshake messages to write buffer
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

        // Encrypted handshake record(s)
        self.ciphertext_write_buf
            .extend_from_slice(&handshake_ciphertext);

        log::debug!(
            "REALITY: ServerHello and encrypted handshake messages buffered ({} bytes)",
            self.ciphertext_write_buf.len()
        );

        // Update handshake state
        self.handshake_state = HandshakeState::ServerHelloSent {
            handshake_hash_with_server_finished: handshake_hash_with_server_finished
                .as_ref()
                .to_vec(),
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret.clone(),
            master_secret: hs_keys.master_secret,
            cipher_suite,
        };

        Ok(())
    }

    /// Process client's Finished message and complete handshake
    /// Returns true if a complete record was processed, false if more data needed
    #[inline]
    fn process_client_finished(&mut self) -> io::Result<bool> {
        // Check if we have enough data for a TLS record header BEFORE extracting state
        if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false); // Need more data
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
                return Ok(false); // Need more data
            }

            // Skip ChangeCipherSpec (compatibility message)
            log::debug!("REALITY: Skipping ChangeCipherSpec (compatibility message)");
            self.ciphertext_read_buf
                .consume(TLS_RECORD_HEADER_SIZE + ccs_len);

            // Check if we have the next record header
            if self.ciphertext_read_buf.len() < TLS_RECORD_HEADER_SIZE {
                return Ok(false); // Need more data
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
            return Ok(false); // Need more data
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
        let HandshakeState::ServerHelloSent {
            client_handshake_traffic_secret,
            master_secret,
            cipher_suite,
            handshake_hash_with_server_finished,
        } = old_state
        else {
            unreachable!()
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
            cipher_suite,
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
        // Use hash that includes server Finished (per TLS 1.3 RFC 8446)
        let expected_verify_data = compute_finished_verify_data(
            cipher_suite,
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
        // Use hash that includes server Finished (per TLS 1.3 RFC 8446)
        let (client_app_secret, server_app_secret) = derive_application_secrets(
            cipher_suite,
            &master_secret,
            &handshake_hash_with_server_finished,
        )?;

        // Derive application traffic keys
        let (client_app_key_bytes, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key_bytes, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        // Create cached AeadKey objects to avoid per-record key setup overhead
        let client_app_key = AeadKey::new(cipher_suite, &client_app_key_bytes)?;
        let server_app_key = AeadKey::new(cipher_suite, &server_app_key_bytes)?;

        // Store application traffic keys (as cached AeadKey)
        self.app_read_key = Some(client_app_key);
        self.app_read_iv = Some(client_app_iv);
        self.app_write_key = Some(server_app_key);
        self.app_write_iv = Some(server_app_iv);
        self.read_seq = 0;
        self.write_seq = 0;
        self.cipher_suite = Some(cipher_suite);

        // Handshake state already set to Complete above

        log::debug!("REALITY: Handshake complete, application keys derived");

        Ok(true)
    }

    /// Decrypt application data using TLS 1.3 keys
    /// Processes all complete TLS records in the buffer
    #[inline]
    fn process_application_data(&mut self) -> io::Result<()> {
        // Check if we have application keys
        let (app_read_key, app_read_iv) = match (&self.app_read_key, &self.app_read_iv) {
            (Some(key), Some(iv)) => (key, iv),
            _ => unreachable!(), // Wrong state
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

            // Decrypt in-place: get mutable slice of ciphertext, decrypt, copy plaintext out
            let ciphertext_slice = self
                .ciphertext_read_buf
                .slice_mut(TLS_RECORD_HEADER_SIZE..total_record_len);
            let mut decryptor = RecordDecryptor::new(app_read_key, app_read_iv, &mut self.read_seq);
            let (content_type, plaintext) =
                decryptor.decrypt_record_in_place(ciphertext_slice, record_len as u16)?;

            match content_type {
                CONTENT_TYPE_APPLICATION_DATA => {
                    // Compact plaintext buffer if needed before extending
                    self.plaintext_read_buf.maybe_compact(4096);
                    self.plaintext_read_buf.extend_from_slice(plaintext);
                }
                CONTENT_TYPE_ALERT => {
                    // Parse alert: level (1 byte) + description (1 byte)
                    if plaintext.len() >= 2 {
                        let alert_level = plaintext[0];
                        let alert_desc = plaintext[1];

                        if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                            log::debug!("REALITY: Received close_notify alert");
                            self.received_close_notify = true;
                            // Per RFC 8446: "Any data received after a closure alert
                            // has been received MUST be ignored."
                            return Ok(());
                        } else if alert_level != ALERT_LEVEL_WARNING {
                            // Fatal alert - connection must be terminated
                            log::warn!(
                                "REALITY: Received fatal alert: level={}, desc={}",
                                alert_level,
                                alert_desc
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                format!("received fatal alert: {}", alert_desc),
                            ));
                        } else {
                            log::debug!("REALITY: Received warning alert: desc={}", alert_desc);
                        }
                    }
                }
                // CONTENT_TYPE_HANDSHAKE is invalid after handshake complete
                // strip_content_type() validates and returns error for invalid types
                _ => unreachable!(
                    "strip_content_type validates content type; unexpected: 0x{:02x}",
                    content_type
                ),
            }

            // Consume the processed record from the buffer (after plaintext borrow ends)
            self.ciphertext_read_buf.consume(total_record_len);
        }

        Ok(())
    }

    /// Get a reader for accessing decrypted plaintext
    pub fn reader(&mut self) -> RealityReader<'_> {
        // SlideBuffer handles compaction internally via maybe_compact()
        // Compact before returning reader if we've consumed significant data
        self.plaintext_read_buf.maybe_compact(4096);
        RealityReader::new(&mut self.plaintext_read_buf, self.received_close_notify)
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
                    ));
                }
            };

            let mut encryptor =
                RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
            encryptor.encrypt_app_data(
                &mut self.plaintext_write_buf,
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

    /// Check if the connection wants to read more TLS data
    ///
    /// Returns true if we need more data to make progress (handshake or decryption).
    /// This mirrors rustls::Connection::wants_read().
    pub fn wants_read(&self) -> bool {
        // Don't read more after receiving close_notify (RFC 8446)
        if self.received_close_notify {
            return false;
        }

        // Don't read more if we're in a fatal error state
        if self.fatal_error.is_some() {
            return false;
        }

        // During handshake, we always want to read
        if self.is_handshaking() {
            return true;
        }

        // After handshake, we want to read if:
        // 1. Plaintext buffer is empty (need more application data), OR
        // 2. Ciphertext buffer has incomplete records that need more data
        //
        // Note: If plaintext buffer has data, the caller should consume it first.
        // If ciphertext buffer has complete records, process_new_packets should be called.
        self.plaintext_read_buf.is_empty()
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

        // Encrypt close_notify alert using RecordEncryptor
        let mut encryptor = RecordEncryptor::new(app_write_key, app_write_iv, &mut self.write_seq);
        match encryptor.encrypt_close_notify(&mut self.ciphertext_write_buf) {
            Ok(()) => {
                log::debug!("REALITY: Encrypted close_notify alert queued");
            }
            Err(e) => {
                log::error!("REALITY: Failed to encrypt close_notify: {}", e);
            }
        }
    }
}

#[inline]
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
            cipher_suites: Vec::new(),
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
            cipher_suites: Vec::new(),
        };

        let mut conn = RealityServerConnection::new(config).unwrap();
        let state = conn.process_new_packets().unwrap();

        assert_eq!(state.plaintext_bytes_to_read(), 0);
        assert!(!conn.wants_write());
    }
}
