use crate::buf_reader::BufReader;

// TLS record types
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

// TLS handshake types
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

// TLS ciphers
const TLS13_CIPHER_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// TLS extension type for supported_versions
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

/// VISION protocol filter state
///
/// This structure maintains only the state needed for TLS record filtering
/// and detection, tracking TLS patterns and remaining records to analyze.
#[derive(Debug)]
pub struct VisionFilter {
    /// Number of records remaining to analyze for TLS patterns
    record_filter_count: usize,

    /// Any TLS version detected (ClientHello seen)
    is_tls: bool,

    /// TLS 1.2 or above detected (ServerHello seen)
    is_tls12_or_above: bool,

    /// Whether XTLS can be enabled (TLS 1.3 + supported cipher)
    supports_xtls: bool,
}

impl VisionFilter {
    /// Create a new VisionFilter with default record count
    pub fn new() -> Self {
        Self::new_with_record_count(8)
    }

    fn new_with_record_count(record_count: usize) -> Self {
        Self {
            record_filter_count: record_count,
            supports_xtls: false,
            is_tls: false,
            is_tls12_or_above: false,
        }
    }

    /// Check if filtering is complete
    pub fn is_filtering(&self) -> bool {
        self.record_filter_count > 0
    }

    pub fn decrement_filter_count(&mut self) {
        self.record_filter_count = self.record_filter_count.saturating_sub(1);
    }

    pub fn stop_filtering(&mut self, reason: String) {
        log::debug!("VISION: Stopping filtering - {}", reason);
        self.record_filter_count = 0;
    }

    /// Returns true if any TLS version has been detected (ClientHello seen)
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Returns true if TLS 1.2 or above has been detected (ServerHello seen)
    pub fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    /// Returns true if XTLS can be enabled (TLS 1.3 + supported cipher)
    pub fn supports_xtls(&self) -> bool {
        self.supports_xtls
    }

    /// Analyze a complete TLS record for patterns and update state accordingly
    ///
    /// Caller must extract complete TLS records using TlsDeframer before calling this.
    /// This method detects ClientHello, ServerHello, TLS version, cipher suite, and
    /// ApplicationData to determine when to switch to direct copy mode.
    ///
    /// This is a public method now - VisionStream will call it after recordizing.
    pub fn filter_record(&mut self, data: &[u8]) {
        if self.record_filter_count == 0 {
            return;
        }

        self.record_filter_count = self.record_filter_count.saturating_sub(1);

        if data.len() < 5 {
            // invalid record length
            self.stop_filtering(format!("invalid record length: {}", data.len()));
            return;
        }

        // Detect ClientHello - minimal check for TLS handshake record
        if !self.is_tls
            && data.len() >= 6
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03 // TLS version major
            && data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            self.is_tls = true;
            log::debug!("VISION: Detected TLS ClientHello");
        }

        // Detect and parse ServerHello
        if !self.is_tls12_or_above
            && data.len() >= 6
            && data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03 // TLS version major
            && data[2] == 0x03 // TLS version minor (1.2)
            && data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            self.is_tls12_or_above = true;
            self.is_tls = true;

            // Parse ServerHello properly - delegate to vision_tls_util
            match parse_server_hello(data) {
                Ok(parsed) => {
                    log::debug!(
                        "VISION: Detected TLS cipher suite: 0x{:04x}",
                        parsed.cipher_suite
                    );

                    if parsed.has_tls13_version {
                        log::debug!("VISION: Detected TLS 1.3 via supported_versions extension");

                        // Check if cipher is supported for XTLS
                        // Following Xray-core: all TLS 1.3 ciphers EXCEPT 0x1305 support XTLS
                        if parsed.cipher_suite == TLS13_CIPHER_AES_128_CCM_8_SHA256 {
                            log::warn!(
                                "VISION: TLS 1.3 detected but cipher 0x{:04x} (TLS_AES_128_CCM_8_SHA256) not supported for XTLS",
                                parsed.cipher_suite
                            );
                        } else {
                            // Assume all other TLS 1.3 ciphers support XTLS
                            self.supports_xtls = true;
                            log::debug!(
                                "VISION: TLS 1.3 with supported cipher 0x{:04x} - XTLS enabled",
                                parsed.cipher_suite
                            );
                        }

                        // Stop filtering early
                        self.stop_filtering("TLS 1.3 handshake detected".to_string());
                    }
                }
                Err(e) => {
                    self.stop_filtering(format!("invalid ServerHello: {}", e));
                }
            }
        }
    }
}

/// Result of parsing a ServerHello message
struct ParsedServerHello {
    pub cipher_suite: u16,
    pub has_tls13_version: bool,
}

/// Parse ServerHello structure following RFC 8446 format
///
/// ServerHello format:
/// - TLS Record Header (5 bytes):
///   - ContentType (1 byte): 0x16 (Handshake)
///   - ProtocolVersion (2 bytes): 0x0303 (TLS 1.2 for compatibility)
///   - Length (2 bytes): payload length
/// - Handshake Header (4 bytes):
///   - HandshakeType (1 byte): 0x02 (ServerHello)
///   - Length (3 bytes): message length
/// - ServerHello Content:
///   - LegacyVersion (2 bytes): 0x0303 (TLS 1.2)
///   - Random (32 bytes): server random
///   - LegacySessionIdEcho (1 + N bytes): session ID length + session ID
///   - CipherSuite (2 bytes): selected cipher
///   - LegacyCompressionMethod (1 byte): 0x00
///   - Extensions (2 + N bytes): extensions length + extensions
///
/// TODO: consolidate with ShadowTLS version
fn parse_server_hello(data: &[u8]) -> std::io::Result<ParsedServerHello> {
    // Minimum size: 5 (record header) + 4 (handshake header) + 2 (version) + 32 (random) + 1 (session id len) + 2 (cipher) + 1 (compression) = 47
    if data.len() < 47 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ServerHello too short",
        ));
    }

    // Skip TLS record header (5 bytes) and handshake type (1 byte)
    let mut reader = BufReader::new(&data[6..]);

    // Read handshake message length (3 bytes)
    let _message_len = reader.read_u24_be()?;

    // Read legacy version (2 bytes) - should be 0x0303 for TLS 1.2
    let legacy_version_major = reader.read_u8()?;
    let legacy_version_minor = reader.read_u8()?;
    if legacy_version_major != 3 || legacy_version_minor != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "expected TLS 1.2 (major/minor 3.3), got major/minor {}.{}",
                legacy_version_major, legacy_version_minor
            ),
        ));
    }

    // Skip server random (32 bytes)
    reader.skip(32)?;

    // Read session ID length and skip session ID
    let session_id_len = reader.read_u8()?;
    if session_id_len > 0 {
        reader.skip(session_id_len as usize)?;
    }

    // Read cipher suite (2 bytes)
    let cipher_suite = reader.read_u16_be()?;

    // Skip compression method (1 byte)
    reader.skip(1)?;

    // Check if we have extensions
    if reader.is_consumed() {
        // No extensions, assume not TLS 1.3
        return Ok(ParsedServerHello {
            cipher_suite,
            has_tls13_version: false,
        });
    }

    // Read extensions length
    let extensions_len = match reader.read_u16_be() {
        Ok(len) => len as usize,
        Err(_) => {
            // No extensions
            return Ok(ParsedServerHello {
                cipher_suite,
                has_tls13_version: false,
            });
        }
    };

    // Parse extensions to find supported_versions
    let mut has_tls13_version = false;
    let extensions_data = match reader.read_slice(extensions_len) {
        Ok(data) => data,
        Err(_) => {
            // Invalid extensions length
            return Ok(ParsedServerHello {
                cipher_suite,
                has_tls13_version: false,
            });
        }
    };

    let mut ext_reader = BufReader::new(extensions_data);

    while !ext_reader.is_consumed() {
        let extension_type = match ext_reader.read_u16_be() {
            Ok(t) => t,
            Err(_) => break,
        };
        let extension_len = match ext_reader.read_u16_be() {
            Ok(l) => l as usize,
            Err(_) => break,
        };

        if extension_type == TLS_EXT_SUPPORTED_VERSIONS {
            // supported_versions extension found
            // In ServerHello, this is 2 bytes: the selected version
            if extension_len == 2 {
                match ext_reader.read_slice(2) {
                    Ok(version_bytes) => {
                        // TLS 1.3 is 0x0304
                        if version_bytes[0] == 0x03 && version_bytes[1] == 0x04 {
                            has_tls13_version = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            } else if ext_reader.skip(extension_len).is_err() {
                break;
            }
        } else if ext_reader.skip(extension_len).is_err() {
            // Skip unknown extension
            break;
        }
    }

    Ok(ParsedServerHello {
        cipher_suite,
        has_tls13_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vision_filter_initialization() {
        let filter = VisionFilter::new();

        assert!(filter.is_filtering());
        assert!(!filter.supports_xtls());
        assert!(!filter.is_tls());
        assert!(!filter.is_tls12_or_above());
    }

    #[test]
    fn test_vision_filter_with_custom_record_count() {
        let filter = VisionFilter::new_with_record_count(5);

        assert!(filter.is_filtering());
        assert!(!filter.supports_xtls());
        assert!(!filter.is_tls());
    }

    #[test]
    fn test_stop_filtering() {
        let mut filter = VisionFilter::new();

        assert!(filter.is_filtering());

        filter.stop_filtering("test".to_string());

        assert!(!filter.is_filtering());
    }

    #[test]
    fn test_detect_client_hello() {
        let mut filter = VisionFilter::new();

        // Mock ClientHello record
        let client_hello = vec![
            0x16, 0x03, 0x01, // TLS Handshake, version 3.1
            0x00, 0x05, // Length: 5
            0x01, // ClientHello type
            0x00, 0x00, 0x00, // Rest of handshake
        ];

        filter.filter_record(&client_hello);

        assert!(filter.is_tls());
        assert!(!filter.supports_xtls()); // Not enabled until TLS 1.3 ServerHello
    }

    #[test]
    fn test_detect_server_hello_tls12() {
        let mut filter = VisionFilter::new();

        // Mock ServerHello record (TLS 1.2)
        let server_hello = vec![
            0x16, 0x03, 0x03, // TLS Handshake, version 3.3 (TLS 1.2)
            0x00, 0x05, // Length: 5
            0x02, // ServerHello type
            0x00, 0x00, 0x00, // Rest of handshake
        ];

        filter.filter_record(&server_hello);

        assert!(filter.is_tls());
        assert!(filter.is_tls12_or_above());
    }

    #[test]
    fn test_detect_application_data() {
        let mut filter = VisionFilter::new();

        // First detect TLS
        let client_hello = vec![
            0x16, 0x03, 0x01, // TLS Handshake
            0x00, 0x05, // Length: 5
            0x01, // ClientHello type
            0x00, 0x00, 0x00,
        ];
        filter.filter_record(&client_hello);

        // Then ApplicationData
        let app_data = vec![
            0x17, 0x03, 0x03, // ApplicationData, TLS 1.2
            0x00, 0x05, // Length: 5
            0x00, 0x00, 0x00, 0x00, 0x00, // Encrypted data
        ];

        filter.filter_record(&app_data);

        assert!(filter.is_tls());
        assert!(filter.is_filtering());
    }

    #[test]
    fn test_record_count_decrements() {
        let mut filter = VisionFilter::new_with_record_count(3);

        let dummy_record = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x00];

        filter.filter_record(&dummy_record);
        assert!(filter.is_filtering());

        filter.filter_record(&dummy_record);
        assert!(filter.is_filtering());

        filter.filter_record(&dummy_record);
        assert!(!filter.is_filtering());

        // Further calls should not decrement
        filter.filter_record(&dummy_record);
        assert!(!filter.is_filtering());
    }

    #[test]
    fn test_filter_record_no_processing_when_complete() {
        let mut filter = VisionFilter::new();
        filter.stop_filtering("test".to_string());

        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00];

        // Should return immediately without processing
        filter.filter_record(&data);

        assert!(!filter.is_tls()); // State shouldn't change
        assert!(!filter.is_filtering());
    }

    #[test]
    fn test_short_record_ignored() {
        let mut filter = VisionFilter::new();

        let short_record = vec![0x16, 0x03, 0x01]; // Less than 6 bytes

        filter.filter_record(&short_record);

        assert!(!filter.is_tls()); // Should not detect anything
        assert!(!filter.is_filtering()); // Filtering stopped due to invalid record
    }

    #[test]
    fn test_non_tls_record_ignored() {
        let mut filter = VisionFilter::new();

        let non_tls_record = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        filter.filter_record(&non_tls_record);

        assert!(!filter.is_tls());
        assert!(!filter.supports_xtls());
        assert!(filter.is_filtering());
    }

    #[test]
    fn test_filter_record_client_hello() {
        let mut filter = VisionFilter::new();

        // Simulate ClientHello
        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&client_hello);

        assert!(filter.is_tls());
        assert!(!filter.supports_xtls()); // Not optimistically enabled anymore
    }

    #[test]
    fn test_filter_record_server_hello() {
        let mut filter = VisionFilter::new();

        // Simulate ServerHello
        let server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&server_hello);

        assert!(filter.is_tls());
        assert!(filter.is_tls12_or_above());
    }

    #[test]
    fn test_client_hello_only_detected_once() {
        let mut filter = VisionFilter::new();

        let client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&client_hello);
        assert!(filter.is_tls());
        assert!(filter.is_filtering());

        // Send again - should not reset state
        filter.filter_record(&client_hello);
        assert!(filter.is_tls());
        assert!(filter.is_filtering());
    }

    #[test]
    fn test_server_hello_only_detected_once() {
        let mut filter = VisionFilter::new();

        let server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00];

        filter.filter_record(&server_hello);
        assert!(filter.is_tls12_or_above());
        // Note: This mock ServerHello is too short and will cause parse_server_hello to fail,
        // which stops filtering. This is expected behavior - invalid records stop filtering.
        assert!(!filter.is_filtering());
    }
}
