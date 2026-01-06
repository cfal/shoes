//! Hysteria2 protocol constants.
//!
//! This module defines the protocol constants from the Hysteria2 specification.
//! Reference: https://github.com/apernet/hysteria/blob/master/PROTOCOL.md

/// HTTP/3 authentication request URI host
pub const AUTH_HOST: &str = "hysteria";

/// HTTP/3 authentication request URI path
pub const AUTH_PATH: &str = "/auth";

/// Full HTTP/3 authentication request URI
pub const AUTH_URI: &str = "https://hysteria/auth";

/// HTTP/3 authentication request method
pub const AUTH_METHOD: &str = "POST";

/// HTTP status code for successful authentication (HyOK)
pub const STATUS_AUTH_OK: u16 = 233;

/// Header names
pub mod header {
    /// Client authentication header
    pub const AUTH: &str = "Hysteria-Auth";
    /// UDP enabled response header
    pub const UDP: &str = "Hysteria-UDP";
    /// Congestion control (bandwidth) header
    pub const CC_RX: &str = "Hysteria-CC-RX";
    /// Padding header for obfuscation
    pub const PADDING: &str = "Hysteria-Padding";
}

/// TCP request frame type from Hysteria2 protocol
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// TCP response status codes
pub mod tcp_status {
    /// Request accepted
    pub const OK: u8 = 0x00;
    /// Request rejected
    pub const ERROR: u8 = 0x01;
}

/// Maximum address length (from official Go implementation)
pub const MAX_ADDRESS_LENGTH: usize = 2048;

/// Maximum padding length (from official Go implementation)
pub const MAX_PADDING_LENGTH: usize = 4096;

/// Authentication timeout - close connection if client doesn't authenticate within this time.
/// Per protocol reference implementation, default is 3 seconds.
pub const AUTH_TIMEOUT_SECS: u64 = 3;
