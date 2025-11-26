//! TLS 1.3 Cipher Suite definitions for REALITY protocol
//!
//! This module defines the CipherSuite type which bundles cipher suite ID
//! with its associated algorithms for AEAD encryption, transcript hashing,
//! and HKDF key derivation.

use aws_lc_rs::{
    aead::{AES_128_GCM, AES_256_GCM, Algorithm, CHACHA20_POLY1305},
    digest,
    hmac::{self, HMAC_SHA256, HMAC_SHA384},
};

/// Default TLS 1.3 cipher suites in preference order
pub const DEFAULT_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::AES_128_GCM_SHA256,
    CipherSuite::AES_256_GCM_SHA384,
    CipherSuite::CHACHA20_POLY1305_SHA256,
];

/// TLS 1.3 Cipher Suite with all associated algorithms
///
/// This struct bundles the cipher suite ID with its corresponding AEAD algorithm,
/// digest algorithm (for transcript hashing), and HMAC algorithm (for HKDF operations).
/// Per RFC 8446, different cipher suites require different hash algorithms:
/// - TLS_AES_128_GCM_SHA256 (0x1301): SHA256
/// - TLS_AES_256_GCM_SHA384 (0x1302): SHA384
/// - TLS_CHACHA20_POLY1305_SHA256 (0x1303): SHA256
#[derive(Clone, Copy)]
pub struct CipherSuite {
    id: u16,
    algorithm: &'static Algorithm,
    digest_algorithm: &'static digest::Algorithm,
    hmac_algorithm: hmac::Algorithm,
}

impl PartialEq for CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for CipherSuite {}

impl CipherSuite {
    pub const AES_128_GCM_SHA256: Self = Self {
        id: 0x1301,
        algorithm: &AES_128_GCM,
        digest_algorithm: &digest::SHA256,
        hmac_algorithm: HMAC_SHA256,
    };

    pub const AES_256_GCM_SHA384: Self = Self {
        id: 0x1302,
        algorithm: &AES_256_GCM,
        digest_algorithm: &digest::SHA384,
        hmac_algorithm: HMAC_SHA384,
    };

    pub const CHACHA20_POLY1305_SHA256: Self = Self {
        id: 0x1303,
        algorithm: &CHACHA20_POLY1305,
        digest_algorithm: &digest::SHA256,
        hmac_algorithm: HMAC_SHA256,
    };

    /// Get CipherSuite from wire format ID
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::AES_128_GCM_SHA256),
            0x1302 => Some(Self::AES_256_GCM_SHA384),
            0x1303 => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    /// Get CipherSuite from standard TLS name
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "TLS_AES_128_GCM_SHA256" => Some(Self::AES_128_GCM_SHA256),
            "TLS_AES_256_GCM_SHA384" => Some(Self::AES_256_GCM_SHA384),
            "TLS_CHACHA20_POLY1305_SHA256" => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    /// Get standard TLS name for this cipher suite
    pub fn name(&self) -> &'static str {
        match self.id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => unreachable!(),
        }
    }

    /// Wire format ID (e.g., 0x1301)
    #[inline]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// AEAD algorithm (AES_128_GCM, AES_256_GCM, or CHACHA20_POLY1305)
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    /// Key length in bytes (16 for AES-128, 32 for AES-256/ChaCha20)
    #[inline]
    pub fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    /// Nonce/IV length in bytes (always 12 for TLS 1.3)
    #[inline]
    pub fn nonce_len(&self) -> usize {
        self.algorithm.nonce_len()
    }

    /// Hash output length in bytes (32 for SHA256, 48 for SHA384)
    #[inline]
    pub fn hash_len(&self) -> usize {
        self.digest_algorithm.output_len()
    }

    /// Digest algorithm for transcript hashing
    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.digest_algorithm
    }

    /// HMAC algorithm for HKDF operations
    #[inline]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.hmac_algorithm
    }
}

impl std::fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::LowerHex for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.id, f)
    }
}
