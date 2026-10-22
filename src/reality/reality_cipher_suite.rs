//! Configurable TLS 1.3 cipher suite identifiers for REALITY.

/// Default TLS 1.3 cipher suites in preference order
pub const DEFAULT_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::AES_128_GCM_SHA256,
    CipherSuite::AES_256_GCM_SHA384,
    CipherSuite::CHACHA20_POLY1305_SHA256,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    id: u16,
}

impl CipherSuite {
    pub const AES_128_GCM_SHA256: Self = Self { id: 0x1301 };

    pub const AES_256_GCM_SHA384: Self = Self { id: 0x1302 };

    pub const CHACHA20_POLY1305_SHA256: Self = Self { id: 0x1303 };

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
