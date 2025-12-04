//! User authentication lookup for NaiveProxy
//!
//! Provides O(1) user lookup with constant-time credential comparison
//! to prevent timing attacks.

use std::collections::HashMap;

use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use subtle::ConstantTimeEq;

/// Single user credential entry
struct UserEntry {
    /// Base64-encoded "user:pass" for comparison
    encoded: Vec<u8>,
    /// Display name (for logging)
    name: String,
}

/// O(1) user lookup with constant-time credential comparison.
///
/// Uses BLAKE3 hash for fast lookup, then constant-time comparison
/// of actual credentials to prevent timing attacks.
pub struct UserLookup {
    /// Hash of encoded credentials -> index in users vec
    lookup: HashMap<[u8; 32], usize>,
    /// User entries
    users: Vec<UserEntry>,
}

impl std::fmt::Debug for UserLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserLookup")
            .field("num_users", &self.users.len())
            .finish()
    }
}

impl UserLookup {
    /// Create a new user lookup table from (name, username, password) tuples.
    ///
    /// # Panics
    /// Panics if credentials is empty (config validation should prevent this).
    pub fn new(credentials: Vec<(String, String, String)>) -> Self {
        assert!(
            !credentials.is_empty(),
            "NaiveProxy requires at least one user"
        );
        let mut lookup = HashMap::with_capacity(credentials.len());
        let mut users = Vec::with_capacity(credentials.len());

        for (i, (name, username, password)) in credentials.into_iter().enumerate() {
            let cred_string = format!("{}:{}", username, password);
            let encoded = BASE64.encode(&cred_string).into_bytes();
            let hash = blake3::hash(&encoded);
            lookup.insert(*hash.as_bytes(), i);
            users.push(UserEntry { encoded, name });
        }

        Self { lookup, users }
    }

    /// Validate credentials, returning the user's name if valid.
    ///
    /// O(1) lookup via hash, then constant-time comparison for security.
    pub fn validate(&self, auth_header: &str) -> Option<&str> {
        let encoded = auth_header.strip_prefix("Basic ")?.as_bytes();
        let hash = blake3::hash(encoded);
        let idx = self.lookup.get(hash.as_bytes())?;
        let user = &self.users[*idx];

        // Constant-time comparison as defense in depth
        if user.encoded.ct_eq(encoded).unwrap_u8() == 1 {
            Some(&user.name)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_lookup_basic() {
        let lookup = UserLookup::new(vec![(
            "alice".to_string(),
            "user".to_string(),
            "pass".to_string(),
        )]);
        // Base64 of "user:pass" is "dXNlcjpwYXNz"
        assert_eq!(lookup.validate("Basic dXNlcjpwYXNz"), Some("alice"));
        assert_eq!(lookup.users.len(), 1);
    }

    #[test]
    fn test_user_lookup_special_chars() {
        // Test with special characters in password
        let lookup = UserLookup::new(vec![(
            "bob".to_string(),
            "user".to_string(),
            "p@ss:w0rd!".to_string(),
        )]);
        // Encode "user:p@ss:w0rd!" to base64
        let encoded = BASE64.encode("user:p@ss:w0rd!");
        let header = format!("Basic {}", encoded);
        assert_eq!(lookup.validate(&header), Some("bob"));
    }

    #[test]
    fn test_user_lookup_empty_password() {
        let lookup = UserLookup::new(vec![(
            "test".to_string(),
            "user".to_string(),
            "".to_string(),
        )]);
        let encoded = BASE64.encode("user:");
        let header = format!("Basic {}", encoded);
        assert_eq!(lookup.validate(&header), Some("test"));
    }

    #[test]
    fn test_user_lookup_invalid_credentials() {
        let lookup = UserLookup::new(vec![(
            "alice".to_string(),
            "user".to_string(),
            "pass".to_string(),
        )]);
        assert_eq!(lookup.validate("Basic invalid"), None);
        assert_eq!(lookup.validate("Basic d3Jvbmc6cGFzcw=="), None); // wrong:pass
        assert_eq!(lookup.validate("Bearer token"), None);
        assert_eq!(lookup.validate(""), None);
    }

    #[test]
    fn test_user_lookup_multiple_users() {
        let lookup = UserLookup::new(vec![
            (
                "alice".to_string(),
                "alice".to_string(),
                "alice123".to_string(),
            ),
            ("bob".to_string(), "bob".to_string(), "bob456".to_string()),
            (
                "charlie".to_string(),
                "charlie".to_string(),
                "charlie789".to_string(),
            ),
        ]);
        assert_eq!(lookup.users.len(), 3);

        let alice_header = format!("Basic {}", BASE64.encode("alice:alice123"));
        let bob_header = format!("Basic {}", BASE64.encode("bob:bob456"));
        let charlie_header = format!("Basic {}", BASE64.encode("charlie:charlie789"));

        assert_eq!(lookup.validate(&alice_header), Some("alice"));
        assert_eq!(lookup.validate(&bob_header), Some("bob"));
        assert_eq!(lookup.validate(&charlie_header), Some("charlie"));
    }
}
