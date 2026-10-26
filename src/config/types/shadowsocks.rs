//! Shadowsocks configuration types.

use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use serde::Deserialize;

use crate::shadowsocks::ShadowsocksCipher;

#[derive(Clone)]
pub enum ShadowsocksConfig {
    Legacy {
        cipher: ShadowsocksCipher,
        password: String,
    },
    Aead2022 {
        cipher: ShadowsocksCipher,
        key_bytes: Box<[u8]>,
        /// Outermost identity first; key_bytes remains the final user key.
        identity_keys: Vec<Box<[u8]>>,
    },
}

impl std::fmt::Debug for ShadowsocksConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy { cipher, .. } => f
                .debug_struct("Legacy")
                .field("cipher", cipher)
                .finish_non_exhaustive(),
            Self::Aead2022 {
                cipher,
                identity_keys,
                ..
            } => f
                .debug_struct("Aead2022")
                .field("cipher", cipher)
                .field("identity_count", &identity_keys.len())
                .finish_non_exhaustive(),
        }
    }
}

impl ShadowsocksConfig {
    /// Parses an outbound password, including AES-2022 identity chains.
    pub fn from_client_fields(cipher: &str, password: &str) -> std::io::Result<Self> {
        if !cipher.starts_with("2022-blake3-") || !password.contains(':') {
            return Self::from_fields(cipher, password);
        }
        if !matches!(
            cipher,
            "2022-blake3-aes-128-gcm" | "2022-blake3-aes-256-gcm"
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 identity keys require an AES-GCM cipher",
            ));
        }
        let mut parts = password.split(':');
        let mut config = Self::from_fields(cipher, parts.next_back().unwrap())?;
        let Self::Aead2022 { identity_keys, .. } = &mut config else {
            unreachable!()
        };
        for part in parts {
            identity_keys.push(
                BASE64
                    .decode(part)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid base64 Shadowsocks 2022 identity key",
                        )
                    })?
                    .into_boxed_slice(),
            );
        }
        config.validate_keys()?;
        Ok(config)
    }

    /// Create a ShadowsocksConfig from cipher and password strings.
    /// Handles both legacy ciphers and 2022-blake3-* ciphers.
    pub fn from_fields(cipher: &str, password: &str) -> std::io::Result<Self> {
        match cipher.strip_prefix("2022-blake3-") {
            Some(stripped) => {
                let cipher: ShadowsocksCipher = stripped.try_into()?;
                let key_bytes = BASE64.decode(password).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Failed to base64 decode password for 2022-blake3 cipher: {}",
                            e
                        ),
                    )
                })?;
                let config = ShadowsocksConfig::Aead2022 {
                    cipher,
                    key_bytes: key_bytes.into_boxed_slice(),
                    identity_keys: Vec::new(),
                };
                config.validate_keys()?;
                Ok(config)
            }
            None => {
                let cipher: ShadowsocksCipher = cipher.try_into()?;
                Ok(ShadowsocksConfig::Legacy {
                    cipher,
                    password: password.to_string(),
                })
            }
        }
    }

    pub(crate) fn validate_keys(&self) -> std::io::Result<()> {
        let Self::Aead2022 {
            cipher,
            key_bytes,
            identity_keys,
        } = self
        else {
            return Ok(());
        };
        let key_len = cipher.key_len();
        if key_bytes.len() != key_len || identity_keys.iter().any(|key| key.len() != key_len) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Shadowsocks 2022 keys must each decode to exactly {key_len} bytes"),
            ));
        }
        if !identity_keys.is_empty() && !matches!(cipher.name(), "aes-128-gcm" | "aes-256-gcm") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 identity keys require an AES-GCM cipher",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_server_key(&self) -> std::io::Result<()> {
        self.validate_keys()?;
        if matches!(self, Self::Aead2022 { identity_keys, .. } if !identity_keys.is_empty()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Shadowsocks 2022 identity keys are only supported by clients",
            ));
        }
        Ok(())
    }

    /// Serialize cipher and password fields to a SerializeStruct.
    /// Used by custom serializers to flatten ShadowsocksConfig fields.
    pub fn serialize_fields<S: serde::ser::SerializeStruct>(
        &self,
        state: &mut S,
    ) -> Result<(), S::Error> {
        match self {
            ShadowsocksConfig::Legacy { cipher, password } => {
                state.serialize_field("cipher", cipher.name())?;
                state.serialize_field("password", password)?;
            }
            ShadowsocksConfig::Aead2022 {
                cipher,
                key_bytes,
                identity_keys,
            } => {
                let cipher_name = format!("2022-blake3-{}", cipher.name());
                state.serialize_field("cipher", &cipher_name)?;
                let password = identity_keys
                    .iter()
                    .chain(std::iter::once(key_bytes))
                    .map(|key| BASE64.encode(key))
                    .collect::<Vec<_>>()
                    .join(":");
                state.serialize_field("password", &password)?;
            }
        }
        Ok(())
    }
}

impl<'de> serde::de::Deserialize<'de> for ShadowsocksConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ShadowsocksConfigTemp {
            cipher: String,
            password: String,
        }

        let temp = ShadowsocksConfigTemp::deserialize(deserializer)?;
        Self::from_fields(&temp.cipher, &temp.password).map_err(serde::de::Error::custom)
    }
}

impl serde::ser::Serialize for ShadowsocksConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ShadowsocksConfig", 2)?;
        self.serialize_fields(&mut state)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientProxyConfig, ServerProxyConfig};

    #[test]
    fn client_identity_keys_round_trip_in_order() {
        for (cipher, len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
        ] {
            for count in [1, 2, 3] {
                let keys: Vec<_> = (1..=count)
                    .map(|value| vec![value; len].into_boxed_slice())
                    .collect();
                let password = keys
                    .iter()
                    .map(|key| BASE64.encode(key))
                    .collect::<Vec<_>>()
                    .join(":");
                let input = serde_json::json!({"type":"shadowsocks", "cipher":cipher, "password":password, "udp_enabled":false});
                let client: ClientProxyConfig = serde_json::from_value(input.clone()).unwrap();
                let ClientProxyConfig::Shadowsocks { config, .. } = &client else {
                    unreachable!()
                };
                let ShadowsocksConfig::Aead2022 {
                    key_bytes,
                    identity_keys,
                    ..
                } = config
                else {
                    unreachable!()
                };
                assert_eq!(key_bytes, keys.last().unwrap());
                assert_eq!(identity_keys, &keys[..keys.len() - 1]);
                assert_eq!(serde_json::to_value(&client).unwrap(), input);
                let yaml = serde_yaml::to_string(&client).unwrap();
                let from_yaml: ClientProxyConfig = serde_yaml::from_str(&yaml).unwrap();
                assert_eq!(serde_json::to_value(from_yaml).unwrap(), input);
                assert_eq!(
                    serde_json::from_value::<ServerProxyConfig>(input).is_ok(),
                    count == 1
                );
                assert_eq!(config.validate_server_key().is_ok(), count == 1);
                let debug = format!("{config:?}");
                for key in &keys {
                    assert!(!debug.contains(&BASE64.encode(key)));
                    assert!(!debug.contains(&format!("{key:?}")));
                }
            }
        }
    }

    #[test]
    fn client_identity_keys_reject_invalid_components_and_ciphers() {
        for (cipher, len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
        ] {
            let valid = BASE64.encode(vec![0x42; len]);
            for invalid in [
                String::new(),
                "not-base64!".into(),
                BASE64.encode(vec![0; len - 1]),
                BASE64.encode(vec![0; len + 1]),
            ] {
                for password in [
                    format!("{invalid}:{valid}"),
                    format!("{valid}:{invalid}"),
                    format!("{valid}:{invalid}:{valid}"),
                ] {
                    let error =
                        ShadowsocksConfig::from_client_fields(cipher, &password).unwrap_err();
                    assert!(!error.to_string().contains(&valid));
                }
            }
        }
        let password = format!("{0}:{0}", BASE64.encode([0x42; 32]));
        assert!(
            ShadowsocksConfig::from_client_fields("2022-blake3-chacha20-poly1305", &password)
                .is_err()
        );
        let legacy =
            ShadowsocksConfig::from_client_fields("aes-128-gcm", "literal:password").unwrap();
        assert!(!format!("{legacy:?}").contains("literal:password"));
        assert!(
            matches!(legacy, ShadowsocksConfig::Legacy { password, .. } if password == "literal:password")
        );
        let input = serde_json::json!({
            "type": "shadowsocks", "cipher": "aes-128-gcm", "password": "literal:password"
        });
        let client: ClientProxyConfig = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(client).unwrap(), input);
    }

    #[test]
    fn client_identity_key_errors_preserve_precedence() {
        for (cipher, len) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
        ] {
            let valid = BASE64.encode(vec![0x42; len]);
            let short = BASE64.encode(vec![0x42; len - 1]);
            for user_key in ["not-base64!", "", short.as_str()] {
                let expected = ShadowsocksConfig::from_fields(cipher, user_key).unwrap_err();
                let password = format!("not-base64!:{user_key}");
                let error = ShadowsocksConfig::from_client_fields(cipher, &password).unwrap_err();
                assert_eq!(error.kind(), expected.kind());
                assert_eq!(error.to_string(), expected.to_string());
            }
            for identities in [
                format!("not-base64!:{short}"),
                format!("{short}:not-base64!"),
            ] {
                let password = format!("{identities}:{valid}");
                let error = ShadowsocksConfig::from_client_fields(cipher, &password).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(
                    error.to_string(),
                    "Invalid base64 Shadowsocks 2022 identity key"
                );
            }
        }
        for cipher in ["2022-blake3-chacha20-poly1305", "2022-blake3-unknown"] {
            let error =
                ShadowsocksConfig::from_client_fields(cipher, "invalid:invalid").unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "Shadowsocks 2022 identity keys require an AES-GCM cipher"
            );
        }
    }

    #[test]
    fn aead2022_requires_exact_key_length() {
        for (cipher, required) in [
            ("2022-blake3-aes-128-gcm", 16),
            ("2022-blake3-aes-256-gcm", 32),
            ("2022-blake3-chacha20-poly1305", 32),
        ] {
            for len in [0, 1, 15, 16, 17, 31, 32, 33] {
                let password = BASE64.encode(vec![b'x'; len]);
                let result = ShadowsocksConfig::from_fields(cipher, &password);
                assert_eq!(result.is_ok(), len == required, "{cipher}: {len}");
                if let Err(error) = result {
                    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
                    if !password.is_empty() {
                        assert!(!error.to_string().contains(&password));
                    }
                }
            }
        }
        assert!(ShadowsocksConfig::from_fields("aes-128-gcm", "").is_ok());
    }
}
