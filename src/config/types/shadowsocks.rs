//! Shadowsocks configuration types.

use base64::engine::{Engine as _, general_purpose::STANDARD as BASE64};
use serde::Deserialize;

use crate::shadowsocks::ShadowsocksCipher;

#[derive(Debug, Clone)]
pub enum ShadowsocksConfig {
    Legacy {
        cipher: ShadowsocksCipher,
        password: String,
    },
    Aead2022 {
        cipher: ShadowsocksCipher,
        key_bytes: Box<[u8]>,
    },
}

impl ShadowsocksConfig {
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
                Ok(ShadowsocksConfig::Aead2022 {
                    cipher,
                    key_bytes: key_bytes.into_boxed_slice(),
                })
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
            ShadowsocksConfig::Aead2022 { cipher, key_bytes } => {
                let cipher_name = format!("2022-blake3-{}", cipher.name());
                state.serialize_field("cipher", &cipher_name)?;
                state.serialize_field("password", &BASE64.encode(key_bytes))?;
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
