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

impl<'de> serde::de::Deserialize<'de> for ShadowsocksConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ShadowsocksConfigTemp {
            cipher: String,
            password: String,
        }

        let temp = ShadowsocksConfigTemp::deserialize(deserializer)?;

        match temp.cipher.strip_prefix("2022-blake3-") {
            Some(stripped) => {
                let cipher: ShadowsocksCipher =
                    stripped.try_into().map_err(serde::de::Error::custom)?;
                let key_bytes = BASE64
                    .decode(&temp.password)
                    .map_err(|e| {
                        serde::de::Error::custom(format!(
                            "Failed to base64 decode password for 2022-blake3 cipher: {}",
                            e
                        ))
                    })?
                    .into_boxed_slice();
                Ok(ShadowsocksConfig::Aead2022 { cipher, key_bytes })
            }
            None => {
                let cipher: ShadowsocksCipher = temp
                    .cipher
                    .as_str()
                    .try_into()
                    .map_err(serde::de::Error::custom)?;
                Ok(ShadowsocksConfig::Legacy {
                    cipher,
                    password: temp.password,
                })
            }
        }
    }
}

impl serde::ser::Serialize for ShadowsocksConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ShadowsocksConfig", 2)?;
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
        state.end()
    }
}
