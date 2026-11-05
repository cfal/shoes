//! AmneziaWG and Phobos settings for WireGuard records.
//!
//! These types only describe the YAML. Validation is delegated to the
//! gotatun fork so shoes is never stricter or looser than amneziawg-go.

use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use super::wireguard::invalid;

/// A number or an inclusive `lo-hi` range, as written in a `.conf` file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum AmneziaValue {
    Number(u32),
    Range(String),
}

impl AmneziaValue {
    /// The text form of the UAPI line.
    pub fn uapi(&self) -> String {
        match self {
            AmneziaValue::Number(n) => n.to_string(),
            AmneziaValue::Range(text) => text.clone(),
        }
    }
}

/// The 32-byte AmneziaWG 3.0 header protection key.
#[derive(Clone, PartialEq)]
pub struct HeaderProtectionKey(pub [u8; 32]);

impl fmt::Debug for HeaderProtectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

fn decode_hex_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

impl Serialize for HeaderProtectionKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for HeaderProtectionKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Parses through Value to keep rejected key material out of deserialization errors.
        let value = serde_yaml::Value::deserialize(deserializer)?;
        value
            .as_str()
            .and_then(|text| {
                decode_hex_32(text).or_else(|| {
                    STANDARD
                        .decode(text)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                })
            })
            .map(Self)
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "header_protection_key must be 64 hex characters or base64 of 32 bytes",
                )
            })
    }
}

/// AmneziaWG 2.0, 3.0 and 3.1 settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AmneziaSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jc: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmin: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jmax: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s1: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s2: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s4: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h1: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h3: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h4: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i5: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_protection_key: Option<HeaderProtectionKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_padding_addition: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_after_time: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekey_timeout: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_after_time: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_timeout: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_handshake_attempts: Option<AmneziaValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub random_trailers: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_cookies: Option<bool>,
}

impl AmneziaSettings {
    /// True when the block asks for nothing beyond plain WireGuard: it is empty, or the fork
    /// normalises it to plain WireGuard. An invalid block is not plain, so validation still
    /// reports it.
    pub fn is_plain(&self) -> bool {
        #[cfg(unix)]
        {
            self.to_gotatun()
                .is_ok_and(|config| config.is_plain_wireguard())
        }
        #[cfg(not(unix))]
        {
            *self == Self::default()
        }
    }

    /// The block as the device should see it: a plain block behaves as no block.
    pub fn effective(block: Option<Self>) -> Option<Self> {
        block.filter(|block| !block.is_plain())
    }

    /// Bytes prepended to every transport packet (`s4`).
    pub fn transport_overhead(&self) -> u16 {
        self.s4.unwrap_or(0)
    }
}

#[cfg(unix)]
impl AmneziaSettings {
    /// Build the fork's configuration through its UAPI parser and validator.
    pub fn to_gotatun(&self) -> std::io::Result<gotatun::amnezia::AmneziaConfig> {
        let numbers = [
            ("jc", self.jc),
            ("jmin", self.jmin),
            ("jmax", self.jmax),
            ("s1", self.s1),
            ("s2", self.s2),
            ("s3", self.s3),
            ("s4", self.s4),
        ];
        let values = [
            ("h1", &self.h1),
            ("h2", &self.h2),
            ("h3", &self.h3),
            ("h4", &self.h4),
            ("content_padding_addition", &self.content_padding_addition),
            ("rekey_after_time", &self.rekey_after_time),
            ("rekey_timeout", &self.rekey_timeout),
            ("reject_after_time", &self.reject_after_time),
            ("keepalive_timeout", &self.keepalive_timeout),
            ("max_handshake_attempts", &self.max_handshake_attempts),
        ];
        let chains = [
            ("i1", &self.i1),
            ("i2", &self.i2),
            ("i3", &self.i3),
            ("i4", &self.i4),
            ("i5", &self.i5),
        ];
        let flags = [
            ("random_trailers", self.random_trailers),
            ("disable_cookies", self.disable_cookies),
        ];

        let mut lines: Vec<(&str, String)> = Vec::new();
        lines.extend(
            numbers
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| (k, v.to_string()))),
        );
        lines.extend(
            values
                .into_iter()
                .filter_map(|(k, v)| v.as_ref().map(|v| (k, v.uapi()))),
        );
        lines.extend(
            chains
                .into_iter()
                .filter_map(|(k, v)| v.as_ref().map(|v| (k, v.clone()))),
        );
        lines.extend(
            flags
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| (k, u8::from(v).to_string()))),
        );
        if let Some(key) = &self.header_protection_key {
            let hex: String = key.0.iter().map(|b| format!("{b:02x}")).collect();
            lines.push(("header_protection_key", hex));
        }

        let mut config = gotatun::amnezia::AmneziaConfig::default();
        for (key, value) in lines {
            let known = config
                .apply_uapi_line(key, &value)
                .map_err(|error| invalid(format!("WireGuard amnezia: {error}")))?;
            if !known {
                return Err(invalid(format!(
                    "WireGuard amnezia: internal error, `{key}` is not a known setting"
                )));
            }
        }
        config
            .validate()
            .map_err(|error| invalid(format!("WireGuard amnezia: {error}")))?;
        Ok(config)
    }
}

/// The Phobos shared key.
#[derive(Clone, PartialEq)]
pub struct PhobosSecret(pub String);

impl fmt::Debug for PhobosSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Serialize for PhobosSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PhobosSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Parses through Value to keep rejected key material out of deserialization errors.
        let value = serde_yaml::Value::deserialize(deserializer)?;
        value
            .as_str()
            .map(|text| Self(text.to_owned()))
            .ok_or_else(|| serde::de::Error::custom("Phobos key must be a string"))
    }
}

/// The cover protocol Phobos frames datagrams in.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PhobosMasking {
    None,
    Stun,
    Media,
    Auto,
    Tls,
}

impl PhobosMasking {
    /// Bytes the frame adds to every datagram.
    pub fn overhead(self) -> u16 {
        match self {
            PhobosMasking::Stun => 24,
            PhobosMasking::Media => 12,
            PhobosMasking::None | PhobosMasking::Auto | PhobosMasking::Tls => 0,
        }
    }
}

/// Phobos settings.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PhobosSettings {
    pub key: PhobosSecret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masking: Option<PhobosMasking>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_dummy: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscate_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_pt: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_ssrc: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_clock: Option<u16>,
}

#[cfg(unix)]
impl PhobosSettings {
    /// Build the fork's configuration through its parser.
    pub fn to_gotatun(&self) -> std::io::Result<gotatun::phobos::PhobosConfig> {
        let map =
            |error: gotatun::phobos::ConfigError| invalid(format!("WireGuard phobos: {error}"));
        let mut config = gotatun::phobos::PhobosConfig::new(self.key.0.as_bytes()).map_err(map)?;
        let masking = self.masking.map(|masking| {
            match masking {
                PhobosMasking::None => "none",
                PhobosMasking::Stun => "stun",
                PhobosMasking::Media => "media",
                PhobosMasking::Auto => "auto",
                PhobosMasking::Tls => "tls",
            }
            .to_owned()
        });
        let settings = [
            ("masking", masking),
            ("max-dummy", self.max_dummy.map(|v| v.to_string())),
            (
                "obfuscate-bytes",
                self.obfuscate_bytes.map(|v| v.to_string()),
            ),
            ("media-pt", self.media_pt.map(|v| v.to_string())),
            ("media-ssrc", self.media_ssrc.map(|v| v.to_string())),
            ("media-clock", self.media_clock.map(|v| v.to_string())),
        ];
        for (name, value) in settings {
            let Some(value) = value else { continue };
            if !config.set(name, &value).map_err(map)? {
                return Err(invalid(format!(
                    "WireGuard phobos: internal error, `{name}` is not a known setting"
                )));
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests;
