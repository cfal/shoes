use std::{fmt, io};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub(super) fn reject_client_decryption<'de, D: serde::Deserializer<'de>>(
    _: D,
) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "VLESS client uses encryption, not decryption",
    ))
}

pub(super) fn reject_server_encryption<'de, D: serde::Deserializer<'de>>(
    _: D,
) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "VLESS server uses decryption, not encryption",
    ))
}

/// Exportable configuration credential, never included in diagnostic output.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct VlessEncryptionSetting(String);

impl VlessEncryptionSetting {
    pub fn is_disabled(&self) -> bool {
        matches!(self.0.as_str(), "" | "none")
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for VlessEncryptionSetting {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for VlessEncryptionSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_disabled() {
            "Disabled"
        } else {
            "[REDACTED]"
        })
    }
}

impl Drop for VlessEncryptionSetting {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct VlessEncryptionLimits {
    pub max_sessions: usize,
    pub max_replays: usize,
    pub max_replays_per_session: usize,
}

impl Default for VlessEncryptionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 4096,
            max_replays: 262144,
            max_replays_per_session: 65536,
        }
    }
}

impl VlessEncryptionLimits {
    pub fn validate(&self) -> io::Result<()> {
        if self.max_sessions == 0 || self.max_replays == 0 || self.max_replays_per_session == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VLESS encryption_limits counts must be positive",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_side_settings_are_rejected_without_echoing_values() {
        for value in ["private-key-must-not-appear", "none", "null", "true", "{}"] {
            let config = format!(
                "type: vless\nuser_id: 550e8400-e29b-41d4-a716-446655440000\ndecryption: {value}"
            );
            let error = serde_yaml::from_str::<crate::config::ClientProxyConfig>(&config)
                .unwrap_err()
                .to_string();
            assert!(error.contains("VLESS client uses encryption, not decryption"));
            assert!(!error.contains("private-key-must-not-appear"));
            let config = config.replace("decryption:", "encryption:");
            let error = serde_yaml::from_str::<crate::config::ServerProxyConfig>(&config)
                .unwrap_err()
                .to_string();
            assert!(error.contains("VLESS server uses decryption, not encryption"));
            assert!(!error.contains("private-key-must-not-appear"));
        }
    }

    #[test]
    fn settings_redact_debug_but_preserve_exports() {
        let setting = VlessEncryptionSetting::from("private configuration".to_owned());
        assert_eq!(format!("{setting:?}"), "[REDACTED]");
        let exported = serde_yaml::to_string(&setting).unwrap();
        let parsed: VlessEncryptionSetting = serde_yaml::from_str(&exported).unwrap();
        assert_eq!(parsed.as_str(), setting.as_str());
        assert!(VlessEncryptionSetting::default().is_disabled());
        assert!(VlessEncryptionSetting::from("none".to_owned()).is_disabled());
    }

    #[test]
    fn finite_limits_round_trip_and_reject_zero() {
        let limits: VlessEncryptionLimits = serde_yaml::from_str("{}").unwrap();
        assert_eq!(limits, VlessEncryptionLimits::default());
        limits.validate().unwrap();
        for field in ["max_sessions", "max_replays", "max_replays_per_session"] {
            let limits: VlessEncryptionLimits =
                serde_yaml::from_str(&format!("{field}: 0")).unwrap();
            assert!(limits.validate().is_err());
        }
        assert!(serde_yaml::from_str::<VlessEncryptionLimits>("unknown: 10").is_err());
    }
}
