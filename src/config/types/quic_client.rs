use std::{fmt, io};

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2ClientConfig {
    pub password: Secret,
    #[serde(default = "super::common::default_true")]
    pub udp_enabled: bool,
}

impl Hysteria2ClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        http::HeaderValue::from_str(&self.password.0)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid HY2 auth header"))?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TuicUdpMode {
    #[default]
    Native,
    Quic,
}

fn default_heartbeat() -> u64 {
    10
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TuicClientConfig {
    pub uuid: Secret,
    pub password: Secret,
    #[serde(default)]
    pub udp_relay_mode: TuicUdpMode,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "super::common::default_true")]
    pub udp_enabled: bool,
}

impl TuicClientConfig {
    pub fn uuid_bytes(&self) -> io::Result<[u8; 16]> {
        if !matches!(self.uuid.0.len(), 32 | 36) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC requires a hexadecimal UUID",
            ));
        }
        uuid::Uuid::parse_str(&self.uuid.0)
            .map(|id| *id.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TUIC UUID"))
    }
    pub fn validate(&self) -> io::Result<()> {
        self.uuid_bytes()?;
        if !(1..=30).contains(&self.heartbeat_interval_secs) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC heartbeat_interval_secs must be 1..=30",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{ClientConfig, Transport};

    #[test]
    fn hy2_defaults_and_validation() {
        let config: ClientConfig = serde_yaml::from_str(
            "address: '127.0.0.1:443'\nprotocol: {type: hy2, password: secret}",
        )
        .unwrap();
        assert_eq!(config.transport, Transport::Quic);
        assert!(!format!("{config:?}").contains("secret"));
        assert!(crate::quic_client::validate(&config, true).is_ok());
        assert!(crate::quic_client::validate(&config, false).is_err());
        for field in ["up_mbps: 1", "zero_rtt: true", "typo: true"] {
            assert!(
                serde_yaml::from_str::<ClientConfig>(&format!(
                    "address: '127.0.0.1:443'\nprotocol: {{type: hy2, password: secret, {field}}}"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn tuic_defaults_and_strict_uuid_validation() {
        let base = "address: '127.0.0.1:443'\nprotocol: {type: tuic, password: secret-password, uuid: '01234567-89ab-1def-0123-456789abcdef'}";
        let config: ClientConfig = serde_yaml::from_str(base).unwrap();
        assert_eq!(config.transport, Transport::Quic);
        assert!(crate::quic_client::validate(&config, true).is_ok());
        assert!(!format!("{config:?}").contains("secret-password"));
        assert!(!format!("{config:?}").contains("01234567"));
        for invalid in [
            base.replace("01234567-89ab-1def-0123-456789abcdef", "named-user"),
            base.replace("type: tuic", "type: tuic, heartbeat_interval_secs: 0"),
        ] {
            let config = serde_yaml::from_str(&invalid).unwrap();
            assert!(crate::quic_client::validate(&config, true).is_err());
        }
    }
}
