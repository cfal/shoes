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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Obfuscation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hopping: Option<HoppingConfig>,
    #[serde(default = "super::common::default_true")]
    pub udp_enabled: bool,
}

impl Hysteria2ClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        http::HeaderValue::from_str(&self.password.0)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid HY2 auth header"))?;
        if self
            .obfs
            .as_ref()
            .is_some_and(|obfs| obfs.password().0.len() < 4)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander password must contain at least 4 bytes",
            ));
        }
        if let Some(hopping) = &self.hopping {
            hopping.parse_ports()?;
            hopping.interval()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Obfuscation {
    Salamander { password: Secret },
}

impl Obfuscation {
    pub fn password(&self) -> &Secret {
        match self {
            Self::Salamander { password } => password,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoppingConfig {
    pub ports: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interval_secs: Option<u64>,
}

impl HoppingConfig {
    pub(crate) fn parse_ports(&self) -> io::Result<Vec<u16>> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid HY2 hopping ports: expected ports or inclusive start-end ranges in 1..65535",
            )
        };
        let mut ports = std::collections::BTreeSet::new();
        for part in self.ports.split(',') {
            let (start, end) = part.split_once('-').unwrap_or((part, part));
            let start: u16 = start.trim().parse().map_err(|_| invalid())?;
            let end: u16 = end.trim().parse().map_err(|_| invalid())?;
            if start == 0 || end < start {
                return Err(invalid());
            }
            ports.extend(start..=end);
        }
        Ok(ports.into_iter().collect())
    }

    pub(crate) fn interval(&self) -> io::Result<(u64, u64)> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "HY2 hopping requires interval_secs (default 30) or an ordered min_interval_secs/max_interval_secs pair, at least 5 seconds",
            )
        };
        let (min, max) = match (
            self.interval_secs,
            self.min_interval_secs,
            self.max_interval_secs,
        ) {
            (None, None, None) => (30, 30),
            (Some(interval), None, None) => (interval, interval),
            (None, Some(min), Some(max)) => (min, max),
            _ => return Err(invalid()),
        };
        if min < 5
            || max < min
            || std::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(max))
                .is_none()
        {
            return Err(invalid());
        }
        Ok((min, max))
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
    use super::HoppingConfig;
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

    #[test]
    fn hopping_ranges_and_intervals_are_validated() {
        let mut config = HoppingConfig {
            ports: "443, 1000-1002,443,65535".into(),
            interval_secs: None,
            min_interval_secs: None,
            max_interval_secs: None,
        };
        assert_eq!(
            config.parse_ports().unwrap(),
            [443, 1000, 1001, 1002, 65535]
        );
        assert_eq!(config.interval().unwrap(), (30, 30));
        config.min_interval_secs = Some(5);
        config.max_interval_secs = Some(10);
        assert_eq!(config.interval().unwrap(), (5, 10));
        config.interval_secs = Some(5);
        assert!(config.interval().is_err());
        config.interval_secs = None;
        config.max_interval_secs = None;
        assert!(config.interval().is_err());
        config.max_interval_secs = Some(4);
        assert!(config.interval().is_err());
        for ports in ["", "0", "443,0", "65536", "3-1", "1-", "1:3"] {
            config.ports = ports.into();
            assert!(config.parse_ports().is_err());
        }
    }
}
