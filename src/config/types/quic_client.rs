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
}
