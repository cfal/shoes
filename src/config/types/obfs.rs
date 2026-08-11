//! Obfuscation configuration, shared by the Hysteria2 client and server.

use serde::{Deserialize, Serialize};

use super::redacted::Redacted;

/// QUIC packet obfuscation.
///
/// Internally tagged with the per-type fields alongside, which is the shape
/// both the reference implementation and sing-box use. `gecko` - the other
/// official type, which adds handshake packet fragmentation on top of
/// Salamander's scrambling - slots in here with its `min_packet_size` and
/// `max_packet_size` without a schema change.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ObfsConfig {
    Salamander { password: Redacted<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_salamander() {
        let yaml = r#"
type: salamander
password: obfspass
"#;
        let config: ObfsConfig = serde_yaml::from_str(yaml).unwrap();
        let ObfsConfig::Salamander { password } = &config;
        assert_eq!(password.expose(), "obfspass");
    }

    #[test]
    fn test_rejects_unknown_type() {
        let yaml = r#"
type: gecko
password: obfspass
"#;
        let err = serde_yaml::from_str::<ObfsConfig>(yaml)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("salamander"),
            "error should name the supported types: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field() {
        let yaml = r#"
type: salamander
password: obfspass
min_packet_size: 512
"#;
        let err = serde_yaml::from_str::<ObfsConfig>(yaml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("min_packet_size"), "{err}");
    }

    #[test]
    fn test_round_trip() {
        let config = ObfsConfig::Salamander {
            password: "obfspass".into(),
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let back: ObfsConfig = serde_yaml::from_str(&yaml).unwrap();
        let ObfsConfig::Salamander { password } = &back;
        assert_eq!(password.expose(), "obfspass");
    }
}
