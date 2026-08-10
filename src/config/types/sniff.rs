use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sniff::{SniffSettings, SniffedProtocol};

fn default_sniff_timeout_ms() -> u32 {
    300
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SniffProtocolConfig {
    Tls,
    Http,
}

impl From<SniffProtocolConfig> for SniffedProtocol {
    fn from(value: SniffProtocolConfig) -> Self {
        match value {
            SniffProtocolConfig::Tls => SniffedProtocol::Tls,
            SniffProtocolConfig::Http => SniffedProtocol::Http,
        }
    }
}

/// Accepts either one protocol name or a list of them.
///
/// Hand-written rather than reusing `NoneOrSome`, which is `#[serde(untagged)]`
/// and therefore reports "data did not match any variant" instead of naming
/// the protocol that was misspelled. For a config file the name matters.
fn deserialize_protocols<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<SniffProtocolConfig>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ProtocolsVisitor;

    impl<'de> serde::de::Visitor<'de> for ProtocolsVisitor {
        type Value = Option<Vec<SniffProtocolConfig>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a protocol name or a list of protocol names")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let one =
                SniffProtocolConfig::deserialize(serde::de::value::StrDeserializer::new(value))?;
            Ok(Some(vec![one]))
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut protocols = Vec::new();
            while let Some(protocol) = seq.next_element::<SniffProtocolConfig>()? {
                protocols.push(protocol);
            }
            Ok(Some(protocols))
        }
    }

    deserializer.deserialize_any(ProtocolsVisitor)
}

// No PartialEq: comparing two configs is only ever wanted in tests, and the
// fields that matter are compared directly there.
#[derive(Debug, Clone, Serialize)]
pub struct SniffConfig {
    pub enabled: bool,
    /// `None` means unspecified, which is every supported protocol. An
    /// explicitly empty list is a config error, caught in validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<SniffProtocolConfig>>,
    pub timeout_ms: u32,
}

impl SniffConfig {
    /// The runtime view, or `None` when this listener does not sniff.
    pub fn to_settings(&self) -> Option<SniffSettings> {
        if !self.enabled {
            return None;
        }
        let protocols: Vec<SniffedProtocol> = match &self.protocols {
            None => vec![SniffedProtocol::Tls, SniffedProtocol::Http],
            Some(listed) => listed.iter().map(|p| (*p).into()).collect(),
        };
        if protocols.is_empty() {
            return None;
        }
        Some(SniffSettings {
            protocols,
            timeout: Duration::from_millis(self.timeout_ms as u64),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SniffFields {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(
        alias = "protocol",
        default,
        deserialize_with = "deserialize_protocols"
    )]
    protocols: Option<Vec<SniffProtocolConfig>>,
    #[serde(default = "default_sniff_timeout_ms")]
    timeout_ms: u32,
}

impl<'de> Deserialize<'de> for SniffConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Hand-written rather than `#[serde(untagged)]`: an untagged enum
        // discards the inner error and reports "data did not match any
        // variant", which for a config file is useless. A visitor keeps
        // "unknown variant `tsl`, expected `tls` or `http`" intact.
        struct SniffVisitor;

        impl<'de> serde::de::Visitor<'de> for SniffVisitor {
            type Value = SniffConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a boolean or a sniff settings map")
            }

            fn visit_bool<E>(self, enabled: bool) -> Result<SniffConfig, E>
            where
                E: serde::de::Error,
            {
                Ok(SniffConfig {
                    enabled,
                    protocols: None,
                    timeout_ms: default_sniff_timeout_ms(),
                })
            }

            fn visit_map<M>(self, map: M) -> Result<SniffConfig, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let fields =
                    SniffFields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(SniffConfig {
                    enabled: fields.enabled,
                    protocols: fields.protocols,
                    timeout_ms: fields.timeout_ms,
                })
            }
        }

        deserializer.deserialize_any(SniffVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorthand_true_enables_both_protocols_with_the_default_timeout() {
        let config: SniffConfig = serde_yaml::from_str("true").unwrap();
        assert!(config.enabled);
        assert_eq!(config.timeout_ms, 300);

        let settings = config.to_settings().unwrap();
        assert_eq!(
            settings.protocols,
            vec![SniffedProtocol::Tls, SniffedProtocol::Http]
        );
        assert_eq!(settings.timeout, Duration::from_millis(300));
    }

    #[test]
    fn shorthand_false_disables() {
        let config: SniffConfig = serde_yaml::from_str("false").unwrap();
        assert!(!config.enabled);
        assert!(config.to_settings().is_none());
    }

    #[test]
    fn a_map_without_enabled_is_enabled() {
        let config: SniffConfig = serde_yaml::from_str("protocols: [tls]").unwrap();
        assert!(config.enabled);
        let settings = config.to_settings().unwrap();
        assert_eq!(settings.protocols, vec![SniffedProtocol::Tls]);
    }

    #[test]
    fn a_single_protocol_may_be_written_without_a_list() {
        let config: SniffConfig = serde_yaml::from_str("protocol: http").unwrap();
        assert_eq!(
            config.to_settings().unwrap().protocols,
            vec![SniffedProtocol::Http]
        );
    }

    #[test]
    fn timeout_is_read_in_milliseconds() {
        let config: SniffConfig = serde_yaml::from_str("enabled: true\ntimeout_ms: 50").unwrap();
        assert_eq!(
            config.to_settings().unwrap().timeout,
            Duration::from_millis(50)
        );
    }

    #[test]
    fn a_zero_timeout_is_accepted() {
        let config: SniffConfig = serde_yaml::from_str("enabled: true\ntimeout_ms: 0").unwrap();
        assert_eq!(
            config.to_settings().unwrap().timeout,
            Duration::from_millis(0)
        );
    }

    #[test]
    fn an_unknown_protocol_is_rejected_by_name() {
        let error = serde_yaml::from_str::<SniffConfig>("protocols: [tsl]")
            .expect_err("tsl is not a protocol");
        let message = error.to_string();
        assert!(message.contains("tls"), "message was: {message}");
        assert!(message.contains("http"), "message was: {message}");
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        serde_yaml::from_str::<SniffConfig>("enabled: true\nsniff_timeout: 5")
            .expect_err("sniff_timeout is not a field");
    }

    #[test]
    fn round_trips_through_yaml() {
        let config: SniffConfig =
            serde_yaml::from_str("enabled: true\nprotocols: [tls]\ntimeout_ms: 120").unwrap();
        let encoded = serde_yaml::to_string(&config).unwrap();
        let decoded: SniffConfig = serde_yaml::from_str(&encoded).unwrap();

        assert_eq!(decoded.enabled, config.enabled);
        assert_eq!(decoded.timeout_ms, config.timeout_ms);
        assert_eq!(
            decoded.to_settings().unwrap().protocols,
            config.to_settings().unwrap().protocols
        );
    }

    #[test]
    fn an_unspecified_protocol_list_is_omitted_when_serialized() {
        let config: SniffConfig = serde_yaml::from_str("true").unwrap();
        let encoded = serde_yaml::to_string(&config).unwrap();
        assert!(
            !encoded.contains("protocols"),
            "an empty list would not deserialize back; encoded was: {encoded}"
        );
    }
}
