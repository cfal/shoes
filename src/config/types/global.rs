use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize)]
pub struct GlobalSettings {
    #[serde(flatten)]
    pub limits: GlobalLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_cache_dir: Option<std::path::PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_dns: Option<super::dns::DnsConfig>,
}

impl<'de> Deserialize<'de> for GlobalSettings {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        use serde_yaml::{Mapping, Value};

        // Splitting the map preserves strict limit validation without flatten + deny_unknown_fields.
        let mut fields = Mapping::deserialize(deserializer)?;
        let rule_cache_dir = match fields.remove("rule_cache_dir") {
            Some(value) => serde_yaml::from_value(value).map_err(Error::custom)?,
            None => None,
        };
        let default_dns = match fields.remove("default_dns") {
            Some(value) => serde_yaml::from_value(value).map_err(Error::custom)?,
            None => None,
        };
        let limits = serde_yaml::from_value(Value::Mapping(fields)).map_err(Error::custom)?;
        Ok(Self {
            limits,
            rule_cache_dir,
            default_dns,
        })
    }
}

/// Omitted admission caps are unlimited; transport buffer sizes remain finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalLimits {
    pub max_connections: Option<usize>,
    pub max_connections_per_ip: Option<usize>,
    pub max_streams: Option<usize>,
    pub max_streams_per_connection: Option<usize>,
    pub max_udp_destinations: Option<usize>,
    pub quic_memory_bytes: Option<usize>,
    pub quic_receive_window: usize,
    pub quic_send_window: usize,
    pub quic_stream_window: usize,
    /// Admission estimate for Hickory's private H3 transport, not a hard buffer limit.
    pub quic_dns_memory_bytes: usize,
    pub quic_socket_buffer: usize,
    pub reload_grace_secs: u64,
}

impl Default for GlobalLimits {
    fn default() -> Self {
        Self {
            max_connections: None,
            max_connections_per_ip: None,
            max_streams: None,
            max_streams_per_connection: None,
            max_udp_destinations: None,
            quic_memory_bytes: None,
            quic_receive_window: 2 << 20,
            quic_send_window: 2 << 20,
            quic_stream_window: 256 << 10,
            quic_dns_memory_bytes: 16 << 20,
            quic_socket_buffer: 8 << 20,
            reload_grace_secs: 300,
        }
    }
}

impl GlobalLimits {
    pub fn validate(&self) -> std::io::Result<()> {
        for (name, value, max) in [
            ("max_connections", self.max_connections, usize::MAX),
            (
                "max_connections_per_ip",
                self.max_connections_per_ip,
                usize::MAX,
            ),
            ("max_streams", self.max_streams, usize::MAX),
            (
                "max_streams_per_connection",
                self.max_streams_per_connection,
                65535,
            ),
            (
                "max_udp_destinations",
                self.max_udp_destinations,
                usize::MAX,
            ),
            ("quic_memory_bytes", self.quic_memory_bytes, usize::MAX),
        ] {
            if value.is_some_and(|value| value == 0 || value > max) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("global_settings.{name} must be in 1..={max}; omit it for unlimited"),
                ));
            }
        }
        for (name, value, min, max) in [
            (
                "quic_receive_window",
                self.quic_receive_window,
                65536,
                64 << 20,
            ),
            ("quic_send_window", self.quic_send_window, 65536, 64 << 20),
            (
                "quic_stream_window",
                self.quic_stream_window,
                16384,
                64 << 20,
            ),
            (
                "quic_dns_memory_bytes",
                self.quic_dns_memory_bytes,
                1 << 20,
                1 << 30,
            ),
            (
                "quic_socket_buffer",
                self.quic_socket_buffer,
                65536,
                16 << 20,
            ),
        ] {
            if !(min..=max).contains(&value) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("global_settings.{name} must be in {min}..={max}"),
                ));
            }
        }
        if self.reload_grace_secs > 86400 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "global_settings.reload_grace_secs must be at most 86400",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, create_server_configs};

    #[test]
    fn omitted_and_empty_limits_are_unlimited() {
        for yaml in [
            "[]",
            "- global_settings:",
            "- global_settings: {}",
            "- global_limits:",
            "- global_limits: {}",
        ] {
            let configs = serde_yaml::from_str(yaml).unwrap();
            let result = create_server_configs(configs).unwrap();
            assert!(result.configs.is_empty());
            assert_eq!(result.global_limits, GlobalLimits::default());
            assert!(result.global_limits.max_connections.is_none());
            assert!(result.global_limits.max_connections_per_ip.is_none());
            assert!(result.global_limits.max_streams.is_none());
            assert!(result.global_limits.max_streams_per_connection.is_none());
            assert!(result.global_limits.max_udp_destinations.is_none());
            assert!(result.global_limits.quic_memory_bytes.is_none());
            assert_eq!(result.global_limits.quic_socket_buffer, 8 << 20);
        }
    }

    #[test]
    fn limits_round_trip_and_do_not_become_listeners() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"- global_settings:
    max_connections: 1024
    reload_grace_secs: 0
- address: '0.0.0.0:1080'
  protocol:
    type: socks
"#,
        )
        .unwrap();
        let serialized = serde_yaml::to_string(&configs).unwrap();
        let result = create_server_configs(serde_yaml::from_str(&serialized).unwrap()).unwrap();
        assert_eq!(result.global_limits.max_connections, Some(1024));
        assert_eq!(result.global_limits.reload_grace_secs, 0);
        assert_eq!(result.configs.len(), 1);
    }

    #[test]
    fn quic_socket_buffer_override_is_preserved() {
        let configs =
            serde_yaml::from_str("- global_settings: {quic_socket_buffer: 65536}").unwrap();
        let result = create_server_configs(configs).unwrap();
        assert_eq!(result.global_limits.quic_socket_buffer, 65536);
    }

    #[test]
    fn duplicate_entries_are_rejected_even_when_empty() {
        for yaml in [
            "- global_settings:\n- global_settings:",
            "- global_settings: {}\n- global_limits: {max_connections: 2}",
            "- global_limits:\n- global_settings:",
            "- global_limits:\n- global_limits:",
            "- global_limits: {}\n- global_limits: {max_connections: 2}",
        ] {
            let error = create_server_configs(serde_yaml::from_str(yaml).unwrap())
                .err()
                .unwrap();
            assert!(error.to_string().contains("only be specified once"));
        }
        let mut configs: Vec<Config> = serde_yaml::from_str("- global_settings: {}").unwrap();
        configs.extend(serde_yaml::from_str::<Vec<Config>>("- global_limits: {}").unwrap());
        assert!(create_server_configs(configs).is_err());
    }

    #[test]
    fn invalid_limits_and_unknown_fields_are_rejected() {
        for fields in [
            "max_connections: 0",
            "max_streams: 0",
            "quic_memory_bytes: 0",
            "quic_receive_window: 1",
            "quic_send_window: 67108865",
            "quic_dns_memory_bytes: 0",
            "quic_socket_buffer: 0",
            "quic_socket_buffer: 16777217",
            "reload_grace_secs: 86401",
        ] {
            for name in ["global_settings", "global_limits"] {
                let configs = serde_yaml::from_str(&format!("- {name}: {{{fields}}}")).unwrap();
                assert!(create_server_configs(configs).is_err(), "accepted {fields}");
            }
        }
        for name in ["global_settings", "global_limits"] {
            for fields in [
                "{unknown: 2}",
                "{rule_cache_dir: ./cache, unknown: 2}",
                "{limits: {max_connections: 2}}",
                "{rule_cache_dir: []}",
                "{}\n  address: '0.0.0.0:1080'",
                "false",
                "[]",
                "{}\n  global_settings: null",
                "{}\n  global_limits: null",
                "null\n  global_settings: {}",
                "null\n  global_limits: {}",
            ] {
                let yaml = format!("- {name}: {fields}");
                assert!(
                    serde_yaml::from_str::<Vec<Config>>(&yaml).is_err(),
                    "{yaml}"
                );
            }
        }
    }

    #[test]
    fn alias_round_trips_as_flat_global_settings() {
        for name in ["global_settings", "global_limits"] {
            for cache in ["null", "./cache"] {
                let yaml = format!(
                    "- {name}: {{max_connections: 42, reload_grace_secs: 7, rule_cache_dir: {cache}, default_dns: {{servers: system, fake_ip: false}}}}"
                );
                let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
                let Config::GlobalSettings(settings) = &configs[0] else {
                    panic!("expected global settings");
                };
                assert_eq!(settings.limits.max_connections, Some(42));
                assert_eq!(settings.limits.reload_grace_secs, 7);
                assert_eq!(settings.limits.quic_socket_buffer, 8 << 20);
                assert_eq!(
                    settings.rule_cache_dir,
                    (cache != "null").then(|| cache.into())
                );
                let json = serde_json::to_value(&configs).unwrap();
                assert!(json[0].get("global_limits").is_none());
                assert!(json[0]["global_settings"].get("limits").is_none());
                assert_eq!(json[0]["global_settings"]["max_connections"], 42);
                assert_eq!(
                    json[0]["global_settings"]["default_dns"]["servers"],
                    "system"
                );
                assert_eq!(json[0]["global_settings"]["default_dns"]["fake_ip"], false);
                let decoded: Vec<Config> = serde_json::from_value(json.clone()).unwrap();
                assert_eq!(serde_json::to_value(decoded).unwrap(), json);
                let serialized = serde_yaml::to_string(&configs).unwrap();
                let decoded: Vec<Config> = serde_yaml::from_str(&serialized).unwrap();
                assert_eq!(serde_json::to_value(decoded).unwrap(), json);
            }
        }
    }

    #[test]
    fn standalone_cache_directory_has_migration_error() {
        let error = serde_yaml::from_str::<Vec<Config>>("- rule_cache_dir: ./cache").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("rule_cache_dir must be inside global_settings")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn settings_cache_directory_is_anchored_to_declaring_file_without_creating_it() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.yaml");
        let cache = dir.path().join("cache");
        for name in ["global_settings", "global_limits"] {
            std::fs::write(
                &file,
                format!("- {name}: {{max_connections: 42, rule_cache_dir: ./cache}}"),
            )
            .unwrap();
            let configs = crate::config::load_configs(&[file.to_str().unwrap().into()])
                .await
                .unwrap();
            let validated = create_server_configs(configs).unwrap();
            assert_eq!(validated.rule_cache_dir.as_ref(), Some(&cache));
            assert_eq!(validated.global_limits.max_connections, Some(42));
            assert!(!cache.exists());

            let other = dir.path().join("other.yaml");
            std::fs::write(&other, "- global_settings: {}").unwrap();
            let error = crate::config::load_configs(&[
                file.to_str().unwrap().into(),
                other.to_str().unwrap().into(),
            ])
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("only be specified once"),
                "{error}"
            );
            assert!(!cache.exists());
        }
    }
}
