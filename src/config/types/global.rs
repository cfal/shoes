use serde::{Deserialize, Serialize};

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
            quic_socket_buffer: 1 << 20,
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
                    format!("global_limits.{name} must be in 1..={max}; omit it for unlimited"),
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
                    format!("global_limits.{name} must be in {min}..={max}"),
                ));
            }
        }
        if self.reload_grace_secs > 86400 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "global_limits.reload_grace_secs must be at most 86400",
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
        for yaml in ["[]", "- global_limits:", "- global_limits: {}"] {
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
        }
    }

    #[test]
    fn limits_round_trip_and_do_not_become_listeners() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"- global_limits:
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
    fn duplicate_entries_are_rejected_even_when_empty() {
        for yaml in [
            "- global_limits:\n- global_limits:",
            "- global_limits: {}\n- global_limits: {max_connections: 2}",
        ] {
            let error = create_server_configs(serde_yaml::from_str(yaml).unwrap())
                .err()
                .unwrap();
            assert!(error.to_string().contains("only be specified once"));
        }
        let mut configs: Vec<Config> = serde_yaml::from_str("- global_limits: {}").unwrap();
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
            "reload_grace_secs: 86401",
        ] {
            let configs = serde_yaml::from_str(&format!("- global_limits: {{{fields}}}")).unwrap();
            assert!(create_server_configs(configs).is_err(), "accepted {fields}");
        }
        for yaml in [
            "- global_limits: {unknown: 2}",
            "- global_limits: {}\n  address: '0.0.0.0:1080'",
            "- global_limits: false",
        ] {
            assert!(serde_yaml::from_str::<Vec<Config>>(yaml).is_err());
        }
    }
}
