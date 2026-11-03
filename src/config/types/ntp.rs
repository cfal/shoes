use std::io;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::address::NetLocation;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NtpConfig {
    pub server: NetLocation,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_interval() -> u64 {
    1800
}
fn default_timeout() -> u64 {
    5
}

impl NtpConfig {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.server.port() == 0 {
            return Err(invalid("server port must be nonzero"));
        }
        if self.server.address().hostname().is_some_and(str::is_empty) {
            return Err(invalid("server host must be nonempty"));
        }
        if !(60..=86400).contains(&self.interval_secs) {
            return Err(invalid("interval_secs must be in 60..=86400"));
        }
        if !(1..=30).contains(&self.timeout_secs) {
            return Err(invalid("timeout_secs must be in 1..=30"));
        }
        if let Some(address) = self.server.to_socket_addr_nonblocking() {
            validate_server_ip(address.ip())?;
        }
        Ok(())
    }
}

pub(crate) fn validate_server_ip(ip: IpAddr) -> io::Result<()> {
    let ip = ip.to_canonical();
    if ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err(invalid("server must be a unicast address"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("global_settings.ntp: {message}"),
    )
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, create_server_configs};

    #[test]
    fn ntp_is_opt_in_and_round_trips_through_both_global_names() {
        for name in ["global_settings", "global_limits"] {
            for fields in ["{}", "{ntp: null}"] {
                let configs = serde_yaml::from_str(&format!("- {name}: {fields}")).unwrap();
                assert!(create_server_configs(configs).unwrap().ntp.is_none());
            }
            for server in ["time.example:123", "127.0.0.1:123", "[::1]:123"] {
                let configs: Vec<Config> =
                    serde_yaml::from_str(&format!("- {name}:\n    ntp:\n      server: '{server}'"))
                        .unwrap();
                let json = serde_json::to_value(&configs).unwrap();
                assert!(json[0].get("global_settings").is_some());
                let validated =
                    create_server_configs(serde_json::from_value(json).unwrap()).unwrap();
                let config = validated.ntp.unwrap();
                assert_eq!(config.interval_secs, 1800);
                assert_eq!(config.timeout_secs, 5);
                let yaml = serde_yaml::to_string(&configs).unwrap();
                let validated =
                    create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
                assert_eq!(validated.ntp.unwrap(), config);
            }
        }
    }

    #[test]
    fn ntp_rejects_invalid_config_without_network_access() {
        for fields in [
            "{}",
            "{server: ':123'}",
            "{server: 'time.example'}",
            "{server: '127.0.0.1:0'}",
            "{server: '0.0.0.0:123'}",
            "{server: '[::]:123'}",
            "{server: '[::ffff:0.0.0.0]:123'}",
            "{server: '224.0.0.1:123'}",
            "{server: '[ff02::1]:123'}",
            "{server: '[::ffff:224.0.0.1]:123'}",
            "{server: '255.255.255.255:123'}",
            "{server: '127.0.0.1:123', enabled: true}",
            "{server: '127.0.0.1:123', interval_secs: 59}",
            "{server: '127.0.0.1:123', interval_secs: 86401}",
            "{server: '127.0.0.1:123', timeout_secs: 0}",
            "{server: '127.0.0.1:123', timeout_secs: 31}",
            "{server: '127.0.0.1:123', timeout_secs: '5s'}",
        ] {
            let yaml = format!("- global_settings: {{ntp: {fields}}}");
            let result = serde_yaml::from_str(&yaml)
                .map_err(std::io::Error::other)
                .and_then(create_server_configs);
            assert!(result.is_err(), "{fields}");
        }
        for (interval, timeout) in [(60, 1), (86400, 30)] {
            let yaml = format!(
                "- global_settings: {{ntp: {{server: 'unresolvable.invalid:123', interval_secs: {interval}, timeout_secs: {timeout}}}}}"
            );
            create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
        }
    }
}
