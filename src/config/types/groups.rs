//! Configuration group types (top-level Config, groups, and NamedPem).

use serde::{Deserialize, Serialize};

use crate::option_util::OneOrSome;

use super::client::ClientConfig;
use super::rules::RuleConfig;
use super::selection::ConfigSelection;
use super::server::ServerConfig;
use super::tun::TunConfig;

/// A named group of client proxies.
///
/// Groups can reference other groups using `ConfigSelection::GroupName`.
/// Group references are resolved using topological sort during validation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfigGroup {
    pub client_group: String,
    #[serde(alias = "client_proxy")]
    pub client_proxies: OneOrSome<ConfigSelection<ClientConfig>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfigGroup {
    pub rule_group: String,
    #[serde(alias = "rule")]
    pub rules: OneOrSome<RuleConfig>,
}

#[derive(Debug, Clone)]
pub struct NamedPem {
    pub pem: String, // The name identifier
    pub source: PemSource,
}

#[derive(Debug, Clone)]
pub enum PemSource {
    Path(String),
    Data(String),
}

impl<'de> Deserialize<'de> for NamedPem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use std::fmt;

        struct NamedPemVisitor;

        impl<'de> Visitor<'de> for NamedPemVisitor {
            type Value = NamedPem;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a NamedPem with 'pem' and either 'path' or 'data' fields")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut pem_name: Option<String> = None;
                let mut path: Option<String> = None;
                let mut data: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "pem" => {
                            if pem_name.is_some() {
                                return Err(Error::duplicate_field("pem"));
                            }
                            pem_name = Some(map.next_value()?);
                        }
                        "path" => {
                            if path.is_some() {
                                return Err(Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                        "data" => {
                            if data.is_some() {
                                return Err(Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?);
                        }
                        _ => {
                            // Ignore unknown fields
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let pem_name = pem_name.ok_or_else(|| Error::missing_field("pem"))?;

                let source = match (path, data) {
                    (Some(p), None) => PemSource::Path(p),
                    (None, Some(d)) => PemSource::Data(d),
                    (Some(_), Some(_)) => {
                        return Err(Error::custom(
                            "NamedPem cannot have both 'path' and 'data' fields",
                        ));
                    }
                    (None, None) => {
                        return Err(Error::custom(
                            "NamedPem must have either 'path' or 'data' field",
                        ));
                    }
                };

                Ok(NamedPem {
                    pem: pem_name,
                    source,
                })
            }
        }

        deserializer.deserialize_map(NamedPemVisitor)
    }
}

impl Serialize for NamedPem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("pem", &self.pem)?;

        match &self.source {
            PemSource::Path(path) => {
                map.serialize_entry("path", path)?;
            }
            PemSource::Data(data) => {
                map.serialize_entry("data", data)?;
            }
        }

        map.end()
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Config {
    Server(ServerConfig),
    /// TUN device server - accepts IP packets from a TUN device.
    /// This is separate from Server because TUN doesn't use bind_location or transport.
    TunServer(TunConfig),
    ClientConfigGroup(ClientConfigGroup),
    RuleConfigGroup(RuleConfigGroup),
    NamedPem(NamedPem),
}

impl<'de> serde::de::Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        use serde_yaml::Value;

        // First deserialize to a generic Value to inspect the structure
        let value = Value::deserialize(deserializer)?;

        // Check if it's a mapping (as all our configs should be)
        let map = value.as_mapping().ok_or_else(|| {
            Error::custom("Expected a YAML mapping for Config, but found a different type")
        })?;

        // Look for discriminating fields
        let has_client_group = map.contains_key(Value::String("client_group".to_string()));
        let has_rule_group = map.contains_key(Value::String("rule_group".to_string()));
        let has_address = map.contains_key(Value::String("address".to_string()));
        let has_path_field = map.contains_key(Value::String("path".to_string()));
        let has_pem = map.contains_key(Value::String("pem".to_string()));

        // Check if this is a TUN config
        // TUN configs have 'device_name' (Linux) or 'device_fd' (iOS/Android)
        // These fields are unique to TUN and don't appear in other config types
        let has_device_name = map.contains_key(Value::String("device_name".to_string()));
        let has_device_fd = map.contains_key(Value::String("device_fd".to_string()));
        let is_tun_config = has_device_name || has_device_fd;

        // Try to determine which variant based on fields
        if has_pem {
            // NamedPem (pem field is unique to NamedPem)
            serde_yaml::from_value(value)
                .map(Config::NamedPem)
                .map_err(|e| Error::custom(format!("invalid named PEM config: {e}")))
        } else if has_client_group {
            // ClientConfigGroup
            serde_yaml::from_value(value)
                .map(Config::ClientConfigGroup)
                .map_err(|e| Error::custom(format!("invalid client config group: {e}")))
        } else if has_rule_group {
            // RuleConfigGroup
            serde_yaml::from_value(value)
                .map(Config::RuleConfigGroup)
                .map_err(|e| Error::custom(format!("invalid rule config group: {e}")))
        } else if is_tun_config {
            // TunConfig - identified by having 'name' or 'raw_fd' without 'protocol' wrapper
            serde_yaml::from_value(value)
                .map(Config::TunServer)
                .map_err(|e| Error::custom(format!("invalid TUN config: {e}")))
        } else if has_address || has_path_field {
            // ServerConfig - its custom deserializer validates unknown fields
            serde_yaml::from_value(value)
                .map(Config::Server)
                .map_err(|e| Error::custom(format!("invalid server config: {e}")))
        } else {
            // Provide a helpful error message listing what fields we found
            let found_fields: Vec<String> = map
                .keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .collect();

            Err(Error::custom(format!(
                "Unable to determine config type. Found fields: {found_fields:?}. Expected one of:\n\
                - Server config: must have 'address' or 'path' field\n\
                - Client config group: must have 'client_group' field\n\
                - Rule config group: must have 'rule_group' field"
            )))
        }
    }
}

impl serde::ser::Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            Config::Server(server) => server.serialize(serializer),
            Config::TunServer(tun) => tun.serialize(serializer),
            Config::ClientConfigGroup(group) => group.serialize(serializer),
            Config::RuleConfigGroup(group) => group.serialize(serializer),
            Config::NamedPem(pem) => pem.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{NetLocation, NetLocationMask};
    use crate::config::types::client::ClientProxyConfig;
    use crate::config::types::rules::ClientChain;
    use crate::config::types::rules::{ClientChainHop, RuleActionConfig};
    use crate::config::types::transport::Transport;
    use crate::option_util::NoneOrSome;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_client_config() -> ClientConfig {
        ClientConfig {
            bind_interface: crate::option_util::NoneOrOne::One("eth0".to_string()),
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1080),
            protocol: ClientProxyConfig::Socks {
                username: Some("client_user".to_string()),
                password: Some("client_pass".to_string()),
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
        }
    }

    fn create_test_rule_config() -> RuleConfig {
        RuleConfig {
            masks: OneOrSome::Some(vec![
                NetLocationMask::from("192.168.0.0/16:80").unwrap(),
                NetLocationMask::from("10.0.0.0/8:443").unwrap(),
            ]),
            action: RuleActionConfig::Allow {
                override_address: Some(NetLocation::from_ip_addr(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    8080,
                )),
                client_chains: NoneOrSome::One(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        "test-proxy-group".to_string(),
                    ))),
                }),
            },
        }
    }

    #[test]
    fn test_client_config_group() {
        let original = vec![Config::ClientConfigGroup(ClientConfigGroup {
            client_group: "test-client-group".to_string(),
            client_proxies: OneOrSome::Some(vec![
                ConfigSelection::Config(create_test_client_config()),
                ConfigSelection::Config(ClientConfig {
                    bind_interface: crate::option_util::NoneOrOne::None,
                    address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                    protocol: ClientProxyConfig::Http {
                        username: None,
                        password: None,
                    },
                    transport: Transport::Tcp,
                    tcp_settings: None,
                    quic_settings: None,
                }),
            ]),
        })];

        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::ClientConfigGroup(group) = &deserialized[0] {
            assert_eq!(group.client_group, "test-client-group");
            // Check that we have the correct number of proxies by converting to vec
            match &group.client_proxies {
                OneOrSome::Some(vec) => assert_eq!(vec.len(), 2),
                OneOrSome::One(_) => panic!("Expected Some(vec), got One"),
            }
        } else {
            panic!("Expected client config group");
        }
    }

    #[test]
    fn test_client_config_group_with_group_refs() {
        let yaml = r#"
client_group: all-proxies
client_proxies:
  - us-proxies
  - eu-proxies
"#;
        let group: ClientConfigGroup = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(group.client_group, "all-proxies");
        let proxies: Vec<_> = group.client_proxies.into_vec();
        assert_eq!(proxies.len(), 2);
        assert!(matches!(&proxies[0], ConfigSelection::GroupName(n) if n == "us-proxies"));
        assert!(matches!(&proxies[1], ConfigSelection::GroupName(n) if n == "eu-proxies"));
    }

    #[test]
    fn test_client_config_group_mixed() {
        let yaml = r#"
client_group: mixed-group
client_proxies:
  - other-group
  - address: "127.0.0.1:1080"
    protocol:
      type: direct
"#;
        let group: ClientConfigGroup = serde_yaml::from_str(yaml).unwrap();
        let proxies: Vec<_> = group.client_proxies.into_vec();
        assert_eq!(proxies.len(), 2);
        assert!(matches!(&proxies[0], ConfigSelection::GroupName(_)));
        assert!(matches!(&proxies[1], ConfigSelection::Config(_)));
    }

    #[test]
    fn test_rule_config_group() {
        let original = vec![Config::RuleConfigGroup(RuleConfigGroup {
            rule_group: "test-rule-group".to_string(),
            rules: OneOrSome::Some(vec![
                create_test_rule_config(),
                RuleConfig {
                    masks: OneOrSome::One(NetLocationMask::ANY),
                    action: RuleActionConfig::Block,
                },
            ]),
        })];

        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::RuleConfigGroup(group) = &deserialized[0] {
            assert_eq!(group.rule_group, "test-rule-group");
            // Check that we have the correct number of rules by pattern matching
            match &group.rules {
                OneOrSome::Some(vec) => assert_eq!(vec.len(), 2),
                OneOrSome::One(_) => panic!("Expected Some(vec), got One"),
            }
        } else {
            panic!("Expected rule config group");
        }
    }

    #[test]
    fn test_config_error_messages() {
        // Test invalid config with no recognized fields
        let invalid_yaml = r#"
        - foo: bar
          baz: qux
        "#;

        let result: Result<Vec<Config>, _> = serde_yaml::from_str(invalid_yaml);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        println!("Error for invalid config: {error_msg}");
        assert!(error_msg.contains("Unable to determine config type"));
        assert!(error_msg.contains("Found fields: "));
        assert!(error_msg.contains("foo"));
        assert!(error_msg.contains("baz"));
    }

    #[test]
    fn test_named_pem() {
        // Test with path
        let pem_with_path = NamedPem {
            pem: "my-server-pem".to_string(),
            source: PemSource::Path("/etc/certs/server.pem".to_string()),
        };

        let yaml = serde_yaml::to_string(&pem_with_path).unwrap();
        println!("NamedPem with path YAML:\n{yaml}");
        assert!(yaml.contains("pem: my-server-pem"));
        assert!(yaml.contains("path: /etc/certs/server.pem"));

        let deserialized: NamedPem = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.pem, "my-server-pem");
        match deserialized.source {
            PemSource::Path(p) => assert_eq!(p, "/etc/certs/server.pem"),
            _ => panic!("Expected Path source"),
        }

        // Test with data (combined cert and key)
        let pem_with_data = NamedPem {
            pem: "inline-pem".to_string(),
            source: PemSource::Data(
                "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHI...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----".to_string(),
            ),
        };

        let yaml = serde_yaml::to_string(&pem_with_data).unwrap();
        println!("NamedPem with data YAML:\n{yaml}");
        assert!(yaml.contains("pem: inline-pem"));
        assert!(yaml.contains("data: "));
        assert!(yaml.contains("-----BEGIN CERTIFICATE-----"));
        assert!(yaml.contains("-----BEGIN PRIVATE KEY-----"));

        let deserialized: NamedPem = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.pem, "inline-pem");
        match deserialized.source {
            PemSource::Data(d) => {
                assert!(d.contains("-----BEGIN CERTIFICATE-----"));
                assert!(d.contains("-----BEGIN PRIVATE KEY-----"));
            }
            _ => panic!("Expected Data source"),
        }
    }

    #[test]
    fn test_named_pem_invalid_yaml() {
        // Missing pem field
        let yaml = r#"
        path: /etc/certs/server.pem
        "#;
        let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing field `pem`")
        );

        // Missing source (no path or data)
        let yaml = r#"
        pem: my-pem
        "#;
        let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must have either 'path' or 'data'")
        );

        // Both path and data
        let yaml = r#"
        pem: my-pem
        path: /etc/certs/server.pem
        data: "-----BEGIN CERTIFICATE-----"
        "#;
        let result: Result<NamedPem, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot have both 'path' and 'data'")
        );
    }

    #[test]
    fn test_config_with_named_pems() {
        // Test NamedPem as Config with path
        let pem_config = Config::NamedPem(NamedPem {
            pem: "web-server-pem".to_string(),
            source: PemSource::Path("/etc/certs/web.pem".to_string()),
        });

        let yaml = serde_yaml::to_string(&pem_config).unwrap();
        println!("Config::NamedPem YAML:\n{yaml}");

        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        match deserialized {
            Config::NamedPem(pem) => {
                assert_eq!(pem.pem, "web-server-pem");
                match pem.source {
                    PemSource::Path(p) => assert_eq!(p, "/etc/certs/web.pem"),
                    _ => panic!("Expected Path source"),
                }
            }
            _ => panic!("Expected NamedPem config"),
        }

        // Test NamedPem as Config with data
        let pem_config_data = Config::NamedPem(NamedPem {
            pem: "web-server-pem-data".to_string(),
            source: PemSource::Data("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string()),
        });

        let yaml = serde_yaml::to_string(&pem_config_data).unwrap();
        println!("Config::NamedPem with data YAML:\n{yaml}");

        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        match deserialized {
            Config::NamedPem(pem) => {
                assert_eq!(pem.pem, "web-server-pem-data");
                match pem.source {
                    PemSource::Data(d) => {
                        assert!(d.contains("-----BEGIN CERTIFICATE-----"));
                        assert!(d.contains("-----BEGIN PRIVATE KEY-----"));
                    }
                    _ => panic!("Expected Data source"),
                }
            }
            _ => panic!("Expected NamedPem config"),
        }
    }

    #[test]
    fn test_rejects_unknown_field_in_client_config_group() {
        let yaml = r#"
- client_group: my-proxies
  client_proxies:
    - address: "127.0.0.1:9090"
      protocol:
        type: socks
  extra_field: "should fail"
"#;
        let result: Result<Vec<Config>, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `extra_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field_in_rule_config_group() {
        let yaml = r#"
- rule_group: my-rules
  rules:
    - mask: 0.0.0.0/0
      action: allow
  bogus_field: 42
"#;
        let result: Result<Vec<Config>, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown field `bogus_field`"),
            "Error should mention unknown field: {err}"
        );
    }

    #[test]
    fn test_example_files_load_and_validate() {
        use crate::thread_util;
        use std::path::{Path, PathBuf};

        // Initialize thread count for the test environment if not already set
        // set_num_threads will panic if NUM_THREADS is already set by another test
        let _ = std::panic::catch_unwind(|| {
            thread_util::set_num_threads(4);
        });

        // Get the examples directory relative to the project root
        let examples_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");

        // Read all YAML files in the examples directory
        let mut example_files: Vec<PathBuf> = std::fs::read_dir(&examples_dir)
            .expect("Failed to read examples directory")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()?.to_str()? == "yaml" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        // Sort files for consistent test output
        example_files.sort();

        assert!(!example_files.is_empty(), "No example YAML files found");
        println!("Found {} example files to test", example_files.len());

        let mut failures = Vec::new();

        // Test each example file
        for example_file in &example_files {
            let file_name = example_file.file_name().unwrap().to_str().unwrap();
            println!("\nTesting example file: {file_name}");

            // Read the file
            let content = match std::fs::read_to_string(example_file) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("- {file_name}: Failed to read file: {e}"));
                    continue;
                }
            };

            // Parse the YAML
            let configs: Vec<Config> = match serde_yaml::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("- {file_name}: Failed to parse YAML: {e}"));
                    continue;
                }
            };

            // Just test parsing, not full validation with file reads
            // since certificate files don't exist in test environment
            println!("  ✓ Parsed successfully ({} configs)", configs.len());
        }

        if !failures.is_empty() {
            panic!(
                "Example config validation failed for {} files:\n{}",
                failures.len(),
                failures.join("\n")
            );
        }
    }
}
