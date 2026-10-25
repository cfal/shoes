//! Configuration group types (top-level Config, groups, and NamedPem).

use serde::{Deserialize, Serialize};

use crate::option_util::OneOrSome;

use super::client::ClientConfig;
use super::dns::DnsConfigGroup;
use super::global::GlobalLimits;
use super::rules::RuleConfig;
use super::selection::ConfigSelection;
use super::server::ServerConfig;
use super::tun::TunConfig;

/// A named group of client proxies.
///
/// Groups can reference other groups using `ConfigSelection::GroupName`.
/// Group references are resolved using topological sort during validation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(try_from = "RawClientGroup")]
pub struct ClientConfigGroup {
    pub client_group: String,
    #[serde(flatten)]
    pub group_type: GroupType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    pub client_proxies: OneOrSome<ConfigSelection<ClientConfig>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum GroupType {
    #[default]
    RoundRobin,
    Selector,
    UrlTest(UrlTestConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UrlTestConfig {
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub tolerance: u16,
    pub lazy: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClientGroup {
    client_group: String,
    #[serde(rename = "type", default = "default_group_type")]
    kind: String,
    default: Option<String>,
    #[serde(alias = "client_proxy")]
    client_proxies: OneOrSome<ConfigSelection<ClientConfig>>,
    url: Option<String>,
    interval: Option<u64>,
    timeout: Option<u64>,
    tolerance: Option<u16>,
    lazy: Option<bool>,
}

fn default_group_type() -> String {
    "round-robin".into()
}

impl TryFrom<RawClientGroup> for ClientConfigGroup {
    type Error = String;

    fn try_from(raw: RawClientGroup) -> Result<Self, Self::Error> {
        let kind = raw.kind.as_str();
        if kind != "selector" && raw.default.is_some() {
            return Err("default is only valid for selector groups".into());
        }
        if kind != "url-test"
            && (raw.url.is_some()
                || raw.interval.is_some()
                || raw.timeout.is_some()
                || raw.tolerance.is_some()
                || raw.lazy.is_some())
        {
            return Err("url, interval, timeout, tolerance and lazy require type: url-test".into());
        }
        let group_type = match kind {
            "round-robin" => GroupType::RoundRobin,
            "selector" => GroupType::Selector,
            "url-test" => {
                let config = UrlTestConfig {
                    url: raw.url.ok_or("url-test requires url")?,
                    interval: raw.interval.unwrap_or(300),
                    timeout: raw.timeout.unwrap_or(5000),
                    tolerance: raw.tolerance.unwrap_or(50),
                    lazy: raw.lazy.unwrap_or(true),
                };
                config.validate().map_err(|error| error.to_string())?;
                GroupType::UrlTest(config)
            }
            _ => return Err(format!("unknown client group type: {kind}")),
        };
        Ok(Self {
            client_group: raw.client_group,
            group_type,
            default: raw.default,
            client_proxies: raw.client_proxies,
        })
    }
}

impl UrlTestConfig {
    pub fn validate(&self) -> std::io::Result<()> {
        if !(1..=86_400).contains(&self.interval)
            || !(1..=60_000).contains(&self.timeout)
            || self.timeout > self.interval * 1000
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "url-test interval must be 1..86400 seconds; timeout 1..60000 ms and no longer than interval",
            ));
        }
        crate::clash_api::probes::ProbeQuery::parse(
            &std::collections::HashMap::from([
                ("url".into(), self.url.clone()),
                ("timeout".into(), self.timeout.to_string()),
            ]),
            true,
        )?
        .validate_automatic_target()
    }
}

#[cfg(test)]
mod group_type_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn url_test_defaults_and_serialization_use_only_type() {
        let raw = json!({"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/", "client_proxies":["direct"]});
        let group: ClientConfigGroup = serde_json::from_value(raw).unwrap();
        assert_eq!(
            group.group_type,
            GroupType::UrlTest(UrlTestConfig {
                url: "http://probe.invalid/".into(),
                interval: 300,
                timeout: 5000,
                tolerance: 50,
                lazy: true,
            })
        );
        let encoded = serde_json::to_value(&group).unwrap();
        assert_eq!(encoded["type"], "url-test");
        assert!(encoded.get("strategy").is_none());
        assert_eq!(
            serde_json::from_value::<ClientConfigGroup>(encoded)
                .unwrap()
                .group_type,
            group.group_type
        );
        let group: ClientConfigGroup =
            serde_json::from_value(json!({"client_group":"rr", "client_proxies":["direct"]}))
                .unwrap();
        assert_eq!(group.group_type, GroupType::RoundRobin);
    }

    #[test]
    fn client_proxy_alias_preserves_canonical_serialization() {
        let group: ClientConfigGroup = serde_json::from_value(json!({
            "client_group": "rr",
            "client_proxy": ["direct"]
        }))
        .unwrap();
        assert_eq!(group.group_type, GroupType::RoundRobin);
        assert!(group.default.is_none());
        assert_eq!(
            serde_json::to_value(group).unwrap(),
            json!({
                "client_group": "rr",
                "type": "round-robin",
                "client_proxies": ["direct"]
            })
        );
    }

    #[test]
    fn url_test_rejects_removed_unknown_and_incompatible_group_settings() {
        let base = json!({"client_group":"auto", "type":"url-test", "url":"http://probe.invalid/", "client_proxies":["direct"]});
        for (field, value) in [
            ("strategy", json!("url-test")),
            ("type", json!("urltest")),
            ("type", json!(null)),
            ("type", json!("fallback")),
            ("default", json!("DIRECT")),
            ("url", json!("ftp://probe.invalid/")),
            ("url", json!("http://u:p@probe.invalid/")),
            ("url", json!("http://127.0.0.1/")),
            ("url", json!("http://[::ffff:127.0.0.1]/")),
            ("url", json!("http://169.254.1.1/")),
            ("url", json!("http://198.18.0.1/")),
            ("url", json!("http://[::]/")),
            ("url", json!("http://224.0.0.1/")),
            ("interval", json!(0)),
            ("interval", json!(86401)),
            ("interval", json!(1)),
            ("timeout", json!(0)),
            ("timeout", json!(60001)),
            ("tolerance", json!(-1)),
            ("tolerance", json!(65536)),
            ("lazy", json!("true")),
            ("typo", json!(true)),
        ] {
            let mut raw = base.clone();
            raw[field] = value;
            assert!(
                serde_json::from_value::<ClientConfigGroup>(raw.clone()).is_err(),
                "{raw}"
            );
        }
        for kind in ["round-robin", "selector"] {
            for (field, value) in [
                ("url", json!("http://probe.invalid/")),
                ("interval", json!(10)),
                ("timeout", json!(10)),
                ("tolerance", json!(0)),
                ("lazy", json!(false)),
                ("strategy", json!(kind)),
            ] {
                let mut raw =
                    json!({"client_group":"test", "type":kind, "client_proxies":["direct"]});
                raw[field] = value;
                assert!(
                    serde_json::from_value::<ClientConfigGroup>(raw.clone()).is_err(),
                    "{raw}"
                );
            }
        }
        for members in [json!([]), json!(["direct", "direct"])] {
            let mut raw = base.clone();
            raw["client_proxies"] = members;
            let configs = serde_json::from_value(json!([raw]));
            assert!(
                configs.is_err() || crate::config::create_server_configs(configs.unwrap()).is_err()
            );
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfigGroup {
    pub rule_group: String,
    #[serde(alias = "rule")]
    pub rules: RuleGroupRules,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum RuleGroupRules {
    Policies(Box<OneOrSome<RuleConfig>>),
    Sources(OneOrSome<crate::rule_set::RuleSource>),
}

impl<'de> Deserialize<'de> for RuleGroupRules {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        use serde_yaml::Value;

        let value = Value::deserialize(deserializer)?;
        let is_list = value.is_sequence();
        let values = match value {
            Value::Sequence(values) => values,
            value => vec![value],
        };
        if values.is_empty() {
            return Err(Error::custom("rule group cannot be empty"));
        }
        let mut policies = Vec::new();
        let mut sources = Vec::new();
        for value in values {
            match value {
                Value::String(path) => {
                    sources.push(crate::rule_set::RuleSource::from_path(path.into()))
                }
                Value::Mapping(ref fields) if fields.contains_key("path") => {
                    sources.push(serde_yaml::from_value(value).map_err(Error::custom)?);
                }
                value => policies.push(serde_yaml::from_value(value).map_err(Error::custom)?),
            }
        }
        if !policies.is_empty() && !sources.is_empty() {
            return Err(Error::custom(
                "rule group cannot mix policies with file sources",
            ));
        }
        if sources.is_empty() {
            Ok(Self::Policies(Box::new(if is_list {
                OneOrSome::Some(policies)
            } else {
                OneOrSome::One(policies.pop().unwrap())
            })))
        } else {
            Ok(Self::Sources(if is_list {
                OneOrSome::Some(sources)
            } else {
                OneOrSome::One(sources.pop().unwrap())
            }))
        }
    }
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
    ClashApi(super::ClashApiConfig),
    CacheFile(super::CacheFileConfig),
    CertificateSource(crate::certificates::NamedSource),
    GlobalLimits(GlobalLimits),
    Server(ServerConfig),
    /// TUN device server - accepts IP packets from a TUN device.
    /// This is separate from Server because TUN doesn't use bind_location or transport.
    TunServer(TunConfig),
    ClientConfigGroup(ClientConfigGroup),
    RuleConfigGroup(RuleConfigGroup),
    DnsConfigGroup(DnsConfigGroup),
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

        if map.contains_key("clash_api_address") || map.contains_key("clash_api_path") {
            return serde_yaml::from_value(value)
                .map(Config::ClashApi)
                .map_err(Error::custom);
        }
        if map.contains_key("cache_file_path") {
            return serde_yaml::from_value(value)
                .map(Config::CacheFile)
                .map_err(Error::custom);
        }

        // Look for discriminating fields
        let has_client_group = map.contains_key(Value::String("client_group".to_string()));
        let has_rule_group = map.contains_key(Value::String("rule_group".to_string()));
        let has_dns_group = map.contains_key(Value::String("dns_group".to_string()));
        let has_address = map.contains_key(Value::String("address".to_string()));
        let has_addresses = map.contains_key(Value::String("addresses".to_string()));
        let has_path_field = map.contains_key(Value::String("path".to_string()));
        let has_pem = map.contains_key(Value::String("pem".to_string()));

        // Check if this is a TUN config
        // TUN configs have 'device_name' (Linux) or 'device_fd' (iOS/Android)
        // These fields are unique to TUN and don't appear in other config types
        let has_device_name = map.contains_key(Value::String("device_name".to_string()));
        let has_device_fd = map.contains_key(Value::String("device_fd".to_string()));
        let is_tun_config = has_device_name || has_device_fd;

        // Try to determine which variant based on fields
        if map.contains_key(Value::String("rule_set".to_string())) {
            Err(Error::custom(
                "rule_set was replaced by rule_group with file paths in rules",
            ))
        } else if map.contains_key(Value::String("global_limits".to_string())) {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct GlobalLimitsEntry {
                global_limits: Option<GlobalLimits>,
            }
            serde_yaml::from_value::<GlobalLimitsEntry>(value)
                .map(|entry| Config::GlobalLimits(entry.global_limits.unwrap_or_default()))
                .map_err(|e| Error::custom(format!("invalid global limits: {e}")))
        } else if map.contains_key("certificate_source") {
            serde_yaml::from_value(value)
                .map(Config::CertificateSource)
                .map_err(|e| {
                    Error::custom(format!("invalid certificate source configuration: {e}"))
                })
        } else if has_pem {
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
        } else if has_dns_group {
            // DnsConfigGroup
            serde_yaml::from_value(value)
                .map(Config::DnsConfigGroup)
                .map_err(|e| Error::custom(format!("invalid DNS config group: {e}")))
        } else if is_tun_config {
            // TunConfig - identified by having 'name' or 'raw_fd' without 'protocol' wrapper
            serde_yaml::from_value(value)
                .map(Config::TunServer)
                .map_err(|e| Error::custom(format!("invalid TUN config: {e}")))
        } else if has_address || has_addresses || has_path_field || map.contains_key("protocol") {
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
                - Server config: must have 'address', 'addresses', or 'path' field\n\
                - Client config group: must have 'client_group' field\n\
                - Rule config group: must have 'rule_group' field\n\
                - DNS config group: must have 'dns_group' field\n\
                - Global limits: must have 'global_limits' field"
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
            Config::ClashApi(config) => config.serialize(serializer),
            Config::CacheFile(config) => config.serialize(serializer),
            Config::CertificateSource(source) => source.serialize(serializer),
            Config::GlobalLimits(limits) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("global_limits", limits)?;
                map.end()
            }
            Config::Server(server) => server.serialize(serializer),
            Config::TunServer(tun) => tun.serialize(serializer),
            Config::ClientConfigGroup(group) => group.serialize(serializer),
            Config::RuleConfigGroup(group) => group.serialize(serializer),
            Config::DnsConfigGroup(group) => group.serialize(serializer),
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
            name: None,
            control: None,
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
            criteria: super::super::rules::RuleCriteria {
                description: None,
                expression: crate::rules::Expression::Legacy(OneOrSome::Some(vec![
                    NetLocationMask::from("192.168.0.0/16:80").unwrap(),
                    NetLocationMask::from("10.0.0.0/8:443").unwrap(),
                ])),
                ..Default::default()
            },
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
            group_type: Default::default(),
            default: None,
            client_group: "test-client-group".to_string(),
            client_proxies: OneOrSome::Some(vec![
                ConfigSelection::Config(create_test_client_config()),
                ConfigSelection::Config(ClientConfig {
                    name: None,
                    control: None,
                    bind_interface: crate::option_util::NoneOrOne::None,
                    address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                    protocol: ClientProxyConfig::Http {
                        username: None,
                        password: None,
                        resolve_hostname: false,
                        http_version: Default::default(),
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
    fn rule_group_members_determine_kind_not_action_presence() {
        for yaml in [
            "rule_group: policies\nrules: [{masks: example.com}]",
            "rule_group: policies\nrule: {mask: example.com, action: block}",
        ] {
            let group: RuleConfigGroup = serde_yaml::from_str(yaml).unwrap();
            let RuleGroupRules::Policies(_) = group.rules else {
                panic!("expected policies")
            };
            let encoded = serde_yaml::to_string(&group).unwrap();
            let group: RuleConfigGroup = serde_yaml::from_str(&encoded).unwrap();
            assert!(matches!(group.rules, RuleGroupRules::Policies(_)));
        }
        for yaml in [
            "rule_group: files\nrules: [a.srs, {path: b, format: srs}]",
            "rule_group: files\nrule: a.srs",
            "rule_group: files\nrule: [a.srs, {path: b, format: srs}]",
            "rule_group: files\nrules: {path: a.txt, behavior: domain}",
        ] {
            let group: RuleConfigGroup = serde_yaml::from_str(yaml).unwrap();
            assert!(matches!(group.rules, RuleGroupRules::Sources(_)));
            let encoded = serde_yaml::to_string(&group).unwrap();
            let group: RuleConfigGroup = serde_yaml::from_str(&encoded).unwrap();
            assert!(matches!(group.rules, RuleGroupRules::Sources(_)));
        }
        for (rules, error) in [
            ("[]", "cannot be empty"),
            ("[a.srs, {masks: example.com}]", "cannot mix"),
            ("[{masks: example.com}, {path: a.srs}]", "cannot mix"),
            ("[{path: a.srs, action: block}]", "unknown field `action`"),
            ("[{path: a.srs, fromat: srs}]", "unknown field `fromat`"),
            ("[{rule_group: other}]", "unknown field `rule_group`"),
        ] {
            let result =
                serde_yaml::from_str::<RuleConfigGroup>(&format!("rule_group: x\nrules: {rules}"));
            assert!(result.unwrap_err().to_string().contains(error), "{rules}");
        }
        let error = serde_yaml::from_str::<Config>("rule_set: old\npath: a.srs").unwrap_err();
        assert!(error.to_string().contains("replaced by rule_group"));
    }

    #[test]
    fn test_rule_config_group() {
        let original = vec![Config::RuleConfigGroup(RuleConfigGroup {
            rule_group: "test-rule-group".to_string(),
            rules: RuleGroupRules::Policies(Box::new(OneOrSome::Some(vec![
                create_test_rule_config(),
                RuleConfig {
                    criteria: Default::default(),
                    action: RuleActionConfig::Block,
                },
            ]))),
        })];

        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 1);
        if let Config::RuleConfigGroup(group) = &deserialized[0] {
            assert_eq!(group.rule_group, "test-rule-group");
            // Check that we have the correct number of rules by pattern matching
            let RuleGroupRules::Policies(rules) = &group.rules else {
                panic!("Expected policies");
            };
            assert!(matches!(rules.as_ref(), OneOrSome::Some(values) if values.len() == 2));
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
    fn test_server_config_with_addresses_alias() {
        let yaml = r#"
- addresses:
    - "127.0.0.1:22223"
    - "172.17.0.1:22223-22225"
  protocol:
    type: http
"#;

        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        let Config::Server(server) = &configs[0] else {
            panic!("expected server config");
        };
        assert_eq!(
            server.bind_location.to_string(),
            "127.0.0.1:22223, 172.17.0.1:22223-22225"
        );

        let serialized = serde_yaml::to_value(&configs[0]).unwrap();
        let mapping = serialized.as_mapping().unwrap();
        assert!(mapping.contains_key(serde_yaml::Value::String("address".to_string())));
        assert!(!mapping.contains_key(serde_yaml::Value::String("addresses".to_string())));
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
            let mut configs: Vec<Config> = match serde_yaml::from_str(&content) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("- {file_name}: Failed to parse YAML: {e}"));
                    continue;
                }
            };

            let mut compiler = crate::rules::Compiler::default();
            let compiled = crate::rule_set::anchor(&mut configs, example_file)
                .and_then(|()| crate::rule_set::load(&mut configs, &mut compiler))
                .and_then(|()| crate::config::rule_visit::compile(&mut configs, &mut compiler));
            if let Err(error) = compiled {
                failures.push(format!("- {file_name}: invalid rules: {error}"));
                continue;
            }
            if file_name == "mixed.yaml" {
                let certificate =
                    rcgen::generate_simple_self_signed(vec!["proxy.local".into()]).unwrap();
                for config in &mut configs {
                    if let Config::Server(server) = config
                        && let crate::config::ServerProxyConfig::Tls { tls_targets, .. } =
                            &mut server.protocol
                    {
                        for target in tls_targets.values_mut() {
                            target.cert = certificate.cert.pem();
                            target.key = certificate.signing_key.serialize_pem();
                        }
                    }
                }
                crate::config::create_server_configs(configs.clone())
                    .expect("mixed example must pass full validation");
            }
            // Other examples contain deployment-specific certificates and keys.
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
