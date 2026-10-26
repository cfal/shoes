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
    Fallback {
        health_check: HealthCheckConfig,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    pub url: String,
    pub interval_secs: u64,
    #[serde(default = "health_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "health_status")]
    pub expected_status: u16,
}

fn health_timeout() -> u64 {
    5000
}

fn health_status() -> u16 {
    204
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
    #[serde(default, deserialize_with = "health_check_if_present")]
    health_check: Option<HealthCheckConfig>,
}

fn health_check_if_present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<HealthCheckConfig>, D::Error> {
    HealthCheckConfig::deserialize(deserializer).map(Some)
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
        if kind != "fallback" && raw.health_check.is_some() {
            return Err("health_check requires type: fallback".into());
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
            "fallback" => {
                let health_check = raw.health_check.ok_or("fallback requires health_check")?;
                health_check.validate().map_err(|error| error.to_string())?;
                GroupType::Fallback { health_check }
            }
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
        crate::control::probes::ProbeQuery::parse(
            &std::collections::HashMap::from([
                ("url".into(), self.url.clone()),
                ("timeout".into(), self.timeout.to_string()),
            ]),
            true,
        )?
        .validate_automatic_target("url-test URL")
    }
}

#[cfg(test)]
mod group_type_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn review_automatic_policy_errors_keep_group_specific_labels() {
        let automatic = UrlTestConfig {
            url: "http://127.0.0.1/".into(),
            interval: 30,
            timeout: 1000,
            tolerance: 50,
            lazy: true,
        };
        let error = automatic.validate().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "url-test URL is denied by probe destination policy"
        );
        let fallback = HealthCheckConfig {
            url: automatic.url,
            interval_secs: 30,
            timeout_ms: 1000,
            expected_status: 204,
        };
        let error = fallback.validate().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "fallback URL is denied by probe destination policy"
        );
    }

    #[test]
    fn health_review9_invalid_probe_settings_name_health_check_fields() {
        for (url, timeout_ms) in [
            ("ftp://probe.invalid/", 1000),
            ("http://probe.invalid/", 32768),
        ] {
            let check = HealthCheckConfig {
                url: url.into(),
                interval_secs: 30,
                timeout_ms,
                expected_status: 204,
            };
            let error = check.validate().unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "health_check url must be HTTP(S), at most 2048 bytes, without credentials or fragments; timeout_ms must be 1..32767"
            );
        }
    }

    #[test]
    fn fallback_round_trips_with_type_and_rejects_legacy_or_incompatible_fields() {
        let raw = json!({"client_group":"out", "type":"fallback",
            "health_check":{"url":"https://probe.invalid/", "interval_secs":30},
            "client_proxies":["direct"]});
        let group: ClientConfigGroup = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(
            group.group_type,
            GroupType::Fallback {
                health_check: HealthCheckConfig {
                    url: "https://probe.invalid/".into(),
                    interval_secs: 30,
                    timeout_ms: 5000,
                    expected_status: 204,
                }
            }
        );
        let encoded = serde_json::to_value(&group).unwrap();
        assert_eq!(encoded["type"], "fallback");
        assert!(encoded.get("strategy").is_none());
        assert_eq!(
            serde_json::from_value::<ClientConfigGroup>(encoded)
                .unwrap()
                .group_type,
            group.group_type
        );
        let yaml = serde_yaml::to_string(&group).unwrap();
        assert!(yaml.contains("type: fallback"));
        assert_eq!(
            serde_yaml::from_str::<ClientConfigGroup>(&yaml)
                .unwrap()
                .group_type,
            group.group_type
        );
        for (field, value) in [
            ("strategy", json!("fallback")),
            ("default", json!("DIRECT")),
            ("url", json!("https://probe.invalid/")),
            ("interval", json!(30)),
            ("timeout", json!(5000)),
            ("tolerance", json!(50)),
            ("lazy", json!(false)),
            ("health_check", json!(null)),
            ("all_down", json!("direct")),
        ] {
            let mut invalid = raw.clone();
            invalid[field] = value;
            assert!(
                serde_json::from_value::<ClientConfigGroup>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
        let mut legacy = raw.clone();
        legacy.as_object_mut().unwrap().remove("type");
        legacy["strategy"] = json!("fallback");
        assert!(serde_json::from_value::<ClientConfigGroup>(legacy).is_err());
        for kind in ["round-robin", "selector", "url-test"] {
            let mut invalid = raw.clone();
            invalid["type"] = json!(kind);
            if kind == "url-test" {
                invalid["url"] = json!("https://probe.invalid/");
            }
            assert!(
                serde_json::from_value::<ClientConfigGroup>(invalid).is_err(),
                "{kind}"
            );
        }
    }

    #[test]
    fn health_review3_null_checks_are_rejected_for_every_group_type() {
        for kind in ["round-robin", "selector", "url-test", "fallback"] {
            let mut raw = json!({"client_group":"out", "type":kind,
                "client_proxies":["direct"], "health_check":null});
            if kind == "url-test" {
                raw["url"] = json!("http://probe.invalid/");
            }
            assert!(
                serde_json::from_value::<ClientConfigGroup>(raw.clone()).is_err(),
                "JSON {kind}"
            );
            assert!(
                serde_yaml::from_str::<ClientConfigGroup>(&serde_yaml::to_string(&raw).unwrap())
                    .is_err(),
                "YAML {kind}"
            );
            raw.as_object_mut().unwrap().remove("health_check");
            assert_eq!(
                serde_json::from_value::<ClientConfigGroup>(raw).is_ok(),
                kind != "fallback"
            );
        }
    }

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
        for (index, value) in values.into_iter().enumerate() {
            let context = |error| {
                if is_list {
                    D::Error::custom(format!("rules[{index}]: {error}"))
                } else {
                    D::Error::custom(format!("rules: {error}"))
                }
            };
            match value {
                Value::String(path) => {
                    sources.push(crate::rule_set::RuleSource::from_path(path.into()))
                }
                Value::Mapping(ref fields) if fields.contains_key("path") => {
                    sources.push(serde_yaml::from_value(value).map_err(context)?);
                }
                value => policies.push(serde_yaml::from_value(value).map_err(context)?),
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
                            return Err(Error::unknown_field(&key, &["pem", "path", "data"]));
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
mod tests;
