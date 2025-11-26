//! Rule configuration types.

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationMask};
use crate::option_util::{NoneOrSome, OneOrSome};

use super::client::ClientConfig;
use super::selection::ConfigSelection;

#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub masks: OneOrSome<NetLocationMask>,
    pub action: RuleActionConfig,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            masks: OneOrSome::One(NetLocationMask::ANY),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_chains: NoneOrSome::One(ClientChain::default()),
            },
        }
    }
}

/// A complete proxy chain - a sequence of hops that traffic traverses.
///
/// Can be deserialized from:
/// - An array of hops: `[hop1, hop2, ...]`
/// - An object with `chain` key: `{ chain: [hop1, hop2, ...] }`
/// - A single hop (string or inline config): `"group-name"` or `{ address: ..., protocol: ... }`
#[derive(Debug, Clone)]
pub struct ClientChain {
    /// The hops in this chain, from first (closest to client) to last (closest to target).
    pub hops: OneOrSome<ClientChainHop>,
}

impl Default for ClientChain {
    fn default() -> Self {
        Self {
            hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
                ClientConfig::default(),
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for ClientChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;

        struct ClientChainVisitor;

        impl<'de> Visitor<'de> for ClientChainVisitor {
            type Value = ClientChain;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    "a chain: either an array of hops, an object with 'chain' key, \
                     or a single hop (string/object)",
                )
            }

            // String → single hop chain (group reference)
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        value.to_string(),
                    ))),
                })
            }

            // Array → sequence of hops
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut hops = Vec::new();
                while let Some(hop) = seq.next_element::<ClientChainHop>()? {
                    hops.push(hop);
                }
                if hops.is_empty() {
                    return Err(Error::custom("chain cannot be empty"));
                }
                Ok(ClientChain {
                    hops: if hops.len() == 1 {
                        OneOrSome::One(hops.into_iter().next().unwrap())
                    } else {
                        OneOrSome::Some(hops)
                    },
                })
            }

            // Object → check for 'chain' key or treat as inline config
            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;
                use serde_yaml::Value;

                // First deserialize as a generic Value to inspect keys
                let value = Value::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;

                let mapping = match &value {
                    Value::Mapping(m) => m,
                    _ => {
                        return Err(Error::custom("expected a mapping"));
                    }
                };

                // Check if this has a 'chain' key
                let chain_key = Value::String("chain".to_string());
                if let Some(chain_value) = mapping.get(&chain_key) {
                    // { chain: [...] } syntax
                    let hops: OneOrSome<ClientChainHop> =
                        serde_yaml::from_value(chain_value.clone()).map_err(|e| {
                            Error::custom(format!(
                                "Invalid 'chain' value: {}. Expected an array of hops.",
                                e
                            ))
                        })?;

                    // Validate not empty (OneOrSome guarantees at least 1)
                    return Ok(ClientChain { hops });
                }

                // Otherwise, treat as a single inline ClientConfig hop
                let proxy: ClientConfig = serde_yaml::from_value(value).map_err(|e| {
                    Error::custom(format!(
                        "Invalid chain. Expected one of:\n\
                         - An array of hops: [hop1, hop2, ...]\n\
                         - An object with 'chain' key: {{ chain: [...] }}\n\
                         - A single hop (group reference string or inline proxy config)\n\
                         \nParse error: {}",
                        e
                    ))
                })?;

                Ok(ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(proxy))),
                })
            }
        }

        deserializer.deserialize_any(ClientChainVisitor)
    }
}

impl Serialize for ClientChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        // Always serialize as { chain: [...] } for clarity
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("chain", &self.hops)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for RuleConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // Temporary struct with all known fields for RuleConfig
        // This avoids #[serde(flatten)] and gives better error messages
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RuleConfigTemp {
            #[serde(alias = "mask")]
            masks: Option<OneOrSome<NetLocationMask>>,
            // Action fields (from RuleActionConfig)
            #[serde(default)]
            action: Option<String>,
            #[serde(default)]
            override_address: Option<String>,
            /// Legacy field - will be converted to client_chains
            #[serde(alias = "client_proxy", default)]
            client_proxies: NoneOrSome<ConfigSelection<ClientConfig>>,
            /// New field: multiple chains for round-robin selection
            /// Alias: client_chain (singular) for backward compatibility
            #[serde(alias = "client_chain", default)]
            client_chains: NoneOrSome<ClientChain>,
        }

        let temp = RuleConfigTemp::deserialize(deserializer)?;

        // masks is required
        let masks = temp.masks.ok_or_else(|| D::Error::missing_field("masks"))?;

        // Determine action type
        let action_str = temp.action.as_deref().unwrap_or("allow");
        let action = match action_str {
            "block" => RuleActionConfig::Block,
            "allow" => {
                // Parse override_address if present
                let override_address = if let Some(addr_str) = temp.override_address {
                    Some(NetLocation::from_str(&addr_str, Some(0)).map_err(|_| {
                        D::Error::custom(format!(
                            "invalid override_address '{}': expected format like 'host:port' or 'host'",
                            addr_str
                        ))
                    })?)
                } else {
                    None
                };

                // Check for conflicting fields
                let has_client_proxies = !temp.client_proxies.is_empty();
                let has_client_chains = !temp.client_chains.is_empty();

                if has_client_proxies && has_client_chains {
                    return Err(D::Error::custom(
                        "cannot specify both 'client_proxies' and 'client_chains'/'client_chain' in the same rule. \
                         'client_proxies' is deprecated - please use 'client_chains' instead.",
                    ));
                }

                // Convert client_proxies to client_chains if present
                let client_chains: NoneOrSome<ClientChain> = if has_client_proxies {
                    log::warn!(
                        "The 'client_proxies' field is deprecated and will be removed in a future version. \
                         Please use 'client_chains' instead. Your config will continue to work, but consider updating it."
                    );

                    // Convert to client_chains format:
                    // All proxies become a single chain with one hop (pool if multiple)
                    let proxy_list = temp.client_proxies.into_vec();
                    let hop = if proxy_list.len() == 1 {
                        ClientChainHop::Single(proxy_list.into_iter().next().unwrap())
                    } else {
                        ClientChainHop::Pool(OneOrSome::Some(proxy_list))
                    };
                    NoneOrSome::One(ClientChain {
                        hops: OneOrSome::One(hop),
                    })
                } else if has_client_chains {
                    temp.client_chains
                } else {
                    // Default: unspecified means single chain with direct hop
                    NoneOrSome::Unspecified
                };

                RuleActionConfig::Allow {
                    override_address,
                    client_chains,
                }
            }
            other => {
                return Err(D::Error::custom(format!(
                    "invalid action '{}': expected 'allow' or 'block'",
                    other
                )));
            }
        };

        Ok(RuleConfig { masks, action })
    }
}

impl Serialize for RuleConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        // Count fields: masks + action fields
        let action_field_count = match &self.action {
            RuleActionConfig::Block => 1, // action
            RuleActionConfig::Allow {
                override_address,
                client_chains,
            } => {
                let mut count = 1; // action
                if override_address.is_some() {
                    count += 1;
                }
                if !client_chains.is_empty() {
                    count += 1;
                }
                count
            }
        };

        let mut map = serializer.serialize_map(Some(1 + action_field_count))?;

        // Serialize masks
        map.serialize_entry("masks", &self.masks)?;

        // Serialize action fields (flattened)
        match &self.action {
            RuleActionConfig::Block => {
                map.serialize_entry("action", "block")?;
            }
            RuleActionConfig::Allow {
                override_address,
                client_chains,
            } => {
                map.serialize_entry("action", "allow")?;
                if let Some(addr) = override_address {
                    map.serialize_entry("override_address", &addr.to_string())?;
                }
                if !client_chains.is_empty() {
                    map.serialize_entry("client_chains", client_chains)?;
                }
            }
        }

        map.end()
    }
}

/// A single hop in a proxy chain.
///
/// Each hop represents one step in the chain. A hop can be:
/// - A single proxy (inline config or group reference)
/// - A pool of proxies for load balancing (mix of inline configs and group refs)
#[derive(Debug, Clone)]
pub enum ClientChainHop {
    /// Single proxy for this hop - either an inline config or a group reference.
    /// If a group reference, the group's proxies become the pool for this hop.
    Single(ConfigSelection<ClientConfig>),

    /// Pool of proxies for this hop (round-robin load balancing).
    /// Can mix inline configs and group references.
    /// Group references are expanded, and all configs are combined into one pool.
    Pool(OneOrSome<ConfigSelection<ClientConfig>>),
}

impl<'de> serde::de::Deserialize<'de> for ClientChainHop {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};
        use std::fmt;

        struct ClientChainHopVisitor;

        impl<'de> Visitor<'de> for ClientChainHopVisitor {
            type Value = ClientChainHop;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a string (group reference), an object with 'address'/'protocol' \
                     (single proxy), or an object with 'pool' key (pool of proxies)",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                // String -> Single group reference
                Ok(ClientChainHop::Single(ConfigSelection::GroupName(
                    value.to_string(),
                )))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde_yaml::Value;

                // First deserialize as a generic Value to inspect keys
                let value = Value::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;

                let map = match &value {
                    Value::Mapping(m) => m,
                    _ => {
                        return Err(Error::custom("expected a mapping"));
                    }
                };

                // Check if this is a pool (has "pool" key)
                let pool_key = Value::String("pool".to_string());
                if let Some(pool_value) = map.get(&pool_key) {
                    // pool: [...] syntax - can contain group refs and/or inline configs
                    let selections: OneOrSome<ConfigSelection<ClientConfig>> =
                        serde_yaml::from_value(pool_value.clone()).map_err(|e| {
                            Error::custom(format!(
                                "Invalid pool in chain hop: {}. \
                                 Expected a list of proxy configurations and/or group references.",
                                e
                            ))
                        })?;

                    // OneOrSome is always non-empty by design (One has 1, Some has 1+)
                    return Ok(ClientChainHop::Pool(selections));
                }

                // Otherwise, treat as single inline proxy config
                let proxy: ClientConfig = serde_yaml::from_value(value).map_err(|e| {
                    Error::custom(format!(
                        "Invalid chain hop. Expected one of:\n\
                         - A string referencing a named client_group\n\
                         - A single proxy config with 'address' and 'protocol'\n\
                         - An object with 'pool' key containing a list of proxies/group refs\n\
                         \nParse error: {}",
                        e
                    ))
                })?;

                Ok(ClientChainHop::Single(ConfigSelection::Config(proxy)))
            }
        }

        deserializer.deserialize_any(ClientChainHopVisitor)
    }
}

impl serde::ser::Serialize for ClientChainHop {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::SerializeMap;

        match self {
            ClientChainHop::Single(ConfigSelection::GroupName(name)) => {
                serializer.serialize_str(name)
            }
            ClientChainHop::Single(ConfigSelection::Config(config)) => config.serialize(serializer),
            ClientChainHop::Pool(selections) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("pool", selections)?;
                map.end()
            }
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RuleActionConfig {
    Allow {
        override_address: Option<NetLocation>,

        /// Multiple proxy chains for round-robin selection.
        /// Each chain is a sequence of hops.
        /// Field name: `client_chains` (alias: `client_chain` for backward compatibility)
        ///
        /// - `NoneOrSome::Unspecified` → Default to single chain with direct hop
        /// - `NoneOrSome::None` → Error (validated later)
        /// - `NoneOrSome::One(chain)` → Single chain
        /// - `NoneOrSome::Some(chains)` → Multiple chains for round-robin
        client_chains: NoneOrSome<ClientChain>,
    },
    Block,
}

impl<'de> Deserialize<'de> for RuleActionConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        // Temporary struct to capture all possible fields including deprecated ones
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RuleActionTemp {
            #[serde(default)]
            action: Option<String>,
            #[serde(default)]
            override_address: Option<String>,
            /// Legacy field - will be converted to client_chains
            #[serde(alias = "client_proxy", default)]
            client_proxies: NoneOrSome<ConfigSelection<ClientConfig>>,
            /// New field: multiple chains for round-robin selection
            /// Alias: client_chain (singular) for backward compatibility
            #[serde(alias = "client_chain", default)]
            client_chains: NoneOrSome<ClientChain>,
        }

        let temp = RuleActionTemp::deserialize(deserializer)?;

        // Determine action type
        let action_str = temp.action.as_deref().unwrap_or("allow");
        match action_str {
            "block" => Ok(RuleActionConfig::Block),
            "allow" => {
                // Parse override_address if present
                let override_address = if let Some(addr_str) = temp.override_address {
                    Some(NetLocation::from_str(&addr_str, Some(0)).map_err(|_| {
                        D::Error::custom(format!(
                            "invalid override_address '{}': expected format like 'host:port' or 'host'",
                            addr_str
                        ))
                    })?)
                } else {
                    None
                };

                // Check for conflicting fields
                let has_client_proxies = !temp.client_proxies.is_empty();
                let has_client_chains = !temp.client_chains.is_empty();

                if has_client_proxies && has_client_chains {
                    return Err(D::Error::custom(
                        "cannot specify both 'client_proxies' and 'client_chains'/'client_chain' in the same rule. \
                         'client_proxies' is deprecated - please use 'client_chains' instead.",
                    ));
                }

                // Convert client_proxies to client_chains if present
                let client_chains: NoneOrSome<ClientChain> = if has_client_proxies {
                    log::warn!(
                        "The 'client_proxies' field is deprecated and will be removed in a future version. \
                         Please use 'client_chains' instead. Your config will continue to work, but consider updating it."
                    );

                    // Convert to client_chains format:
                    // All proxies become a single chain with one hop (pool if multiple)
                    let proxy_list = temp.client_proxies.into_vec();
                    let hop = if proxy_list.len() == 1 {
                        ClientChainHop::Single(proxy_list.into_iter().next().unwrap())
                    } else {
                        ClientChainHop::Pool(OneOrSome::Some(proxy_list))
                    };
                    NoneOrSome::One(ClientChain {
                        hops: OneOrSome::One(hop),
                    })
                } else if has_client_chains {
                    temp.client_chains
                } else {
                    // Default: unspecified means single chain with direct hop
                    NoneOrSome::Unspecified
                };

                Ok(RuleActionConfig::Allow {
                    override_address,
                    client_chains,
                })
            }
            other => Err(D::Error::custom(format!(
                "invalid action '{}': expected 'allow' or 'block'",
                other
            ))),
        }
    }
}

impl Serialize for RuleActionConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        match self {
            RuleActionConfig::Block => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("action", "block")?;
                map.end()
            }
            RuleActionConfig::Allow {
                override_address,
                client_chains,
            } => {
                let mut count = 1; // action
                if override_address.is_some() {
                    count += 1;
                }
                if !client_chains.is_empty() {
                    count += 1;
                }

                let mut map = serializer.serialize_map(Some(count))?;
                map.serialize_entry("action", "allow")?;
                if let Some(addr) = override_address {
                    map.serialize_entry("override_address", &addr.to_string())?;
                }
                if !client_chains.is_empty() {
                    map.serialize_entry("client_chains", client_chains)?;
                }
                map.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn test_rule_config_serialization() {
        let original = create_test_rule_config();
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        println!("Rule config YAML:\n{yaml_str}");
        let deserialized: RuleConfig =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");
        assert!(matches!(
            deserialized.action,
            RuleActionConfig::Allow { .. }
        ));
    }

    #[test]
    fn test_rule_config_block() {
        let yaml = r#"
masks: 0.0.0.0/0
action: block
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().action, RuleActionConfig::Block));
    }

    #[test]
    fn test_rule_config_allow() {
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap().action,
            RuleActionConfig::Allow { .. }
        ));
    }

    #[test]
    fn test_rule_config_with_override() {
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
override_address: "127.0.0.1:8080"
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let RuleActionConfig::Allow {
            override_address, ..
        } = result.unwrap().action
        {
            assert!(override_address.is_some());
        } else {
            panic!("Expected Allow action");
        }
    }

    // =========================================================================
    // ClientChain deserialization tests
    // =========================================================================

    #[test]
    fn test_client_chain_from_array_of_hops() {
        // Array syntax: [hop1, hop2, ...]
        let yaml = r#"
- my-proxy-group
- exit-proxy
"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.hops.len(), 2);
    }

    #[test]
    fn test_client_chain_from_object_with_chain_key() {
        // Object syntax: { chain: [...] }
        let yaml = r#"
chain:
  - my-proxy-group
  - exit-proxy
"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.hops.len(), 2);
    }

    #[test]
    fn test_client_chain_from_single_string() {
        // Single string: "group-name"
        let yaml = r#"my-proxy-group"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.hops.len(), 1);
        assert!(matches!(
            chain.hops.iter().next().unwrap(),
            ClientChainHop::Single(ConfigSelection::GroupName(n)) if n == "my-proxy-group"
        ));
    }

    #[test]
    fn test_client_chain_from_inline_config() {
        // Inline config object (without 'chain' key)
        let yaml = r#"
address: "127.0.0.1:1080"
protocol:
  type: socks
"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.hops.len(), 1);
        assert!(matches!(
            chain.hops.iter().next().unwrap(),
            ClientChainHop::Single(ConfigSelection::Config(_))
        ));
    }

    #[test]
    fn test_client_chain_differentiates_chain_key_from_proxy_config() {
        // Object with 'chain' key should be parsed as chain syntax
        let yaml_chain = r#"
chain:
  - my-proxy
  - exit-proxy
"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml_chain);
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.hops.len(), 2); // Two hops from the chain array

        // Object without 'chain' key should be parsed as inline proxy config
        let yaml_proxy = r#"
address: "127.0.0.1:1080"
protocol:
  type: socks
"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml_proxy);
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.hops.len(), 1); // Single hop from inline config
        assert!(matches!(
            chain.hops.iter().next().unwrap(),
            ClientChainHop::Single(ConfigSelection::Config(_))
        ));
    }

    #[test]
    fn test_client_chain_empty_array_rejected() {
        let yaml = r#"[]"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "Error should mention empty: {err}");
    }

    #[test]
    fn test_client_chain_empty_chain_key_rejected() {
        let yaml = r#"
chain: []
"#;
        let result: Result<ClientChain, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    // =========================================================================
    // client_chains (plural) tests - multiple chains for round-robin
    // =========================================================================

    #[test]
    fn test_rule_config_with_single_client_chain_backward_compat() {
        // Using singular 'client_chain' should still work
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chain:
  - my-proxy-group
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 1);
            let chain = client_chains.iter().next().unwrap();
            assert_eq!(chain.hops.len(), 1);
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_rule_config_with_multiple_chains_object_syntax() {
        // Multiple chains using object syntax { chain: [...] }
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [direct]
  - chain: [proxy1, proxy2, proxy3]
  - chain: [proxy4, proxy5]
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 3);
            let chains: Vec<_> = client_chains.iter().collect();
            assert_eq!(chains[0].hops.len(), 1); // direct
            assert_eq!(chains[1].hops.len(), 3); // proxy1, proxy2, proxy3
            assert_eq!(chains[2].hops.len(), 2); // proxy4, proxy5
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_rule_config_with_multiple_chains_array_syntax() {
        // Multiple chains using bare array syntax [[...], [...]]
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - [direct]
  - [proxy1, proxy2, proxy3]
  - [proxy4, proxy5]
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 3);
            let chains: Vec<_> = client_chains.iter().collect();
            assert_eq!(chains[0].hops.len(), 1);
            assert_eq!(chains[1].hops.len(), 3);
            assert_eq!(chains[2].hops.len(), 2);
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_rule_config_with_mixed_chain_syntax() {
        // Mix of object and array syntax
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - [direct]
  - chain: [proxy1, proxy2]
  - my-proxy-group
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 3);
            let chains: Vec<_> = client_chains.iter().collect();
            assert_eq!(chains[0].hops.len(), 1); // [direct]
            assert_eq!(chains[1].hops.len(), 2); // chain: [proxy1, proxy2]
            assert_eq!(chains[2].hops.len(), 1); // my-proxy-group (single string)
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_rule_config_defaults_to_unspecified() {
        // When no client_chains is specified, defaults to Unspecified
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert!(client_chains.is_unspecified());
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_rule_config_chains_with_pools() {
        // Chains that contain pools at various hops
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain:
      - pool: [entry-us, entry-eu]
      - exit-proxy
  - chain:
      - direct
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 2);
            let chains: Vec<_> = client_chains.iter().collect();
            // First chain has 2 hops, first hop is a pool
            assert_eq!(chains[0].hops.len(), 2);
            assert!(matches!(
                chains[0].hops.iter().next().unwrap(),
                ClientChainHop::Pool(_)
            ));
        } else {
            panic!("Expected Allow action");
        }
    }

    // =========================================================================
    // ClientChainHop tests (unchanged from before)
    // =========================================================================

    #[test]
    fn test_client_chain_hop_single_group_ref() {
        let yaml = r#"my-proxy-group"#;
        let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ClientChainHop::Single(ConfigSelection::GroupName(_))
        ));
    }

    #[test]
    fn test_client_chain_hop_single_inline_config() {
        let yaml = r#"
address: "127.0.0.1:1080"
protocol:
  type: socks
"#;
        let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            ClientChainHop::Single(ConfigSelection::Config(_))
        ));
    }

    #[test]
    fn test_client_chain_hop_pool_group_refs() {
        let yaml = r#"
pool:
  - us-proxies
  - eu-proxies
"#;
        let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let ClientChainHop::Pool(selections) = result.unwrap() {
            let vec: Vec<_> = selections.into_vec();
            assert_eq!(vec.len(), 2);
            assert!(matches!(&vec[0], ConfigSelection::GroupName(n) if n == "us-proxies"));
            assert!(matches!(&vec[1], ConfigSelection::GroupName(n) if n == "eu-proxies"));
        } else {
            panic!("Expected Pool");
        }
    }

    #[test]
    fn test_client_chain_hop_pool_mixed() {
        let yaml = r#"
pool:
  - my-proxy-group
  - address: "127.0.0.1:1080"
    protocol:
      type: socks
"#;
        let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let ClientChainHop::Pool(selections) = result.unwrap() {
            let vec: Vec<_> = selections.into_vec();
            assert_eq!(vec.len(), 2);
            assert!(matches!(&vec[0], ConfigSelection::GroupName(_)));
            assert!(matches!(&vec[1], ConfigSelection::Config(_)));
        } else {
            panic!("Expected Pool");
        }
    }

    #[test]
    fn test_client_chain_hop_pool_cannot_be_empty() {
        let yaml = r#"
pool: []
"#;
        let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("pool") || err.contains("empty"),
            "Error should mention pool or empty: {err}"
        );
    }

    #[test]
    fn test_client_chain_hop_pool_single_item() {
        // OneOrSome allows a single item without array syntax
        let yaml = r#"
pool: my-proxy-group
"#;
        let result: Result<ClientChainHop, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let ClientChainHop::Pool(selections) = result.unwrap() {
            let vec: Vec<_> = selections.into_vec();
            assert_eq!(vec.len(), 1);
            assert!(matches!(&vec[0], ConfigSelection::GroupName(n) if n == "my-proxy-group"));
        } else {
            panic!("Expected Pool");
        }
    }

    #[test]
    fn test_rejects_both_client_proxies_and_client_chains() {
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_proxies:
  - my-group
client_chains:
  - chain: [other-group]
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot specify both"));
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_chain_hop_serialization_roundtrip_single_group() {
        let original = ClientChainHop::Single(ConfigSelection::GroupName("my-group".to_string()));
        let yaml = serde_yaml::to_string(&original).unwrap();
        println!("Single group YAML: {yaml}");
        let deserialized: ClientChainHop = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(
            deserialized,
            ClientChainHop::Single(ConfigSelection::GroupName(_))
        ));
    }

    #[test]
    fn test_chain_hop_serialization_roundtrip_single_config() {
        let original = ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default()));
        let yaml = serde_yaml::to_string(&original).unwrap();
        println!("Single config YAML: {yaml}");
        let deserialized: ClientChainHop = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(
            deserialized,
            ClientChainHop::Single(ConfigSelection::Config(_))
        ));
    }

    #[test]
    fn test_chain_hop_serialization_roundtrip_pool() {
        let original = ClientChainHop::Pool(OneOrSome::Some(vec![
            ConfigSelection::GroupName("group-a".to_string()),
            ConfigSelection::Config(ClientConfig::default()),
        ]));
        let yaml = serde_yaml::to_string(&original).unwrap();
        println!("Pool YAML: {yaml}");
        assert!(yaml.contains("pool:"));
        let deserialized: ClientChainHop = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(deserialized, ClientChainHop::Pool(_)));
    }

    #[test]
    fn test_client_chain_serialization_roundtrip() {
        let original = ClientChain {
            hops: OneOrSome::Some(vec![
                ClientChainHop::Single(ConfigSelection::GroupName("entry".to_string())),
                ClientChainHop::Single(ConfigSelection::GroupName("exit".to_string())),
            ]),
        };
        let yaml = serde_yaml::to_string(&original).unwrap();
        println!("ClientChain YAML:\n{yaml}");
        assert!(yaml.contains("chain:"));
        let deserialized: ClientChain = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.hops.len(), 2);
    }

    #[test]
    fn test_multi_hop_chain() {
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chain:
  - pool:
      - entry-proxies-us
      - entry-proxies-eu
  - exit-proxies
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 1);
            let chain = client_chains.iter().next().unwrap();
            assert_eq!(chain.hops.len(), 2);
            // First hop is a pool
            assert!(matches!(
                chain.hops.iter().next().unwrap(),
                ClientChainHop::Pool(_)
            ));
            // Second hop is a single group ref
            assert!(matches!(
                chain.hops.iter().nth(1).unwrap(),
                ClientChainHop::Single(ConfigSelection::GroupName(_))
            ));
        } else {
            panic!("Expected Allow action");
        }
    }

    // =========================================================================
    // Complex multi-chain scenarios
    // =========================================================================

    #[test]
    fn test_direct_with_proxy_fallback() {
        // Round-robin between direct and a proxy chain
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [direct]
  - chain:
      - address: "proxy.example.com:1080"
        protocol:
          type: socks
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 2);
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_geographic_load_balancing() {
        // Different paths for different regions
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [us-entry, asia-exit]
  - chain: [eu-entry, asia-exit]
  - chain: [direct]
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 3);
            let chains: Vec<_> = client_chains.iter().collect();
            assert_eq!(chains[0].hops.len(), 2); // us-entry, asia-exit
            assert_eq!(chains[1].hops.len(), 2); // eu-entry, asia-exit
            assert_eq!(chains[2].hops.len(), 1); // direct
        } else {
            panic!("Expected Allow action");
        }
    }

    #[test]
    fn test_complex_multi_hop_with_pools() {
        // Per-hop load balancing within multi-chain selection
        let yaml = r#"
masks: 0.0.0.0/0
action: allow
client_chains:
  - chain: [direct]
  - chain:
      - pool: [entry-us-1, entry-us-2, entry-eu-1]
      - pool: [middle-relay-a, middle-relay-b]
      - pool: [exit-asia, exit-europe]
  - chain:
      - fast-entry
      - fast-exit
"#;
        let result: Result<RuleConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok(), "Parse error: {:?}", result.err());
        if let RuleActionConfig::Allow { client_chains, .. } = result.unwrap().action {
            assert_eq!(client_chains.len(), 3);
            let chains: Vec<_> = client_chains.iter().collect();

            // Chain 1: direct (1 hop)
            assert_eq!(chains[0].hops.len(), 1);

            // Chain 2: 3 hops, all pools
            assert_eq!(chains[1].hops.len(), 3);
            for hop in chains[1].hops.iter() {
                assert!(matches!(hop, ClientChainHop::Pool(_)));
            }

            // Chain 3: 2 hops
            assert_eq!(chains[2].hops.len(), 2);
        } else {
            panic!("Expected Allow action");
        }
    }
}
