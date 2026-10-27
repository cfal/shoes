//! Rule configuration types.

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationMask};
use crate::option_util::{NoneOrSome, OneOrSome};
use crate::rules::Expression;

use super::client::ClientConfig;
use super::selection::ConfigSelection;

#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub criteria: RuleCriteria,
    pub action: RuleActionConfig,
}

#[derive(Debug, Clone)]
pub struct RuleCriteria {
    pub description: Option<std::sync::Arc<crate::control::catalog::RuleDescription>>,
    pub expression: Expression,
    pub no_resolve: bool,
    pub compiled: Option<std::sync::Arc<crate::rules::Predicate>>,
}

impl Default for RuleCriteria {
    fn default() -> Self {
        Self {
            description: None,
            expression: Expression::Legacy(OneOrSome::One(NetLocationMask::ANY)),
            no_resolve: false,
            compiled: None,
        }
    }
}

impl RuleConfig {
    pub(crate) fn compile(&mut self, compiler: &mut crate::rules::Compiler) -> std::io::Result<()> {
        if self.criteria.compiled.is_some() {
            return Ok(());
        }
        let expression = std::mem::replace(
            &mut self.criteria.expression,
            Expression::Legacy(OneOrSome::Some(Vec::new())),
        );
        let predicate = match expression {
            Expression::Legacy(masks) => compiler.legacy(masks.into_vec())?,
            expression => compiler.compile(expression)?,
        };
        if matches!(self.action, RuleActionConfig::Block)
            && predicate.dependencies.ip
            && (self.criteria.no_resolve || predicate.has_no_resolve_ip())
        {
            log::warn!(
                "block rule with no_resolve IP predicates can fall through when no address is available (including under not)"
            );
        }
        self.criteria.compiled = Some(predicate);
        Ok(())
    }
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            criteria: RuleCriteria::default(),
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
            masks: serde_json::Value,
            #[serde(default)]
            no_resolve: bool,
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

        let expression = Expression::from_config(temp.masks).map_err(D::Error::custom)?;
        let criteria = RuleCriteria {
            description: None,
            expression,
            no_resolve: temp.no_resolve,
            compiled: None,
        };

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

        Ok(RuleConfig { criteria, action })
    }
}

impl Serialize for RuleConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        if self.criteria.compiled.is_some() {
            return Err(serde::ser::Error::custom(
                "compiled runtime rules cannot be serialized",
            ));
        }

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

        let mut map = serializer.serialize_map(Some(
            action_field_count + 1 + usize::from(self.criteria.no_resolve),
        ))?;

        match &self.criteria.expression {
            Expression::Legacy(masks) => map.serialize_entry("masks", masks)?,
            expression => {
                // Direct YAML enum serialization emits tags, not predicate mappings.
                map.serialize_entry(
                    "masks",
                    &serde_json::to_value(expression).map_err(serde::ser::Error::custom)?,
                )?;
            }
        }
        if self.criteria.no_resolve {
            map.serialize_entry("no_resolve", &true)?;
        }

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
mod tests;
