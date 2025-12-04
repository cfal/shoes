//! Common types and helpers shared across config modules.

use serde::{Deserialize, Serialize};

use crate::address::{NetLocation, NetLocationMask, NetLocationPortRange};
use crate::option_util::OneOrSome;

/// Default Reality short_id: all zeros (16 hex chars = 8 bytes of zeros)
pub const DEFAULT_REALITY_SHORT_ID: &str = "0000000000000000";

pub fn default_true() -> bool {
    true
}

pub fn is_false(b: &bool) -> bool {
    !*b
}

pub fn is_true(b: &bool) -> bool {
    *b
}

pub fn default_reality_client_short_id() -> String {
    DEFAULT_REALITY_SHORT_ID.to_string()
}

pub fn default_reality_server_short_ids() -> OneOrSome<String> {
    OneOrSome::One(DEFAULT_REALITY_SHORT_ID.to_string())
}

pub fn default_reality_time_diff() -> Option<u64> {
    // 1 minute
    Some(1000 * 60)
}

pub fn unspecified_address() -> NetLocation {
    NetLocation::UNSPECIFIED
}

/// Implement Serialize for CipherSuite - serializes as the standard TLS cipher suite name
impl Serialize for crate::reality::CipherSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.name())
    }
}

/// Implement Deserialize for CipherSuite - deserializes from standard TLS cipher suite name
impl<'de> Deserialize<'de> for crate::reality::CipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let name = String::deserialize(deserializer)?;
        crate::reality::CipherSuite::from_name(&name).ok_or_else(|| {
            let valid_names: Vec<&str> = crate::reality::DEFAULT_CIPHER_SUITES
                .iter()
                .map(|cs| cs.name())
                .collect();
            D::Error::custom(format!(
                "invalid cipher suite '{}', valid values are: {}",
                name,
                valid_names.join(", ")
            ))
        })
    }
}

pub fn deserialize_net_location<'de, D>(
    deserializer: D,
    default_port: Option<u16>,
) -> Result<NetLocation, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let net_location = NetLocation::from_str(&value, default_port).map_err(|_| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("invalid net location"),
            &"invalid net location",
        )
    })?;

    Ok(net_location)
}

impl<'de> serde::de::Deserialize<'de> for NetLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserialize_net_location(deserializer, None)
    }
}

impl<'de> serde::de::Deserialize<'de> for NetLocationMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let net_location_mask = NetLocationMask::from(&value).map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other("invalid net location mask"),
                &"invalid net location mask",
            )
        })?;

        Ok(net_location_mask)
    }
}

impl<'de> serde::de::Deserialize<'de> for NetLocationPortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let net_location_port_range = NetLocationPortRange::from_str(&value).map_err(|e| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Other(&format!("invalid net location port range: {e}")),
                &"valid net location port range (address:port[-port][,port])",
            )
        })?;

        Ok(net_location_port_range)
    }
}
