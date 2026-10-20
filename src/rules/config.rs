use std::io;

use serde_json::Value;

use super::{Expression, compile::MAX_DEPTH, invalid};
use crate::rule_set::RuleSource;

impl Expression {
    pub(crate) fn from_config(value: Value) -> io::Result<Self> {
        Self::parse_config(value, 0)
    }

    fn parse_config(value: Value, depth: usize) -> io::Result<Self> {
        if depth > MAX_DEPTH {
            return Err(invalid("rule nesting exceeds 100 levels"));
        }
        match value {
            Value::String(_) => decode(value).map(Self::Legacy),
            Value::Array(values) => {
                if values.is_empty() {
                    return Err(invalid("masks cannot be empty"));
                }
                if values.iter().all(Value::is_string) {
                    return decode(Value::Array(values)).map(Self::Legacy);
                }
                Self::parse_children(Value::Array(values), depth).map(Self::Any)
            }
            Value::Object(fields) if fields.contains_key("path") => {
                decode(Value::Object(fields)).map(Self::Source)
            }
            Value::Object(fields) => {
                if fields.len() != 1 {
                    return Err(invalid(
                        "a masks object requires exactly one predicate or a path",
                    ));
                }
                let (field, value) = fields.into_iter().next().unwrap();
                match field.as_str() {
                    "any_destination" => decode(value).map(Self::AnyDestination),
                    "domain" => decode(value).map(Self::Domain),
                    "domain_suffix" => decode(value).map(Self::DomainSuffix),
                    "subdomains" => decode(value).map(Self::Subdomains),
                    "domain_pattern" => decode(value).map(Self::DomainPattern),
                    "domain_keyword" => decode(value).map(Self::DomainKeyword),
                    "domain_regex" => decode(value).map(Self::DomainRegex),
                    "ip_cidr" => decode(value).map(Self::IpCidr),
                    "destination_port" => decode(value).map(Self::DestinationPort),
                    "destination_port_range" => decode(value).map(Self::DestinationPortRange),
                    "rule_group" => decode(value).map(Self::RuleGroup),
                    "all" => Self::parse_children(value, depth).map(Self::All),
                    "any" => Self::parse_children(value, depth).map(Self::Any),
                    "not" => Self::parse_config(value, depth + 1).map(|p| Self::Not(Box::new(p))),
                    _ => Err(invalid(format!("unknown masks field: {field}"))),
                }
            }
            _ => Err(invalid(
                "masks requires a mask string, predicate object, or nonempty list",
            )),
        }
    }

    fn parse_children(value: Value, depth: usize) -> io::Result<Vec<Self>> {
        let values: Vec<Value> = decode(value)?;
        if values.is_empty() {
            return Err(invalid("all/any requires at least one predicate"));
        }
        values
            .into_iter()
            .map(|v| Self::parse_config(v, depth + 1))
            .collect()
    }

    pub(crate) fn visit_sources(
        &mut self,
        visitor: &mut dyn FnMut(&mut RuleSource) -> io::Result<()>,
    ) -> io::Result<()> {
        match self {
            Self::Source(source) => visitor(source)?,
            Self::All(children) | Self::Any(children) => {
                for child in children {
                    child.visit_sources(visitor)?;
                }
            }
            Self::Not(child) => child.visit_sources(visitor)?,
            _ => {}
        }
        Ok(())
    }
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> io::Result<T> {
    serde_json::from_value(value).map_err(|e| invalid(e.to_string()))
}
