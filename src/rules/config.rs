use std::io;

use serde_json::Value;

use super::{Expression, MAX_DEPTH, invalid};
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
                Self::parse_children(values, depth).map(Self::Any)
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
                    "all" => Self::parse_children(decode(value)?, depth).map(Self::All),
                    "any" => Self::parse_children(decode(value)?, depth).map(Self::Any),
                    "not" => Self::parse_config(value, depth + 1).map(|p| Self::Not(Box::new(p))),
                    _ => Err(invalid(format!("unknown masks field: {field}"))),
                }
            }
            _ => Err(invalid(
                "masks requires a mask string, predicate object, or nonempty list",
            )),
        }
    }

    fn parse_children(values: Vec<Value>, depth: usize) -> io::Result<Vec<Self>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn composite_errors_preserve_list_context_and_child_order() {
        for (value, message) in [
            (json!([]), "masks cannot be empty"),
            (
                json!({"all": []}),
                "all/any requires at least one predicate",
            ),
            (
                json!({"any": []}),
                "all/any requires at least one predicate",
            ),
            (
                json!({"all": true}),
                "invalid type: boolean `true`, expected a sequence",
            ),
            (
                json!(["example.com", {"any": []}]),
                "all/any requires at least one predicate",
            ),
            (
                json!({"any": [{"unknown": true}, false]}),
                "unknown masks field: unknown",
            ),
        ] {
            let error = Expression::from_config(value).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn composite_forms_share_the_same_depth_limit() {
        for form in ["list", "all", "any", "not"] {
            let wrap = |value| match form {
                "list" => json!([value]),
                "not" => json!({"not": value}),
                operator => json!({operator: [value]}),
            };
            let value =
                (0..MAX_DEPTH).fold(json!({"any_destination": true}), |value, _| wrap(value));
            Expression::from_config(value.clone()).unwrap();
            assert_eq!(
                Expression::from_config(wrap(value))
                    .unwrap_err()
                    .to_string(),
                "rule nesting exceeds 100 levels",
                "{form}"
            );
        }
    }
}
