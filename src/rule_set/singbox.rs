use std::io;

use serde::Deserialize;
use serde_json::Value;

use crate::rules::{Compiler, Expression, MAX_DEPTH, MAX_STRING_BYTES, domain, invalid};

#[derive(Deserialize)]
#[serde(untagged)]
enum Values<T> {
    One(T),
    Many(Vec<T>),
}

fn values<T>(values: Option<Values<T>>) -> Vec<T> {
    match values {
        Some(Values::One(v)) => vec![v],
        Some(Values::Many(v)) => v,
        None => Vec::new(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    version: u8,
    rules: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultRule {
    #[serde(rename = "type")]
    kind: Option<String>,
    domain: Option<Values<String>>,
    domain_suffix: Option<Values<String>>,
    domain_keyword: Option<Values<String>>,
    domain_regex: Option<Values<String>>,
    ip_cidr: Option<Values<String>>,
    port: Option<Values<u16>>,
    port_range: Option<Values<String>>,
    #[serde(default)]
    invert: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalRule {
    #[serde(rename = "type")]
    kind: String,
    mode: String,
    rules: Vec<Value>,
    #[serde(default)]
    invert: bool,
}

pub fn decode(bytes: &[u8], budget: &mut Compiler) -> io::Result<Expression> {
    let source: Source = serde_json::from_value(super::json::decode(bytes, budget)?)
        .map_err(|e| invalid(format!("sing-box JSON: {e}")))?;
    if !(1..=5).contains(&source.version) {
        return Err(invalid(
            "unsupported sing-box rule-set version (expected 1-5)",
        ));
    }
    Ok(Expression::or(
        source
            .rules
            .into_iter()
            .enumerate()
            .map(|(i, r)| rule(r, 0).map_err(|e| invalid(format!("rule {i}: {e}"))))
            .collect::<io::Result<Vec<_>>>()?,
    ))
}

fn rule(value: Value, depth: usize) -> io::Result<Expression> {
    if depth > MAX_DEPTH {
        return Err(invalid("rule nesting exceeds 100"));
    }
    if value.get("type").and_then(Value::as_str) == Some("logical") {
        logical_rule(value, depth)
    } else {
        default_rule(value)
    }
}

fn logical_rule(value: Value, depth: usize) -> io::Result<Expression> {
    let rule: LogicalRule = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
    if rule.kind != "logical" || rule.rules.is_empty() {
        return Err(invalid("empty/invalid logical rule"));
    }
    let children = rule
        .rules
        .into_iter()
        .map(|v| self::rule(v, depth + 1))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(match rule.mode.as_str() {
        "and" => Expression::All(children),
        "or" => Expression::Any(children),
        _ => return Err(invalid("logical mode must be and or or")),
    }
    .inverted(rule.invert))
}

fn default_rule(value: Value) -> io::Result<Expression> {
    let rule: DefaultRule = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
    if rule.kind.as_deref().is_some_and(|s| s != "default") {
        return Err(invalid("unsupported rule type"));
    }
    let mut parts = Parts::default();
    for (kind, v) in [
        (LiteralKind::Exact, rule.domain),
        (LiteralKind::Suffix, rule.domain_suffix),
        (LiteralKind::Keyword, rule.domain_keyword),
    ] {
        let v = values(v);
        if !v.is_empty() {
            parts.address.push(literals(v, kind)?);
        }
    }
    let regex = values(rule.domain_regex);
    if !regex.is_empty() {
        parts.address.push(Expression::DomainRegex(regex));
    }
    let ips = values(rule.ip_cidr);
    if !ips.is_empty() {
        parts.address.push(Expression::IpCidr(ips));
    }
    let ports = values(rule.port);
    if !ports.is_empty() {
        parts.ports.push(Expression::PortRanges(
            ports.into_iter().map(|p| (p, p)).collect(),
        ));
    }
    let ranges = values(rule.port_range);
    if !ranges.is_empty() {
        parts.ports.push(port_ranges(ranges)?);
    }
    parts.finish(rule.invert)
}

pub(super) fn port_ranges(values: Vec<String>) -> io::Result<Expression> {
    let ranges = values
        .into_iter()
        .map(|s| {
            let (a, b) = s
                .split_once(':')
                .ok_or_else(|| invalid("port range requires start:end"))?;
            let a = if a.is_empty() {
                0
            } else {
                a.parse().map_err(|_| invalid("invalid port range start"))?
            };
            let b = if b.is_empty() {
                u16::MAX
            } else {
                b.parse().map_err(|_| invalid("invalid port range end"))?
            };
            if a > b {
                return Err(invalid("descending port range"));
            }
            Ok((a, b))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Expression::PortRanges(ranges))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LiteralKind {
    Exact,
    Suffix,
    Keyword,
}

// The source folds query case, not literal pattern case. False alternatives must
// remain false under enclosing AND/NOT nodes, not disappear as missing fields.
pub(super) fn literals(input: Vec<String>, kind: LiteralKind) -> io::Result<Expression> {
    let mut names = Vec::new();
    let mut strict = Vec::new();
    let mut uppercase = 0;
    for value in input {
        if !value.is_ascii() || value.is_empty() || value.len() > MAX_STRING_BYTES {
            return Err(invalid(
                "sing-box literals must be nonempty ASCII strings of at most 64 KiB",
            ));
        }
        let name = if kind == LiteralKind::Suffix {
            value.strip_prefix('.').unwrap_or(&value)
        } else {
            &value
        };
        if kind != LiteralKind::Keyword {
            domain::normalize(name)?;
        }
        if value.bytes().any(|b| b.is_ascii_uppercase()) {
            uppercase += 1;
            continue;
        }
        if kind == LiteralKind::Suffix && value.starts_with('.') {
            strict.push(name.to_owned());
        } else {
            names.push(value);
        }
    }
    if uppercase != 0 {
        log::warn!(
            "{uppercase} uppercase sing-box literal alternatives cannot match lowercase query names"
        );
    }
    Ok(match kind {
        LiteralKind::Exact => Expression::Domain(names),
        LiteralKind::Suffix => Expression::or(vec![
            Expression::DomainSuffix(names),
            Expression::Subdomains(strict),
        ]),
        LiteralKind::Keyword => Expression::DomainKeyword(names),
    })
}

#[derive(Default)]
pub(super) struct Parts {
    pub address: Vec<Expression>,
    pub ports: Vec<Expression>,
}

impl Parts {
    pub fn finish(self, invert: bool) -> io::Result<Expression> {
        if self.address.is_empty() && self.ports.is_empty() {
            return Err(invalid("empty rule"));
        }
        let mut groups = Vec::new();
        if !self.address.is_empty() {
            groups.push(Expression::or(self.address));
        }
        if !self.ports.is_empty() {
            groups.push(Expression::or(self.ports));
        }
        Ok(Expression::and(groups).inverted(invert))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Compiler, Outcome};

    fn decode(bytes: &[u8]) -> io::Result<Expression> {
        super::decode(bytes, &mut Compiler::default())
    }

    #[test]
    fn malformed_literals_do_not_suggest_native_rule_syntax() {
        let source = br#"{"version":1,"rules":[{"domain":"a*.example.com"}]}"#;
        assert_eq!(
            decode(source).unwrap_err().to_string(),
            "rule 0: invalid hostname label"
        );
    }

    #[test]
    fn logical_children_are_validated_before_mode() {
        let invalid_child =
            br#"{"version":1,"rules":[{"type":"logical","mode":"invalid","rules":[{}]}]}"#;
        assert_eq!(
            decode(invalid_child).unwrap_err().to_string(),
            "rule 0: empty rule"
        );
        let valid_child = br#"{"version":1,"rules":[{"type":"logical","mode":"invalid","rules":[{"domain":"example.com"}]}]}"#;
        assert_eq!(
            decode(valid_child).unwrap_err().to_string(),
            "rule 0: logical mode must be and or or"
        );
        let empty = br#"{"version":1,"rules":[{"type":"logical","mode":"invalid","rules":[]}]}"#;
        assert_eq!(
            decode(empty).unwrap_err().to_string(),
            "rule 0: empty/invalid logical rule"
        );
    }

    #[test]
    fn empty_fields_are_absent_but_invalid_uppercase_is_rejected() {
        let p = Compiler::default().compile(decode(br#"{"version":1,"rules":[{"domain_suffix":["example.com"],"port":[],"domain":[] }]}"#).unwrap()).unwrap();
        assert_eq!(p.evaluate(Some("example.com"), None, 443), Outcome::Match);
        assert!(decode(br#"{"version":1,"rules":[{"domain":[],"port":[]}]}"#).is_err());
        for invert in [false, true] {
            let source = format!(
                r#"{{"version":1,"rules":[{{"domain_keyword":["{}"],"invert":{invert}}}]}}"#,
                "A".repeat(65_537)
            );
            assert!(decode(source.as_bytes()).is_err());
            assert!(literals(vec!["A".repeat(65_537)], LiteralKind::Keyword).is_err());
        }
    }

    #[test]
    fn source_groups_and_case_are_preserved() {
        let p = decode(br#"{"version":5,"rules":[{"domain":["EXAMPLE.com","a.example"],"ip_cidr":["10.0.0.0/8"],"port":[443]}]}"#).unwrap();
        let p = Compiler::default().compile(p).unwrap();
        assert_eq!(p.evaluate(Some("a.example"), None, 443), Outcome::Match);
        assert_eq!(p.evaluate(Some("a.example"), None, 80), Outcome::Miss);
        assert_eq!(
            p.evaluate(Some("example.com"), None, 443),
            Outcome::Unknown { may_resolve: true }
        );
        for field in ["domain", "domain_suffix", "domain_keyword"] {
            let source =
                format!(r#"{{"version":1,"rules":[{{"{field}":["EXAMPLE"],"invert":true}}]}}"#);
            let p = Compiler::default()
                .compile(decode(source.as_bytes()).unwrap())
                .unwrap();
            assert_eq!(p.evaluate(Some("example"), None, 1), Outcome::Match);
        }
        for source in [
            r#"{"version":6,"rules":[]}"#,
            r#"{"version":1,"rules":[{}]}"#,
            r#"{"version":1,"rules":[{"domain":["x"],"network":"tcp"}]}"#,
        ] {
            assert!(decode(source.as_bytes()).is_err());
        }
    }
}
