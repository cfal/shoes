use std::io;

use serde::{Deserialize, Serialize};

use crate::rules::{
    Compiler, Expression, IpRanges, MAX_ENTRIES, MAX_STRING_BYTES, domain, invalid,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Behavior {
    Domain,
    Ipcidr,
    Classical,
}

pub(super) fn decode(
    bytes: &[u8],
    yaml: bool,
    behavior: Behavior,
    budget: &mut Compiler,
) -> io::Result<Expression> {
    let entries = if yaml {
        super::yaml::decode(bytes, budget)?
    } else {
        let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid UTF-8 provider"))?;
        text.strip_prefix('\u{feff}')
            .unwrap_or(text)
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with("//"))
            .map(|entry| {
                if entry.len() > MAX_STRING_BYTES {
                    return Err(invalid("provider entry exceeds 64 KiB"));
                }
                budget.charge(entry.len() * 4 + 256, 1)?;
                Ok(entry.to_owned())
            })
            .collect::<io::Result<Vec<_>>>()?
    };
    if entries.len() > MAX_ENTRIES {
        return Err(invalid("provider entry limit exceeded"));
    }
    let mut rules = Vec::with_capacity(entries.len());
    for (i, entry) in entries.into_iter().enumerate() {
        let result = match behavior {
            Behavior::Domain => domain_entry(&entry),
            Behavior::Ipcidr => ip(&entry, false),
            Behavior::Classical => classical(&entry),
        }
        .map_err(|e| invalid(format!("provider entry {i}: {e}")))?;
        rules.push(result);
    }
    Ok(Expression::or(rules))
}

pub(super) fn domain_entry(value: &str) -> io::Result<Expression> {
    let suffix = value
        .strip_prefix("+.")
        .map(|name| (name, true))
        .or_else(|| value.strip_prefix('.').map(|name| (name, false)));
    if let Some((name, include_root)) = suffix {
        if name.contains('*') {
            let pattern = domain::wildcard(name)?;
            let repeat = if include_root { '*' } else { '+' };
            return Ok(Expression::DomainRegex(vec![format!(
                r"^(?:[^.]+\.){repeat}{}",
                &pattern[1..]
            )]));
        }
        let names = vec![domain::normalize(name)?.into_owned()];
        return Ok(if include_root {
            Expression::DomainSuffix(names)
        } else {
            Expression::Subdomains(names)
        });
    }
    if value.contains('*') {
        return Ok(Expression::DomainRegex(vec![domain::wildcard(value)?]));
    }
    Ok(Expression::Domain(vec![
        domain::normalize(value)?.into_owned(),
    ]))
}

fn ip(value: &str, no_resolve: bool) -> io::Result<Expression> {
    let mut ranges = IpRanges::default();
    ranges.add_cidr(value)?;
    Ok(Expression::Ranges(ranges, no_resolve))
}

fn classical(value: &str) -> io::Result<Expression> {
    let (kind, payload) = value
        .split_once(',')
        .ok_or_else(|| invalid("classical entry requires TYPE,payload"))?;
    let kind = kind.trim();
    let payload = payload.trim();
    if payload.is_empty() {
        return Err(invalid("empty classical payload"));
    }
    match kind {
        "DOMAIN" => Ok(Expression::Domain(vec![
            domain::normalize(payload)?.into_owned(),
        ])),
        "DOMAIN-SUFFIX" => Ok(Expression::DomainSuffix(vec![
            domain::normalize(payload)?.into_owned(),
        ])),
        "DOMAIN-KEYWORD" if !payload.contains(',') => {
            Ok(Expression::DomainKeyword(vec![payload.to_owned()]))
        }
        "DOMAIN-REGEX" => Ok(Expression::DomainRegex(vec![format!("(?i){payload}")])),
        "IP-CIDR" | "IP-CIDR6" => {
            let (cidr, no_resolve) = match payload.split_once(',') {
                Some((cidr, flag)) if flag.trim() == "no-resolve" => (cidr.trim(), true),
                Some(_) => return Err(invalid("unsupported IP-CIDR option")),
                None => (payload, false),
            };
            let network: ipnetwork::IpNetwork = cidr
                .parse()
                .map_err(|_| invalid("invalid classical CIDR"))?;
            if kind == "IP-CIDR6" && !network.is_ipv6() {
                return Err(invalid("IP-CIDR6 requires IPv6"));
            }
            ip(cidr, no_resolve)
        }
        "DST-PORT" => {
            let ranges = payload
                .split('/')
                .map(|part| {
                    let (a, b) = part.split_once('-').unwrap_or((part, part));
                    let a = a.parse::<u16>().map_err(|_| invalid("invalid DST-PORT"))?;
                    let b = b.parse::<u16>().map_err(|_| invalid("invalid DST-PORT"))?;
                    if a > b {
                        return Err(invalid("descending DST-PORT range"));
                    }
                    Ok((a, b))
                })
                .collect::<io::Result<Vec<_>>>()?;
            Ok(Expression::PortRanges(ranges))
        }
        _ => Err(invalid(format!("unsupported classical operator {kind}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Compiler, Outcome};

    fn decode(bytes: &[u8], yaml: bool, behavior: Behavior) -> io::Result<Expression> {
        super::decode(bytes, yaml, behavior, &mut Compiler::default())
    }

    #[test]
    fn malformed_wildcards_describe_the_provider_grammar() {
        for entry in ["a*.example.com", "**.x", "+.a*.example.com", ".**.x"] {
            let error = domain_entry(entry).unwrap_err().to_string();
            assert!(
                error.contains("wildcard labels must be '*'"),
                "{entry}: {error}"
            );
            assert!(!error.contains("domain_pattern"));
        }
        let overlong = format!("*.{}", "a".repeat(252));
        let error = decode(overlong.as_bytes(), false, Behavior::Domain).unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider entry 0: wildcard pattern must be 1-253 bytes"
        );
    }

    #[test]
    fn text_providers_accept_bom_and_both_comment_styles() {
        for (behavior, entry) in [
            (Behavior::Domain, "example.com"),
            (Behavior::Ipcidr, "192.0.2.0/24"),
            (Behavior::Classical, "DOMAIN,example.com"),
        ] {
            let text = format!("\u{feff}{entry}\r\n # comment\r\n  // Premium comment\r\n\r\n");
            let predicate = Compiler::default()
                .compile(decode(text.as_bytes(), false, behavior).unwrap())
                .unwrap();
            assert_eq!(
                predicate.evaluate(Some("example.com"), Some("192.0.2.1".parse().unwrap()), 443),
                Outcome::Match
            );
            let empty = Compiler::default()
                .compile(
                    decode("\u{feff}// comment\n# comment".as_bytes(), false, behavior).unwrap(),
                )
                .unwrap();
            assert_eq!(empty.evaluate(None, None, 443), Outcome::Miss);
        }
    }

    #[test]
    fn domain_provider_boundaries_and_case() {
        for (entry, yes, no) in [
            ("Example.COM", "example.com", "a.example.com"),
            ("+.Example.COM", "example.com", "badexample.com"),
            (".Example.COM", "a.b.example.com", "example.com"),
            ("*.Example.COM", "a.example.com", "a.b.example.com"),
            ("a.*.Example.COM", "a.b.example.com", "a.b.c.example.com"),
            ("+.*.Example.COM", "a.example.com", "example.com"),
            (
                "+.a.*.Example.COM",
                "x.a.b.example.com",
                "a.b.c.example.com",
            ),
            (".a.*.Example.COM", "x.a.b.example.com", "a.b.example.com"),
        ] {
            let p = Compiler::default()
                .compile(domain_entry(entry).unwrap())
                .unwrap();
            assert_eq!(p.evaluate(Some(yes), None, 80), Outcome::Match);
            assert_eq!(p.evaluate(Some(no), None, 80), Outcome::Miss);
        }
        assert!(decode(b"payload: [a]\nunknown: true", true, Behavior::Domain).is_err());
    }

    #[test]
    fn classical_casing_ports_and_resolution() {
        for payload in ["foo)|(.*", "a)b(", "ads)|(?i:tracker"] {
            assert!(
                Compiler::default()
                    .compile(classical(&format!("DOMAIN-REGEX,{payload}")).unwrap())
                    .is_err()
            );
        }
        let comment = classical("DOMAIN-REGEX,(?x)^EXAMPLE$ # trailing comment").unwrap();
        let predicate = Compiler::default().compile(comment).unwrap();
        assert_eq!(
            predicate.evaluate(Some("example"), None, 80),
            Outcome::Match
        );
        for entry in ["DOMAIN-KEYWORD,EXAMPLE", "DOMAIN-REGEX,^EXAMPLE$"] {
            let p = Compiler::default()
                .compile(classical(entry).unwrap())
                .unwrap();
            assert_eq!(p.evaluate(Some("example"), None, 80), Outcome::Match);
        }
        let p = Compiler::default()
            .compile(classical("DOMAIN-REGEX,(?-i:EXAMPLE)").unwrap())
            .unwrap();
        assert_eq!(p.evaluate(Some("example"), None, 80), Outcome::Miss);
        let p = Compiler::default()
            .compile(classical("IP-CIDR,10.0.0.0/8,no-resolve").unwrap())
            .unwrap();
        assert_eq!(
            p.evaluate(Some("example"), None, 80),
            Outcome::Unknown { may_resolve: false }
        );
        assert_eq!(
            p.evaluate(None, Some("10.1.2.3".parse().unwrap()), 80),
            Outcome::Match
        );
        let p = Compiler::default()
            .compile(classical("DST-PORT,80/443/8000-9000").unwrap())
            .unwrap();
        assert_eq!(p.evaluate(None, None, 8500), Outcome::Match);
        assert_eq!(p.evaluate(None, None, 81), Outcome::Miss);
        for entry in [
            "MATCH",
            "RULE-SET,foo",
            "DOMAIN,a,no-resolve",
            "IP-CIDR,10.0.0.0/8,bad",
            "DST-PORT,80-79",
        ] {
            assert!(classical(entry).is_err(), "{entry}");
        }
        let p = Compiler::default()
            .compile(decode(b"# empty\n\n", false, Behavior::Domain).unwrap())
            .unwrap();
        assert_eq!(p.evaluate(None, None, 80), Outcome::Miss);
    }
}
