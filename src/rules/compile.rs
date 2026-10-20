use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::Arc;

use super::{Expression, IpRanges, Kind, Predicate, domain, invalid};
use crate::address::{Address, NetLocationMask};
use domain::{DomainKind, Names};

pub const MAX_ENTRIES: usize = 2_000_000;
pub const MAX_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_DEPTH: usize = 100;

#[derive(Default)]
pub struct Compiler {
    pub sets: HashMap<String, Arc<Predicate>>,
    bytes: usize,
    entries: usize,
}

impl Compiler {
    pub fn charge(&mut self, bytes: usize, entries: usize) -> io::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("rule compilation budget overflow"))?;
        self.entries = self
            .entries
            .checked_add(entries)
            .ok_or_else(|| invalid("rule count overflow"))?;
        if self.bytes > MAX_BYTES || self.entries > MAX_ENTRIES {
            return Err(invalid("rule compilation budget exceeded"));
        }
        Ok(())
    }

    pub fn compile(&mut self, expression: Expression) -> io::Result<Arc<Predicate>> {
        self.visit(expression, 0)
    }

    fn strings(&mut self, values: &[String]) -> io::Result<()> {
        for value in values {
            if value.len() > 64 * 1024 || !value.is_ascii() {
                return Err(invalid("rule strings must be ASCII and at most 64 KiB"));
            }
            self.charge(value.capacity().saturating_mul(4).saturating_add(96), 1)?;
        }
        Ok(())
    }

    fn visit(&mut self, expression: Expression, depth: usize) -> io::Result<Arc<Predicate>> {
        if depth > MAX_DEPTH {
            return Err(invalid("rule nesting exceeds 100 levels"));
        }
        self.charge(128, 0)?;
        let kind = match expression {
            Expression::AnyDestination(true) => Kind::Constant(true),
            Expression::AnyDestination(false) => {
                return Err(invalid("any_destination must be true"));
            }
            Expression::Never => Kind::Constant(false),
            p @ (Expression::Domain(_)
            | Expression::DomainSuffix(_)
            | Expression::Subdomains(_)) => return self.visit_domain(p, depth),
            Expression::DomainPattern(v) => {
                self.strings(&v)?;
                let patterns = v
                    .iter()
                    .map(|s| domain::wildcard(s))
                    .collect::<io::Result<Vec<_>>>()?;
                return self.visit(Expression::DomainRegex(patterns), depth + 1);
            }
            Expression::DomainKeyword(v) => {
                self.strings(&v)?;
                if v.is_empty() {
                    return Ok(Predicate::new(Kind::Constant(false)));
                }
                if v.iter().any(String::is_empty) {
                    return Err(invalid("empty domain keyword"));
                }
                if v.iter().map(String::len).sum::<usize>() > 4 * 1024 * 1024 {
                    return Err(invalid("keyword pattern budget exceeded"));
                }
                let v: Vec<_> = v.into_iter().map(|s| s.to_ascii_lowercase()).collect();
                let matcher = aho_corasick::AhoCorasick::builder()
                    .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
                    .build(&v)
                    .map_err(|e| invalid(format!("keywords: {e}")))?;
                self.charge(matcher.memory_usage(), 0)?;
                Kind::Keywords(matcher)
            }
            Expression::DomainRegex(v) => {
                self.strings(&v)?;
                if v.iter().map(String::len).sum::<usize>() > 4 * 1024 * 1024 {
                    return Err(invalid("regex pattern budget exceeded"));
                }
                let matcher = regex::bytes::RegexSetBuilder::new(v)
                    .unicode(false)
                    .size_limit(16 * 1024 * 1024)
                    .build()
                    .map_err(|e| invalid(format!("unsupported or oversized regex: {e}")))?;
                self.charge(16 * 1024 * 1024, 0)?;
                Kind::Regex(matcher)
            }
            Expression::IpCidr(v) => {
                self.strings(&v)?;
                let mut ranges = IpRanges::default();
                for cidr in v {
                    ranges.add_cidr(&cidr)?;
                }
                if ranges.v4.is_empty() && ranges.v6.is_empty() {
                    return Ok(Predicate::new(Kind::Constant(false)));
                }
                Kind::Ips(ranges.finish(), false)
            }
            Expression::Ranges(ranges, no_resolve) => {
                self.charge(
                    ranges.v4.capacity() * 16 + ranges.v6.capacity() * 64,
                    ranges.v4.len() + ranges.v6.len(),
                )?;
                if ranges.v4.is_empty() && ranges.v6.is_empty() {
                    return Ok(Predicate::new(Kind::Constant(false)));
                }
                Kind::Ips(ranges.finish(), no_resolve)
            }
            Expression::DestinationPort(v) => {
                if v.contains(&0) {
                    return Err(invalid("typed destination ports must be 1-65535"));
                }
                self.charge(v.len() * 8, v.len())?;
                Kind::Ports(merge_ports(v.into_iter().map(|p| (p, p)).collect()).into())
            }
            Expression::PortRanges(v) => {
                self.charge(v.capacity() * 8, v.len())?;
                if v.iter().any(|(a, b)| a > b) {
                    return Err(invalid("descending port range"));
                }
                Kind::Ports(merge_ports(v).into())
            }
            Expression::DestinationPortRange(v) => {
                self.strings(&v)?;
                let ranges = v
                    .into_iter()
                    .map(|s| {
                        let (a, b) = s
                            .split_once(':')
                            .ok_or_else(|| invalid("port range requires start:end"))?;
                        let a = a
                            .parse::<u16>()
                            .map_err(|_| invalid("invalid port range start"))?;
                        let b = b
                            .parse::<u16>()
                            .map_err(|_| invalid("invalid port range end"))?;
                        if a == 0 || a > b {
                            return Err(invalid("port range must be within 1-65535 and ascending"));
                        }
                        Ok((a, b))
                    })
                    .collect::<io::Result<Vec<_>>>()?;
                Kind::Ports(merge_ports(ranges).into())
            }
            Expression::RuleSet(name) => {
                return self
                    .sets
                    .get(&name)
                    .cloned()
                    .ok_or_else(|| invalid(format!("unknown rule_set: {name}")));
            }
            Expression::All(v) => {
                if v.is_empty() {
                    return Err(invalid("empty all expression"));
                }
                Kind::All(
                    v.into_iter()
                        .map(|p| self.visit_domain(p, depth + 1))
                        .collect::<io::Result<Vec<_>>>()?
                        .into(),
                )
            }
            Expression::Any(v) => {
                if v.is_empty() {
                    return Err(invalid("empty any expression"));
                }
                Kind::Any(
                    group_literals(v)
                        .into_iter()
                        .map(|p| self.visit_domain(p, depth + 1))
                        .collect::<io::Result<Vec<_>>>()?
                        .into(),
                )
            }
            Expression::Not(p) => Kind::Not(self.visit_domain(*p, depth + 1)?),
        };
        Ok(Predicate::new(kind))
    }

    fn visit_domain(&mut self, expression: Expression, depth: usize) -> io::Result<Arc<Predicate>> {
        let (v, kind) = match expression {
            Expression::Domain(v) => (v, DomainKind::Exact),
            Expression::DomainSuffix(v) => (v, DomainKind::Suffix),
            Expression::Subdomains(v) => (v, DomainKind::Subdomains),
            other => return self.visit(other, depth),
        };
        if depth > MAX_DEPTH {
            return Err(invalid("rule nesting exceeds 100 levels"));
        }
        self.strings(&v)?;
        Ok(Predicate::new(Kind::Domains(Names::new(v)?, kind)))
    }

    pub fn legacy(&mut self, masks: Vec<NetLocationMask>) -> io::Result<Arc<Predicate>> {
        let mut buckets: BTreeMap<u16, (Vec<String>, IpRanges, bool)> = BTreeMap::new();
        for mask in masks {
            self.charge(128, 0)?;
            let (names, ips, any) = buckets.entry(mask.port).or_default();
            if mask.address_mask.netmask == 0 {
                *any = true;
            } else if let Address::Hostname(name) = mask.address_mask.address {
                if name.starts_with('.') || name.contains('*') {
                    return Err(invalid(
                        "legacy wildcard masks are unsupported; use subdomains or domain_pattern",
                    ));
                }
                names.push(name);
            } else {
                ips.add_legacy(&mask.address_mask)?;
            }
        }
        let mut cases = Vec::with_capacity(buckets.len());
        for (port, (names, ips, any)) in buckets {
            // Validate every entry even when another alternative is universal.
            let names = self.visit_domain(Expression::DomainSuffix(names), 0)?;
            let has_ip = !ips.v4.is_empty() || !ips.v6.is_empty();
            let ips = self.visit(Expression::Ranges(ips, false), 0)?;
            let predicate = if any {
                Predicate::any_destination()
            } else if has_ip {
                Predicate::new(Kind::Any(vec![names, ips].into()))
            } else {
                names
            };
            cases.push((port, predicate));
        }
        if cases.len() == 1 && cases[0].0 == 0 {
            return Ok(cases.pop().unwrap().1);
        }
        Ok(Predicate::new(Kind::ByPort(cases.into())))
    }
}

fn merge_ports(mut ranges: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    ranges.sort_unstable();
    let mut result: Vec<(u16, u16)> = Vec::new();
    for (a, b) in ranges {
        if let Some(last) = result.last_mut()
            && a <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(b);
        } else {
            result.push((a, b));
        }
    }
    result
}

fn group_literals(expressions: Vec<Expression>) -> Vec<Expression> {
    let mut result = Vec::new();
    let mut ranges = [IpRanges::default(), IpRanges::default()];
    let mut ports = Vec::new();
    let mut domains = [
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ];
    for expression in expressions {
        let (i, mut v) = match expression {
            Expression::Domain(v) => (0, v),
            Expression::DomainSuffix(v) => (1, v),
            Expression::Subdomains(v) => (2, v),
            Expression::DomainPattern(v) => (3, v),
            Expression::DomainKeyword(v) => (4, v),
            Expression::DomainRegex(v) => (5, v),
            Expression::IpCidr(v) => (6, v),
            Expression::Ranges(v, no_resolve) => {
                ranges[usize::from(no_resolve)].append(v);
                continue;
            }
            Expression::PortRanges(mut v) => {
                ports.append(&mut v);
                continue;
            }
            other => {
                result.push(other);
                continue;
            }
        };
        domains[i].append(&mut v);
    }
    for (i, ranges) in ranges.into_iter().enumerate() {
        if !ranges.v4.is_empty() || !ranges.v6.is_empty() {
            result.push(Expression::Ranges(ranges, i != 0));
        }
    }
    if !ports.is_empty() {
        result.push(Expression::PortRanges(ports));
    }
    for (i, v) in domains.into_iter().enumerate() {
        if !v.is_empty() {
            result.push(match i {
                0 => Expression::Domain(v),
                1 => Expression::DomainSuffix(v),
                2 => Expression::Subdomains(v),
                3 => Expression::DomainPattern(v),
                4 => Expression::DomainKeyword(v),
                5 => Expression::DomainRegex(v),
                _ => Expression::IpCidr(v),
            });
        }
    }
    if result.is_empty() {
        result.push(Expression::Never);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Outcome;

    #[test]
    fn port_buckets_preserve_pairs_and_dns_permissions() {
        let mut compiler = Compiler::default();
        let p = compiler
            .legacy(
                ["a.example:80", "b.example:443", "10.0.0.0/8:443"]
                    .into_iter()
                    .map(|s| NetLocationMask::from(s).unwrap())
                    .collect(),
            )
            .unwrap();
        assert_eq!(p.evaluate(Some("a.example"), None, 80), Outcome::Match);
        assert_eq!(p.evaluate(Some("b.example"), None, 80), Outcome::Miss);
        assert_eq!(p.evaluate(Some("b.example"), None, 443), Outcome::Match);
        assert_eq!(
            p.evaluate(Some("a.example"), None, 443),
            Outcome::Unknown { may_resolve: true }
        );
        assert_eq!(p.evaluate(None, None, 22), Outcome::Miss);
        assert!(
            compiler
                .legacy(vec![NetLocationMask::from("*.x").unwrap()])
                .is_err()
        );
    }

    #[test]
    fn compiled_matches_linear_legacy_membership() {
        let raw: Vec<_> = (0..100)
            .flat_map(|i| [format!("h{i}.example:443"), format!("10.0.{i}.0/24:80")])
            .map(|s| NetLocationMask::from(&s).unwrap())
            .collect();
        let indexed = Compiler::default().legacy(raw.clone()).unwrap();
        let single: Vec<_> = raw
            .into_iter()
            .map(|m| Compiler::default().legacy(vec![m]).unwrap())
            .collect();
        for i in 0..200 {
            for port in [0, 80, 443, 9000] {
                for ip in [None, Some(format!("10.0.{i}.7").parse().unwrap())] {
                    let name = format!("a.h{i}.example");
                    let expected = Outcome::combine(
                        single.iter().map(|p| p.evaluate(Some(&name), ip, port)),
                        false,
                    );
                    assert_eq!(indexed.evaluate(Some(&name), ip, port), expected);
                }
            }
        }
    }

    #[test]
    fn limits_patterns_and_empty_sets() {
        let mut c = Compiler::default();
        let p = c
            .compile(Expression::Any(vec![
                Expression::DomainKeyword(vec!["EXAMPLE".into()]),
                Expression::DomainRegex(vec!["(?i)^HELLO$".into()]),
            ]))
            .unwrap();
        assert_eq!(p.evaluate(Some("hello"), None, 443), Outcome::Match);
        assert_eq!(p.evaluate(Some("a.example"), None, 443), Outcome::Match);
        assert_eq!(
            c.compile(Expression::IpCidr(vec![]))
                .unwrap()
                .evaluate(None, None, 0),
            Outcome::Miss
        );
        assert!(
            c.compile(Expression::DomainRegex(vec!["(?=a)".into()]))
                .is_err()
        );
        assert!(c.compile(Expression::RuleSet("missing".into())).is_err());
        assert!(c.compile(Expression::All(vec![])).is_err());
        let deep = (0..102).fold(Expression::AnyDestination(true), |e, _| {
            Expression::Not(Box::new(e))
        });
        assert!(c.compile(deep).is_err());
        assert!(c.charge(MAX_BYTES, 0).is_err());
    }
}
