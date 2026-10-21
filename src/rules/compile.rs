use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::sync::Arc;

use super::{
    Expression, IpRanges, Kind, MAX_DEPTH, MAX_ENTRIES, MAX_STRING_BYTES, Predicate, domain,
    invalid,
};
use crate::address::{Address, NetLocationMask};
use domain::{DomainKind, Names};

pub const MAX_BYTES: usize = 512 * 1024 * 1024;
const MAX_REGEX_MATCHER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub struct Compiler {
    pub groups: HashMap<String, Arc<Predicate>>,
    pub(crate) policy_groups: HashSet<String>,
    pub(crate) sources: HashMap<crate::rule_set::SourceKey, Arc<Predicate>>,
    bytes: usize,
    entries: usize,
}

impl Compiler {
    // Temporary decode/build costs overlap only within one source. Other sources
    // retain their immutable indexes, not their parser buffers or entry counts.
    pub fn source(
        &mut self,
        decode: impl FnOnce(&mut Self) -> io::Result<Expression>,
    ) -> io::Result<Arc<Predicate>> {
        let (bytes, entries) = (self.bytes, self.entries);
        self.entries = 0;
        let result = decode(self).and_then(|expression| {
            self.entries = 0;
            self.compile(expression)
        });
        self.bytes = bytes;
        self.entries = entries;
        let predicate = result?;
        self.charge(predicate.retained_bytes(), 0)?;
        Ok(predicate)
    }

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
            if value.len() > MAX_STRING_BYTES || !value.is_ascii() {
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
            | Expression::Subdomains(_)) => return self.visit_child(p, depth),
            Expression::DomainPattern(v) => {
                self.strings(&v)?;
                let patterns = v
                    .iter()
                    .map(|s| domain::wildcard(s))
                    .collect::<io::Result<Vec<_>>>()?;
                return self.visit(Expression::DomainRegex(patterns), depth + 1);
            }
            Expression::DomainKeyword(patterns) => self.compile_keywords(patterns)?,
            Expression::DomainRegex(patterns) => self.compile_regex(patterns)?,
            Expression::IpCidr(v) => {
                self.strings(&v)?;
                let mut ranges = IpRanges::default();
                for cidr in v {
                    ranges.add_cidr(&cidr)?;
                }
                if ranges.is_empty() {
                    return Ok(Predicate::new(Kind::Constant(false)));
                }
                Kind::Ips(ranges.finish(), false)
            }
            Expression::Ranges(ranges, no_resolve) => {
                self.charge(
                    ranges.v4.capacity() * 16 + ranges.v6.capacity() * 64,
                    ranges.v4.len() + ranges.v6.len(),
                )?;
                if ranges.is_empty() {
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
            Expression::Legacy(masks) => return self.legacy(masks.into_vec()),
            Expression::Source(source) => return crate::rule_set::load_source(&source, self),
            Expression::RuleGroup(name) => {
                if self.policy_groups.contains(&name) {
                    return Err(invalid(format!(
                        "rule group '{name}' contains policies with actions; use it in rules, not masks"
                    )));
                }
                return self
                    .groups
                    .get(&name)
                    .cloned()
                    .ok_or_else(|| invalid(format!("unknown rule group: {name}")));
            }
            Expression::All(v) => {
                if v.is_empty() {
                    return Err(invalid("empty all expression"));
                }
                Kind::All(
                    v.into_iter()
                        .map(|p| self.visit_child(p, depth + 1))
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
                        .map(|p| self.visit_child(p, depth + 1))
                        .collect::<io::Result<Vec<_>>>()?
                        .into(),
                )
            }
            Expression::Not(p) => Kind::Not(self.visit_child(*p, depth + 1)?),
        };
        Ok(Predicate::new(kind))
    }

    fn compile_keywords(&mut self, patterns: Vec<String>) -> io::Result<Kind> {
        self.strings(&patterns)?;
        if patterns.is_empty() {
            return Ok(Kind::Constant(false));
        }
        if patterns.iter().any(String::is_empty) {
            return Err(invalid("empty domain keyword"));
        }
        let pattern_bytes = patterns.iter().map(String::len).sum::<usize>();
        if pattern_bytes > 4 * 1024 * 1024 {
            return Err(invalid("keyword pattern budget exceeded"));
        }
        let before = self.bytes;
        self.charge(pattern_bytes.saturating_mul(256).saturating_add(4096), 0)?;
        let patterns: Vec<_> = patterns
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let matcher = aho_corasick::AhoCorasick::builder()
            .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
            .build(&patterns)
            .map_err(|e| invalid(format!("keywords: {e}")))?;
        self.bytes = before;
        self.charge(matcher.memory_usage(), 0)?;
        Ok(Kind::Keywords(matcher))
    }

    fn compile_regex(&mut self, patterns: Vec<String>) -> io::Result<Kind> {
        self.strings(&patterns)?;
        if patterns.is_empty() {
            return Ok(Kind::Constant(false));
        }
        let pattern_bytes = patterns.iter().map(String::len).sum::<usize>();
        if pattern_bytes > 512 * 1024 {
            return Err(invalid("regex pattern budget exceeded"));
        }
        let before = self.bytes;
        // AST/HIR construction precedes the NFA size limit. ASCII
        // case-folded classes can cost hundreds of bytes per character.
        self.charge(pattern_bytes * 512 + 64 * 1024 * 1024, 0)?;
        let matcher = regex_automata::meta::Regex::builder()
            .configure(
                regex_automata::meta::Regex::config()
                    .which_captures(regex_automata::nfa::thompson::WhichCaptures::None)
                    .hybrid_cache_capacity(256 * 1024)
                    .nfa_size_limit(Some(MAX_REGEX_MATCHER_BYTES))
                    .dfa_size_limit(Some(MAX_REGEX_MATCHER_BYTES))
                    .onepass_size_limit(Some(MAX_REGEX_MATCHER_BYTES)),
            )
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .unicode(false)
                    .utf8(false),
            )
            .build_many(&patterns)
            .map_err(|e| invalid(format!("unsupported or oversized regex: {e}")))?;
        self.bytes = before;
        if matcher.memory_usage() > MAX_REGEX_MATCHER_BYTES {
            return Err(invalid("compiled regex exceeds 16 MiB"));
        }
        self.charge(matcher.memory_usage(), 0)?;
        Ok(Kind::Regex(matcher))
    }

    // Domain leaves share their parent or legacy bucket's node charge. Other
    // expressions still go through visit and pay their own 128-byte charge.
    fn visit_child(&mut self, expression: Expression, depth: usize) -> io::Result<Arc<Predicate>> {
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
        if v.is_empty() {
            return Ok(Predicate::new(Kind::Constant(false)));
        }
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
                    return Err(invalid(format!(
                        "legacy wildcard mask {name:?} is unsupported; use subdomains or domain_pattern"
                    )));
                }
                names.push(name);
            } else {
                ips.add_legacy(&mask.address_mask)?;
            }
        }
        let mut cases = Vec::with_capacity(buckets.len());
        for (port, (names, ips, any)) in buckets {
            // Validate every entry even when another alternative is universal.
            let names = self.visit_child(Expression::DomainSuffix(names), 0)?;
            let has_ip = !ips.is_empty();
            let ips = self.visit(Expression::Ranges(ips, false), 0)?;
            let predicate = if any {
                // Sniff eligibility is observable before matching. Preserve the
                // dependencies of alternatives shadowed by a universal mask.
                let mut children = vec![Predicate::any_destination()];
                if names.dependencies.hostname {
                    children.push(names);
                }
                if has_ip {
                    children.push(ips);
                }
                Predicate::any(children)
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
    let mut masks = Vec::new();
    let mut resolving_ranges = IpRanges::default();
    let mut no_resolve_ranges = IpRanges::default();
    let mut ports = Vec::new();
    let mut exact = Vec::new();
    let mut suffixes = Vec::new();
    let mut subdomains = Vec::new();
    let mut patterns = Vec::new();
    let mut keywords = Vec::new();
    let mut regexes = Vec::new();
    let mut cidrs = Vec::new();
    for expression in expressions {
        let (group, mut values) = match expression {
            Expression::Legacy(values) => {
                masks.extend(values.into_vec());
                continue;
            }
            Expression::Domain(values) => (&mut exact, values),
            Expression::DomainSuffix(values) => (&mut suffixes, values),
            Expression::Subdomains(values) => (&mut subdomains, values),
            Expression::DomainPattern(values) => (&mut patterns, values),
            Expression::DomainKeyword(values) => (&mut keywords, values),
            Expression::DomainRegex(values) => (&mut regexes, values),
            Expression::IpCidr(values) => (&mut cidrs, values),
            Expression::Ranges(ranges, true) => {
                no_resolve_ranges.append(ranges);
                continue;
            }
            Expression::Ranges(ranges, false) => {
                resolving_ranges.append(ranges);
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
        group.append(&mut values);
    }
    for (ranges, no_resolve) in [(resolving_ranges, false), (no_resolve_ranges, true)] {
        if !ranges.is_empty() {
            result.push(Expression::Ranges(ranges, no_resolve));
        }
    }
    if !ports.is_empty() {
        result.push(Expression::PortRanges(ports));
    }
    if !masks.is_empty() {
        result.push(Expression::Legacy(crate::option_util::OneOrSome::Some(
            masks,
        )));
    }
    let mut push_literals = |values: Vec<String>, expression: fn(Vec<String>) -> Expression| {
        if !values.is_empty() {
            result.push(expression(values));
        }
    };
    push_literals(exact, Expression::Domain);
    push_literals(suffixes, Expression::DomainSuffix);
    push_literals(subdomains, Expression::Subdomains);
    push_literals(patterns, Expression::DomainPattern);
    push_literals(keywords, Expression::DomainKeyword);
    push_literals(regexes, Expression::DomainRegex);
    push_literals(cidrs, Expression::IpCidr);
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
    fn legacy_rule_config_keeps_its_compilation_budget() {
        let mut rule: crate::config::RuleConfig =
            serde_yaml::from_str("masks: 0.0.0.0/0\naction: block").unwrap();
        let mut compiler = Compiler::default();
        rule.compile(&mut compiler).unwrap();
        assert_eq!(compiler.bytes, 256);
        assert_eq!(compiler.entries, 0);
        rule.compile(&mut compiler).unwrap();
        assert_eq!(compiler.bytes, 256);
    }

    #[test]
    fn mixed_mask_lists_keep_legacy_entries_in_one_index() {
        let masks = ["example.com:443", "192.0.2.0/24", "0.0.0.0/0:80"];
        let mut expressions: Vec<_> = masks
            .iter()
            .map(|value| {
                Expression::Legacy(crate::option_util::OneOrSome::One(
                    NetLocationMask::from(value).unwrap(),
                ))
            })
            .collect();
        expressions.push(Expression::Domain(vec!["exact.example".into()]));
        let grouped = group_literals(expressions);
        assert!(
            matches!(&grouped[..], [Expression::Legacy(values), Expression::Domain(_)] if values.len() == 3)
        );
        let predicate = Compiler::default()
            .compile(Expression::Any(grouped))
            .unwrap();
        for (name, ip, port, expected) in [
            (Some("sub.example.com"), None, 443, Outcome::Match),
            (Some("other.example"), None, 80, Outcome::Match),
            (
                Some("other.example"),
                None,
                443,
                Outcome::Unknown { may_resolve: true },
            ),
            (
                Some("other.example"),
                Some("198.51.100.1".parse().unwrap()),
                443,
                Outcome::Miss,
            ),
            (
                None,
                Some("192.0.2.1".parse().unwrap()),
                443,
                Outcome::Match,
            ),
        ] {
            assert_eq!(predicate.evaluate(name, ip, port), expected);
        }
    }

    #[test]
    fn matcher_builders_preserve_empty_predicates_and_budget_charges() {
        for expression in [
            Expression::DomainKeyword(Vec::new()),
            Expression::DomainRegex(Vec::new()),
        ] {
            let mut compiler = Compiler::default();
            let predicate = compiler.compile(expression).unwrap();
            assert_eq!(predicate.evaluate(None, None, 443), Outcome::Miss);
            assert!(!predicate.dependencies.hostname);
            assert_eq!((compiler.bytes, compiler.entries), (128, 0));
        }
        for regex in [false, true] {
            let pattern = String::from("example");
            let string_bytes = pattern.capacity() * 4 + 96;
            let expression = if regex {
                Expression::DomainRegex(vec![pattern])
            } else {
                Expression::DomainKeyword(vec![pattern])
            };
            let mut compiler = Compiler::default();
            let predicate = compiler.compile(expression).unwrap();
            let retained = match &predicate.kind {
                Kind::Keywords(matcher) => matcher.memory_usage(),
                Kind::Regex(matcher) => matcher.memory_usage(),
                other => panic!("unexpected matcher: {other:?}"),
            };
            assert_eq!(compiler.bytes, 128 + string_bytes + retained);
            assert_eq!(compiler.entries, 1);
        }
    }

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
    fn literal_groups_preserve_kinds_order_and_resolution_permissions() {
        let mut resolving = IpRanges::default();
        resolving.add_cidr("192.0.2.0/24").unwrap();
        let mut no_resolve = IpRanges::default();
        no_resolve.add_cidr("198.51.100.0/24").unwrap();
        let grouped = group_literals(vec![
            Expression::Domain(vec!["first.example".into()]),
            Expression::DomainSuffix(vec!["suffix.example".into()]),
            Expression::Subdomains(vec!["strict.example".into()]),
            Expression::DomainPattern(vec!["*.pattern.example".into()]),
            Expression::DomainKeyword(vec!["keyword".into()]),
            Expression::DomainRegex(vec!["^regex$".into()]),
            Expression::IpCidr(vec!["203.0.113.0/24".into()]),
            Expression::Ranges(no_resolve, true),
            Expression::Ranges(resolving, false),
            Expression::PortRanges(vec![(80, 80)]),
            Expression::Never,
            Expression::Domain(vec!["second.example".into()]),
            Expression::PortRanges(vec![(443, 443)]),
            Expression::Domain(Vec::new()),
        ]);
        let [
            Expression::Never,
            Expression::Ranges(resolving, false),
            Expression::Ranges(no_resolve, true),
            Expression::PortRanges(ports),
            Expression::Domain(exact),
            Expression::DomainSuffix(suffixes),
            Expression::Subdomains(subdomains),
            Expression::DomainPattern(patterns),
            Expression::DomainKeyword(keywords),
            Expression::DomainRegex(regexes),
            Expression::IpCidr(cidrs),
        ] = grouped.as_slice()
        else {
            panic!("unexpected groups: {grouped:?}");
        };
        assert!(resolving.contains("192.0.2.1".parse().unwrap()));
        assert!(!resolving.contains("198.51.100.1".parse().unwrap()));
        assert!(no_resolve.contains("198.51.100.1".parse().unwrap()));
        assert!(!no_resolve.contains("192.0.2.1".parse().unwrap()));
        assert_eq!(ports, &[(80, 80), (443, 443)]);
        assert_eq!(exact, &["first.example", "second.example"]);
        assert_eq!(suffixes, &["suffix.example"]);
        assert_eq!(subdomains, &["strict.example"]);
        assert_eq!(patterns, &["*.pattern.example"]);
        assert_eq!(keywords, &["keyword"]);
        assert_eq!(regexes, &["^regex$"]);
        assert_eq!(cidrs, &["203.0.113.0/24"]);
        assert!(matches!(
            group_literals(vec![Expression::Domain(Vec::new())]).as_slice(),
            [Expression::Never]
        ));
    }

    #[test]
    fn compiled_matches_linear_legacy_membership() {
        let raw: Vec<_> = (0..100)
            .flat_map(|i| [format!("h{i}.example:443"), format!("10.0.{i}.0/24:80")])
            .map(|s| NetLocationMask::from(&s).unwrap())
            .collect();
        let indexed = Compiler::default().legacy(raw.clone()).unwrap();
        for i in 0..200 {
            for port in [0, 80, 443, 9000] {
                for ip in [None, Some(format!("10.0.{i}.7").parse().unwrap())] {
                    let name = format!("a.h{i}.example");
                    let expected = Outcome::combine(
                        raw.iter().map(|m| {
                            if m.port != 0 && m.port != port {
                                return Outcome::Miss;
                            }
                            let matched = match &m.address_mask.address {
                                Address::Hostname(base) => {
                                    name == *base
                                        || name
                                            .strip_suffix(base)
                                            .is_some_and(|prefix| prefix.ends_with('.'))
                                }
                                Address::Ipv4(base) => match ip {
                                    None => return Outcome::Unknown { may_resolve: true },
                                    Some(std::net::IpAddr::V4(ip)) => {
                                        (u32::from(ip) & m.address_mask.netmask as u32)
                                            == (u32::from(*base) & m.address_mask.netmask as u32)
                                    }
                                    _ => false,
                                },
                                Address::Ipv6(_) => unreachable!(),
                            };
                            if matched {
                                Outcome::Match
                            } else {
                                Outcome::Miss
                            }
                        }),
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
        assert!(c.compile(Expression::RuleGroup("missing".into())).is_err());
        assert!(c.compile(Expression::All(vec![])).is_err());
        let deep = (0..102).fold(Expression::AnyDestination(true), |e, _| {
            Expression::Not(Box::new(e))
        });
        assert!(c.compile(deep).is_err());
        assert!(c.charge(MAX_BYTES, 0).is_err());
    }

    #[test]
    fn universal_keeps_real_dependencies_but_empty_sets_add_none() {
        for (masks, hostname, ip) in [
            (vec!["0.0.0.0/0"], false, false),
            (vec!["10.0.0.0/8"], false, true),
            (vec!["example.com", "0.0.0.0/0"], true, false),
            (vec!["10.0.0.0/8", "example.com", "0.0.0.0/0"], true, true),
        ] {
            let p = Compiler::default()
                .legacy(
                    masks
                        .into_iter()
                        .map(|m| NetLocationMask::from(m).unwrap())
                        .collect(),
                )
                .unwrap();
            assert_eq!(p.dependencies.hostname, hostname);
            assert_eq!(p.dependencies.ip, ip);
        }
    }

    #[test]
    fn source_budgets_release_scratch_and_reset_entry_counts() {
        let mut compiler = Compiler::default();
        for _ in 0..8 {
            compiler
                .source(|budget| {
                    budget.charge(400 * 1024 * 1024, MAX_ENTRIES)?;
                    Ok(Expression::Never)
                })
                .unwrap();
        }
        assert!(compiler.bytes < 4096);
        assert_eq!(compiler.entries, 0);
        assert!(
            compiler
                .source(|budget| {
                    budget.charge(MAX_BYTES, 0)?;
                    Ok(Expression::Never)
                })
                .is_err()
        );
    }

    #[test]
    fn many_small_regex_leaves_charge_retained_memory_not_each_size_limit() {
        let mut compiler = Compiler::default();
        for _ in 0..128 {
            let p = compiler
                .compile(Expression::DomainPattern(vec!["*.example.com".into()]))
                .unwrap();
            assert_eq!(p.evaluate(Some("a.example.com"), None, 80), Outcome::Match);
        }
        assert!(compiler.bytes < 16 * 1024 * 1024);
    }

    #[test]
    fn regex_syntax_reserve_precedes_building() {
        let patterns = vec![format!("(?i){}", "a".repeat(60_000)); 8];
        let mut compiler = Compiler::default();
        compiler.charge(300 * 1024 * 1024, 0).unwrap();
        let error = compiler
            .compile(Expression::DomainRegex(patterns))
            .unwrap_err();
        assert!(error.to_string().contains("budget"));
    }

    #[test]
    fn merged_regexes_have_no_quadratic_capture_cache() {
        let patterns = (0..4096)
            .map(|i| format!(r"^([^.]+)\.host{i}\.example$"))
            .collect();
        let predicate = Compiler::default()
            .compile(Expression::DomainRegex(patterns))
            .unwrap();
        let Kind::Regex(matcher) = &predicate.kind else {
            panic!("expected regex")
        };
        // Check this before creating a cache: default capture slots would make
        // the PikeVM allocation quadratic in the number of patterns.
        assert_eq!(matcher.group_info().slot_len(), 0);
        let cache = matcher.create_cache();
        assert!(cache.memory_usage() < 16 * 1024 * 1024);
        assert!(
            matcher.is_match("a-long-label-that-exceeds-the-backtracker-limit.host4095.example")
        );
    }
}
