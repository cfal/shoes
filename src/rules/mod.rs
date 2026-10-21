mod compile;
mod config;
pub mod domain;
pub mod ip;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use serde::Serialize;

pub use compile::Compiler;
use domain::{DomainKind, Names};
pub use ip::IpRanges;

pub(crate) const MAX_ENTRIES: usize = 2_000_000;
pub(crate) const MAX_DEPTH: usize = 100;
pub(crate) const MAX_STRING_BYTES: usize = 64 * 1024;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expression {
    AnyDestination(bool),
    Domain(Vec<String>),
    DomainSuffix(Vec<String>),
    Subdomains(Vec<String>),
    DomainPattern(Vec<String>),
    DomainKeyword(Vec<String>),
    DomainRegex(Vec<String>),
    IpCidr(Vec<String>),
    DestinationPort(Vec<u16>),
    DestinationPortRange(Vec<String>),
    RuleGroup(String),
    All(Vec<Expression>),
    Any(Vec<Expression>),
    Not(Box<Expression>),
    #[serde(skip)]
    Ranges(IpRanges, bool),
    #[serde(skip)]
    PortRanges(Vec<(u16, u16)>),
    #[serde(skip)]
    Never,
    #[serde(untagged)]
    Legacy(crate::option_util::OneOrSome<crate::address::NetLocationMask>),
    #[serde(untagged)]
    Source(crate::rule_set::RuleSource),
}

impl Expression {
    pub fn or(mut children: Vec<Self>) -> Self {
        match children.len() {
            0 => Self::Never,
            1 => children.pop().unwrap(),
            _ => Self::Any(children),
        }
    }
    pub fn and(mut children: Vec<Self>) -> Self {
        match children.len() {
            0 => Self::AnyDestination(true),
            1 => children.pop().unwrap(),
            _ => Self::All(children),
        }
    }
    pub fn inverted(self, invert: bool) -> Self {
        if invert {
            Self::Not(Box::new(self))
        } else {
            self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Match,
    Miss,
    Unknown { may_resolve: bool },
}

impl Outcome {
    fn any(values: impl Iterator<Item = Self>) -> Self {
        Self::combine(values, false)
    }

    fn all(values: impl Iterator<Item = Self>) -> Self {
        Self::combine(values, true)
    }

    pub fn negate(self) -> Self {
        match self {
            Self::Match => Self::Miss,
            Self::Miss => Self::Match,
            unknown => unknown,
        }
    }
    fn combine(values: impl Iterator<Item = Self>, and: bool) -> Self {
        let mut unknown = None;
        for value in values {
            match value {
                Self::Miss if and => return Self::Miss,
                Self::Match if !and => return Self::Match,
                Self::Unknown { may_resolve } => {
                    unknown = Some(unknown.unwrap_or(false) || may_resolve);
                }
                _ => {}
            }
        }
        unknown.map_or(if and { Self::Match } else { Self::Miss }, |may_resolve| {
            Self::Unknown { may_resolve }
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Dependencies {
    pub hostname: bool,
    pub ip: bool,
}

#[derive(Debug)]
pub struct Predicate {
    pub dependencies: Dependencies,
    pub(crate) kind: Kind,
}

#[derive(Debug)]
pub(crate) enum Kind {
    Constant(bool),
    Domains(Names, DomainKind),
    Keywords(aho_corasick::AhoCorasick),
    Regex(regex_automata::meta::Regex),
    Ips(IpRanges, bool),
    Ports(Box<[(u16, u16)]>),
    ByPort(Box<[(u16, Arc<Predicate>)]>),
    Any(Box<[Arc<Predicate>]>),
    All(Box<[Arc<Predicate>]>),
    Not(Arc<Predicate>),
}

impl Predicate {
    pub(crate) fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + 32
            + match &self.kind {
                Kind::Domains(names, _) => names.retained_bytes(),
                Kind::Keywords(matcher) => matcher.memory_usage(),
                Kind::Regex(matcher) => matcher.memory_usage(),
                Kind::Ips(ranges, _) => ranges.v4.capacity() * 8 + ranges.v6.capacity() * 32,
                Kind::Ports(ports) => ports.len() * 4,
                Kind::ByPort(children) => {
                    children.iter().map(|(_, p)| p.retained_bytes() + 16).sum()
                }
                Kind::Any(children) | Kind::All(children) => {
                    children.iter().map(|p| p.retained_bytes() + 8).sum()
                }
                Kind::Not(p) => p.retained_bytes(),
                Kind::Constant(_) => 0,
            }
    }

    pub fn any(children: Vec<Arc<Self>>) -> Arc<Self> {
        if children.len() == 1 {
            return children.into_iter().next().unwrap();
        }
        Self::new(Kind::Any(children.into()))
    }

    pub fn has_no_resolve_ip(&self) -> bool {
        match &self.kind {
            Kind::Ips(_, no_resolve) => *no_resolve,
            Kind::Any(ps) | Kind::All(ps) => ps.iter().any(|p| p.has_no_resolve_ip()),
            Kind::ByPort(ps) => ps.iter().any(|(_, p)| p.has_no_resolve_ip()),
            Kind::Not(p) => p.has_no_resolve_ip(),
            _ => false,
        }
    }
    pub(crate) fn new(kind: Kind) -> Arc<Self> {
        let dependencies = match &kind {
            Kind::Domains(..) | Kind::Keywords(..) | Kind::Regex(..) => Dependencies {
                hostname: true,
                ..Dependencies::default()
            },
            Kind::Ips(..) => Dependencies {
                ip: true,
                ..Dependencies::default()
            },
            Kind::Not(p) => p.dependencies,
            Kind::Any(ps) | Kind::All(ps) => Self::union(ps.iter().map(|p| p.dependencies)),
            Kind::ByPort(ps) => Self::union(ps.iter().map(|(_, p)| p.dependencies)),
            _ => Dependencies::default(),
        };
        Arc::new(Self { kind, dependencies })
    }

    fn union(values: impl Iterator<Item = Dependencies>) -> Dependencies {
        values.fold(Dependencies::default(), |a, b| Dependencies {
            hostname: a.hostname || b.hostname,
            ip: a.ip || b.ip,
        })
    }

    pub fn any_destination() -> Arc<Self> {
        Self::new(Kind::Constant(true))
    }

    pub fn evaluate(&self, name: Option<&str>, ip: Option<IpAddr>, port: u16) -> Outcome {
        let matched = match &self.kind {
            Kind::Constant(value) => *value,
            Kind::Domains(names, kind) => name.is_some_and(|name| names.matches(name, *kind)),
            Kind::Keywords(keywords) => name.is_some_and(|name| keywords.is_match(name)),
            Kind::Regex(regex) => name.is_some_and(|name| regex.is_match(name.as_bytes())),
            Kind::Ips(ranges, no_resolve) => match ip {
                Some(ip) => ranges.contains(ip),
                None => {
                    return Outcome::Unknown {
                        may_resolve: !no_resolve,
                    };
                }
            },
            Kind::Ports(ports) => contains_sorted(ports, port),
            Kind::ByPort(cases) => {
                let unrestricted = cases.first().filter(|(p, _)| *p == 0).map(|(_, p)| p);
                let selected = cases
                    .binary_search_by_key(&port, |(p, _)| *p)
                    .ok()
                    .filter(|i| cases[*i].0 != 0)
                    .map(|i| &cases[i].1);
                return Outcome::any(
                    unrestricted
                        .into_iter()
                        .chain(selected)
                        .map(|p| p.evaluate(name, ip, port)),
                );
            }
            Kind::Any(children) => {
                return Outcome::any(children.iter().map(|p| p.evaluate(name, ip, port)));
            }
            Kind::All(children) => {
                return Outcome::all(children.iter().map(|p| p.evaluate(name, ip, port)));
            }
            Kind::Not(p) => return p.evaluate(name, ip, port).negate(),
        };
        if matched {
            Outcome::Match
        } else {
            Outcome::Miss
        }
    }
}

fn contains_sorted<T: Ord>(ranges: &[(T, T)], value: T) -> bool {
    let i = ranges.partition_point(|(start, _)| start <= &value);
    i.checked_sub(1).is_some_and(|i| value <= ranges[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_lookup_handles_boundaries_and_gaps() {
        let ranges = [(0, 0), (80, 90), (u16::MAX, u16::MAX)];
        for port in [0, 80, 85, 90, u16::MAX] {
            assert!(contains_sorted(&ranges, port));
        }
        for port in [1, 79, 91, u16::MAX - 1] {
            assert!(!contains_sorted(&ranges, port));
        }
        assert!(!contains_sorted(&[], 0u16));
    }

    #[test]
    fn combinations_keep_empty_identities_and_short_circuit() {
        assert_eq!(Outcome::any(std::iter::empty()), Outcome::Miss);
        assert_eq!(Outcome::all(std::iter::empty()), Outcome::Match);
        let unreachable = || panic!("evaluated after a decisive outcome");
        assert_eq!(
            Outcome::any(std::iter::once(Outcome::Match).chain(std::iter::once_with(unreachable))),
            Outcome::Match
        );
        assert_eq!(
            Outcome::all(std::iter::once(Outcome::Miss).chain(std::iter::once_with(unreachable))),
            Outcome::Miss
        );
    }

    #[test]
    fn unavailable_truth_table() {
        use Outcome::*;
        for unknown in [
            Unknown { may_resolve: false },
            Unknown { may_resolve: true },
        ] {
            assert_eq!(unknown.negate(), unknown);
            assert_eq!(Outcome::combine([unknown, Match].into_iter(), false), Match);
            assert_eq!(Outcome::combine([unknown, Miss].into_iter(), true), Miss);
            assert_eq!(
                Outcome::combine([unknown, Match].into_iter(), true),
                unknown
            );
            assert_eq!(
                Outcome::combine([unknown, Miss].into_iter(), false),
                unknown
            );
        }
        assert_eq!(
            Outcome::combine(
                [
                    Unknown { may_resolve: false },
                    Unknown { may_resolve: true }
                ]
                .into_iter(),
                true
            ),
            Unknown { may_resolve: true }
        );
        let p = Compiler::default()
            .compile(Expression::Not(Box::new(Expression::Domain(vec![
                "a.example".into(),
            ]))))
            .unwrap();
        assert_eq!(
            p.evaluate(None, Some("1.2.3.4".parse().unwrap()), 80),
            Match
        );
    }
}
