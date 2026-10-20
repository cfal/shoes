mod compile;
pub mod domain;
pub mod ip;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use compile::Compiler;
use domain::{DomainKind, Names};
pub use ip::IpRanges;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    RuleSet(String),
    All(Vec<Expression>),
    Any(Vec<Expression>),
    Not(Box<Expression>),
    #[serde(skip)]
    Ranges(IpRanges, bool),
    #[serde(skip)]
    Never,
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
    pub may_resolve: bool,
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
    Regex(regex::bytes::RegexSet),
    Ips(IpRanges, bool),
    Ports(Box<[(u16, u16)]>),
    ByPort(Box<[(u16, Arc<Predicate>)]>),
    Any(Box<[Arc<Predicate>]>),
    All(Box<[Arc<Predicate>]>),
    Not(Arc<Predicate>),
}

impl Predicate {
    pub(crate) fn new(kind: Kind) -> Arc<Self> {
        let dependencies = match &kind {
            Kind::Domains(..) | Kind::Keywords(..) | Kind::Regex(..) => Dependencies {
                hostname: true,
                ..Dependencies::default()
            },
            Kind::Ips(_, no_resolve) => Dependencies {
                ip: true,
                may_resolve: !no_resolve,
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
            may_resolve: a.may_resolve || b.may_resolve,
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
            Kind::Ports(ports) => {
                let i = ports.partition_point(|&(start, _)| start <= port);
                i.checked_sub(1).is_some_and(|i| port <= ports[i].1)
            }
            Kind::ByPort(cases) => {
                let unrestricted = cases.first().filter(|(p, _)| *p == 0).map(|(_, p)| p);
                let selected = cases
                    .binary_search_by_key(&port, |(p, _)| *p)
                    .ok()
                    .filter(|i| cases[*i].0 != 0)
                    .map(|i| &cases[i].1);
                return Outcome::combine(
                    unrestricted
                        .into_iter()
                        .chain(selected)
                        .map(|p| p.evaluate(name, ip, port)),
                    false,
                );
            }
            Kind::Any(children) => {
                return Outcome::combine(children.iter().map(|p| p.evaluate(name, ip, port)), false);
            }
            Kind::All(children) => {
                return Outcome::combine(children.iter().map(|p| p.evaluate(name, ip, port)), true);
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

#[cfg(test)]
mod tests {
    use super::*;
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
