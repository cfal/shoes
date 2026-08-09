//! A single decoded rule and its matching semantics.
//!
//! Taken from sing-box's `route/rule/rule_abstract.go`: items are bucketed into
//! groups, `matchAnyItem` runs within a group, and the groups are ANDed. Only
//! the destination-address group survives here, because `ip_cidr` belongs to it
//! alongside the domain matchers, and `source_ip_cidr` is rejected.

use regex_lite::Regex;

use super::MatchTarget;
use super::ip_set::IpSet;
use super::srs::RawRule;
use super::succinct::DomainMatcher;

#[derive(Debug)]
pub struct HeadlessRule {
    domain: Option<DomainMatcher>,
    domain_keyword: Vec<String>,
    domain_regex: Vec<Regex>,
    ip_cidr: Option<IpSet>,
    invert: bool,
}

impl HeadlessRule {
    pub fn from_raw(raw: RawRule) -> std::io::Result<Self> {
        if raw.has_source_ip_cidr {
            return Err(std::io::Error::other(
                "source_ip_cidr is not supported: the routing decision has no \
                 source address in scope, so such a rule could never match",
            ));
        }

        let mut domain_regex = Vec::with_capacity(raw.domain_regex.len());
        for pattern in &raw.domain_regex {
            let compiled = Regex::new(pattern).map_err(|e| {
                std::io::Error::other(format!("invalid domain_regex {pattern:?}: {e}"))
            })?;
            domain_regex.push(compiled);
        }

        Ok(Self {
            domain: raw.domain,
            domain_keyword: raw.domain_keyword,
            domain_regex,
            ip_cidr: raw.ip_cidr,
            invert: raw.invert,
        })
    }

    fn has_destination_items(&self) -> bool {
        self.domain.is_some()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || self.ip_cidr.is_some()
    }

    fn match_destination(&self, target: &MatchTarget<'_>) -> bool {
        if let Some(domain) = target.domain {
            if let Some(matcher) = &self.domain
                && matcher.matches(domain)
            {
                return true;
            }
            if self
                .domain_keyword
                .iter()
                .any(|keyword| domain.contains(keyword.as_str()))
            {
                return true;
            }
            if self.domain_regex.iter().any(|re| re.is_match(domain)) {
                return true;
            }
        }
        match (target.ip, &self.ip_cidr) {
            (Some(ip), Some(set)) => set.contains(ip),
            _ => false,
        }
    }

    pub fn matches(&self, target: &MatchTarget<'_>) -> bool {
        // sing-box returns true for an item-less rule before invert is applied.
        if !self.has_destination_items() {
            return true;
        }
        let matched = self.match_destination(target);
        if self.invert { !matched } else { matched }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> u128 {
        u128::from(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())
    }

    fn dest(domain: Option<&str>, ip: Option<u128>) -> MatchTarget<'_> {
        MatchTarget { domain, ip }
    }

    #[test]
    fn domain_and_ip_are_ored_not_anded() {
        // This is the case that a naive AND would get wrong: geosite sets pair a
        // domain trie with other destination matchers and expect either to hit.
        let raw = RawRule {
            domain: Some(DomainMatcher::build(&[], &["example.com"])),
            ip_cidr: Some(IpSet::new(vec![(v4(10, 0, 0, 0), v4(10, 0, 0, 255))]).unwrap()),
            ..Default::default()
        };
        let rule = HeadlessRule::from_raw(raw).unwrap();

        assert!(rule.matches(&dest(Some("example.com"), Some(v4(1, 1, 1, 1)))));
        assert!(rule.matches(&dest(Some("other.net"), Some(v4(10, 0, 0, 7)))));
        assert!(!rule.matches(&dest(Some("other.net"), Some(v4(1, 1, 1, 1)))));
    }

    #[test]
    fn regex_and_keyword_join_the_same_group() {
        let raw = RawRule {
            domain: Some(DomainMatcher::build(&["exact.com"], &[])),
            domain_keyword: vec!["tracker".to_string()],
            domain_regex: vec![r"^ads-\d+\.net$".to_string()],
            ..Default::default()
        };
        let rule = HeadlessRule::from_raw(raw).unwrap();

        assert!(rule.matches(&dest(Some("exact.com"), None)));
        assert!(rule.matches(&dest(Some("a.tracker.io"), None)));
        assert!(rule.matches(&dest(Some("ads-42.net"), None)));
        assert!(!rule.matches(&dest(Some("unrelated.org"), None)));
    }

    #[test]
    fn invert_negates_the_result() {
        let raw = RawRule {
            domain: Some(DomainMatcher::build(&[], &["example.com"])),
            invert: true,
            ..Default::default()
        };
        let rule = HeadlessRule::from_raw(raw).unwrap();
        assert!(!rule.matches(&dest(Some("example.com"), None)));
        assert!(rule.matches(&dest(Some("other.net"), None)));
    }

    #[test]
    fn a_rule_with_no_items_matches_everything_and_ignores_invert() {
        let rule = HeadlessRule::from_raw(RawRule {
            invert: true,
            ..Default::default()
        })
        .unwrap();
        assert!(rule.matches(&dest(Some("anything.example"), None)));
        assert!(rule.matches(&dest(None, None)));
    }

    #[test]
    fn source_ip_cidr_is_rejected() {
        let err = HeadlessRule::from_raw(RawRule {
            has_source_ip_cidr: true,
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("source_ip_cidr"), "{err}");
    }

    #[test]
    fn an_uncompilable_regex_is_rejected_with_its_pattern() {
        let err = HeadlessRule::from_raw(RawRule {
            domain_regex: vec!["(unclosed".to_string()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("(unclosed"), "{err}");
    }
}
