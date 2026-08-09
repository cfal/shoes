//! Rule-sets: sing-box `.srs` domain and IP lists used as routing matchers.
//!
//! See docs/specs/2026-08-09-rule-sets.md.

mod ip_set;
mod rule;
mod srs;
mod succinct;

use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;

use rule::HeadlessRule;

/// Everything a rule-set is allowed to look at when deciding a match.
///
/// `domain` must already be normalised with [`normalize_domain`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MatchTarget<'a> {
    pub domain: Option<&'a str>,
    pub ip: Option<u128>,
}

/// Lowercase and strip one trailing dot.
///
/// Published lists are lowercase and DNS labels are case-insensitive. This is
/// deliberately stricter than `matches_domain` in client_proxy_selector.rs,
/// which is case-sensitive; changing mask behaviour is out of scope.
pub fn normalize_domain(host: &str) -> Cow<'_, str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host)
    }
}

/// A parsed rule-set, shared by every rule that references it by name.
#[derive(Debug)]
pub struct RuleSet {
    name: String,
    rules: Vec<HeadlessRule>,
}

impl RuleSet {
    pub fn load(name: &str, path: &Path) -> std::io::Result<Arc<Self>> {
        let bytes = std::fs::read(path).map_err(|e| {
            std::io::Error::other(format!(
                "rule-set {name:?}: could not read {}: {e}",
                path.display()
            ))
        })?;
        Self::from_bytes(name, &bytes)
    }

    pub fn from_bytes(name: &str, bytes: &[u8]) -> std::io::Result<Arc<Self>> {
        let raw = srs::decode(bytes)
            .map_err(|e| std::io::Error::other(format!("rule-set {name:?}: {e}")))?;
        let mut rules = Vec::with_capacity(raw.len());
        for raw_rule in raw {
            let rule = HeadlessRule::from_raw(raw_rule)
                .map_err(|e| std::io::Error::other(format!("rule-set {name:?}: {e}")))?;
            rules.push(rule);
        }
        Ok(Arc::new(Self {
            name: name.to_string(),
            rules,
        }))
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn matches(&self, target: &MatchTarget<'_>) -> bool {
        self.rules.iter().any(|rule| rule.matches(target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_set_matches_if_any_of_its_rules_matches() {
        // Two rules, one keyed on a domain and one on an IP range.
        use crate::rule_set::ip_set::IpSet;
        use crate::rule_set::srs::RawRule;
        use crate::rule_set::succinct::DomainMatcher;
        use std::net::Ipv4Addr;

        let ip = u128::from(Ipv4Addr::new(10, 0, 0, 7).to_ipv6_mapped());
        let range = u128::from(Ipv4Addr::new(10, 0, 0, 0).to_ipv6_mapped());
        let range_end = u128::from(Ipv4Addr::new(10, 0, 0, 255).to_ipv6_mapped());

        let set = RuleSet {
            name: "test".to_string(),
            rules: vec![
                HeadlessRule::from_raw(RawRule {
                    domain: Some(DomainMatcher::build(&[], &["example.com"])),
                    ..Default::default()
                })
                .unwrap(),
                HeadlessRule::from_raw(RawRule {
                    ip_cidr: Some(IpSet::new(vec![(range, range_end)]).unwrap()),
                    ..Default::default()
                })
                .unwrap(),
            ],
        };

        assert!(set.matches(&MatchTarget {
            domain: Some("sub.example.com"),
            ip: None
        }));
        assert!(set.matches(&MatchTarget {
            domain: None,
            ip: Some(ip)
        }));
        assert!(!set.matches(&MatchTarget {
            domain: Some("other.net"),
            ip: None
        }));
    }

    #[test]
    fn loading_a_missing_file_names_the_rule_set_and_the_path() {
        let err = RuleSet::load("geosite-ru", Path::new("/nonexistent.srs")).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("geosite-ru"), "{message}");
        assert!(message.contains("/nonexistent.srs"), "{message}");
    }

    #[test]
    fn normalize_domain_lowercases_and_strips_the_root_dot() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert!(matches!(normalize_domain("example.com"), Cow::Borrowed(_)));
    }
}
