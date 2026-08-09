//! Rule-sets: sing-box `.srs` domain and IP lists used as routing matchers.
//!
//! See docs/specs/2026-08-09-rule-sets.md.

mod ip_set;
mod rule;
mod srs;
mod succinct;

use std::borrow::Cow;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_domain_lowercases_and_strips_the_root_dot() {
        assert_eq!(normalize_domain("Example.COM."), "example.com");
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert!(matches!(normalize_domain("example.com"), Cow::Borrowed(_)));
    }
}
