//! Domain patterns that must resolve for real.
//!
//! A fake address is useless to anything that needs to reach the host outside
//! the tunnel, or that compares the answer against something: captive-portal
//! probes, NTP, STUN, and `.local`/`.lan` names the tunnel does not carry.

/// A compiled list of glob patterns matched against query names.
///
/// Patterns are lowercased at construction and matched case-insensitively, as
/// DNS names are. `*` matches any run of characters, including dots, so
/// `*.local` matches `printer.local` and `time.*.apple.com` matches
/// `time.euro.apple.com`.
#[derive(Debug, Default, Clone)]
pub struct BypassList {
    patterns: Vec<Pattern>,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// No wildcard: compare the whole name.
    Exact(String),
    /// Wildcard: the literal runs between `*`s, in order.
    Glob {
        /// Text before the first `*`, empty if the pattern starts with one.
        prefix: String,
        /// Literals between wildcards, in order.
        middles: Vec<String>,
        /// Text after the last `*`, empty if the pattern ends with one.
        suffix: String,
    },
}

impl BypassList {
    pub fn new<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let patterns = patterns
            .into_iter()
            .filter_map(|p| Pattern::compile(p.as_ref()))
            .collect();
        Self { patterns }
    }

    /// True if `domain` should skip fake IP and be resolved for real.
    ///
    /// `domain` is expected already normalized: lowercase, no trailing dot.
    pub fn matches(&self, domain: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(domain))
    }
}

impl Pattern {
    fn compile(raw: &str) -> Option<Self> {
        let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if raw.is_empty() {
            return None;
        }

        if !raw.contains('*') {
            return Some(Pattern::Exact(raw));
        }

        // "a*b*c" -> prefix "a", middles ["b"], suffix "c".
        // A leading or trailing `*` yields an empty prefix or suffix, which
        // matches anything, so no special case is needed for them.
        let mut parts = raw.split('*');
        let prefix = parts.next().unwrap_or_default().to_string();
        let mut rest: Vec<String> = parts.map(str::to_string).collect();
        let suffix = rest.pop().unwrap_or_default();
        let middles = rest.into_iter().filter(|m| !m.is_empty()).collect();

        Some(Pattern::Glob {
            prefix,
            middles,
            suffix,
        })
    }

    fn matches(&self, domain: &str) -> bool {
        match self {
            Pattern::Exact(pattern) => pattern == domain,
            Pattern::Glob {
                prefix,
                middles,
                suffix,
            } => {
                let Some(mut rest) = domain.strip_prefix(prefix.as_str()) else {
                    return false;
                };

                // Each middle must appear after the previous one. Leftmost
                // match is sufficient: the literals cannot overlap, so an
                // earlier match never rules out a later one.
                for middle in middles {
                    match rest.find(middle.as_str()) {
                        Some(idx) => rest = &rest[idx + middle.len()..],
                        None => return false,
                    }
                }

                rest.len() >= suffix.len() && rest.ends_with(suffix.as_str())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_matches_nothing() {
        let list = BypassList::new(Vec::<String>::new());
        assert!(!list.matches("example.com"));
    }

    #[test]
    fn exact_pattern_matches_only_itself() {
        let list = BypassList::new(["captive.apple.com"]);
        assert!(list.matches("captive.apple.com"));
        assert!(!list.matches("apple.com"));
        assert!(!list.matches("evil-captive.apple.com"));
        assert!(!list.matches("captive.apple.com.evil.test"));
    }

    #[test]
    fn leading_wildcard_matches_any_subdomain() {
        let list = BypassList::new(["*.local"]);
        assert!(list.matches("printer.local"));
        assert!(list.matches("a.b.c.local"));
        assert!(!list.matches("local"));
        assert!(!list.matches("notlocal"));
        assert!(!list.matches("printer.local.example.com"));
    }

    #[test]
    fn middle_wildcard_matches_between_literals() {
        let list = BypassList::new(["time.*.apple.com"]);
        assert!(list.matches("time.euro.apple.com"));
        assert!(list.matches("time.a.b.apple.com"));
        assert!(!list.matches("time.apple.com.evil.test"));
        assert!(!list.matches("nottime.euro.apple.com"));
    }

    #[test]
    fn trailing_wildcard_matches_any_suffix() {
        let list = BypassList::new(["internal.*"]);
        assert!(list.matches("internal.example.com"));
        assert!(list.matches("internal."));
        assert!(!list.matches("an.internal.example.com"));
    }

    #[test]
    fn matching_is_case_insensitive_and_dot_insensitive() {
        let list = BypassList::new(["*.LOCAL.", "Captive.Apple.Com"]);
        assert!(list.matches("printer.local"));
        assert!(list.matches("captive.apple.com"));
    }

    #[test]
    fn blank_patterns_are_dropped() {
        let list = BypassList::new(["", "   ", "."]);
        assert!(!list.matches(""));
        assert!(!list.matches("example.com"));
    }

    #[test]
    fn bare_wildcard_matches_everything() {
        let list = BypassList::new(["*"]);
        assert!(list.matches("example.com"));
        assert!(list.matches("a"));
    }

    #[test]
    fn any_matching_pattern_wins() {
        let list = BypassList::new(["*.local", "captive.apple.com", "*.pool.ntp.org"]);
        assert!(list.matches("0.pool.ntp.org"));
        assert!(list.matches("printer.local"));
        assert!(!list.matches("example.com"));
    }
}
