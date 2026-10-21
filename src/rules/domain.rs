use std::borrow::Cow;
use std::collections::HashSet;
use std::io;

use super::invalid;

pub fn normalize(name: &str) -> io::Result<Cow<'_, str>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(invalid(
            "invalid hostname: use an ASCII A-label name of 1-253 bytes",
        ));
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    }) {
        return Err(invalid("invalid hostname label"));
    }
    Ok(if name.bytes().any(|c| c.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    })
}

#[derive(Debug)]
pub enum Names {
    Small(Box<[Box<str>]>),
    Indexed(HashSet<Box<str>>),
}

impl Names {
    pub(super) fn retained_bytes(&self) -> usize {
        match self {
            Self::Small(names) => names.iter().map(|name| name.len() + 32).sum(),
            Self::Indexed(names) => {
                names.capacity() * 32 + names.iter().map(|name| name.len() + 16).sum::<usize>()
            }
        }
    }

    pub fn new(names: Vec<String>) -> io::Result<Self> {
        let mut names = names
            .into_iter()
            .map(|s| {
                normalize(&s)
                    .map(|s| s.into_owned().into_boxed_str())
                    .map_err(|e| invalid(format!("domain {s:?}: {e}")))
            })
            .collect::<io::Result<Vec<_>>>()?;
        names.sort_unstable();
        names.dedup();
        Ok(if names.len() <= 16 {
            Self::Small(names.into())
        } else {
            Self::Indexed(names.into_iter().collect())
        })
    }

    pub fn matches(&self, name: &str, kind: DomainKind) -> bool {
        let names = match self {
            Self::Small(names) => {
                return names.iter().any(|base| {
                    (kind != DomainKind::Subdomains && &**base == name)
                        || (kind != DomainKind::Exact
                            && name.strip_suffix(&**base).is_some_and(|p| p.ends_with('.')))
                });
            }
            Self::Indexed(names) => names,
        };
        if kind != DomainKind::Subdomains && names.contains(name) {
            return true;
        }
        if kind == DomainKind::Exact {
            return false;
        }
        name.match_indices('.')
            .any(|(i, _)| names.contains(&name[i + 1..]))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainKind {
    Exact,
    Suffix,
    Subdomains,
}

pub fn wildcard(pattern: &str) -> io::Result<String> {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    if pattern.is_empty() || pattern.len() > 253 {
        return Err(invalid("wildcard pattern must be 1-253 bytes"));
    }
    let mut result = String::from("^(?:");
    for (i, label) in pattern.split('.').enumerate() {
        if i != 0 {
            result.push_str("\\.");
        }
        if label == "*" {
            result.push_str("[^.]+");
        } else {
            // Normalize only literal labels; '*' is an operator, not a hostname.
            let label = normalize(label).map_err(|error| {
                invalid(format!(
                    "wildcard labels must be '*' or a literal hostname label: {error}"
                ))
            })?;
            result.push_str(&regex::escape(&label));
        }
    }
    result.push_str(")$");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_labels_have_context_appropriate_diagnostics() {
        for pattern in ["a*.example.com", "**.x"] {
            assert_eq!(
                normalize(pattern).unwrap_err().to_string(),
                "invalid hostname label"
            );
            assert_eq!(
                wildcard(pattern).unwrap_err().to_string(),
                "wildcard labels must be '*' or a literal hostname label: invalid hostname label"
            );
        }
        for pattern in ["", ".", &"*".repeat(254)] {
            assert_eq!(
                wildcard(pattern).unwrap_err().to_string(),
                "wildcard pattern must be 1-253 bytes"
            );
        }
    }

    #[test]
    fn normalization_and_boundaries() {
        assert_eq!(normalize("ExAmPlE.com.").unwrap(), "example.com");
        for bad in [
            "",
            ".",
            "example.com..",
            "*.x",
            "a b",
            "x/y",
            "a\n",
            "é.com",
        ] {
            assert!(normalize(bad).is_err(), "{bad:?}");
        }
        for count in [1, 16, 17] {
            let names = Names::new((0..count).map(|i| format!("{i}.example")).collect()).unwrap();
            assert!(names.matches("a.0.example", DomainKind::Suffix));
            assert!(names.matches("0.example", DomainKind::Suffix));
            assert!(!names.matches("0.example", DomainKind::Subdomains));
            assert!(!names.matches("a0.example", DomainKind::Suffix));
            assert!(names.matches("0.example", DomainKind::Exact));
            assert!(!names.matches("a.0.example", DomainKind::Exact));
            assert!(names.matches("a.b.0.example", DomainKind::Subdomains));
            assert!(!names.matches("a0.example", DomainKind::Subdomains));
        }
        let regex = regex::Regex::new(&wildcard("*.Example.com").unwrap()).unwrap();
        assert!(regex.is_match("a.example.com"));
        assert!(!regex.is_match("a.b.example.com"));
        assert!(!regex.is_match("example.com"));
    }
}
