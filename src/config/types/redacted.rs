//! A wrapper for configuration values that must never reach a log.
//!
//! Config types derive `Debug`, and the CLI dumps every parsed config at debug
//! level. Without this, a private key, a pre-shared key or a password is one
//! `--log-file` away from being written to disk in cleartext.

use std::fmt;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};

/// What a redacted value formats as. Deliberately not the empty string, so a
/// log reader can tell "withheld" from "unset".
const PLACEHOLDER: &str = "<redacted>";

/// A secret configuration value.
///
/// Transparent to serde, so it parses and re-serializes exactly like the type
/// it wraps, and derefs to that type so call sites read unchanged. What it does
/// not do is print:
///
/// * `Debug` yields `<redacted>`, which is what protects the config dump and
///   any future `{:?}` of a struct that contains one.
/// * There is deliberately **no** `Display`. `format!("{}", secret)` fails to
///   compile rather than leaking, so reaching the value in a message has to be
///   spelled out with [`Redacted::expose`].
///
/// ```
/// # use shoes::config::Redacted;
/// let key: Redacted<String> = "hunter2".to_string().into();
/// assert_eq!(format!("{:?}", key), "<redacted>");
/// assert_eq!(key.expose(), "hunter2");
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Redacted<T = String>(T);

impl<T> Redacted<T> {
    /// Read the value.
    ///
    /// Named for what it does: every call site is a place where a secret leaves
    /// its wrapper, so they should be easy to find and few in number.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Take ownership of the value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PLACEHOLDER)
    }
}

impl<T> Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Redacted<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl From<&str> for Redacted<String> {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_the_value() {
        let secret: Redacted<String> = "correct-horse-battery-staple".into();
        assert_eq!(format!("{:?}", secret), PLACEHOLDER);
        assert_eq!(format!("{:#?}", secret), PLACEHOLDER);
    }

    /// The wrapper is worthless if a containing struct's derived `Debug` prints
    /// through it — that is the exact shape of the config dump.
    #[test]
    fn debug_hides_the_value_inside_a_containing_struct() {
        #[derive(Debug)]
        struct Config {
            name: String,
            password: Redacted<String>,
            optional: Option<Redacted<String>>,
        }

        let config = Config {
            name: "server".to_string(),
            password: "s3cr3t-password".into(),
            optional: Some("s3cr3t-psk".into()),
        };

        let pretty = format!("{:#?}", config);
        assert!(!pretty.contains("s3cr3t-password"));
        assert!(!pretty.contains("s3cr3t-psk"));
        assert!(
            pretty.contains("server"),
            "non-secrets must still be visible"
        );
        assert!(pretty.contains(PLACEHOLDER));
    }

    #[test]
    fn serde_round_trips_transparently() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Config {
            password: Redacted<String>,
        }

        let parsed: Config = serde_yaml::from_str("password: hunter2\n").unwrap();
        assert_eq!(parsed.password.expose(), "hunter2");

        // Re-serializing must produce the real value, not the placeholder —
        // a config that round-trips through the placeholder is corrupted.
        let yaml = serde_yaml::to_string(&parsed).unwrap();
        assert!(yaml.contains("hunter2"), "got: {yaml}");
        assert!(!yaml.contains(PLACEHOLDER));
    }

    #[test]
    fn derefs_to_the_wrapped_type() {
        let secret: Redacted<String> = "hunter2".into();
        assert_eq!(secret.len(), 7);
        assert!(secret.starts_with("hunt"));

        // Deref coercion reaches &str, which is what most call sites want.
        fn takes_str(s: &str) -> usize {
            s.len()
        }
        assert_eq!(takes_str(&secret), 7);
    }

    #[test]
    fn wraps_types_other_than_string() {
        let key: Redacted<Vec<u8>> = vec![1, 2, 3].into();
        assert_eq!(format!("{:?}", key), PLACEHOLDER);
        assert_eq!(key.expose(), &vec![1, 2, 3]);
    }
}
