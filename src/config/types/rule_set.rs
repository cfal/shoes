//! Top-level rule-set declaration.

use serde::{Deserialize, Serialize};

/// ```yaml
/// - rule_set: geosite-ru
///   path: /etc/shoes/geosite-ru.srs
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    /// The name rules refer to.
    pub rule_set: String,
    /// Path to a sing-box `.srs` file. Relative paths resolve against the
    /// directory of the config file that declared them.
    pub path: String,
}
