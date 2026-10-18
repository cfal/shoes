use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FakeIpConfig {
    Enabled(bool),
    Options(FakeIpOptions),
}

impl FakeIpConfig {
    pub fn options(&self) -> Option<FakeIpOptions> {
        match self {
            Self::Enabled(false) => None,
            Self::Enabled(true) => Some(FakeIpOptions::default()),
            Self::Options(options) => Some(options.clone()),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingFamily {
    #[default]
    Forward,
    Nodata,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsRecords {
    #[default]
    Forward,
    Suppress,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FakeIpOptions {
    pub ipv4_range: Option<String>,
    pub ipv6_range: Option<String>,
    pub max_entries: usize,
    pub bypass_domains: Vec<String>,
    pub missing_family: MissingFamily,
    pub https_records: HttpsRecords,
    pub state_file: Option<PathBuf>,
}

impl Default for FakeIpOptions {
    fn default() -> Self {
        Self {
            ipv4_range: Some("198.18.0.0/15".into()),
            ipv6_range: None,
            max_entries: 65_536,
            bypass_domains: Vec::new(),
            missing_family: MissingFamily::Forward,
            https_records: HttpsRecords::Forward,
            state_file: None,
        }
    }
}

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
