//! Configuration module for the proxy server.
//!
//! This module provides:
//! - [`types`]: All configuration types (server, client, rules, etc.)
//! - [`pem`]: PEM file handling and certificate loading
//! - [`validate`]: Configuration validation and server config creation
//! - [`singbox`]: Sing-box JSON configuration conversion
//! - [`convert_util`]: Utilities for preprocessing JSON-like configs
//!
//! The main entry points are:
//! - [`load_configs`]: Load config files from disk
//! - [`convert_cert_paths`]: Convert PEM file paths to inline data
//! - [`create_server_configs`]: Validate and create final server configs
//! - [`singbox::convert_singbox_config`]: Convert sing-box configs to shoes format

pub(crate) mod client_visit;
mod fake_dns;
pub(crate) mod health;
mod pem;
pub(crate) mod rule_visit;
#[cfg(test)]
mod tests;
mod types;
mod validate;
#[cfg(unix)]
mod wireguard_devices;

pub(crate) use fake_dns::{tun_endpoint_ips, validate_tun_endpoints};
pub use pem::convert_cert_paths;
pub(crate) use pem::{is_pem_file_path, pem_candidate_dependencies, pem_reload_dependencies};
pub use types::*;
pub use validate::{ValidatedConfigs, create_server_configs};
pub(crate) use validate::{validate_client_vision_protocol, validate_server_vision};

fn parse_config_yaml(config_str: &str) -> Result<Vec<Config>, serde_yaml::Error> {
    use serde::de::{Deserializer, Error, SeqAccess, Visitor};

    struct ConfigList;

    impl<'de> Visitor<'de> for ConfigList {
        type Value = Vec<Config>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of Shoes configuration entries")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut configs = Vec::new();
            // Keep YAML locations intact; only Config decoding needs an added index.
            while let Some(value) = seq.next_element::<serde_yaml::Value>()? {
                let config = serde_yaml::from_value(value).map_err(|error| {
                    A::Error::custom(format!("config[{}]: {error}", configs.len()))
                })?;
                configs.push(config);
            }
            Ok(configs)
        }
    }

    serde_yaml::Deserializer::from_str(config_str).deserialize_seq(ConfigList)
}

/// Loads configuration files from the provided paths.
///
/// Reads each file, parses it as YAML, and returns the combined list of configs.
pub async fn load_configs(args: &Vec<String>) -> std::io::Result<Vec<Config>> {
    let mut all_configs = vec![];
    for config_filename in args {
        let config_bytes = match tokio::fs::read(config_filename).await {
            Ok(b) => b,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not read config file {config_filename}: {e}"),
                ));
            }
        };

        let config_str = match String::from_utf8(config_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as UTF8: {e}"),
                ));
            }
        };

        let parsed = tokio::task::spawn_blocking(move || parse_config_yaml(&config_str))
            .await
            .map_err(std::io::Error::other)?;
        let mut configs = match parsed {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as config YAML: {e}"),
                ));
            }
        };
        crate::rule_set::anchor(&mut configs, std::path::Path::new(config_filename))?;
        all_configs.append(&mut configs)
    }

    Ok(all_configs)
}

pub async fn compile_configs(configs: Vec<Config>) -> std::io::Result<ValidatedConfigs> {
    static COMPILER: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let permit = COMPILER.acquire().await.map_err(std::io::Error::other)?;
    tokio::task::spawn_blocking(move || {
        // A canceled caller cannot release the permit while its build is still running.
        let _permit = permit;
        create_server_configs(configs)
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Load config from a string (used by FFI targets)
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
#[cfg_attr(
    all(feature = "ffi", not(any(target_os = "android", target_os = "ios"))),
    allow(dead_code)
)]
pub fn load_config_str(config_str: &str) -> std::io::Result<Vec<Config>> {
    parse_config_yaml(config_str).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Could not parse config string as config YAML: {e}"),
        )
    })
}
