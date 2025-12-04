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

mod pem;
mod types;
mod validate;

pub use pem::convert_cert_paths;
pub use types::*;
pub use validate::create_server_configs;

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

        let mut configs = match serde_yaml::from_str::<Vec<Config>>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as config YAML: {e}"),
                ));
            }
        };
        all_configs.append(&mut configs)
    }

    Ok(all_configs)
}

/// Load config from a string (used by FFI targets)
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub fn load_config_str(config_str: &str) -> std::io::Result<Vec<Config>> {
    serde_yaml::from_str::<Vec<Config>>(&config_str).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Could not parse config string as config YAML: {e}"),
        )
    })
}
