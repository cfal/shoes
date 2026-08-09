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
pub use validate::{ValidatedConfigs, create_server_configs};

/// Rewrite relative rule-set paths so they resolve against the config file that
/// declared them, letting a config directory be relocated intact.
///
/// This has to happen here: `load_configs` is the last point that still knows
/// which file an entry came from, since the configs are flattened into one list
/// immediately afterwards.
fn resolve_rule_set_paths(configs: &mut [Config], config_filename: &str) {
    let Some(base) = std::path::Path::new(config_filename).parent() else {
        return;
    };
    if base.as_os_str().is_empty() {
        return;
    }
    for config in configs.iter_mut() {
        if let Config::RuleSet(rule_set) = config {
            let path = std::path::Path::new(&rule_set.path);
            if path.is_relative() {
                rule_set.path = base.join(path).to_string_lossy().into_owned();
            }
        }
    }
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

        let mut configs = match serde_yaml::from_str::<Vec<Config>>(&config_str) {
            Ok(c) => c,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Could not parse config file {config_filename} as config YAML: {e}"),
                ));
            }
        };
        resolve_rule_set_paths(&mut configs, config_filename);
        all_configs.append(&mut configs)
    }

    Ok(all_configs)
}

/// Load config from a string (used by FFI targets)
#[cfg(any(target_os = "android", target_os = "ios", feature = "ffi"))]
pub fn load_config_str(config_str: &str) -> std::io::Result<Vec<Config>> {
    serde_yaml::from_str::<Vec<Config>>(config_str).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Could not parse config string as config YAML: {e}"),
        )
    })
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// A config touching every kind of secret the parser accepts. Each value is
    /// distinctive so a leak is unambiguous rather than a coincidental substring.
    const CONFIG_WITH_SECRETS: &str = r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
    username: alice
    password: LEAK-socks-inbound-password
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "wg.example.com:51820"
        protocol:
          type: amneziawg
          private_key: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
          peer_public_key: "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="
          preshared_key: "ERERERERERERERERERERERERERERERERERERERERERE="
          local_addresses: "10.8.0.2/32"
          allowed_ips: "0.0.0.0/0"
          awg:
            s1: 20
            s2: 20
            s3: 20
            s4: 20
            header_protection_key: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
- address: "127.0.0.1:8388"
  protocol:
    type: shadowsocks
    cipher: chacha20-ietf-poly1305
    password: LEAK-shadowsocks-password
- address: "127.0.0.1:1443"
  protocol:
    type: trojan
    password: LEAK-trojan-password
- address: "127.0.0.1:2443"
  protocol:
    type: vless
    user_id: 11111111-2222-3333-4444-555555555555
"#;

    /// Every secret above, as it appears in the YAML.
    const SECRET_VALUES: &[&str] = &[
        "LEAK-socks-inbound-password",
        "LEAK-shadowsocks-password",
        "LEAK-trojan-password",
        "11111111-2222-3333-4444-555555555555",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", // private key
        "ERERERERERERERERERERERERERERERERERERERERERE=", // preshared key
        "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=", // header protection key
    ];

    /// `load_config_str` is gated to the FFI targets; this is the same parse.
    fn parse(yaml: &str) -> Vec<Config> {
        serde_yaml::from_str::<Vec<Config>>(yaml).expect("config must parse")
    }

    /// The CLI dumps every parsed config at debug level. That dump must not
    /// carry credentials: with `--log-file` it lands on disk in cleartext, and
    /// logs get pasted into bug reports.
    #[test]
    fn the_config_debug_dump_contains_no_secrets() {
        let configs = parse(CONFIG_WITH_SECRETS);
        assert!(!configs.is_empty());

        // Exactly what main.rs writes for each config.
        let dump = configs
            .iter()
            .map(|config| format!("{config:#?}"))
            .collect::<Vec<_>>()
            .join("\n");

        for secret in SECRET_VALUES {
            assert!(
                !dump.contains(secret),
                "the debug dump leaked a secret: {secret}\n\ndump:\n{dump}"
            );
        }

        // The dump is still worth having: non-secret fields survive.
        assert!(dump.contains("alice"), "usernames should remain visible");
        assert!(
            dump.contains("wg.example.com"),
            "endpoints should remain visible"
        );
        assert!(
            dump.contains("<redacted>"),
            "secrets should be marked, not dropped"
        );
    }

    /// Redaction must not corrupt the config. Re-serializing has to reproduce
    /// the real values, or a round-trip would silently destroy credentials.
    #[test]
    fn secrets_survive_a_serde_round_trip() {
        let configs = parse(CONFIG_WITH_SECRETS);
        let yaml = serde_yaml::to_string(&configs).expect("config must re-serialize");

        for secret in SECRET_VALUES {
            assert!(
                yaml.contains(secret),
                "re-serializing lost a secret: {secret}"
            );
        }
    }
}

#[cfg(test)]
mod rule_set_path_tests {
    use super::*;

    fn rule_set(path: &str) -> Config {
        Config::RuleSet(RuleSetConfig {
            rule_set: "geo".to_string(),
            path: path.to_string(),
        })
    }

    fn path_of(config: &Config) -> &str {
        match config {
            Config::RuleSet(c) => &c.path,
            other => panic!("expected a rule-set config, got {other:?}"),
        }
    }

    #[test]
    fn relative_rule_set_paths_resolve_against_the_config_file() {
        let mut configs = vec![rule_set("lists/geo.srs")];
        resolve_rule_set_paths(&mut configs, "/etc/shoes/main.yaml");
        assert_eq!(path_of(&configs[0]), "/etc/shoes/lists/geo.srs");
    }

    #[test]
    fn absolute_rule_set_paths_are_left_alone() {
        let mut configs = vec![rule_set("/opt/geo.srs")];
        resolve_rule_set_paths(&mut configs, "/etc/shoes/main.yaml");
        assert_eq!(path_of(&configs[0]), "/opt/geo.srs");
    }

    #[test]
    fn a_config_in_the_working_directory_leaves_paths_untouched() {
        let mut configs = vec![rule_set("geo.srs")];
        resolve_rule_set_paths(&mut configs, "config.yaml");
        assert_eq!(path_of(&configs[0]), "geo.srs");
    }
}
