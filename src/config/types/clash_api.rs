use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::BindLocation;
use crate::address::NetLocationPortRange;
use crate::option_util::OneOrSome;

#[derive(Clone, PartialEq)]
pub struct ClashApiConfig {
    pub bind: BindLocation,
    pub secret: String,
    pub cors_origins: Vec<String>,
    pub allow_private_network: bool,
    pub connection_notes: bool,
}

impl fmt::Debug for ClashApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClashApiConfig")
            .field("bind", &self.bind)
            .field("secret", &"[redacted]")
            .field("cors_origins", &self.cors_origins)
            .field("allow_private_network", &self.allow_private_network)
            .field("connection_notes", &self.connection_notes)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ClashApiConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            clash_api_address: Option<OneOrSome<NetLocationPortRange>>,
            clash_api_path: Option<PathBuf>,
            secret: String,
            #[serde(default)]
            cors_origins: Vec<String>,
            #[serde(default)]
            allow_private_network: bool,
            #[serde(default)]
            connection_notes: bool,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        let map = value
            .as_mapping()
            .ok_or_else(|| Error::custom("Clash API config must be a mapping"))?;
        if usize::from(map.contains_key("clash_api_address"))
            + usize::from(map.contains_key("clash_api_path"))
            != 1
        {
            return Err(Error::custom(
                "specify exactly one of clash_api_address and clash_api_path",
            ));
        }
        // Serde's value errors can contain the supplied secret.
        let fields: Fields =
            serde_yaml::from_value(value).map_err(|_| Error::custom("invalid Clash API fields"))?;
        if fields.secret.is_empty() {
            return Err(Error::custom("Clash API secret must be nonempty"));
        }
        for origin in &fields.cors_origins {
            if origin == "*" {
                continue;
            }
            let parsed = url::Url::parse(origin)
                .map_err(|_| Error::custom("invalid Clash API CORS origin"))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.origin().ascii_serialization() != *origin
            {
                return Err(Error::custom(
                    "Clash API CORS origins must be '*' or exact HTTP(S) origins without paths or credentials",
                ));
            }
        }
        let bind = match (fields.clash_api_address, fields.clash_api_path) {
            (Some(addresses), None) if addresses.iter().next().is_some() => {
                BindLocation::Address(addresses)
            }
            (None, Some(path)) if path.is_absolute() && path.file_name().is_some() => {
                if !cfg!(unix) {
                    return Err(Error::custom("clash_api_path requires a Unix platform"));
                }
                BindLocation::Path(path)
            }
            _ => {
                return Err(Error::custom(
                    "Clash API requires nonempty addresses or an absolute Unix socket path",
                ));
            }
        };
        Ok(Self {
            bind,
            secret: fields.secret,
            cors_origins: fields.cors_origins,
            allow_private_network: fields.allow_private_network,
            connection_notes: fields.connection_notes,
        })
    }
}

impl Serialize for ClashApiConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        match &self.bind {
            BindLocation::Address(addresses) => {
                map.serialize_entry("clash_api_address", addresses)?
            }
            BindLocation::Path(path) => map.serialize_entry("clash_api_path", path)?,
            BindLocation::Unspecified {} => {
                return Err(serde::ser::Error::custom("Clash API listener has no bind"));
            }
        }
        map.serialize_entry("secret", &self.secret)?;
        if !self.cors_origins.is_empty() {
            map.serialize_entry("cors_origins", &self.cors_origins)?;
        }
        if self.allow_private_network {
            map.serialize_entry("allow_private_network", &true)?;
        }
        if self.connection_notes {
            map.serialize_entry("connection_notes", &true)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CacheFileConfig {
    pub cache_file_path: PathBuf,
}

impl<'de> Deserialize<'de> for CacheFileConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            cache_file_path: PathBuf,
        }
        let fields = Fields::deserialize(deserializer)?;
        let path = &fields.cache_file_path;
        if path.as_os_str().is_empty()
            || path.file_name().is_none()
            || path.as_os_str().to_string_lossy().ends_with(".lock")
        {
            return Err(serde::de::Error::custom(
                "cache_file_path must name a nonempty file; the .lock suffix is reserved",
            ));
        }
        Ok(Self {
            cache_file_path: fields.cache_file_path,
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ControlConfig {
    pub listeners: Vec<ClashApiConfig>,
    pub cache_file_path: Option<PathBuf>,
}

impl ControlConfig {
    #[cfg(any(target_os = "android", target_os = "ios", feature = "ffi", test))]
    pub fn reject_ffi(&self) -> std::io::Result<()> {
        if !self.listeners.is_empty() || self.cache_file_path.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Clash controller and cache configuration are not supported by the FFI lifecycle",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, create_server_configs};

    #[test]
    fn connection_notes_opt_in_roundtrips_and_defaults_off() {
        let base = "clash_api_address: '127.0.0.1:9090'\nsecret: test";
        let disabled: ClashApiConfig = serde_yaml::from_str(base).unwrap();
        assert!(!disabled.connection_notes);
        assert!(
            !serde_yaml::to_string(&disabled)
                .unwrap()
                .contains("connection_notes")
        );
        let enabled: ClashApiConfig =
            serde_yaml::from_str(&format!("{base}\nconnection_notes: true")).unwrap();
        assert!(enabled.connection_notes);
        assert_eq!(
            serde_yaml::from_str::<ClashApiConfig>(&serde_yaml::to_string(&enabled).unwrap())
                .unwrap(),
            enabled
        );
        assert_ne!(disabled, enabled);
    }

    #[test]
    fn flat_clash_api_entries_share_one_control_config() {
        let configs = serde_yaml::from_str(
            "- clash_api_address: '0.0.0.0:9090'\n  secret: first\n\
             - clash_api_address: ['127.0.0.1:9091', '[::1]:9091']\n  secret: second\n\
             - cache_file_path: ./cache.db\n",
        )
        .unwrap();
        let validated = create_server_configs(configs).unwrap();
        assert!(validated.configs.is_empty());
        assert_eq!(validated.control.listeners.len(), 2);
        assert_eq!(validated.control.cache_file_path, Some("./cache.db".into()));
        assert!(validated.control.reject_ffi().is_err());
        assert!(ControlConfig::default().reject_ffi().is_ok());
        assert!(!format!("{:?}", validated.control).contains("first"));
        let yaml = serde_yaml::to_string(&validated.control.listeners[0]).unwrap();
        assert_eq!(
            serde_yaml::from_str::<ClashApiConfig>(&yaml).unwrap(),
            validated.control.listeners[0]
        );
    }

    #[test]
    fn clash_api_rejects_ambiguous_and_secret_leaking_shapes() {
        for input in [
            "clash_api_address: null\nsecret: hidden",
            "clash_api_address: []\nsecret: hidden",
            "clash_api_address: '127.0.0.1:9'\nclash_api_path: null\nsecret: hidden",
            "clash_api_address: '127.0.0.1:9'\nsecret: ''",
            "clash_api_address: '127.0.0.1:9'\nsecret: hidden\npem: x\ndata: hidden",
            "clash_api_address: '127.0.0.1:9'\nsecret: hidden\ncache_file_path: cache.db",
            "clash_api_path: relative.sock\nsecret: hidden",
            "clash_api: {address: '127.0.0.1:9', secret: hidden}",
        ] {
            let error = serde_yaml::from_str::<Config>(input).unwrap_err();
            assert!(!error.to_string().contains("hidden"));
        }
    }

    #[test]
    fn clash_api_origins_are_exact_or_explicitly_unrestricted() {
        for origin in [
            "null",
            "https://example.com/",
            "https://user@example.com",
            "https://example.com/path",
        ] {
            let input = format!(
                "clash_api_address: '127.0.0.1:9'\nsecret: hidden\ncors_origins: ['{origin}']"
            );
            assert!(serde_yaml::from_str::<ClashApiConfig>(&input).is_err());
        }
        let config: ClashApiConfig = serde_yaml::from_str(
            "clash_api_address: '127.0.0.1:9'\nsecret: hidden\ncors_origins: ['https://dashboard.example.com']",
        ).unwrap();
        assert_eq!(config.cors_origins, ["https://dashboard.example.com"]);
        for origins in ["['*']", "['https://dashboard.example.com', '*']"] {
            let input = format!(
                "clash_api_address: '127.0.0.1:9'\nsecret: hidden\ncors_origins: {origins}"
            );
            let config: ClashApiConfig = serde_yaml::from_str(&input).unwrap();
            assert!(config.cors_origins.iter().any(|origin| origin == "*"));
            let yaml = serde_yaml::to_string(&config).unwrap();
            assert_eq!(
                serde_yaml::from_str::<ClashApiConfig>(&yaml).unwrap(),
                config
            );
        }
    }

    #[test]
    fn clash_api_cache_is_explicit_and_unique() {
        for input in [
            "cache_file_path: ''",
            "cache_file_path: null",
            "cache_file_path: cache.db.lock",
            "cache_file_path: cache.db\nenabled: true",
        ] {
            assert!(serde_yaml::from_str::<Config>(input).is_err());
        }
        let configs =
            serde_yaml::from_str("- cache_file_path: first.db\n- cache_file_path: second.db\n")
                .unwrap();
        assert!(create_server_configs(configs).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn clash_api_unix_socket_roundtrips() {
        let config: ClashApiConfig =
            serde_yaml::from_str("clash_api_path: /run/shoes/clash.sock\nsecret: hidden").unwrap();
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert_eq!(
            serde_yaml::from_str::<ClashApiConfig>(&yaml).unwrap(),
            config
        );
    }
}
