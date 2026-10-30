mod codec;
mod go_rng;
pub(crate) mod handler;
mod layout;
mod stream;
mod table;

use std::{fmt, io, sync::Arc};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::config::{ClientProxyConfig, ServerProxyConfig, Transport};

use layout::Layout;
use table::Mapping;

pub(crate) use stream::SudokuStream;

pub(crate) fn validate_client(
    mut protocol: &ClientProxyConfig,
    transport: &Transport,
) -> io::Result<()> {
    check_transport(contains_client(protocol), transport)?;
    while let ClientProxyConfig::SudokuMask(config) = protocol {
        protocol = &config.protocol;
    }
    if contains_client(protocol) {
        return Err(invalid("sudoku_mask must be an outermost protocol layer"));
    }
    Ok(())
}

pub(crate) fn validate_server(
    mut protocol: &ServerProxyConfig,
    transport: &Transport,
) -> io::Result<()> {
    check_transport(contains_server(protocol), transport)?;
    while let ServerProxyConfig::SudokuMask(config) = protocol {
        protocol = &config.protocol;
    }
    if contains_server(protocol) {
        return Err(invalid("sudoku_mask must be an outermost protocol layer"));
    }
    Ok(())
}

fn contains_client(protocol: &ClientProxyConfig) -> bool {
    use crate::config::ClientProxyConfig as P;
    match protocol {
        P::SudokuMask(_) => true,
        P::Tls(c) => contains_client(&c.protocol),
        P::Reality { protocol, .. } | P::ShadowTls { protocol, .. } => contains_client(protocol),
        P::Websocket(c) => contains_client(&c.protocol),
        P::Xhttp(c) => contains_client(&c.protocol),
        _ => false,
    }
}

fn contains_server(protocol: &ServerProxyConfig) -> bool {
    use crate::config::ServerProxyConfig as P;
    match protocol {
        P::SudokuMask(_) => true,
        P::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            tls_targets
                .values()
                .chain(default_tls_target.as_deref())
                .any(|c| contains_server(&c.protocol))
                || shadowtls_targets
                    .values()
                    .any(|c| contains_server(&c.protocol))
                || reality_targets
                    .values()
                    .any(|c| contains_server(&c.protocol))
        }
        P::Websocket { targets } => targets.iter().any(|c| contains_server(&c.protocol)),
        P::Xhttp(c) => contains_server(&c.protocol),
        _ => false,
    }
}

fn check_transport(present: bool, transport: &Transport) -> io::Result<()> {
    if present && *transport != Transport::Tcp {
        return Err(invalid(
            "sudoku_mask requires TCP transport; native UDP/QUIC masking is not supported",
        ));
    }
    Ok(())
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Password(String);

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SudokuMaskConfig<P> {
    #[serde(default)]
    pub password: Password,
    #[serde(default)]
    pub ascii: String,
    #[serde(default, alias = "customTable")]
    pub custom_table: String,
    #[serde(default, alias = "customTables")]
    pub custom_tables: Vec<String>,
    #[serde(default, alias = "paddingMin")]
    pub padding_min: u32,
    #[serde(default, alias = "paddingMax")]
    pub padding_max: u32,
    pub protocol: Box<P>,
}

impl<P> SudokuMaskConfig<P> {
    pub(crate) fn prepare(&self) -> io::Result<Arc<Prepared>> {
        let layouts = self.layouts()?;
        let padding_min = self.padding_min.min(100) as u8;
        let padding_max = self.padding_max.min(100).max(padding_min.into()) as u8;
        Ok(Arc::new(Prepared {
            mapping: Mapping::new(&self.password.0),
            layouts,
            padding_min,
            padding_max,
        }))
    }

    fn layouts(&self) -> io::Result<Vec<Layout>> {
        match self.ascii.trim().to_ascii_lowercase().as_str() {
            "ascii" | "prefer_ascii" => return Ok(vec![Layout::ascii()]),
            "" | "entropy" | "prefer_entropy" => {}
            _ => return Err(invalid("invalid sudoku ascii mode")),
        }
        let patterns = if self.custom_tables.is_empty() {
            std::slice::from_ref(&self.custom_table)
        } else {
            &self.custom_tables
        };
        let mut seen = Vec::new();
        let mut layouts = Vec::new();
        for pattern in patterns {
            let normalized = pattern.trim().to_ascii_lowercase().replace(' ', "");
            if seen.contains(&normalized) {
                continue;
            }
            layouts.push(if normalized.is_empty() {
                Layout::entropy()
            } else {
                Layout::custom(&normalized)?
            });
            seen.push(normalized);
        }
        Ok(layouts)
    }
}

pub(crate) struct Prepared {
    mapping: Mapping,
    layouts: Vec<Layout>,
    padding_min: u8,
    padding_max: u8,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SudokuMask")
            .field("layouts", &self.layouts.len())
            .field("padding_min", &self.padding_min)
            .field("padding_max", &self.padding_max)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Role {
    Client,
    Server,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn config(value: serde_json::Value) -> Arc<Prepared> {
        let mut value = value;
        value["protocol"] = serde_json::Value::Null;
        serde_json::from_value::<SudokuMaskConfig<()>>(value)
            .unwrap()
            .prepare()
            .unwrap()
    }

    #[test]
    fn options_match_xray_normalization_and_redact_password() {
        let raw = json!({"protocol": null, "password": "not-for-logs", "ascii": " ENTROPY ",
            "customTable": "invalid and ignored", "customTables": [" XPXVVPVV ", "xpxvvpvv", ""],
            "paddingMin": 300, "paddingMax": 1});
        let options: SudokuMaskConfig<()> = serde_json::from_value(raw).unwrap();
        assert!(!format!("{options:?}").contains("not-for-logs"));
        let prepared = options.prepare().unwrap();
        assert_eq!(prepared.layouts.len(), 2);
        assert_eq!((prepared.padding_min, prepared.padding_max), (100, 100));
        assert_eq!(
            serde_json::to_value(options).unwrap()["password"],
            "not-for-logs"
        );
        let ascii = config(json!({"ascii":"Ascii", "custom_tables":["invalid"]}));
        assert_eq!(ascii.layouts.len(), 1);
        assert_eq!(ascii.layouts[0].encode[63], b'\n');
        assert_eq!(config(json!({})).layouts[0].encode[0], 0);
    }

    #[test]
    fn invalid_options_are_rejected() {
        for fields in [
            json!({"padding_min":-1}),
            json!({"padding_max":4294967296u64}),
            json!({"paddingMin":0,"padding_min":1}),
            json!({"unknown":0}),
        ] {
            let mut fields = fields;
            fields["protocol"] = serde_json::Value::Null;
            assert!(serde_json::from_value::<SudokuMaskConfig<()>>(fields).is_err());
        }
        for fields in [
            json!({"ascii":"wat"}),
            json!({"custom_table":"xxxxxxxx"}),
            json!({"custom_table":"xpxvvpv"}),
            json!({"custom_table":"xpxvvpv!"}),
        ] {
            let mut fields = fields;
            fields["protocol"] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<SudokuMaskConfig<()>>(fields)
                    .unwrap()
                    .prepare()
                    .is_err()
            );
        }
    }
}
