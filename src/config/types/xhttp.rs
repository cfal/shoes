use std::{collections::BTreeMap, io};

use serde::{Deserialize, Serialize};

use super::{ClientProxyConfig, ServerProxyConfig};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum XhttpVersion {
    #[default]
    Auto,
    H1,
    H2,
    H3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum XhttpRange {
    Number(i64),
    Range(String),
}

impl Default for XhttpRange {
    fn default() -> Self {
        Self::Number(0)
    }
}

impl XhttpRange {
    pub fn bounds(&self, default: (u32, u32), allow_disable: bool) -> io::Result<(u32, u32)> {
        let (min, max) = match self {
            Self::Number(n) => (*n, *n),
            Self::Range(value) => {
                if let Ok(n) = value.parse::<i64>() {
                    (n, n)
                } else {
                    let (min, max) = value
                        .split_once('-')
                        .ok_or_else(|| invalid("expected integer or min-max range"))?;
                    (
                        min.parse().map_err(|_| invalid("invalid range minimum"))?,
                        max.parse().map_err(|_| invalid("invalid range maximum"))?,
                    )
                }
            }
        };
        if min == 0 && max == 0 {
            return Ok(default);
        }
        if allow_disable && min == -1 && max == -1 {
            return Ok((0, 0));
        }
        if min < 0 || max < min || max > u32::MAX as i64 {
            return Err(invalid("invalid XHTTP range"));
        }
        Ok((min as u32, max as u32))
    }
}

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn validate_path_and_host(path: &str, host: Option<&str>) -> io::Result<()> {
    crate::xhttp::wire::Path::new(path)?;
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        host.parse::<http::uri::Authority>()
            .map_err(io::Error::other)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpLimits {
    pub max_sessions: usize,
    pub max_pending_sessions: usize,
    pub max_buffered_bytes: usize,
    pub max_session_buffered_bytes: usize,
    pub max_requests_per_connection: usize,
    pub setup_timeout_secs: u64,
    pub packet_timeout_secs: u64,
    pub response_header_timeout_secs: u64,
}

impl Default for XhttpLimits {
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            max_pending_sessions: 256,
            max_buffered_bytes: 64 * 1024 * 1024,
            max_session_buffered_bytes: 4 * 1024 * 1024,
            max_requests_per_connection: 128,
            setup_timeout_secs: 60,
            packet_timeout_secs: 300,
            response_header_timeout_secs: 60,
        }
    }
}

impl XhttpLimits {
    pub(crate) fn request_limit(&self) -> usize {
        crate::resources::limits()
            .max_streams_per_connection
            .map_or(self.max_requests_per_connection, |limit| {
                self.max_requests_per_connection.min(limit)
            })
    }

    pub fn validate(&self) -> io::Result<()> {
        if [
            self.max_sessions,
            self.max_pending_sessions,
            self.max_buffered_bytes,
            self.max_session_buffered_bytes,
            self.max_requests_per_connection,
        ]
        .contains(&0)
            || [
                self.setup_timeout_secs,
                self.packet_timeout_secs,
                self.response_header_timeout_secs,
            ]
            .contains(&0)
            || self.max_requests_per_connection > u32::MAX as usize
            || self.max_requests_per_connection > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(invalid(
                "XHTTP limits must be positive and request count must fit u32",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpPool {
    pub max_connections: usize,
    pub max_h1_connections: usize,
    pub idle_timeout_secs: u64,
}

impl Default for XhttpPool {
    fn default() -> Self {
        Self {
            max_connections: 3,
            max_h1_connections: 64,
            idle_timeout_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpClientConfig {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: XhttpMode,
    #[serde(default)]
    pub http_version: XhttpVersion,
    #[serde(default)]
    pub x_padding_bytes: XhttpRange,
    #[serde(default)]
    pub sc_max_each_post_bytes: XhttpRange,
    #[serde(default)]
    pub sc_min_posts_interval_ms: XhttpRange,
    #[serde(default)]
    pub no_grpc_header: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub limits: XhttpLimits,
    #[serde(default)]
    pub pool: XhttpPool,
    pub protocol: Box<ClientProxyConfig>,
}

impl XhttpClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        validate_path_and_host(&self.path, self.host.as_deref())?;
        self.limits.validate()?;
        if self.x_padding_bytes.bounds((100, 1000), false)?.1 > 65536 {
            return Err(invalid("XHTTP padding must not exceed 65536 bytes"));
        }
        let (min, _) = self
            .sc_max_each_post_bytes
            .bounds((1_000_000, 1_000_000), false)?;
        self.sc_min_posts_interval_ms.bounds((30, 30), false)?;
        if min == 0
            || self.pool.max_connections == 0
            || self.pool.max_h1_connections == 0
            || self.pool.max_h1_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.pool.idle_timeout_secs == 0
        {
            return Err(invalid(
                "XHTTP packet size and pool limits must be positive",
            ));
        }
        if self.protocol.is_direct() {
            return Err(invalid("direct cannot be an XHTTP inner protocol"));
        }
        for (name, value) in &self.headers {
            let name = http::HeaderName::try_from(name).map_err(io::Error::other)?;
            http::HeaderValue::try_from(value).map_err(io::Error::other)?;
            if matches!(
                name.as_str(),
                "host"
                    | "keep-alive"
                    | "proxy-connection"
                    | "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "upgrade"
                    | "te"
                    | "trailer"
                    | "referer"
            ) {
                return Err(invalid(
                    "XHTTP custom header conflicts with transport framing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpServerConfig {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub mode: XhttpMode,
    #[serde(default)]
    pub http_version: XhttpVersion,
    #[serde(default)]
    pub x_padding_bytes: XhttpRange,
    #[serde(default)]
    pub sc_max_each_post_bytes: XhttpRange,
    #[serde(default)]
    pub sc_max_buffered_posts: usize,
    #[serde(default)]
    pub sc_stream_up_server_secs: XhttpRange,
    #[serde(default)]
    pub server_max_header_bytes: usize,
    #[serde(default)]
    pub no_sse_header: bool,
    #[serde(default)]
    pub limits: XhttpLimits,
    pub protocol: Box<ServerProxyConfig>,
}

impl XhttpServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        validate_path_and_host(&self.path, self.host.as_deref())?;
        if contains_server(&self.protocol) {
            return Err(invalid("nested XHTTP is not supported"));
        }
        self.limits.validate()?;
        if self.x_padding_bytes.bounds((100, 1000), false)?.1 > 65536 {
            return Err(invalid("XHTTP padding must not exceed 65536 bytes"));
        }
        let (min, max) = self
            .sc_max_each_post_bytes
            .bounds((1_000_000, 1_000_000), false)?;
        if min == 0 {
            return Err(invalid("XHTTP packet size must be positive"));
        }
        if matches!(self.mode, XhttpMode::Auto | XhttpMode::PacketUp)
            && max as usize > self.limits.max_session_buffered_bytes
        {
            return Err(invalid(
                "XHTTP maximum packet size exceeds the session byte budget",
            ));
        }
        self.sc_stream_up_server_secs.bounds((20, 80), true)?;
        Ok(())
    }

    pub(crate) fn tls_alpn(
        &self,
        protocols: &crate::option_util::NoneOrSome<String>,
    ) -> io::Result<Vec<String>> {
        let allowed: &[&str] = match self.http_version {
            XhttpVersion::Auto => &["h2", "http/1.1"],
            XhttpVersion::H1 => &["http/1.1"],
            XhttpVersion::H2 => &["h2"],
            XhttpVersion::H3 => return Err(invalid("H3 requires QUIC transport")),
        };
        if protocols.is_unspecified() {
            return Ok(allowed
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect());
        }
        let protocols = protocols.clone().into_vec();
        if protocols
            .iter()
            .any(|protocol| !allowed.contains(&protocol.as_str()))
            || (protocols.is_empty() && self.http_version == XhttpVersion::H2)
        {
            return Err(invalid("XHTTP TLS ALPN conflicts with HTTP version"));
        }
        Ok(protocols)
    }
    pub fn header_limit(&self) -> usize {
        if self.server_max_header_bytes == 0 {
            8192
        } else {
            self.server_max_header_bytes
        }
    }
    pub fn buffered_posts(&self) -> usize {
        if self.sc_max_buffered_posts == 0 {
            30
        } else {
            self.sc_max_buffered_posts
        }
    }
}

pub(crate) fn contains_server(protocol: &ServerProxyConfig) -> bool {
    match protocol {
        ServerProxyConfig::Xhttp(_) => true,
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            tls_targets.values().any(|t| contains_server(&t.protocol))
                || default_tls_target
                    .as_ref()
                    .is_some_and(|t| contains_server(&t.protocol))
                || shadowtls_targets
                    .values()
                    .any(|t| contains_server(&t.protocol))
                || reality_targets
                    .values()
                    .any(|t| contains_server(&t.protocol))
        }
        ServerProxyConfig::Websocket { targets } => {
            targets.iter().any(|t| contains_server(&t.protocol))
        }
        _ => false,
    }
}

pub(crate) fn validate_server_transport(
    protocol: &ServerProxyConfig,
    transport: &super::Transport,
) -> io::Result<()> {
    match protocol {
        ServerProxyConfig::Xhttp(config) => {
            let quic = *transport == super::Transport::Quic;
            if (quic && !matches!(config.http_version, XhttpVersion::Auto | XhttpVersion::H3))
                || (!quic && config.http_version == XhttpVersion::H3)
            {
                return Err(invalid(
                    "XHTTP HTTP version does not match listener transport",
                ));
            }
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            ..
        } => {
            if *transport == super::Transport::Quic && contains_server(protocol) {
                return Err(invalid("QUIC XHTTP must be a top-level protocol"));
            }
            for target in tls_targets.values() {
                if let ServerProxyConfig::Xhttp(config) = &target.protocol {
                    config.tls_alpn(&target.alpn_protocols)?;
                }
                validate_server_transport(&target.protocol, transport)?;
            }
            if let Some(target) = default_tls_target {
                if let ServerProxyConfig::Xhttp(config) = &target.protocol {
                    config.tls_alpn(&target.alpn_protocols)?;
                }
                validate_server_transport(&target.protocol, transport)?;
            }
            for target in shadowtls_targets.values() {
                if contains_server(&target.protocol) {
                    return Err(invalid("ShadowTLS cannot wrap XHTTP"));
                }
                validate_server_transport(&target.protocol, transport)?;
            }
            for target in reality_targets.values() {
                if let ServerProxyConfig::Xhttp(config) = &target.protocol
                    && !matches!(config.http_version, XhttpVersion::Auto | XhttpVersion::H2)
                {
                    return Err(invalid("REALITY XHTTP requires H2"));
                }
                validate_server_transport(&target.protocol, transport)?;
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            if contains_server(protocol) {
                return Err(invalid("WebSocket cannot wrap XHTTP"));
            }
            for target in targets.iter() {
                validate_server_transport(&target.protocol, transport)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhttp_rejects_invalid_wire_settings_before_startup() {
        for (path, host) in [
            ("/?bad=\n", "front.test"),
            ("/", "https://front.test"),
            ("/", "::1"),
        ] {
            let value =
                serde_json::json!({"path": path, "host": host, "protocol": {"type": "socks"}});
            assert!(
                serde_json::from_value::<XhttpClientConfig>(value.clone())
                    .unwrap()
                    .validate()
                    .is_err()
            );
            assert!(
                serde_json::from_value::<XhttpServerConfig>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let xhttp = serde_json::json!({"type": "xhttp", "http_version": "h1", "protocol": {"type": "socks"}});
        for protocol in [
            serde_json::json!({"type": "tls", "default_target": {"cert": "unused", "key": "unused", "alpn_protocols": ["h2"], "protocol": xhttp}}),
            serde_json::json!({"type": "tls", "shadowtls_targets": {"front.test": {"password": "unused", "handshake": {"address": "example.com:443"}, "protocol": xhttp}}}),
            serde_json::json!({"type": "tls", "reality_targets": {"front.test": {"private_key": "unused", "dest": "example.com:443", "protocol": xhttp}}}),
        ] {
            let config = serde_json::from_value(protocol).unwrap();
            assert!(validate_server_transport(&config, &super::super::Transport::Tcp).is_err());
        }
    }
    #[test]
    fn xhttp_range_defaults_and_sentinels() {
        let limits: XhttpLimits = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(limits.packet_timeout_secs, 300);
        assert_eq!(limits.setup_timeout_secs, 60);
        assert_eq!(limits.response_header_timeout_secs, 60);
        assert_eq!(
            XhttpRange::Number(0).bounds((100, 1000), false).unwrap(),
            (100, 1000)
        );
        assert_eq!(
            XhttpRange::Number(-1).bounds((20, 80), true).unwrap(),
            (0, 0)
        );
        for value in ["2-1", "-2", "1-4294967296", "hello"] {
            assert!(
                XhttpRange::Range(value.into())
                    .bounds((1, 1), false)
                    .is_err()
            );
        }
    }
    #[test]
    fn xhttp_alias_and_strict_fields() {
        for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
            let value =
                serde_json::json!({"type":"splithttp", "mode":mode, "protocol":{"type":"socks"}});
            let config: ClientProxyConfig = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(config).unwrap()["type"], "xhttp");
            for field in [
                "download_settings",
                "xmux",
                "session_id",
                "x_padding_obfs_mode",
            ] {
                let mut bad = value.clone();
                bad[field] = serde_json::json!({});
                assert!(serde_json::from_value::<ClientProxyConfig>(bad).is_err());
            }
        }
    }
}
#[test]
fn server_packet_size_must_fit_the_session_budget() {
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        for (packet, fits) in [
            (serde_json::json!(32), true),
            (serde_json::json!(33), false),
            (serde_json::json!("16-32"), true),
            (serde_json::json!("16-33"), false),
            (serde_json::json!(0), false),
        ] {
            let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
                "mode": mode, "sc_max_each_post_bytes": packet,
                "limits": {"max_session_buffered_bytes": 32},
                "protocol": {"type": "socks"}
            }))
            .unwrap();
            assert_eq!(
                config.validate().is_ok(),
                fits || mode.starts_with("stream-")
            );
        }
    }
}
