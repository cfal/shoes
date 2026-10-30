use std::{
    collections::{BTreeMap, HashSet},
    io,
};

use serde::{Deserialize, Serialize};

use super::{ClientProxyConfig, GlobalLimits, ServerProxyConfig};
use crate::option_util::OneOrSome;

pub(crate) const MAX_PADDING_BYTES: u32 = 65536;

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

fn conflicts_with_framing(name: &http::HeaderName) -> bool {
    matches!(
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
    )
}

fn validate_header_names<'a>(
    field: &str,
    names: impl IntoIterator<Item = &'a String>,
) -> io::Result<()> {
    let mut seen = HashSet::new();
    for name in names {
        let name = http::HeaderName::try_from(name).map_err(io::Error::other)?;
        if name == http::header::HOST {
            return Err(invalid(&format!(
                "XHTTP {field} cannot include Host; use host instead"
            )));
        }
        if conflicts_with_framing(&name) {
            return Err(invalid(&format!(
                "XHTTP {field} cannot include transport framing headers"
            )));
        }
        if !seen.insert(name) {
            return Err(invalid(&format!(
                "XHTTP {field} cannot repeat a header name"
            )));
        }
    }
    Ok(())
}

fn validate_header_values<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a String>,
) -> io::Result<()> {
    for value in values {
        http::HeaderValue::try_from(value).map_err(io::Error::other)?;
        // HTTP/1 receivers strip edge whitespace and HTTP/2 and HTTP/3 forbid it,
        // so such a value never arrives as configured.
        if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
            return Err(invalid(&format!(
                "XHTTP {field} values cannot start or end with whitespace"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct XhttpLimits {
    pub max_sessions: Option<usize>,
    pub max_pending_sessions: Option<usize>,
    pub max_buffered_bytes: Option<usize>,
    pub max_session_buffered_bytes: Option<usize>,
    pub max_requests_per_connection: usize,
    pub max_requests_per_session: Option<usize>,
    pub max_requests: Option<usize>,
    pub h2_stream_window_bytes: usize,
    pub h2_connection_window_bytes: usize,
    pub setup_timeout_secs: u64,
    pub packet_timeout_secs: u64,
    pub response_header_timeout_secs: u64,
}

impl Default for XhttpLimits {
    fn default() -> Self {
        Self {
            max_sessions: None,
            max_pending_sessions: None,
            max_buffered_bytes: None,
            max_session_buffered_bytes: None,
            max_requests_per_connection: 250,
            max_requests_per_session: None,
            max_requests: None,
            h2_stream_window_bytes: 4 * 1024 * 1024,
            h2_connection_window_bytes: 8 * 1024 * 1024,
            setup_timeout_secs: 60,
            packet_timeout_secs: 300,
            response_header_timeout_secs: 60,
        }
    }
}

impl XhttpLimits {
    pub(crate) fn session_byte_limit(&self) -> Option<usize> {
        // Packet admission needs bounded predecessor headroom when bytes are capped globally.
        self.max_session_buffered_bytes.or_else(|| {
            self.max_buffered_bytes
                .map(|limit| limit.min(4 * 1024 * 1024))
        })
    }

    pub(crate) fn session_request_limit(&self) -> Option<usize> {
        self.max_requests_per_session
            .or(self.max_requests.map(|_| 128))
    }

    pub(crate) fn h2_windows(&self) -> (u32, u32) {
        let stream_window = self
            .h2_stream_window_bytes
            .min(self.session_byte_limit().unwrap_or(usize::MAX))
            .min(self.max_buffered_bytes.unwrap_or(usize::MAX)) as u32;
        // HTTP/2 starts every connection with at least 65535 bytes of credit.
        let connection_window = self
            .h2_connection_window_bytes
            .min(self.max_buffered_bytes.unwrap_or(usize::MAX))
            .max(65535) as u32;
        (stream_window, connection_window)
    }

    pub(crate) fn request_limit(&self) -> usize {
        self.request_limit_with(crate::resources::limits())
    }

    pub(crate) fn request_limit_with(&self, global_limits: GlobalLimits) -> usize {
        global_limits
            .max_streams_per_connection
            .map_or(self.max_requests_per_connection, |limit| {
                self.max_requests_per_connection.min(limit)
            })
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.max_requests_per_session.is_some_and(|limit| limit < 2) {
            return Err(invalid("XHTTP session request limit must be at least 2"));
        }
        for (name, limit) in [
            ("max_sessions", self.max_sessions),
            ("max_pending_sessions", self.max_pending_sessions),
            ("max_buffered_bytes", self.max_buffered_bytes),
            (
                "max_session_buffered_bytes",
                self.max_session_buffered_bytes,
            ),
            ("max_requests", self.max_requests),
        ] {
            if limit == Some(0) {
                return Err(invalid(&format!(
                    "XHTTP limits.{name} must be positive; omit it for unlimited"
                )));
            }
        }
        if [
            self.max_requests_per_connection,
            self.h2_stream_window_bytes,
            self.h2_connection_window_bytes,
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
            || self.h2_stream_window_bytes > i32::MAX as usize
            || self.h2_connection_window_bytes > i32::MAX as usize
            || self.h2_connection_window_bytes < 65535
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
    #[serde(default = "default_download_idle_timeout_secs")]
    pub download_idle_timeout_secs: u64,
    #[serde(default = "default_packet_pipeline_depth")]
    pub packet_pipeline_depth: usize,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub limits: XhttpLimits,
    #[serde(default)]
    pub pool: XhttpPool,
    pub protocol: Box<ClientProxyConfig>,
}

fn default_download_idle_timeout_secs() -> u64 {
    15 * 60
}

fn default_packet_pipeline_depth() -> usize {
    30
}

impl XhttpClientConfig {
    pub fn validate(&self) -> io::Result<()> {
        validate_path_and_host(&self.path, self.host.as_deref())?;
        self.limits.validate()?;
        if self.download_idle_timeout_secs == 0 {
            return Err(invalid("XHTTP download idle timeout must be positive"));
        }
        if self.packet_pipeline_depth == 0 {
            return Err(invalid("XHTTP packet pipeline depth must be positive"));
        }
        if self.x_padding_bytes.bounds((100, 1000), false)?.1 > MAX_PADDING_BYTES {
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
        validate_header_names("headers", self.headers.keys())?;
        validate_header_values("headers", self.headers.values())?;
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
    pub matching_headers: BTreeMap<String, OneOrSome<String>>,
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
        validate_header_names("matching_headers", self.matching_headers.keys())?;
        validate_header_values(
            "matching_headers",
            self.matching_headers.values().flat_map(OneOrSome::iter),
        )?;
        if contains_server(&self.protocol) {
            return Err(invalid("nested XHTTP is not supported"));
        }
        self.limits.validate()?;
        if self.mode != XhttpMode::StreamOne
            && self.limits.max_requests.is_some_and(|limit| limit < 2)
        {
            return Err(invalid(
                "XHTTP split server modes require at least two aggregate requests",
            ));
        }
        if self.x_padding_bytes.bounds((100, 1000), false)?.1 > MAX_PADDING_BYTES {
            return Err(invalid("XHTTP padding must not exceed 65536 bytes"));
        }
        let (min, max) = self
            .sc_max_each_post_bytes
            .bounds((1_000_000, 1_000_000), false)?;
        if min == 0 {
            return Err(invalid("XHTTP packet size must be positive"));
        }
        if matches!(self.mode, XhttpMode::Auto | XhttpMode::PacketUp) {
            if self
                .limits
                .session_byte_limit()
                .is_some_and(|limit| max as usize > limit)
            {
                return Err(invalid(
                    "XHTTP maximum packet size exceeds the session byte budget",
                ));
            }
            if self
                .limits
                .max_buffered_bytes
                .is_some_and(|limit| max as usize > limit)
            {
                return Err(invalid(
                    "XHTTP maximum packet size exceeds the global byte budget",
                ));
            }
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
        ServerProxyConfig::SudokuMask(config) => contains_server(&config.protocol),
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
    crate::sudoku_mask::validate_server(protocol, transport)?;
    match protocol {
        ServerProxyConfig::SudokuMask(config) => {
            validate_server_transport(&config.protocol, transport)?
        }
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
            for target in tls_targets.values().chain(default_tls_target.as_deref()) {
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
    fn server_request_filters_defaults_and_round_trip() {
        let mut config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        assert!(config.matching_headers.is_empty());
        config
            .matching_headers
            .insert("X-Token".into(), "Secret".into());
        config.matching_headers.insert("X-Empty".into(), "".into());
        config.validate().unwrap();
        let encoded = serde_json::to_value(&config).unwrap();
        let decoded: XhttpServerConfig = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.matching_headers, config.matching_headers);
        decoded.validate().unwrap();
    }

    #[test]
    fn server_rejects_invalid_matching_headers() {
        for headers in [
            serde_json::json!({"bad name": "value"}),
            serde_json::json!({"": "value"}),
            serde_json::json!({":authority": "front.test"}),
            serde_json::json!({"x-token": "secret\r\nx-injected: value"}),
            serde_json::json!({"X-Token": "secret", "x-token": "secret"}),
            serde_json::json!({"Host": "front.test"}),
            serde_json::json!({"connection": "keep-alive"}),
            serde_json::json!({"Keep-Alive": "timeout=60"}),
            serde_json::json!({"proxy-connection": "keep-alive"}),
            serde_json::json!({"content-length": "16"}),
            serde_json::json!({"transfer-encoding": "chunked"}),
            serde_json::json!({"upgrade": "websocket"}),
            serde_json::json!({"te": "trailers"}),
            serde_json::json!({"trailer": "x-token"}),
            serde_json::json!({"referer": "https://front.test/"}),
            serde_json::json!({"x-token": " secret"}),
            serde_json::json!({"x-token": "secret "}),
            serde_json::json!({"x-token": "\tsecret"}),
            serde_json::json!({"x-token": "secret\t"}),
            serde_json::json!({"x-token": ["secret", "secret "]}),
            serde_json::json!({"x-token": ["secret", "a\r\nb"]}),
        ] {
            let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
                "matching_headers": headers, "protocol": {"type": "socks"}
            }))
            .unwrap();
            assert!(config.validate().is_err(), "{headers}");
        }
    }

    #[test]
    fn server_matching_headers_accept_value_lists() {
        let headers = serde_json::json!({"X-Single": "one", "X-Token": ["old", "new"]});
        let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
            "matching_headers": headers, "protocol": {"type": "socks"}
        }))
        .unwrap();
        config.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&config).unwrap()["matching_headers"],
            headers
        );
        assert!(
            serde_json::from_value::<XhttpServerConfig>(serde_json::json!({
                "matching_headers": {"X-Token": []}, "protocol": {"type": "socks"}
            }))
            .is_err()
        );
    }

    #[test]
    fn client_rejects_invalid_headers() {
        for (headers, valid) in [
            (serde_json::json!({"X-Token": "a", "X-Other": "a"}), true),
            (serde_json::json!({"X-Token": "a", "x-token": "b"}), false),
            (serde_json::json!({"X-Token": "a", "X-TOKEN": "a"}), false),
            (serde_json::json!({"bad name": "value"}), false),
            (serde_json::json!({"x-token": "a\r\nx-injected: b"}), false),
            (serde_json::json!({"Host": "front.test"}), false),
            (serde_json::json!({"Connection": "keep-alive"}), false),
            (serde_json::json!({"x-token": "a b\tc"}), true),
            (serde_json::json!({"x-token": " a"}), false),
            (serde_json::json!({"x-token": "a "}), false),
            (serde_json::json!({"x-token": "\ta"}), false),
            (serde_json::json!({"x-token": "a\t"}), false),
        ] {
            let config: XhttpClientConfig = serde_json::from_value(serde_json::json!({
                "headers": headers, "protocol": {"type": "socks"}
            }))
            .unwrap();
            assert_eq!(config.validate().is_ok(), valid, "{headers}");
        }
    }

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
        assert_eq!(limits.max_requests_per_session, None);
        for limit in [0, 1, 2] {
            let limits = XhttpLimits {
                max_requests_per_session: Some(limit),
                ..limits.clone()
            };
            assert_eq!(limits.validate().is_ok(), limit >= 2);
        }
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
    fn xhttp_admission_caps_are_opt_in() {
        let fields = [
            "max_sessions",
            "max_pending_sessions",
            "max_requests",
            "max_requests_per_session",
            "max_buffered_bytes",
            "max_session_buffered_bytes",
        ];
        let mut unlimited = serde_json::json!({});
        for field in fields {
            unlimited[field] = serde_json::Value::Null;
            for value in [0, 1, 2, 8192] {
                let mut input = serde_json::json!({});
                input[field] = value.into();
                let limits: XhttpLimits = serde_json::from_value(input).unwrap();
                assert_eq!(
                    limits.validate().is_ok(),
                    value
                        >= if field == "max_requests_per_session" {
                            2
                        } else {
                            1
                        },
                    "{field}={value}"
                );
                assert_eq!(serde_json::to_value(limits).unwrap()[field], value);
            }
        }
        for input in [serde_json::json!({}), unlimited] {
            let limits: XhttpLimits = serde_json::from_value(input.clone()).unwrap();
            limits.validate().unwrap();
            assert_eq!(limits.max_requests_per_connection, 250);
            assert_eq!(limits.request_limit_with(GlobalLimits::default()), 250);
            let serialized = serde_json::to_value(limits).unwrap();
            for field in fields {
                assert!(serialized[field].is_null(), "{field}");
            }
            let config = serde_json::json!({
                "limits": input,
                "sc_max_each_post_bytes": 8 * 1024 * 1024,
                "protocol": {"type": "socks"}
            });
            serde_json::from_value::<XhttpClientConfig>(config.clone())
                .unwrap()
                .validate()
                .unwrap();
            serde_json::from_value::<XhttpServerConfig>(config)
                .unwrap()
                .validate()
                .unwrap();
        }
        assert_eq!(
            XhttpLimits::default().request_limit_with(GlobalLimits {
                max_streams_per_connection: Some(10),
                ..GlobalLimits::default()
            }),
            10
        );
    }

    #[test]
    fn client_validates_session_request_limits() {
        for limit in [0, 1, 2, 5, 128, 129] {
            let config: XhttpClientConfig = serde_json::from_value(serde_json::json!({
                "limits": {"max_requests_per_session": limit},
                "protocol": {"type": "socks"}
            }))
            .unwrap();
            assert_eq!(config.validate().is_ok(), limit >= 2);
        }
    }

    #[test]
    fn server_aggregate_requests_must_fit_the_mode() {
        for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
            for limit in [0, 1, 2, 4096] {
                let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
                    "mode": mode,
                    "limits": {"max_requests": limit},
                    "protocol": {"type": "socks"}
                }))
                .unwrap();
                assert_eq!(
                    config.validate().is_ok(),
                    limit >= 2 || (mode == "stream-one" && limit == 1),
                    "mode={mode}, max_requests={limit}"
                );
            }
        }
    }

    #[test]
    fn client_download_idle_timeout_defaults_and_validation() {
        let mut config: XhttpClientConfig = serde_json::from_value(serde_json::json!({
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        assert_eq!(config.download_idle_timeout_secs, 900);
        assert_eq!(config.packet_pipeline_depth, 30);
        config.packet_pipeline_depth = 0;
        assert!(config.validate().is_err());
        config.packet_pipeline_depth = 30;
        for seconds in [0, 1, 900, 1800] {
            config.download_idle_timeout_secs = seconds;
            let decoded: XhttpClientConfig =
                serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
            assert_eq!(decoded.download_idle_timeout_secs, seconds);
            assert_eq!(decoded.validate().is_ok(), seconds > 0);
        }
    }

    #[test]
    fn aggregate_caps_derive_session_safeguards() {
        let mut limits = XhttpLimits::default();
        assert_eq!(limits.session_byte_limit(), None);
        assert_eq!(limits.session_request_limit(), None);
        for (global, expected) in [(48, 48), (8 * 1024 * 1024, 4 * 1024 * 1024)] {
            limits.max_buffered_bytes = Some(global);
            assert_eq!(limits.session_byte_limit(), Some(expected));
        }
        for global in [1, 2, 16, 4096] {
            limits.max_requests = Some(global);
            assert_eq!(limits.session_request_limit(), Some(128));
        }
        limits.max_session_buffered_bytes = Some(16 * 1024 * 1024);
        limits.max_requests_per_session = Some(256);
        assert_eq!(limits.session_byte_limit(), Some(16 * 1024 * 1024));
        assert_eq!(limits.session_request_limit(), Some(256));
        for session_limit in [None, Some(8 * 1024 * 1024)] {
            let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
                "sc_max_each_post_bytes": 8 * 1024 * 1024,
                "limits": {"max_buffered_bytes": 16 * 1024 * 1024,
                    "max_session_buffered_bytes": session_limit},
                "protocol": {"type": "socks"}
            }))
            .unwrap();
            assert_eq!(config.validate().is_ok(), session_limit.is_some());
        }
    }

    #[test]
    fn h2_windows_follow_byte_limits_and_protocol_bounds() {
        let mut limits = XhttpLimits::default();
        assert_eq!(limits.h2_windows(), (4 * 1024 * 1024, 8 * 1024 * 1024));
        limits.max_session_buffered_bytes = Some(16384);
        limits.max_buffered_bytes = Some(32768);
        assert_eq!(limits.h2_windows(), (16384, 65535));
        limits.h2_stream_window_bytes = 8192;
        assert_eq!(limits.h2_windows().0, 8192);
        limits.h2_stream_window_bytes = 4 * 1024 * 1024;
        limits.max_session_buffered_bytes = None;
        assert_eq!(limits.h2_windows(), (32768, 65535));
        limits.max_session_buffered_bytes = Some(16384);
        limits.max_buffered_bytes = None;
        assert_eq!(limits.h2_windows(), (16384, 8 * 1024 * 1024));
        limits.h2_connection_window_bytes = i32::MAX as usize + 1;
        assert!(limits.validate().is_err());
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
fn server_packet_size_must_fit_both_byte_budgets() {
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        for (packet, fits) in [
            (serde_json::json!(32), true),
            (serde_json::json!(33), false),
            (serde_json::json!("16-32"), true),
            (serde_json::json!("16-33"), false),
            (serde_json::json!(0), false),
        ] {
            for (session, global) in [
                (Some(32), Some(64)),
                (Some(64), Some(32)),
                (Some(32), Some(32)),
                (Some(32), None),
                (None, Some(32)),
                (None, None),
            ] {
                let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
                    "mode": mode, "sc_max_each_post_bytes": packet,
                    "limits": {
                        "max_session_buffered_bytes": session,
                        "max_buffered_bytes": global
                    },
                    "protocol": {"type": "socks"}
                }))
                .unwrap();
                assert_eq!(
                    config.validate().is_ok(),
                    fits || mode.starts_with("stream-") || (session.is_none() && global.is_none()),
                    "mode={mode}, packet={packet}, session={session:?}, global={global:?}"
                );
            }
        }
    }
}
