use std::collections::{HashMap, HashSet};
use std::io;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub(super) const MAX_LINE: usize = 4096;
pub(super) const MAX_HTTP: usize = 32768;
pub(super) const MAX_HTTP_LINES: usize = 40;
pub(super) const AUTO_EARLY_DATA_HEADER: &str = "sec-websocket-protocol";
pub(super) const AUTO_MAX_EARLY_DATA: usize = 2048;

const REQUEST_LINE_OVERHEAD: usize = "GET ".len() + " HTTP/1.1".len();
// Conservative allowances for fixed handshake bytes and lines, not exact wire sizes.
const HANDSHAKE_BYTE_ALLOWANCE: usize = 256;
const HANDSHAKE_LINE_ALLOWANCE: usize = 7;

#[derive(Clone, Debug, Default)]
pub struct EarlyData {
    pub max: usize,
    pub header: Option<String>,
}

impl EarlyData {
    pub fn new(max: usize, header: Option<&str>) -> Self {
        Self {
            max,
            header: header
                .filter(|name| !name.is_empty())
                .map(str::to_ascii_lowercase),
        }
    }

    pub fn path_mode(&self) -> bool {
        self.max > 0 && self.header.is_none()
    }

    pub fn decode(&self, encoded: &str) -> io::Result<Vec<u8>> {
        if encoded.len() > encoded_len(self.max)? {
            return Err(invalid("WebSocket early data exceeds configured limit"));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| invalid("invalid WebSocket early data encoding"))?;
        if decoded.len() > self.max {
            return Err(invalid("WebSocket early data exceeds configured limit"));
        }
        Ok(decoded)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn encoded_len(size: usize) -> io::Result<usize> {
    size.checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .map(|n| n / 3)
        .ok_or_else(|| invalid("WebSocket early data limit is too large"))
}

fn is_handshake_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "upgrade"
            | "content-length"
            | "transfer-encoding"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-accept"
            | "sec-websocket-extensions"
    )
}

pub(crate) fn validate_early_data(
    path: Option<&str>,
    headers: Option<&HashMap<String, String>>,
    max: usize,
    header: Option<&str>,
    server: bool,
) -> io::Result<()> {
    let early = EarlyData::new(max, header);
    if max == 0 {
        if early.header.is_some() {
            return Err(invalid(
                "early_data_header_name requires max_early_data > 0",
            ));
        }
        return Ok(());
    }
    if server && path.is_none() && early.path_mode() {
        return Err(invalid("WebSocket path early data requires matching_path"));
    }
    let path = path.unwrap_or("/");
    if !path.starts_with('/')
        || !path.is_ascii()
        || path.bytes().any(|b| b.is_ascii_control() || b == b' ')
        || path.contains('#')
    {
        return Err(invalid("invalid WebSocket matching_path"));
    }
    if early.path_mode() && path.contains('?') {
        return Err(invalid(
            "WebSocket path early data does not support query strings",
        ));
    }
    if let Some(header) = &early.header {
        http::header::HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| invalid("invalid early_data_header_name"))?;
        if header == "host" || is_handshake_header(header) {
            return Err(invalid("reserved WebSocket early data header"));
        }
    }
    let encoded = encoded_len(max)?;
    let request_line_len = path.len() + REQUEST_LINE_OVERHEAD;
    let carrier_line_len = early
        .header
        .as_ref()
        .map_or(request_line_len, |name| name.len() + 2);
    if encoded >= MAX_LINE || carrier_line_len >= MAX_LINE - encoded || request_line_len >= MAX_LINE
    {
        return Err(invalid(
            "WebSocket early data limit exceeds HTTP line budget",
        ));
    }
    let mut names = HashSet::new();
    let mut total = request_line_len
        + encoded
        + early.header.as_ref().map_or(0, |name| name.len() + 4)
        + HANDSHAKE_BYTE_ALLOWANCE;
    let mut host = false;
    for (name, value) in headers.into_iter().flatten() {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("invalid WebSocket matching header name"))?;
        http::HeaderValue::from_str(value)
            .map_err(|_| invalid("invalid WebSocket matching header value"))?;
        if !names.insert(name.clone()) || early.header.as_deref() == Some(name.as_str()) {
            return Err(invalid("duplicate or conflicting WebSocket header"));
        }
        if !server && is_handshake_header(name.as_str()) {
            return Err(invalid(
                "matching_headers conflicts with WebSocket handshake",
            ));
        }
        if name == http::header::HOST {
            let authority = value
                .parse::<http::uri::Authority>()
                .map_err(|_| invalid("invalid WebSocket Host authority"))?;
            if authority.host().is_empty() || value.contains('@') {
                return Err(invalid("invalid WebSocket Host authority"));
            }
            host = true;
        }
        if name.as_str().len() + value.len() + 2 >= MAX_LINE {
            return Err(invalid(
                "WebSocket matching header exceeds HTTP line budget",
            ));
        }
        total += name.as_str().len() + value.len() + 4;
    }
    if total > MAX_HTTP || names.len() + HANDSHAKE_LINE_ALLOWANCE >= MAX_HTTP_LINES {
        return Err(invalid("WebSocket matching headers exceed HTTP budget"));
    }
    if !server && !host {
        return Err(invalid(
            "WebSocket early data requires matching_headers.Host",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_ambiguous_unsafe_or_unrepresentable_options() {
        let host = HashMap::from_iter([("Host".into(), "example.test:443".into())]);
        for header in [
            None,
            Some(""),
            Some("X-Early"),
            Some("Sec-WebSocket-Protocol"),
        ] {
            assert!(validate_early_data(Some("/ws"), Some(&host), 2048, header, false).is_ok());
            assert!(validate_early_data(Some("/ws"), None, 2048, header, true).is_ok());
        }
        assert!(validate_early_data(None, None, 0, None, false).is_ok());
        assert!(validate_early_data(None, None, 0, Some(""), false).is_ok());
        assert!(validate_early_data(None, None, 0, Some("X-Early"), false).is_err());
        assert!(validate_early_data(None, None, 32, None, true).is_err());
        assert!(validate_early_data(Some("/ws"), None, 32, None, false).is_err());
        for max in [4096, usize::MAX] {
            assert!(validate_early_data(Some("/ws"), Some(&host), max, None, false).is_err());
        }
        for path in ["", "ws", "/ws?ed=32", "/ws#x", "/ws\r\nX: y", "/ws space"] {
            assert!(
                validate_early_data(Some(path), Some(&host), 32, None, false).is_err(),
                "{path}"
            );
        }
        for header in [
            "Host",
            "Connection",
            "Upgrade",
            "Content-Length",
            "Transfer-Encoding",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Accept",
            "Sec-WebSocket-Extensions",
            "bad name",
            "bad\r\nname",
        ] {
            assert!(
                validate_early_data(Some("/ws"), Some(&host), 32, Some(header), false).is_err(),
                "{header}"
            );
        }
        for (name, value) in [
            ("HOST", "duplicate"),
            ("X-Early", "conflict"),
            ("Upgrade", "duplicate"),
            ("X-Test", "bad\r\nvalue"),
        ] {
            let mut headers = host.clone();
            headers.insert(name.into(), value.into());
            assert!(
                validate_early_data(Some("/ws"), Some(&headers), 32, Some("x-early"), false)
                    .is_err()
            );
        }
        for authority in ["", "http://example.test", "user@example.test", "a b"] {
            let headers = HashMap::from_iter([("Host".into(), authority.into())]);
            assert!(
                validate_early_data(Some("/ws"), Some(&headers), 32, None, false).is_err(),
                "{authority}"
            );
        }
        let long_path = format!("/{}", "a".repeat(4000));
        assert!(validate_early_data(Some(&long_path), Some(&host), 100, None, false).is_err());
        let many_headers = HashMap::from_iter((0..35).map(|i| (format!("X-{i}"), "x".into())));
        assert!(validate_early_data(Some("/ws"), Some(&many_headers), 32, None, true).is_err());
        let large_headers =
            HashMap::from_iter((0..10).map(|i| (format!("X-{i}"), "x".repeat(3500))));
        assert!(validate_early_data(Some("/ws"), Some(&large_headers), 32, None, true).is_err());
    }

    #[test]
    fn handshake_headers_are_reserved_carriers_but_allowed_server_filters() {
        let host_error =
            validate_early_data(Some("/ws"), None, 32, Some("Host"), true).unwrap_err();
        assert_eq!(
            host_error.to_string(),
            "reserved WebSocket early data header"
        );

        for name in [
            "Connection",
            "Upgrade",
            "Content-Length",
            "Transfer-Encoding",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Accept",
            "Sec-WebSocket-Extensions",
        ] {
            let mut headers = HashMap::from_iter([("Host".into(), "example.test".into())]);
            let carrier_error =
                validate_early_data(Some("/ws"), Some(&headers), 32, Some(name), false)
                    .unwrap_err();
            assert_eq!(
                carrier_error.to_string(),
                "reserved WebSocket early data header"
            );

            headers.insert(name.into(), "value".into());
            let client_error =
                validate_early_data(Some("/ws"), Some(&headers), 32, Some("X-Early"), false)
                    .unwrap_err();
            assert_eq!(
                client_error.to_string(),
                "matching_headers conflicts with WebSocket handshake"
            );
            assert!(
                validate_early_data(Some("/ws"), Some(&headers), 32, Some("X-Early"), true).is_ok()
            );
        }
    }

    #[test]
    fn path_carrier_limit_preserves_the_exclusive_line_budget() {
        let host = HashMap::from_iter([("Host".into(), "example.test".into())]);
        assert!(validate_early_data(Some("/ws"), Some(&host), 3059, None, false).is_ok());
        let error = validate_early_data(Some("/ws"), Some(&host), 3060, None, false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "WebSocket early data limit exceeds HTTP line budget"
        );
    }

    #[test]
    fn config_fields_round_trip_and_defaults_are_omitted() {
        for enabled in [false, true] {
            let mut value = serde_json::json!({"type":"ws", "protocol":{"type":"socks"}});
            if enabled {
                value["max_early_data"] = 2048.into();
                value["early_data_header_name"] = "Sec-WebSocket-Protocol".into();
            }
            let config: crate::config::ClientProxyConfig = serde_json::from_value(value).unwrap();
            let serialized = serde_json::to_value(config).unwrap();
            assert_eq!(serialized.get("max_early_data").is_some(), enabled);
            assert_eq!(serialized.get("early_data_header_name").is_some(), enabled);
            let config: crate::config::WebsocketServerConfig =
                serde_json::from_value(serialized).unwrap();
            assert_eq!(config.max_early_data, if enabled { 2048 } else { 0 });
            assert_eq!(
                serde_json::to_value(config)
                    .unwrap()
                    .get("max_early_data")
                    .is_some(),
                enabled
            );
        }
    }
}
