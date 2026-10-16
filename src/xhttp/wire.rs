use std::io;

use base64::Engine;
use http::{HeaderMap, Method, Request, StatusCode};
use subtle::ConstantTimeEq;

use crate::config::xhttp::{XhttpClientConfig, XhttpMode, XhttpServerConfig};

const PATH_ESCAPE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b',')
    .remove(b':')
    .remove(b';')
    .remove(b'=')
    .remove(b'@');

#[derive(Clone, Debug)]
pub struct Path {
    pub base: String,
    query: String,
}

impl Path {
    pub fn new(value: &str) -> io::Result<Self> {
        let (path, query) = value.split_once('?').unwrap_or((value, ""));
        let mut base = path.to_owned();
        if !base.starts_with('/') {
            base.insert(0, '/');
        }
        if !base.ends_with('/') {
            base.push('/');
        }
        let path = Self {
            base,
            query: query.into(),
        };
        let _: http::uri::PathAndQuery =
            path.request("", None).parse().map_err(io::Error::other)?;
        Ok(path)
    }
    pub fn request(&self, session: &str, sequence: Option<u64>) -> String {
        let mut path = format!(
            "{}{session}",
            percent_encoding::utf8_percent_encode(&self.base, PATH_ESCAPE)
        );
        if let Some(sequence) = sequence {
            path.push_str(&format!("/{sequence}"));
        }
        if !self.query.is_empty() {
            path.push('?');
            path.push_str(&self.query);
        }
        path
    }
}

pub fn sample(range: (u32, u32)) -> u32 {
    rand::random_range(range.0..=range.1)
}

pub fn request(
    config: &XhttpClientConfig,
    path: &Path,
    authority: &str,
    secure: bool,
    session: &str,
    sequence: Option<u64>,
    upload: bool,
) -> io::Result<Request<()>> {
    let scheme = if secure { "https" } else { "http" };
    let uri = format!("{scheme}://{authority}{}", path.request(session, sequence));
    let mut request = Request::builder()
        .method(if upload { Method::POST } else { Method::GET })
        .uri(uri);
    for (name, value) in &config.headers {
        request = request.header(name, value);
    }
    let padding =
        "X".repeat(sample(config.x_padding_bytes.bounds((100, 1000), false)?).max(1) as usize);
    let base = percent_encoding::utf8_percent_encode(&path.base, PATH_ESCAPE);
    request = request.header(
        "referer",
        format!("{scheme}://{authority}{base}?x_padding={padding}"),
    );
    let mut request = request.body(()).map_err(io::Error::other)?;
    if upload && sequence.is_none() && !config.no_grpc_header {
        request.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
    }
    Ok(request)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    Options,
    One,
    Download(String),
    Upload(String),
    Packet(String, u64),
}

pub fn check_matching_headers(config: &XhttpServerConfig, headers: &HeaderMap) -> io::Result<()> {
    for (name, expected) in &config.matching_headers {
        let mut values = headers.get_all(name.as_str()).iter();
        let matches = values
            .next()
            .is_some_and(|value| bool::from(value.as_bytes().ct_eq(expected.as_bytes())))
            && values.next().is_none();
        if !matches {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "XHTTP request headers do not match",
            ));
        }
    }
    Ok(())
}

fn query_padding(query: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(name, _)| name == "x_padding")
        .map(|(_, value)| value.into_owned())
}

pub fn classify(
    config: &XhttpServerConfig,
    path: &Path,
    request: &Request<()>,
) -> Result<Kind, StatusCode> {
    if let Some(host) = config.host.as_ref().filter(|host| !host.is_empty()) {
        let actual = request
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| request.headers().get("host").and_then(|v| v.to_str().ok()))
            .unwrap_or("");
        let actual: http::uri::Authority = actual.parse().map_err(|_| StatusCode::NOT_FOUND)?;
        let host: http::uri::Authority = host.parse().map_err(|_| StatusCode::NOT_FOUND)?;
        if !actual.host().eq_ignore_ascii_case(host.host()) {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    let decoded_path = percent_encoding::percent_decode_str(request.uri().path())
        .decode_utf8()
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let suffix = decoded_path
        .strip_prefix(&path.base)
        .ok_or(StatusCode::NOT_FOUND)?;
    if request
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum::<usize>()
        > config.header_limit()
    {
        return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }
    if request.method() == Method::OPTIONS {
        return Ok(Kind::Options);
    }
    let padding = match request.headers().get("referer").filter(|v| !v.is_empty()) {
        Some(referer) => referer
            .to_str()
            .ok()
            .and_then(|v| url::Url::parse("http://localhost/").ok()?.join(v).ok())
            .and_then(|u| query_padding(u.query().unwrap_or(""))),
        None => query_padding(request.uri().query().unwrap_or("")),
    }
    .ok_or(StatusCode::BAD_REQUEST)?;
    let (min, max) = config
        .x_padding_bytes
        .bounds((100, 1000), false)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if padding.is_empty() || padding.len() < min as usize || padding.len() > max as usize {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut segments = suffix.split('/');
    let session = segments.next().unwrap_or("");
    let sequence = segments.next().unwrap_or("");
    if session.len() > 256
        || session
            .bytes()
            .any(|c| !c.is_ascii_alphanumeric() && c != b'-' && c != b'_')
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mode = config.mode;
    let auto = mode == XhttpMode::Auto;
    if session.is_empty() {
        if request.method() != Method::POST
            || !(auto || matches!(mode, XhttpMode::StreamOne | XhttpMode::StreamUp))
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(Kind::One);
    }
    if !sequence.is_empty() {
        if !(auto || mode == XhttpMode::PacketUp) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !matches!(*request.method(), Method::POST | Method::GET) {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !sequence.bytes().all(|c| c.is_ascii_digit()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(Kind::Packet(
            session.into(),
            sequence.parse().map_err(|_| StatusCode::BAD_REQUEST)?,
        ));
    }
    if request.method() == Method::GET && mode != XhttpMode::StreamOne {
        return Ok(Kind::Download(session.into()));
    }
    if request.method() == Method::POST && (auto || mode == XhttpMode::StreamUp) {
        return Ok(Kind::Upload(session.into()));
    }
    Err(StatusCode::BAD_REQUEST)
}

pub fn header_payload(headers: &HeaderMap) -> io::Result<Vec<u8>> {
    let mut header_data = String::new();
    for i in 0..headers.len() {
        let Some(value) = headers.get(format!("x-data-{i}")) else {
            break;
        };
        let value = value.to_str().map_err(io::Error::other)?;
        if value.is_empty() {
            break;
        }
        header_data.push_str(value);
    }
    let cookies: Vec<_> = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .collect();
    let mut cookie_data = String::new();
    for i in 0..cookies.len() {
        let name = format!("X-Data_{i}");
        let Some((_, value)) = cookies.iter().find(|(key, _)| *key == name) else {
            break;
        };
        cookie_data.push_str(value.trim_matches('"'));
    }
    let mut decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_data)
        .map_err(io::Error::other)?;
    decoded.extend(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cookie_data)
            .map_err(io::Error::other)?,
    );
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_uses_decoded_paths() {
        let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
            "path": "/t", "host": "front.test", "protocol": {"type": "socks"}
        }))
        .unwrap();
        let path = Path::new(&config.path).unwrap();
        for (uri, matched) in [
            ("/wrong", false),
            ("/t", false),
            ("/tother/", false),
            ("/t/%FF", false),
            ("/t/", true),
            ("/t/session", true),
            ("/%74/session", true),
            ("/t/?next=/wrong", true),
        ] {
            let request = Request::builder()
                .method("OPTIONS")
                .uri(format!("http://front.test{uri}"))
                .body(())
                .unwrap();
            assert_eq!(classify(&config, &path, &request).is_ok(), matched);
        }
        for (uri, status) in [
            ("http://front.test/t/session", StatusCode::BAD_REQUEST),
            ("http://wrong.test/t/session", StatusCode::NOT_FOUND),
        ] {
            let request = Request::get(uri).body(()).unwrap();
            assert_eq!(classify(&config, &path, &request), Err(status));
        }
    }

    #[test]
    fn matching_headers_require_one_exact_value_per_name() {
        let mut config: XhttpServerConfig = serde_json::from_value(serde_json::json!({
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        assert!(check_matching_headers(&config, &HeaderMap::new()).is_ok());
        config
            .matching_headers
            .insert("X-Token".into(), "Secret".into());
        config
            .matching_headers
            .insert("X-Empty".into(), String::new());
        config.validate().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("x-token", "Secret".parse().unwrap());
        assert!(check_matching_headers(&config, &headers).is_err());
        headers.insert("x-empty", "".parse().unwrap());
        headers.insert("x-extra", "allowed".parse().unwrap());
        assert!(check_matching_headers(&config, &headers).is_ok());
        for values in [
            vec![],
            vec![""],
            vec!["secret"],
            vec!["Secret "],
            vec!["Secret, Secret"],
            vec!["Secret", "Secret"],
            vec!["Secret", "wrong"],
            vec!["wrong", "Secret"],
        ] {
            headers.remove("x-token");
            for value in values {
                headers.append("x-token", value.parse().unwrap());
            }
            assert_eq!(
                check_matching_headers(&config, &headers)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn padding_acceptance_range_does_not_override_request_header_limit() {
        let mut server: XhttpServerConfig = serde_json::from_value(serde_json::json!({
            "host": "front.test", "path": "/upload", "x_padding_bytes": "100-20000",
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        server.validate().unwrap();
        let path = Path::new(&server.path).unwrap();
        for padding in [100, 20000] {
            let client: XhttpClientConfig = serde_json::from_value(serde_json::json!({
                "x_padding_bytes": padding, "protocol": {"type": "socks"}
            }))
            .unwrap();
            let request = request(&client, &path, "front.test", true, "id", None, false).unwrap();
            server.server_max_header_bytes = 0;
            assert_eq!(
                classify(&server, &path, &request),
                if padding == 100 {
                    Ok(Kind::Download("id".into()))
                } else {
                    Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
                }
            );
            server.server_max_header_bytes = 32768;
            assert_eq!(
                classify(&server, &path, &request),
                Ok(Kind::Download("id".into()))
            );
        }
    }

    #[test]
    fn default_wire_classification_and_rejections() {
        let config: XhttpServerConfig = serde_json::from_value(serde_json::json!({"path":"/a%2Fb?q=x", "host":"front.test", "protocol":{"type":"socks"}})).unwrap();
        let path = Path::new(&config.path).unwrap();
        let make = |method: &str, suffix: &str, padding: usize| {
            Request::builder()
                .method(method)
                .uri(format!("http://FRONT.test:8443/a%252Fb/{suffix}"))
                .header(
                    "referer",
                    format!("https://front.test/?x_padding={}", "X".repeat(padding)),
                )
                .body(())
                .unwrap()
        };
        for (method, suffix, expected) in [
            ("GET", "id", Kind::Download("id".into())),
            ("POST", "id", Kind::Upload("id".into())),
            ("POST", "", Kind::One),
            ("POST", "id/0/ignored", Kind::Packet("id".into(), 0)),
            ("GET", "id/1", Kind::Packet("id".into(), 1)),
        ] {
            assert_eq!(
                classify(&config, &path, &make(method, suffix, 100)),
                Ok(expected)
            );
        }
        for size in [0, 99, 1001] {
            assert_eq!(
                classify(&config, &path, &make("GET", "id", size)),
                Err(StatusCode::BAD_REQUEST)
            );
        }
        for seq in ["-1", "18446744073709551616", "abc"] {
            assert_eq!(
                classify(&config, &path, &make("POST", &format!("id/{seq}"), 100)),
                Err(StatusCode::BAD_REQUEST)
            );
        }
        let mut request = make("GET", "id", 100);
        *request.uri_mut() = "/a%252Fb/id?x_padding=short".parse().unwrap();
        request
            .headers_mut()
            .insert("host", "front.test:443".parse().unwrap());
        assert!(classify(&config, &path, &request).is_ok());
        request.headers_mut().remove("referer");
        assert_eq!(
            classify(&config, &path, &request),
            Err(StatusCode::BAD_REQUEST)
        );
        *request.method_mut() = Method::OPTIONS;
        assert_eq!(classify(&config, &path, &request), Ok(Kind::Options));
        request
            .headers_mut()
            .insert("host", "wrong.test".parse().unwrap());
        assert_eq!(
            classify(&config, &path, &request),
            Err(StatusCode::NOT_FOUND)
        );
    }
    #[test]
    fn path_query_and_escaping_preserved() {
        assert_eq!(
            Path::new("a%2Fb?q=a%2Bb")
                .unwrap()
                .request("session", Some(12)),
            "/a%252Fb/session/12?q=a%2Bb"
        );
    }
    #[test]
    fn referer_padding_replaces_query_and_accepts_relative_references() {
        let client: XhttpClientConfig = serde_json::from_value(serde_json::json!({
            "path": "/t?q=a%2Bb&x_padding=short",
            "x_padding_bytes": 100,
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        let server: XhttpServerConfig = serde_json::from_value(serde_json::json!({
            "path": client.path,
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        let path = Path::new(&client.path).unwrap();
        let mut request = request(&client, &path, "front.test", true, "id", None, false).unwrap();
        assert_eq!(request.uri().query(), Some("q=a%2Bb&x_padding=short"));
        assert_eq!(
            request.headers()["referer"],
            format!("https://front.test/t/?x_padding={}", "X".repeat(100))
        );
        for referer in [
            format!("/t/?x_padding={}", "X".repeat(100)),
            format!("?x_padding={}", "X".repeat(100)),
        ] {
            request
                .headers_mut()
                .insert("referer", referer.parse().unwrap());
            assert_eq!(
                classify(&server, &path, &request),
                Ok(Kind::Download("id".into()))
            );
        }
    }

    #[test]
    fn streaming_content_type_overrides_custom_header_unless_disabled() {
        let mut config: XhttpClientConfig = serde_json::from_value(serde_json::json!({
            "headers":{"Content-Type":"application/octet-stream"},
            "protocol":{"type":"socks"}
        }))
        .unwrap();
        let path = Path::new("").unwrap();
        for disabled in [false, true] {
            config.no_grpc_header = disabled;
            let request =
                request(&config, &path, "localhost", true, "session", None, true).unwrap();
            assert_eq!(request.headers().get_all("content-type").iter().count(), 1);
            assert_eq!(
                request.headers()["content-type"],
                if disabled {
                    "application/octet-stream"
                } else {
                    "application/grpc"
                }
            );
        }
    }
    #[test]
    fn default_payload_concatenates_header_and_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert("x-data-0", "YWJj".parse().unwrap());
        headers.insert("cookie", "X-Data_0=ZGVm".parse().unwrap());
        assert_eq!(header_payload(&headers).unwrap(), b"abcdef");
        headers.insert("x-data-0", "**".parse().unwrap());
        assert!(header_payload(&headers).is_err());
    }
}
