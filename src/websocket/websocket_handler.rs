use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use super::early_data::{
    AUTO_EARLY_DATA_HEADER, AUTO_MAX_EARLY_DATA, EarlyData, MAX_HTTP, MAX_HTTP_LINES, MAX_LINE,
};
use super::early_stream::EarlyWebsocketStream;
use super::websocket_stream::WebsocketStream;
use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::config::WebsocketPingType;
use crate::prepend_stream::PrependStream;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    ClientTransport, TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub early_data: EarlyData,
    pub ping_type: WebsocketPingType,
    pub handler: Box<dyn TcpServerHandler>,
}

#[derive(Debug)]
pub struct WebsocketTcpServerHandler {
    server_targets: Vec<WebsocketServerTarget>,
}

impl WebsocketTcpServerHandler {
    pub fn new(server_targets: Vec<WebsocketServerTarget>) -> Self {
        Self { server_targets }
    }
}

async fn reject_upgrade(stream: &mut Box<dyn AsyncStream>, status: &str) -> std::io::Error {
    let version = if status.starts_with("426") {
        "Sec-WebSocket-Version: 13\r\n"
    } else {
        ""
    };
    let response =
        format!("HTTP/1.1 {status}\r\n{version}Content-Length: 0\r\nConnection: close\r\n\r\n");
    if let Err(error) = stream.write_all(response.as_bytes()).await {
        return error;
    }
    if let Err(error) = stream.flush().await {
        return error;
    }
    std::io::Error::new(std::io::ErrorKind::InvalidData, status.to_owned())
}

fn has_token(headers: &HashMap<String, String>, name: &str, token: &str) -> bool {
    headers.get(name).is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use crate::async_stream::test_streams::FlushGatedStream;
    use crate::client_proxy_selector::ClientProxySelector;
    use crate::resolver::NativeResolver;
    use crate::socks_handler::SocksTcpServerHandler;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn invalid_upgrades_receive_flushed_http_errors() {
        let valid = "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        for (request, status) in [
            (valid.replace("Upgrade: websocket\r\n", ""), "400"),
            (valid.replace("Connection: Upgrade\r\n", ""), "400"),
            (valid.replace("Host: example.com\r\n", ""), "400"),
            (valid.replace("Sec-WebSocket-Version: 13\r\n", ""), "400"),
            (valid.replace("Version: 13", "Version: 12"), "426"),
            (valid.replace("dGhlIHNhbXBsZSBub25jZQ==", "invalid"), "400"),
            (
                valid.replace("Host: example.com", "Host: example.com\r\nHost: other"),
                "400",
            ),
            (
                valid.replace("Connection: Upgrade", "Connection: keep-alive, uPgRaDe"),
                "404",
            ),
        ] {
            let (mut client, server) = tokio::io::duplex(2048);
            client.write_all(request.as_bytes()).await.unwrap();
            let result = WebsocketTcpServerHandler::new(vec![])
                .setup_server_stream(Box::new(FlushGatedStream::new(server)))
                .await;
            let error = result.err().unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                match status {
                    "400" => "400 Bad Request",
                    "426" => "426 Upgrade Required",
                    "404" => "404 Not Found",
                    _ => unreachable!(),
                }
            );
            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{response}"
            );
            assert_eq!(
                response.contains("Sec-WebSocket-Version: 13"),
                status == "426"
            );
        }
    }

    #[tokio::test]
    async fn rejection_reports_transport_errors_instead_of_protocol_errors() {
        for buffered in [false, true] {
            let (client, server) = tokio::io::duplex(2048);
            drop(client);
            let mut stream: Box<dyn AsyncStream> = if buffered {
                Box::new(FlushGatedStream::new(server))
            } else {
                Box::new(server)
            };
            let error = reject_upgrade(&mut stream, "400 Bad Request").await;
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
    }

    #[tokio::test]
    async fn outbound_host_defaults_to_authority_and_preserves_override() {
        for authority in ["example.com:80", "192.0.2.1:8080", "[2001:db8::1]:443"] {
            for override_host in [None, Some("front.example")] {
                let (client, peer) = tokio::io::duplex(2048);
                let headers = override_host
                    .map(|host| format!("matching_headers: {{hOsT: '{host}'}}\n"))
                    .unwrap_or_default();
                let config = serde_yaml::from_str(&format!(
                    "type: websocket\n{headers}protocol: {{type: noop}}\n"
                ))
                .unwrap();
                let handler = crate::tcp::tcp_client_handler_factory::create_tcp_client_handler(
                    config,
                    &crate::address::NetLocation::from_str(authority, None).unwrap(),
                    Arc::new(NativeResolver::new()),
                )
                .unwrap();
                let expected = override_host.unwrap_or(authority).to_owned();
                let check = async {
                    let mut io: Box<dyn AsyncStream> = Box::new(peer);
                    let parsed = ParsedHttpData::parse(&mut io).await.unwrap();
                    assert_eq!(parsed.headers.get("host"), Some(&expected));
                    io.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                        .await
                        .unwrap();
                };
                let (result, _) = tokio::join!(
                    handler.setup_client_tcp_stream(
                        Box::new(client),
                        crate::address::NetLocation::UNSPECIFIED.into()
                    ),
                    check
                );
                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn upgrade_response_is_flushed_before_inner_handshake() {
        let handler = WebsocketTcpServerHandler::new(vec![WebsocketServerTarget {
            early_data: EarlyData::default(),
            matching_path: None,
            matching_headers: None,
            ping_type: WebsocketPingType::Disabled,
            // SOCKS reads the client's greeting before writing anything.
            handler: Box::new(SocksTcpServerHandler::new(
                None,
                false,
                "0.0.0.0".parse().unwrap(),
                Arc::new(ClientProxySelector::new(vec![])),
                Arc::new(NativeResolver::new()),
            )),
        }]);
        let (mut client, server) = tokio::io::duplex(1024);
        let setup = tokio::spawn(async move {
            handler
                .setup_server_stream(Box::new(FlushGatedStream::new(server)))
                .await
        });

        let request = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: example.com\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "\r\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut status = [0; 12];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut status))
            .await
            .expect("upgrade response was not flushed")
            .unwrap();
        assert_eq!(&status, b"HTTP/1.1 101");
        setup.abort();
    }

    #[tokio::test]
    async fn malformed_request_targets_are_errors_not_panics() {
        for line in [
            "GET HTTP/1.1",
            "GET  HTTP/1.1",
            "GET / a HTTP/1.1",
            "POST / HTTP/1.1",
        ] {
            let (mut client, server) = tokio::io::duplex(256);
            client
                .write_all(format!("{line}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let result = WebsocketTcpServerHandler::new(vec![])
                .setup_server_stream(Box::new(server))
                .await;
            assert!(result.is_err(), "{line}");
        }
    }
}

#[async_trait]
impl TcpServerHandler for WebsocketTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedHttpData {
            first_line,
            headers: mut request_headers,
            stream_reader,
            duplicates,
        } = match ParsedHttpData::parse(&mut server_stream).await {
            Ok(parsed) => parsed,
            Err(_) => return Err(reject_upgrade(&mut server_stream, "400 Bad Request").await),
        };
        let request_path = first_line
            .strip_prefix("GET ")
            .and_then(|line| line.strip_suffix(" HTTP/1.1"))
            .filter(|path| path.starts_with('/') && !path.bytes().any(|b| b.is_ascii_whitespace()));
        let valid_host = request_headers.get("host").is_some_and(|host| {
            host.parse::<http::uri::Authority>()
                .is_ok_and(|authority| !authority.host().is_empty())
        });
        let websocket_key = request_headers
            .remove("sec-websocket-key")
            .unwrap_or_default();
        if request_path.is_none()
            || !valid_host
            || !has_token(&request_headers, "upgrade", "websocket")
            || !has_token(&request_headers, "connection", "upgrade")
            || !BASE64
                .decode(&websocket_key)
                .is_ok_and(|key| key.len() == 16)
        {
            return Err(reject_upgrade(&mut server_stream, "400 Bad Request").await);
        }
        match request_headers
            .get("sec-websocket-version")
            .map(String::as_str)
        {
            Some("13") => {}
            None | Some("") => {
                return Err(reject_upgrade(&mut server_stream, "400 Bad Request").await);
            }
            _ => return Err(reject_upgrade(&mut server_stream, "426 Upgrade Required").await),
        }
        let request_path = request_path.unwrap();

        let candidates: Vec<_> = self
            .server_targets
            .iter()
            .filter(|target| {
                let path_matches = match &target.matching_path {
                    Some(path) if target.early_data.path_mode() => request_path.starts_with(path),
                    Some(path) => path == request_path,
                    None => true,
                };
                path_matches
                    && target.matching_headers.as_ref().is_none_or(|headers| {
                        headers
                            .iter()
                            .all(|(key, value)| request_headers.get(key) == Some(value))
                    })
            })
            .collect();
        let Some(server_target) = candidates.first() else {
            return Err(reject_upgrade(&mut server_stream, "404 Not Found").await);
        };
        // Static subprotocol selectors retain their literal meaning, even for base64 tokens.
        let auto_early_data = server_target.early_data.max == 0
            && server_target
                .matching_headers
                .as_ref()
                .is_none_or(|headers| !headers.contains_key(AUTO_EARLY_DATA_HEADER))
            && (request_headers
                .get(AUTO_EARLY_DATA_HEADER)
                .is_some_and(|value| !value.is_empty())
                || duplicates.contains(AUTO_EARLY_DATA_HEADER));
        if candidates.len() > 1
            && (auto_early_data || candidates.iter().any(|target| target.early_data.max > 0))
        {
            return Err(std::io::Error::other(
                "ambiguous WebSocket early data target",
            ));
        }
        let WebsocketServerTarget {
            matching_path,
            early_data,
            ping_type,
            handler,
            ..
        } = server_target;
        let automatic = auto_early_data
            .then(|| EarlyData::new(AUTO_MAX_EARLY_DATA, Some(AUTO_EARLY_DATA_HEADER)));
        let early_data = automatic.as_ref().unwrap_or(early_data);

        let encoded = if early_data.max == 0 {
            ""
        } else if let Some(header) = &early_data.header {
            request_headers
                .get(header)
                .map(String::as_str)
                .unwrap_or("")
        } else {
            let path = matching_path.as_deref().ok_or_else(|| {
                std::io::Error::other("WebSocket path early data requires matching_path")
            })?;
            request_path
                .strip_prefix(path)
                .ok_or_else(|| std::io::Error::other("invalid WebSocket early data path"))?
        };
        if early_data.max > 0
            && duplicates.iter().any(|name| {
                early_data.header.as_ref() == Some(name)
                    || matches!(
                        name.as_str(),
                        "host"
                            | "connection"
                            | "upgrade"
                            | "sec-websocket-key"
                            | "sec-websocket-version"
                            | "content-length"
                            | "transfer-encoding"
                    )
                    || server_target
                        .matching_headers
                        .as_ref()
                        .is_some_and(|headers| headers.contains_key(name))
            })
        {
            return Err(std::io::Error::other(
                "duplicate WebSocket handshake header",
            ));
        }
        let prefix = early_data.decode(encoded)?;
        let protocol_response = if early_data.header.as_deref() == Some("sec-websocket-protocol")
            && !prefix.is_empty()
        {
            format!("Sec-WebSocket-Protocol: {encoded}\r\n")
        } else {
            String::new()
        };

        let websocket_key_response = create_websocket_key_response(websocket_key);

        let http_response = format!(
            concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: {}\r\n",
                "{}",
                "\r\n"
            ),
            websocket_key_response, protocol_response,
        );

        server_stream.write_all(http_response.as_bytes()).await?;
        // Clients wait for the 101 before sending frames, and inner handlers read first.
        server_stream.flush().await?;

        let websocket_stream = WebsocketStream::new(
            server_stream,
            false,
            ping_type.clone(),
            stream_reader.unparsed_data(),
        );
        let websocket_stream: Box<dyn AsyncStream> = if prefix.is_empty() {
            Box::new(websocket_stream)
        } else {
            Box::new(PrependStream::new(
                websocket_stream,
                Some(prefix.into_boxed_slice()),
            ))
        };

        let mut result = handler.setup_server_stream(websocket_stream).await?;
        result.set_need_initial_flush(true);
        Ok(result)
    }
}

#[derive(Debug)]
pub struct WebsocketTcpClientHandler {
    handshake: Arc<ClientHandshake>,
    handler: Box<dyn TcpClientHandler>,
}

#[derive(Clone, Debug)]
pub(super) struct ClientHandshake {
    authority: String,
    matching_path: Option<String>,
    matching_headers: Option<FxHashMap<String, String>>,
    pub ping_type: WebsocketPingType,
    pub early_data: EarlyData,
}

impl WebsocketTcpClientHandler {
    pub fn new(
        authority: String,
        matching_path: Option<String>,
        matching_headers: Option<FxHashMap<String, String>>,
        ping_type: WebsocketPingType,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            handshake: Arc::new(ClientHandshake {
                authority,
                matching_path,
                matching_headers,
                ping_type,
                early_data: EarlyData::default(),
            }),
            handler,
        }
    }

    pub fn with_early_data(mut self, max: usize, header: Option<&str>) -> Self {
        Arc::make_mut(&mut self.handshake).early_data = EarlyData::new(max, header);
        self
    }

    async fn setup_client_stream_common(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        if self.handshake.early_data.max > 0 {
            Ok(Box::new(EarlyWebsocketStream::new(
                client_stream,
                self.handshake.clone(),
            )))
        } else {
            Ok(Box::new(self.handshake.upgrade(client_stream, &[]).await?))
        }
    }
}

impl ClientHandshake {
    pub async fn upgrade(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        early: &[u8],
    ) -> std::io::Result<WebsocketStream> {
        let request_path = self.matching_path.as_deref().unwrap_or("/");
        let encoded = URL_SAFE_NO_PAD.encode(early);

        let websocket_key = create_websocket_key();
        let mut http_request = String::with_capacity(1024);
        http_request.push_str("GET ");
        http_request.push_str(request_path);
        if self.early_data.path_mode() {
            http_request.push_str(&encoded);
        }
        http_request.push_str(" HTTP/1.1\r\n");
        http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));

        if !self
            .matching_headers
            .as_ref()
            .is_some_and(|headers| headers.keys().any(|key| key.eq_ignore_ascii_case("host")))
        {
            http_request.push_str("Host: ");
            http_request.push_str(&self.authority);
            http_request.push_str("\r\n");
        }

        if let Some(ref headers) = self.matching_headers {
            for (header_key, header_val) in headers {
                http_request.push_str(header_key);
                http_request.push_str(": ");
                http_request.push_str(header_val);
                http_request.push_str("\r\n");
            }
        }
        if !encoded.is_empty()
            && let Some(header) = &self.early_data.header
        {
            http_request.push_str(header);
            http_request.push_str(": ");
            http_request.push_str(&encoded);
            http_request.push_str("\r\n");
        }

        http_request.push_str(concat!(
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: "
        ));
        http_request.push_str(&websocket_key);
        http_request.push_str("\r\n\r\n");

        client_stream.write_all(&http_request.into_bytes()).await?;
        client_stream.flush().await?;

        let ParsedHttpData {
            first_line,
            headers: response_headers,
            stream_reader,
            duplicates,
        } = ParsedHttpData::parse(&mut client_stream).await?;

        let mut status = first_line.split_whitespace();
        if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) || status.next() != Some("101") {
            return Err(std::io::Error::other("Bad websocket response status"));
        }
        if !has_token(&response_headers, "upgrade", "websocket") {
            return Err(std::io::Error::other(
                "missing or invalid WebSocket Upgrade header",
            ));
        }
        if !has_token(&response_headers, "connection", "upgrade") {
            return Err(std::io::Error::other(
                "missing or invalid WebSocket Connection header",
            ));
        }
        if duplicates.contains("sec-websocket-accept")
            || duplicates.contains("sec-websocket-protocol")
        {
            return Err(std::io::Error::other("duplicate WebSocket response header"));
        }
        if !encoded.is_empty()
            && self.early_data.header.as_deref() == Some("sec-websocket-protocol")
            && response_headers
                .get("sec-websocket-protocol")
                .is_some_and(|value| value != &encoded)
        {
            return Err(std::io::Error::other("unexpected WebSocket subprotocol"));
        }

        let websocket_key_response = response_headers
            .get("sec-websocket-accept")
            .ok_or_else(|| std::io::Error::other("missing websocket key response header"))?;

        let expected_key_response = create_websocket_key_response(websocket_key);
        if websocket_key_response != &expected_key_response {
            return Err(std::io::Error::other("incorrect websocket key response"));
        }

        Ok(WebsocketStream::new(
            client_stream,
            true,
            self.ping_type.clone(),
            stream_reader.unparsed_data(),
        ))
    }
}

#[async_trait]
impl TcpClientHandler for WebsocketTcpClientHandler {
    fn has_session_pool(&self) -> bool {
        self.handler.has_session_pool()
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let transport = transport.wrap(|stream| self.setup_client_stream_common(stream));
        self.handler.connect_client_tcp(transport, target).await
    }

    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let transport = transport.wrap(|stream| self.setup_client_stream_common(stream));
        self.handler.connect_client_udp(transport, target).await
    }

    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &std::sync::Arc<dyn crate::resolver::Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        self.handler.prepare_target(target, resolver).await
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let websocket_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(websocket_stream, remote_location)
            .await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.handler.supports_udp_over_tcp()
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let websocket_stream = self.setup_client_stream_common(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(websocket_stream, target)
            .await
    }
}

struct ParsedHttpData {
    first_line: String,
    headers: HashMap<String, String>,
    stream_reader: StreamReader,
    duplicates: HashSet<String>,
}

impl ParsedHttpData {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let mut first_line: Option<String> = None;
        // don't use FxHashMap for unvalidated user data
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut duplicates = HashSet::new();
        let mut total = 0;

        let mut line_count = 0;
        loop {
            let line = stream_reader.read_line(stream).await?;
            total += line.len() + 2;
            if total > MAX_HTTP {
                return Err(std::io::Error::other("http header block is too long"));
            }
            if line.is_empty() {
                break;
            }

            if line.len() >= MAX_LINE {
                return Err(std::io::Error::other("http request line is too long"));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let (name, value) = line
                    .split_once(':')
                    .ok_or_else(|| std::io::Error::other("invalid http header line"))?;
                let header_key = name.trim().to_lowercase();
                let header_value = value.trim().to_string();
                if let Some(previous) = headers.get_mut(&header_key) {
                    duplicates.insert(header_key.clone());
                    if matches!(
                        header_key.as_str(),
                        "host" | "sec-websocket-key" | "sec-websocket-version"
                    ) {
                        return Err(std::io::Error::other(
                            "duplicate WebSocket handshake header",
                        ));
                    }
                    previous.push_str(", ");
                    previous.push_str(&header_value);
                } else {
                    headers.insert(header_key, header_value);
                }
            }

            line_count += 1;
            if line_count >= MAX_HTTP_LINES {
                return Err(std::io::Error::other("http request is too long"));
            }
        }

        let first_line = first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            stream_reader,
            duplicates,
        })
    }
}

fn create_websocket_key() -> String {
    let key: [u8; 16] = rand::random();
    BASE64.encode(key)
}

fn create_websocket_key_response(key: String) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = key.into_bytes();
    input.extend_from_slice(WS_GUID);
    let hash = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64.encode(hash.as_ref())
}

#[cfg(test)]
#[path = "early_tests.rs"]
mod early_tests;
