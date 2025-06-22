use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use super::websocket_stream::WebsocketStream;
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::WebsocketPingType;
use crate::option_util::NoneOrOne;
use crate::stream_reader::StreamReader;
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

#[derive(Debug)]
pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub ping_type: WebsocketPingType,
    pub handler: Box<dyn TcpServerHandler>,
    pub override_proxy_provider: NoneOrOne<Arc<ClientProxySelector<TcpClientConnector>>>,
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

#[async_trait]
impl TcpServerHandler for WebsocketTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let ParsedHttpData {
            mut first_line,
            headers: mut request_headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut server_stream).await?;
        let request_path = {
            if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
                return Err(std::io::Error::other(
                    format!("invalid http request version: {}", first_line),
                ));
            }

            if !first_line.starts_with("GET ") {
                return Err(std::io::Error::other(
                    format!("invalid http request: {}", first_line),
                ));
            }

            // remove ' HTTP/1.x'
            first_line.truncate(first_line.len() - 9);

            // return the path after 'GET '
            first_line.split_off(4)
        };

        let websocket_key = request_headers.remove("sec-websocket-key").ok_or_else(|| {
            std::io::Error::other("missing websocket key header")
        })?;

        'outer: for server_target in self.server_targets.iter() {
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
                ping_type,
                handler,
                override_proxy_provider,
            } = server_target;

            if let Some(path) = matching_path {
                if path != &request_path {
                    continue;
                }
            }

            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers.get(header_key) != Some(header_val) {
                        continue 'outer;
                    }
                }
            }

            let websocket_key_response = create_websocket_key_response(websocket_key);

            let host_response_header = match request_headers.get("host") {
                Some(v) => format!("Host: {}\r\n", v),
                None => "".to_string(),
            };

            let websocket_version_response_header =
                match request_headers.get("sec-websocket_version") {
                    Some(v) => format!("Sec-WebSocket-Version: {}\r\n", v),
                    None => "".to_string(),
                };

            let http_response = format!(
                concat!(
                    "HTTP/1.1 101 Switching Protocol\r\n",
                    "{}",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "{}",
                    "Sec-WebSocket-Accept: {}\r\n",
                    "\r\n"
                ),
                host_response_header, websocket_version_response_header, websocket_key_response,
            );

            server_stream.write_all(http_response.as_bytes()).await?;

            let websocket_stream = Box::new(WebsocketStream::new(
                server_stream,
                false,
                ping_type.clone(),
                stream_reader.unparsed_data(),
            ));

            let mut target_setup_result = handler.setup_server_stream(websocket_stream).await;

            if let Ok(ref mut setup_result) = target_setup_result {
                setup_result.set_need_initial_flush(true);
                if setup_result.override_proxy_provider_unspecified()
                    && !override_proxy_provider.is_unspecified()
                {
                    setup_result.set_override_proxy_provider(override_proxy_provider.clone());
                }
            }

            return target_setup_result;
        }

        Err(std::io::Error::other(
            "No matching websocket targets",
        ))
    }
}

#[derive(Debug)]
pub struct WebsocketTcpClientHandler {
    matching_path: Option<String>,
    matching_headers: Option<FxHashMap<String, String>>,
    ping_type: WebsocketPingType,
    handler: Box<dyn TcpClientHandler>,
}

impl WebsocketTcpClientHandler {
    pub fn new(
        matching_path: Option<String>,
        matching_headers: Option<FxHashMap<String, String>>,
        ping_type: WebsocketPingType,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            matching_path,
            matching_headers,
            ping_type,
            handler,
        }
    }
}

#[async_trait]
impl TcpClientHandler for WebsocketTcpClientHandler {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let request_path = self.matching_path.as_deref().unwrap_or("/");

        let websocket_key = create_websocket_key();
        let mut http_request = String::with_capacity(1024);
        http_request.push_str("GET ");
        http_request.push_str(request_path);
        http_request.push_str(" HTTP/1.1\r\n");
        http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));

        if let Some(ref headers) = self.matching_headers {
            for (header_key, header_val) in headers {
                http_request.push_str(header_key);
                http_request.push_str(": ");
                http_request.push_str(header_val);
                http_request.push_str("\r\n");
            }
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
        } = ParsedHttpData::parse(&mut client_stream).await?;

        if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
            return Err(std::io::Error::other(
                format!("Bad websocket response: {}", first_line),
            ));
        }

        let websocket_key_response =
            response_headers
                .get("sec-websocket-accept")
                .ok_or_else(|| {
                    std::io::Error::other(
                        "missing websocket key response header",
                    )
                })?;

        let expected_key_response = create_websocket_key_response(websocket_key);
        if websocket_key_response != &expected_key_response {
            return Err(std::io::Error::other(
                format!(
                    "incorrect websocket key response, expected {}, got {}",
                    expected_key_response, websocket_key_response
                ),
            ));
        }

        let websocket_stream = Box::new(WebsocketStream::new(
            client_stream,
            true,
            self.ping_type.clone(),
            stream_reader.unparsed_data(),
        ));
        self.handler
            .setup_client_stream(server_stream, websocket_stream, remote_location)
            .await
    }
}

struct ParsedHttpData {
    first_line: String,
    headers: HashMap<String, String>,
    stream_reader: StreamReader,
}

impl ParsedHttpData {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let mut first_line: Option<String> = None;
        // don't use FxHashMap for unvalidated user data
        let mut headers: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        loop {
            let line = stream_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::other(
                    "http request line is too long",
                ));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::other(
                        format!("invalid http request line: {}", line),
                    ));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.insert(header_key, header_value);
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::other(
                    "http request is too long",
                ));
            }
        }

        let first_line = first_line
            .ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            stream_reader,
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
