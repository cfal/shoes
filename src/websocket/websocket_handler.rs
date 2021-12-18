use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use super::websocket_stream::WebsocketStream;
use crate::address::Location;
use crate::async_stream::AsyncStream;
use crate::client_proxy_provider::ClientProxyProvider;
use crate::config::{WebsocketClientConfig, WebsocketServerConfig};
use crate::line_reader::LineReader;
use crate::protocol_handler::{
    ClientSetupResult, ServerSetupResult, TcpClientHandler, TcpServerHandler,
};
use crate::tls_factory::get_tls_factory;

pub struct WebsocketServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub handler: Box<dyn TcpServerHandler>,
    pub override_proxy_provider: Option<Arc<ClientProxyProvider>>,
}

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
    ) -> std::io::Result<ServerSetupResult> {
        let ParsedHttpData {
            mut first_line,
            headers: mut request_headers,
            line_reader,
        } = ParsedHttpData::parse(&mut server_stream).await?;
        let request_path = {
            if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("invalid http request version: {}", first_line),
                ));
            }

            if !first_line.starts_with("GET ") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("invalid http request: {}", first_line),
                ));
            }

            // remove ' HTTP/1.x'
            first_line.truncate(first_line.len() - 9);

            // return the path after 'GET '
            first_line.split_off(4)
        };

        let websocket_key = request_headers.remove("sec-websocket-key").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "missing websocket key header")
        })?;

        for server_target in self.server_targets.iter() {
            let WebsocketServerTarget {
                matching_path,
                matching_headers,
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
                        continue;
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
                line_reader.unparsed_data(),
            ));

            let mut target_setup_result = handler.setup_server_stream(websocket_stream).await;
            if override_proxy_provider.is_some() {
                if let Ok(mut result) = target_setup_result.as_mut() {
                    if result.override_proxy_provider.is_none() {
                        result.override_proxy_provider = override_proxy_provider.clone();
                    }
                }
            }

            return target_setup_result;
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No matching websocket targets",
        ))
    }
}

pub struct WebsocketClientTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<HashMap<String, String>>,
    pub handler: Box<dyn TcpClientHandler>,
}

pub struct WebsocketTcpClientHandler {
    client_target: WebsocketClientTarget,
}

impl WebsocketTcpClientHandler {
    pub fn new(client_target: WebsocketClientTarget) -> Self {
        Self { client_target }
    }
}

#[async_trait]
impl TcpClientHandler for WebsocketTcpClientHandler {
    async fn setup_client_stream(
        &self,
        server_stream: &mut Box<dyn AsyncStream>,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: Location,
    ) -> std::io::Result<ClientSetupResult> {
        let WebsocketClientTarget {
            matching_path,
            matching_headers,
            handler,
        } = &self.client_target;

        let request_path = matching_path.as_ref().map(String::as_str).unwrap_or("/");

        let websocket_key = create_websocket_key();
        let mut http_request = String::with_capacity(1024);
        http_request.push_str("GET ");
        http_request.push_str(request_path);
        http_request.push_str(" HTTP/1.1\r\n");
        http_request.push_str(concat!("Connection: Upgrade\r\n", "Upgrade: websocket\r\n",));

        if let Some(ref headers) = matching_headers {
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
            line_reader,
        } = ParsedHttpData::parse(&mut client_stream).await?;

        if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Bad websocket response: {}", first_line),
            ));
        }

        let websocket_key_response =
            response_headers
                .get("sec-websocket-accept")
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "missing websocket key response header",
                    )
                })?;

        let expected_key_response = create_websocket_key_response(websocket_key);
        if websocket_key_response != &expected_key_response {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "incorrect websocket key response, expected {}, got {}",
                    expected_key_response, websocket_key_response
                ),
            ));
        }

        let websocket_stream = Box::new(WebsocketStream::new(
            client_stream,
            true,
            line_reader.unparsed_data(),
        ));
        handler
            .setup_client_stream(server_stream, websocket_stream, remote_location)
            .await
    }
}

struct ParsedHttpData {
    first_line: String,
    headers: HashMap<String, String>,
    line_reader: LineReader,
}

impl ParsedHttpData {
    async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut line_reader = LineReader::new();
        let mut first_line: Option<String> = None;
        let mut headers: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        loop {
            let line = line_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "http request line is too long",
                ));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid http request line: {}", line),
                    ));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.insert(header_key, header_value);
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "http request is too long",
                ));
            }
        }

        let first_line = first_line
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            line_reader,
        })
    }
}

fn create_websocket_key() -> String {
    let key: [u8; 16] = rand::random();
    base64::encode(key)
}

fn create_websocket_key_response(mut key: String) -> String {
    // after some testing - the sha1 crate seems faster than sha-1.
    key.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let hash = sha1::Sha1::from(key.into_bytes()).digest().bytes();
    base64::encode(hash)
}

impl From<WebsocketServerConfig> for WebsocketServerTarget {
    fn from(websocket_server_config: WebsocketServerConfig) -> Self {
        let WebsocketServerConfig {
            matching_path,
            matching_headers,
            target_config,
            override_proxies,
            override_rules,
        } = websocket_server_config;

        let override_proxy_provider = if override_proxies.is_some() || override_rules.is_some() {
            let proxies = override_proxies.unwrap_or(vec![]);
            let rules = override_rules.unwrap_or(vec![]);
            Some(Arc::new(ClientProxyProvider::new(
                proxies,
                rules,
                &get_tls_factory(),
            )))
        } else {
            None
        };

        WebsocketServerTarget {
            matching_path,
            matching_headers,
            handler: target_config.into(),
            override_proxy_provider,
        }
    }
}

impl From<Box<WebsocketClientConfig>> for WebsocketClientTarget {
    fn from(websocket_client_config: Box<WebsocketClientConfig>) -> Self {
        let WebsocketClientConfig {
            matching_path,
            matching_headers,
            target_config,
        } = *websocket_client_config;
        WebsocketClientTarget {
            matching_path,
            matching_headers,
            handler: target_config.into(),
        }
    }
}
