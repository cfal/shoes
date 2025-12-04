use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::debug;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

const PROXY_AUTH_HEADER_PREFIX: &str = "proxy-authorization: basic ";
const CONNECTION_HEADER_PREFIX: &str = "connection: ";
const PROXY_CONNECTION_HEADER_PREFIX: &str = "proxy-connection: ";

fn create_http_auth_token(username: &str, password: &str) -> String {
    BASE64.encode(format!("{username}:{password}"))
}

#[derive(Debug)]
pub struct HttpTcpServerHandler {
    auth_token: Option<String>,
    proxy_selector: Arc<ClientProxySelector>,
}

unsafe impl Send for HttpTcpServerHandler {}
unsafe impl Sync for HttpTcpServerHandler {}

impl HttpTcpServerHandler {
    pub fn new(
        auth_credentials: Option<(String, String)>,
        proxy_selector: Arc<ClientProxySelector>,
    ) -> Self {
        let auth_token = auth_credentials
            .map(|(username, password)| create_http_auth_token(&username, &password));
        Self {
            auth_token,
            proxy_selector,
        }
    }
}

#[async_trait]
impl TcpServerHandler for HttpTcpServerHandler {
    async fn setup_server_stream(
        &self,
        server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let stream_reader = StreamReader::new();
        setup_http_server_stream_inner(
            self.auth_token.as_deref(),
            server_stream,
            stream_reader,
            self.proxy_selector.clone(),
        )
        .await
    }
}

/// Core HTTP proxy server setup logic.
/// Can be called from HttpTcpServerHandler or MixedTcpServerHandler.
///
/// Takes ownership of `server_stream` and returns it in the result.
pub async fn setup_http_server_stream_inner(
    auth_token: Option<&str>,
    mut server_stream: Box<dyn AsyncStream>,
    mut stream_reader: StreamReader,
    proxy_selector: Arc<ClientProxySelector>,
) -> std::io::Result<TcpServerSetupResult> {
    let line = stream_reader.read_line(&mut server_stream).await?;
    if !line.ends_with(" HTTP/1.0") && !line.ends_with(" HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Unrecognized http request: {line}"),
        ));
    }

    // GET = 3 (smaller than CONNECT)
    // HTTP/1.1 = 8
    // min address a.ab = 4
    // port 1
    // 3 spaces
    // total = 19
    if line.len() < 19 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid http request: {line}"),
        ));
    }

    let http_version = line[line.len() - 8..].to_string();
    let (remote_location, connection_success_response, initial_remote_data, need_initial_flush) =
        if line.starts_with("CONNECT ") {
            let address = &line[8..line.len() - 9];

            let separator_index = address.find(':').ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid address format")
            })?;

            if address.len() <= separator_index + 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid address format",
                ));
            }

            let domain_name = &address[0..separator_index];

            let port = address[separator_index + 1..]
                .parse::<u16>()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            let remote_location = NetLocation::new(Address::from(domain_name)?, port);

            // wait for an empty \r\n before connecting, and check for auth header line if needed.
            let mut need_auth = auth_token.is_some();

            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }
                if need_auth
                    && line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
                    && line[0..PROXY_AUTH_HEADER_PREFIX.len()].to_ascii_lowercase()
                        == PROXY_AUTH_HEADER_PREFIX
                {
                    if &line[PROXY_AUTH_HEADER_PREFIX.len()..] != auth_token.unwrap() {
                        debug!(
                            "Received incorrect HTTP CONNECT authentication: {}",
                            &line[PROXY_AUTH_HEADER_PREFIX.len()..]
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Incorrect HTTP CONNECT authentication",
                        ));
                    }
                    need_auth = false;
                    continue;
                }
                debug!("Ignored HTTP CONNECT request header: {line}");
            }

            if need_auth {
                // FoxyProxy and similar clients require Proxy-Authenticate header to send credentials
                server_stream.write_all(
                &format!("{http_version} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
            ).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing HTTP CONNECT authentication",
                ));
            }

            // We need an initial flush for this line.
            let connection_success_response = Some(
                format!("{http_version} 200 Connection established\r\n\r\n")
                    .into_bytes()
                    .into_boxed_slice(),
            );

            (
                remote_location,
                connection_success_response,
                stream_reader.unparsed_data_owned(),
                true,
            )
        } else {
            // Request looks a normal HTTP request but with protocol and address:
            // GET http://ipinfo.io/ HTTP/1.1
            // <headers follow..>
            // <empty line>

            let line = &line[0..line.len() - 9];

            let space_index = line.find(' ').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unrecognized http request: {line} {http_version}"),
                )
            })?;

            let directive = &line[0..space_index];
            let url = &line[space_index + 1..];

            if !url.starts_with("http://") {
                // we can't handle https
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unsupported http forward url: {url}"),
                ));
            }

            let url = &url[7..]; // strip "http://"

            let (address, location) = match url.find('/') {
                Some(i) => (&url[0..i], &url[i..]),
                None => (url, "/"),
            };

            let remote_location = match address.find(':') {
                Some(i) => {
                    let port = address[i + 1..]
                        .parse::<u16>()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    NetLocation::new(Address::from(&address[0..i])?, port)
                }
                None => NetLocation::new(Address::from(address)?, 80),
            };

            let mut request = format!("{directive} {location} {http_version}\r\n");

            // wait for an empty \r\n before connecting, and check for auth header line if needed.
            let mut need_auth = auth_token.is_some();

            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }

                let lowercase_line = line.to_ascii_lowercase();

                // && lowercase_line[0..PROXY_AUTH_HEADER_PREFIX.len()] == PROXY_AUTH_HEADER_PREFIX
                if line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
                    && lowercase_line.starts_with(PROXY_AUTH_HEADER_PREFIX)
                {
                    if need_auth {
                        if &line[PROXY_AUTH_HEADER_PREFIX.len()..] != auth_token.unwrap() {
                            debug!(
                                "Received incorrect HTTP GET authentication: {}",
                                &line[PROXY_AUTH_HEADER_PREFIX.len()..]
                            );
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "Incorrect HTTP GET authentication",
                            ));
                        }
                        need_auth = false;
                    }
                    // If some auth header was passed in and we don't have auth configured,
                    // simply ignore it.
                    continue;
                } else if lowercase_line.starts_with(CONNECTION_HEADER_PREFIX)
                    || lowercase_line.starts_with(PROXY_CONNECTION_HEADER_PREFIX)
                {
                    // We can't support 'Connection' or 'Proxy-Connection' for GET style proxy requests.
                    // Because then we'd have to parse the remote server's response to know when it ends,
                    // in order to handle subsequent GET requests.
                    // So filter them out, and then we make sure to add a 'Connection: close' header to prevent
                    // having to worry about that.
                    continue;
                }

                request.push_str(line);
                request.push_str("\r\n");

                if request.len() > 16384 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP GET request is too long",
                    ));
                }
            }

            if need_auth {
                // FoxyProxy and similar clients require Proxy-Authenticate header to send credentials
                server_stream.write_all(
                &format!("{http_version} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
            ).await?;
                server_stream.flush().await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing HTTP GET authentication",
                ));
            }

            request.push_str("Connection: close\r\n\r\n");

            // We don't write "HTTP/xxx 200 Connection established\r\n\r\n" for this type of
            // request, the server's response (eg. "HTTP/1.1 200 OK") is what the client
            // expects as a response.

            let request_bytes = request.into_bytes();

            let unparsed_data = stream_reader.unparsed_data();

            let mut initial_remote_data =
                Vec::with_capacity(request_bytes.len() + unparsed_data.len());
            initial_remote_data.extend(request_bytes.iter());
            initial_remote_data.extend(unparsed_data.iter());

            (
                remote_location,
                None,
                Some(initial_remote_data.into_boxed_slice()),
                false,
            )
        };

    Ok(TcpServerSetupResult::TcpForward {
        remote_location,
        stream: server_stream,
        need_initial_flush,
        connection_success_response,
        initial_remote_data,
        proxy_selector,
    })
}

fn create_http_auth_header_line(username: &str, password: &str) -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        create_http_auth_token(username, password)
    )
}

#[derive(Debug)]
pub struct HttpTcpClientHandler {
    auth_header: Option<String>,
}

impl HttpTcpClientHandler {
    pub fn new(auth_credentials: Option<(String, String)>) -> Self {
        let auth_header = auth_credentials
            .map(|(username, password)| create_http_auth_header_line(&username, &password));
        Self { auth_header }
    }
}

#[async_trait]
impl TcpClientHandler for HttpTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: NetLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        // TODO: clean this up
        let mut connect_str = match remote_location.address() {
            Address::Ipv6(addr) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", addr, remote_location.port())
            }
            Address::Ipv4(addr) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", addr, remote_location.port())
            }
            Address::Hostname(d) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", d, remote_location.port())
            }
        };

        if let Some(ref header) = self.auth_header {
            connect_str.push_str(header);
        }
        connect_str.push_str("\r\n");
        client_stream.write_all(&connect_str.into_bytes()).await?;
        client_stream.flush().await?;

        let mut stream_reader = StreamReader::new();
        let line = stream_reader.read_line(&mut client_stream).await?;

        // Expected response: HTTP/1.1 200 Connection established\r\n\r\n
        if !line.starts_with("HTTP/1.1 200") && !line.starts_with("HTTP/1.0 200") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("HTTP CONNECT request failed: {line}"),
            ));
        }

        loop {
            let line = stream_reader.read_line(&mut client_stream).await?;
            if line.is_empty() {
                break;
            }
        }

        let early_data = stream_reader.unparsed_data();
        let early_data = if early_data.is_empty() {
            None
        } else {
            Some(early_data.to_vec())
        };

        Ok(TcpClientSetupResult {
            client_stream,
            early_data,
        })
    }
}
