use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::HttpVersion;
use crate::http2::client::{H2ClientSession, StreamReservation, format_authority};
use crate::resolver::{Resolver, resolve_single_address};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

const PROXY_AUTH_HEADER_PREFIX: &str = "proxy-authorization: basic ";
const CONNECTION_HEADER_PREFIX: &str = "connection: ";
const PROXY_CONNECTION_HEADER_PREFIX: &str = "proxy-connection: ";

#[cfg(test)]
#[path = "http2/client_proxy_tests.rs"]
mod h2_tests;

#[cfg(test)]
mod request_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn server_request(
        request: &[u8],
    ) -> (
        std::io::Result<TcpServerSetupResult>,
        tokio::io::DuplexStream,
    ) {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let handler = HttpTcpServerHandler::new(
            Some(("user".into(), "password".into())),
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(crate::resolver::NativeResolver::new()),
        );
        (handler.setup_server_stream(Box::new(server)).await, client)
    }

    #[tokio::test]
    async fn authenticated_connect_preserves_coalesced_payload() {
        let token = create_http_auth_token("user", "password");
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\npRoXy-AuThOrIzAtIoN: bAsIc {token}\r\n\r\npayload"
        );
        let (result, _) = server_request(request.as_bytes()).await;
        let TcpServerSetupResult::TcpForward {
            remote_location,
            need_initial_flush,
            connection_success_response,
            initial_remote_data,
            ..
        } = result.unwrap()
        else {
            panic!("expected TCP forwarding");
        };
        assert_eq!(
            remote_location,
            NetLocation::from_str("example.com:443", None).unwrap()
        );
        assert!(need_initial_flush);
        assert_eq!(
            connection_success_response.as_deref(),
            Some(&b"HTTP/1.1 200 Connection established\r\n\r\n"[..])
        );
        assert_eq!(initial_remote_data.as_deref(), Some(&b"payload"[..]));

        let changed_token = token.to_ascii_lowercase();
        assert_ne!(changed_token, token);
        let request = request.replace(&token, &changed_token);
        assert_eq!(
            server_request(request.as_bytes())
                .await
                .0
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn missing_credentials_return_proxy_authentication_challenge() {
        for request in ["CONNECT example.com:443", "GET http://example.com/"] {
            let (result, mut client) =
                server_request(format!("{request} HTTP/1.1\r\n\r\n").as_bytes()).await;
            assert_eq!(
                result.err().unwrap().kind(),
                std::io::ErrorKind::InvalidInput
            );
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    }

    #[tokio::test]
    async fn absolute_form_rewrites_headers_without_losing_body() {
        let token = create_http_auth_token("user", "password");
        let request = format!(
            "POST http://example.com:8080/path?q=1 HTTP/1.0\r\nHost: example.com\r\nProxy-Authorization: Basic {token}\r\nCoNnEcTiOn: keep-alive\r\nProxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\nbody"
        );
        let (result, _) = server_request(request.as_bytes()).await;
        let TcpServerSetupResult::TcpForward {
            remote_location,
            need_initial_flush,
            connection_success_response,
            initial_remote_data,
            ..
        } = result.unwrap()
        else {
            panic!("expected TCP forwarding");
        };
        assert_eq!(
            remote_location,
            NetLocation::from_str("example.com:8080", None).unwrap()
        );
        assert!(!need_initial_flush);
        assert!(connection_success_response.is_none());
        assert_eq!(initial_remote_data.as_deref(), Some(&b"POST /path?q=1 HTTP/1.0\r\nHost: example.com\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"[..]));
    }

    #[tokio::test]
    async fn unsupported_schemes_and_malformed_requests_are_rejected() {
        for (request, kind) in [
            (
                &b"GET https://example.com/ HTTP/1.1\r\n\r\n"[..],
                std::io::ErrorKind::InvalidInput,
            ),
            (
                &b"CONNECT example.com:443 HTTP/2.0\r\n\r\n"[..],
                std::io::ErrorKind::InvalidInput,
            ),
            (
                &b"CONNECT example.com:443 HTTP/1.1\n\n"[..],
                std::io::ErrorKind::InvalidData,
            ),
            (
                &b"CONNECT example.com:443 HTTP/1.1\r\n"[..],
                std::io::ErrorKind::ConnectionAborted,
            ),
        ] {
            assert_eq!(server_request(request).await.0.err().unwrap().kind(), kind);
        }
    }

    async fn client_response(status: &str) -> std::io::Result<TcpClientSetupResult> {
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(format!("{status}\r\nProxy-Agent: test\r\n\r\nbanner").as_bytes())
            .await
            .unwrap();
        server.shutdown().await.unwrap();
        let result = HttpTcpClientHandler::new(None, None, HttpVersion::H1)
            .setup_client_tcp_stream(
                Box::new(client),
                NetLocation::from_str("example.com:443", None)
                    .unwrap()
                    .into(),
            )
            .await;
        let mut request = vec![0; b"CONNECT example.com:443 HTTP/1.1\r\n\r\n".len()];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(request, b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        result
    }

    #[tokio::test]
    async fn connect_client_requires_exact_success_status() {
        for status in [
            "HTTP/1.1 2000 OK",
            "HTTP/1.0 200evil",
            "HTTP/1.1 407 Authentication Required",
            "HTTP/2.0 200 OK",
        ] {
            assert_eq!(
                client_response(status).await.err().expect(status).kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn connect_client_preserves_payload_after_success_response() {
        for status in [
            "HTTP/1.1 200 Connection established",
            "HTTP/1.0 200 OK",
            "HTTP/1.1 200",
        ] {
            assert_eq!(
                client_response(status).await.unwrap().early_data.as_deref(),
                Some(&b"banner"[..])
            );
        }
    }

    #[tokio::test]
    async fn rejected_credentials_are_not_logged() {
        let capture = crate::logging::test_capture::Capture::new();
        for request in ["CONNECT example.com:443", "GET http://example.com/"] {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(format!("{request} HTTP/1.1\r\nProxy-Authorization: Basic rejected-secret-token\r\n\r\n").as_bytes()).await.unwrap();
            let handler = HttpTcpServerHandler::new(
                Some(("user".into(), "password".into())),
                Arc::new(ClientProxySelector::new(vec![])),
                Arc::new(crate::resolver::NativeResolver::new()),
            );
            let error = handler
                .setup_server_stream(Box::new(server))
                .await
                .err()
                .unwrap();
            assert!(!error.to_string().contains("rejected-secret-token"));
        }
        let logs = capture.finish();
        assert!(logs.contains("authentication"));
        assert!(!logs.contains("rejected-secret-token"));
    }

    #[tokio::test]
    async fn non_ascii_auth_header_does_not_panic_at_prefix_boundary() {
        let (mut client, server) = tokio::io::duplex(1024);
        let header = format!(
            "{}\u{e9}invalid",
            "x".repeat(PROXY_AUTH_HEADER_PREFIX.len() - 1)
        );
        client
            .write_all(format!("CONNECT example.com:443 HTTP/1.1\r\n{header}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let handler = HttpTcpServerHandler::new(
            Some(("user".into(), "password".into())),
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(crate::resolver::NativeResolver::new()),
        );
        assert!(handler.setup_server_stream(Box::new(server)).await.is_err());
    }
}

fn create_http_auth_token(username: &str, password: &str) -> String {
    BASE64.encode(format!("{username}:{password}"))
}

#[derive(Debug)]
pub struct HttpTcpServerHandler {
    auth_token: Option<String>,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
}

impl HttpTcpServerHandler {
    pub fn new(
        auth_credentials: Option<(String, String)>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let auth_token = auth_credentials
            .map(|(username, password)| create_http_auth_token(&username, &password));
        Self {
            auth_token,
            proxy_selector,
            resolver,
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
            self.resolver.clone(),
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
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<TcpServerSetupResult> {
    const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut is_h2 = true;
    for length in 1..=H2_PREFACE.len() {
        if stream_reader.peek_slice(&mut server_stream, length).await? != &H2_PREFACE[..length] {
            is_h2 = false;
            break;
        }
    }
    if is_h2 {
        let stream = Box::new(crate::prepend_stream::PrependStream::new(
            server_stream,
            stream_reader.unparsed_data_owned(),
        ));
        let auth = auth_token.map(str::to_owned);
        return Ok(TcpServerSetupResult::Session(Box::pin(async move {
            if let Err(error) =
                crate::http2::server::serve(stream, auth, proxy_selector, resolver).await
            {
                debug!("HTTP/2 proxy connection ended: {error}");
            }
        })));
    }
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
            let remote_location = NetLocation::from_authority(address, None)?;

            // wait for an empty \r\n before connecting, and check for auth header line if needed.
            let mut need_auth = auth_token.is_some();

            loop {
                let line = stream_reader.read_line(&mut server_stream).await?;
                if line.is_empty() {
                    break;
                }
                if need_auth
                    && line.len() > PROXY_AUTH_HEADER_PREFIX.len() + 1
                    && line.as_bytes()[0..PROXY_AUTH_HEADER_PREFIX.len()]
                        .eq_ignore_ascii_case(PROXY_AUTH_HEADER_PREFIX.as_bytes())
                {
                    if !bool::from(
                        line.as_bytes()[PROXY_AUTH_HEADER_PREFIX.len()..]
                            .ct_eq(auth_token.unwrap().as_bytes()),
                    ) {
                        debug!("Received incorrect HTTP CONNECT authentication");
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Incorrect HTTP CONNECT authentication",
                        ));
                    }
                    need_auth = false;
                    continue;
                }
                debug!("Ignored HTTP CONNECT request header");
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

            let remote_location = NetLocation::from_authority(address, Some(80))?;

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
                        if !bool::from(
                            line.as_bytes()[PROXY_AUTH_HEADER_PREFIX.len()..]
                                .ct_eq(auth_token.unwrap().as_bytes()),
                        ) {
                            debug!("Received incorrect HTTP GET authentication");
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

pub struct HttpTcpClientHandler {
    auth_header: Option<String>,
    resolver: Option<Arc<dyn Resolver>>,
    version: HttpVersion,
    session: parking_lot::Mutex<Option<H2ClientSession>>,
    reuse_enabled: AtomicBool,
}

impl std::fmt::Debug for HttpTcpClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTcpClientHandler")
            .field(
                "auth_header",
                &self.auth_header.as_ref().map(|_| "[redacted]"),
            )
            .field("resolver", &self.resolver.is_some())
            .field("version", &self.version)
            .finish()
    }
}

impl HttpTcpClientHandler {
    pub fn new(
        auth_credentials: Option<(String, String)>,
        resolver: Option<Arc<dyn Resolver>>,
        version: HttpVersion,
    ) -> Self {
        let auth_header = auth_credentials.map(|(username, password)| {
            format!("Basic {}", create_http_auth_token(&username, &password))
        });
        Self {
            auth_header,
            resolver,
            version,
            session: parking_lot::Mutex::new(None),
            reuse_enabled: AtomicBool::new(false),
        }
    }

    async fn connect_location(
        &self,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<NetLocation> {
        // Resolve hostname to IP if resolver is configured.
        // Bypasses DNS issues when the upstream proxy has DNS problems.
        // Uses pre-resolved address if available, otherwise resolves here.
        Ok(if let Some(ref resolver) = self.resolver {
            if let Some(resolved_addr) = remote_location.resolved_addr() {
                // Use pre-resolved address
                debug!(
                    "HTTP CONNECT using pre-resolved {} -> {}",
                    remote_location.location(),
                    resolved_addr
                );
                let address = match resolved_addr.ip() {
                    std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
                    std::net::IpAddr::V6(ip) => Address::Ipv6(ip),
                };
                NetLocation::new(address, resolved_addr.port())
            } else if remote_location.address().hostname().is_some() {
                let socket_addr =
                    resolve_single_address(resolver, remote_location.location()).await?;
                debug!(
                    "HTTP CONNECT resolved {} -> {}",
                    remote_location.location(),
                    socket_addr
                );
                let address = match socket_addr.ip() {
                    std::net::IpAddr::V4(ip) => Address::Ipv4(ip),
                    std::net::IpAddr::V6(ip) => Address::Ipv6(ip),
                };
                NetLocation::new(address, socket_addr.port())
            } else {
                remote_location.into_location()
            }
        } else {
            remote_location.into_location()
        })
    }

    async fn open_h2(
        &self,
        session: H2ClientSession,
        reservation: StreamReservation,
        target: ResolvedLocation,
        warm: bool,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        let location = self.connect_location(target).await?;
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .uri(format_authority(&location));
        if let Some(auth) = &self.auth_header {
            let mut value = http::HeaderValue::from_str(auth).map_err(std::io::Error::other)?;
            value.set_sensitive(true);
            request = request.header(http::header::PROXY_AUTHORIZATION, value);
        }
        let result = reservation
            .open(request.body(()).map_err(std::io::Error::other)?)
            .await;
        let (response, stream) = match result {
            Ok(result) => result,
            Err(error) => {
                let mut slot = self.session.lock();
                if !error.error.is_reset()
                    && slot
                        .as_ref()
                        .is_some_and(|current| current.same_generation(&session))
                {
                    *slot = None;
                }
                // A pre-send miss is safe to redial, but submitted CONNECTs are never replayed.
                if warm && !error.sent {
                    return Ok(None);
                }
                return Err(error.into());
            }
        };
        if !response.status.is_success() {
            return Err(std::io::Error::other(format!(
                "HTTP CONNECT failed: {}",
                response.status
            )));
        }
        Ok(Some(TcpClientSetupResult {
            client_stream: Box::new(stream),
            early_data: None,
        }))
    }
}

#[async_trait]
impl TcpClientHandler for HttpTcpClientHandler {
    async fn prepare_target(
        &self,
        mut target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        if self.resolver.is_some()
            && target.resolved_addr().is_none()
            && target.address().hostname().is_some()
        {
            target.set_resolved(resolve_single_address(resolver, target.location()).await?);
        }
        Ok(target)
    }

    fn validate_alpn(&self, alpn: Option<&[u8]>) -> std::io::Result<()> {
        let valid = match self.version {
            HttpVersion::H1 => true,
            HttpVersion::H2 => alpn == Some(b"h2"),
        };
        if valid {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP proxy version does not match negotiated TLS ALPN",
            ))
        }
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        if self.version != HttpVersion::H2 {
            return Ok(None);
        }
        self.reuse_enabled.store(true, Ordering::Relaxed);
        let session = self.session.lock().clone();
        let Some(session) = session else {
            return Ok(None);
        };
        let Some(reservation) = session.try_reserve() else {
            return Ok(None);
        };
        self.open_h2(session, reservation, target.clone(), true)
            .await
    }

    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if self.version == HttpVersion::H2 {
            // The supplied carrier already embodies the selected route and wrappers.
            let session = H2ClientSession::new(client_stream).await?;
            let reservation = session.reserve();
            // Only eligible first-hop routes probe reuse before building a carrier.
            if self.reuse_enabled.load(Ordering::Relaxed) {
                *self.session.lock() = Some(session.clone());
            }
            return self
                .open_h2(session, reservation, remote_location, false)
                .await
                .map(|result| result.expect("cold CONNECT cannot be a reuse miss"));
        }
        let connect_location = self.connect_location(remote_location).await?;

        let mut connect_str = match connect_location.address() {
            Address::Ipv6(addr) => {
                format!(
                    "CONNECT [{}]:{} HTTP/1.1\r\n",
                    addr,
                    connect_location.port()
                )
            }
            Address::Ipv4(addr) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", addr, connect_location.port())
            }
            Address::Hostname(d) => {
                format!("CONNECT {}:{} HTTP/1.1\r\n", d, connect_location.port())
            }
        };

        if let Some(ref header) = self.auth_header {
            connect_str.push_str("Proxy-Authorization: ");
            connect_str.push_str(header);
            connect_str.push_str("\r\n");
        }
        connect_str.push_str("\r\n");
        client_stream.write_all(&connect_str.into_bytes()).await?;
        client_stream.flush().await?;

        let mut stream_reader = StreamReader::new();
        let line = stream_reader.read_line(&mut client_stream).await?;

        // Expected response: HTTP/1.1 200 Connection established\r\n\r\n
        let mut status = line.split(' ');
        if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) || status.next() != Some("200") {
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
