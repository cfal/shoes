use async_trait::async_trait;
use rustc_hash::FxHashMap;
use tokio::io::AsyncWriteExt;

use crate::async_stream::AsyncStream;
use crate::http_parse::ParsedHttpData;
use crate::prepend_stream::PrependStream;
use crate::tcp::tcp_handler::{TcpServerHandler, TcpServerSetupResult};

const NOT_FOUND: &str = "404 Not Found";
const BAD_REQUEST: &str = "400 Bad Request";

const UPGRADE_RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";

#[derive(Debug)]
pub struct HttpUpgradeServerTarget {
    pub matching_path: Option<String>,
    pub matching_headers: Option<FxHashMap<String, String>>,
    pub handler: Box<dyn TcpServerHandler>,
}

#[derive(Debug)]
pub struct HttpUpgradeTcpServerHandler {
    server_targets: Vec<HttpUpgradeServerTarget>,
}

impl HttpUpgradeTcpServerHandler {
    pub fn new(server_targets: Vec<HttpUpgradeServerTarget>) -> Self {
        Self { server_targets }
    }
}

/// A refusal that reads as an ordinary web server's, because looking like one
/// is this transport's entire purpose.
fn refusal_response(status: &str, date: &str) -> String {
    format!("HTTP/1.1 {status}\r\nDate: {date}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

fn http_date_now() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// Writes the refusal and returns the error the caller will log. A failed write
/// is ignored on purpose: the connection is being refused either way, and the
/// interesting error is the reason for the refusal rather than the peer hanging
/// up while hearing it.
async fn refuse(
    stream: &mut Box<dyn AsyncStream>,
    status: &'static str,
    reason: String,
) -> std::io::Error {
    let response = refusal_response(status, &http_date_now());
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    std::io::Error::other(reason)
}

fn header_is(headers: &std::collections::HashMap<String, String>, key: &str, value: &str) -> bool {
    headers
        .get(key)
        .is_some_and(|v| v.eq_ignore_ascii_case(value))
}

#[async_trait]
impl TcpServerHandler for HttpUpgradeTcpServerHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let parsed = match ParsedHttpData::parse(&mut server_stream).await {
            Ok(parsed) => parsed,
            Err(e) => {
                return Err(refuse(
                    &mut server_stream,
                    BAD_REQUEST,
                    format!("httpupgrade: unreadable request: {e}"),
                )
                .await);
            }
        };

        let ParsedHttpData {
            mut first_line,
            headers: request_headers,
            stream_reader,
        } = parsed;

        if !first_line.ends_with(" HTTP/1.0") && !first_line.ends_with(" HTTP/1.1") {
            return Err(refuse(
                &mut server_stream,
                BAD_REQUEST,
                format!("httpupgrade: invalid http version: {first_line}"),
            )
            .await);
        }

        if !first_line.starts_with("GET ") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                format!("httpupgrade: bad method: {first_line}"),
            )
            .await);
        }

        // remove ' HTTP/1.x', then everything after 'GET ' is the path
        first_line.truncate(first_line.len() - 9);
        let request_path = first_line.split_off(4);

        if !header_is(&request_headers, "connection", "upgrade") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                "httpupgrade: not an upgrade request".to_string(),
            )
            .await);
        }

        if !header_is(&request_headers, "upgrade", "websocket") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                "httpupgrade: not a websocket upgrade".to_string(),
            )
            .await);
        }

        // A framed WebSocket peer would read our unframed bytes as garbage, so
        // this is refused rather than served. Same rule and same status code as
        // the reference, which logs it as "real websocket request received".
        if request_headers.contains_key("sec-websocket-key") {
            return Err(refuse(
                &mut server_stream,
                NOT_FOUND,
                "httpupgrade: real websocket request received".to_string(),
            )
            .await);
        }

        'outer: for server_target in self.server_targets.iter() {
            let HttpUpgradeServerTarget {
                matching_path,
                matching_headers,
                handler,
            } = server_target;

            if let Some(path) = matching_path
                && path != &request_path
            {
                continue;
            }

            if let Some(headers) = matching_headers {
                for (header_key, header_val) in headers {
                    if request_headers.get(header_key) != Some(header_val) {
                        continue 'outer;
                    }
                }
            }

            server_stream.write_all(UPGRADE_RESPONSE).await?;

            // Whatever arrived in the same packet as the header block is the
            // tunnel's first payload. There is no stream wrapper here to hold
            // it, so it goes in front of the connection instead.
            let tunnel = PrependStream::new(server_stream, stream_reader.unparsed_data_owned());

            let mut target_setup_result = handler.setup_server_stream(Box::new(tunnel)).await;

            if let Ok(ref mut setup_result) = target_setup_result {
                if matches!(setup_result, TcpServerSetupResult::AlreadyHandled) {
                    return target_setup_result;
                }
                setup_result.set_need_initial_flush(true);
            }

            return target_setup_result;
        }

        Err(refuse(
            &mut server_stream,
            NOT_FOUND,
            format!("httpupgrade: no target matched path {request_path}"),
        )
        .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::testing::TestStream;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Records the stream it was handed so a test can read what survived the
    /// handshake.
    #[derive(Debug)]
    struct RecordingHandler {
        received: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl TcpServerHandler for RecordingHandler {
        async fn setup_server_stream(
            &self,
            mut stream: Box<dyn AsyncStream>,
        ) -> std::io::Result<TcpServerSetupResult> {
            let mut got = vec![0u8; 7];
            // Bounded: a payload that was dropped rather than prepended never
            // arrives, and a test that hangs wedges the whole suite instead of
            // reporting the defect.
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut got))
                .await
                .map_err(|_| std::io::Error::other("the tunnel's first payload never arrived"))??;
            *self.received.lock().unwrap() = got;
            Ok(TcpServerSetupResult::AlreadyHandled)
        }
    }

    fn handler_with(
        matching_path: Option<&str>,
        received: Arc<Mutex<Vec<u8>>>,
    ) -> HttpUpgradeTcpServerHandler {
        HttpUpgradeTcpServerHandler::new(vec![HttpUpgradeServerTarget {
            matching_path: matching_path.map(String::from),
            matching_headers: None,
            handler: Box::new(RecordingHandler { received }),
        }])
    }

    /// Drives the handler against `request` and returns what it wrote back.
    async fn respond_to(
        handler: &HttpUpgradeTcpServerHandler,
        request: &[u8],
    ) -> (std::io::Result<TcpServerSetupResult>, Vec<u8>) {
        let (near, mut far) = duplex(8192);
        far.write_all(request).await.unwrap();
        let result = handler
            .setup_server_stream(Box::new(TestStream(near)))
            .await;
        let mut response = vec![0u8; 512];
        let n = far.read(&mut response).await.unwrap();
        response.truncate(n);
        (result, response)
    }

    /// Byte for byte what sing-box writes. Asserted literally: a round trip
    /// through our own client would pass even if both were wrong.
    #[tokio::test]
    async fn a_matching_request_gets_the_reference_101() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(Some("/download"), received);
        let (result, response) = respond_to(
            &handler,
            b"GET /download HTTP/1.1\r\nHost: cdn.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(
            response,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
    }

    /// The bytes that arrived in the same packet as the header block are the
    /// tunnel's first payload. Without `PrependStream` they vanish.
    #[tokio::test]
    async fn the_payload_after_the_header_block_reaches_the_inner_handler() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(Some("/download"), received.clone());
        let (result, _) = respond_to(
            &handler,
            b"GET /download HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(&*received.lock().unwrap(), b"PAYLOAD");
    }

    /// sing-box logs this one as "real websocket request received". Accepting
    /// it would mean speaking unframed bytes to a peer that expects frames.
    #[tokio::test]
    async fn a_real_websocket_handshake_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) = respond_to(
            &handler,
            b"GET / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(
            response.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
            "got {}",
            String::from_utf8_lossy(&response)
        );
    }

    #[tokio::test]
    async fn a_path_mismatch_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(Some("/download"), received);
        let (result, response) = respond_to(
            &handler,
            b"GET /other HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    #[tokio::test]
    async fn a_non_get_method_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) = respond_to(
            &handler,
            b"POST / HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    #[tokio::test]
    async fn a_request_without_the_upgrade_headers_is_refused() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) =
            respond_to(&handler, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    }

    /// A start line we cannot parse is a malformed request, not a wrong one.
    #[tokio::test]
    async fn a_bad_http_version_is_a_bad_request() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = handler_with(None, received);
        let (result, response) = respond_to(
            &handler,
            b"GET / HTTP/0.9\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    }

    /// A refusal has to look like a web server's, not like a closed socket.
    #[test]
    fn a_refusal_carries_web_server_headers() {
        let response = refusal_response(NOT_FOUND, "Mon, 25 Aug 2026 12:00:00 GMT");
        assert_eq!(
            response,
            "HTTP/1.1 404 Not Found\r\nDate: Mon, 25 Aug 2026 12:00:00 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
}
