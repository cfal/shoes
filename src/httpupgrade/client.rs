use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use crate::address::ResolvedLocation;
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::http_parse::ParsedHttpData;
use crate::prepend_stream::PrependStream;
use crate::tcp::tcp_handler::{TcpClientHandler, TcpClientSetupResult};

#[derive(Debug)]
pub struct HttpUpgradeTcpClientHandler {
    host: Option<String>,
    request_path: String,
    /// Sorted, and with the three headers this transport owns removed, so the
    /// bytes on the wire are the same on every run and cannot be forged from
    /// configuration.
    headers: Vec<(String, String)>,
    handler: Box<dyn TcpClientHandler>,
}

impl HttpUpgradeTcpClientHandler {
    pub fn new(
        host: Option<String>,
        matching_path: Option<String>,
        matching_headers: Option<Vec<(String, String)>>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        let mut headers: Vec<(String, String)> = matching_headers
            .unwrap_or_default()
            .into_iter()
            .filter(|(key, _)| {
                // Host is written from `host`; Connection and Upgrade are what
                // make this an upgrade request. The reference overwrites all
                // three, so taking them from configuration would only let a
                // configuration break itself.
                !key.eq_ignore_ascii_case("host")
                    && !key.eq_ignore_ascii_case("connection")
                    && !key.eq_ignore_ascii_case("upgrade")
            })
            .collect();
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        Self {
            host,
            request_path: matching_path.unwrap_or_else(|| "/".to_string()),
            headers,
            handler,
        }
    }

    fn build_request(&self) -> String {
        let mut request = String::with_capacity(256);
        request.push_str("GET ");
        request.push_str(&self.request_path);
        request.push_str(" HTTP/1.1\r\n");

        if let Some(ref host) = self.host {
            request.push_str("Host: ");
            request.push_str(host);
            request.push_str("\r\n");
        }

        for (key, value) in self.headers.iter() {
            request.push_str(key);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }

        // Last, because the reference applies them over the top of the
        // configured headers rather than merging with them.
        request.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        request
    }

    async fn setup_tunnel(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        client_stream
            .write_all(self.build_request().as_bytes())
            .await?;
        client_stream.flush().await?;

        let ParsedHttpData {
            first_line,
            headers: response_headers,
            stream_reader,
        } = ParsedHttpData::parse(&mut client_stream).await?;

        if !first_line.starts_with("HTTP/1.1 101") && !first_line.starts_with("HTTP/1.0 101") {
            return Err(std::io::Error::other(format!(
                "httpupgrade: server refused the upgrade: {first_line}"
            )));
        }

        for (key, expected) in [("connection", "upgrade"), ("upgrade", "websocket")] {
            let value = response_headers.get(key).map(String::as_str).unwrap_or("");
            if !value.eq_ignore_ascii_case(expected) {
                return Err(std::io::Error::other(format!(
                    "httpupgrade: response header {key} was {value:?}, expected {expected:?}"
                )));
            }
        }

        // Same rule as on the server side, seen from the other end: bytes that
        // came in with the header block belong to the tunnel.
        Ok(Box::new(PrependStream::new(
            client_stream,
            stream_reader.unparsed_data_owned(),
        )))
    }
}

#[async_trait]
impl TcpClientHandler for HttpUpgradeTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let tunnel = self.setup_tunnel(client_stream).await?;
        self.handler
            .setup_client_tcp_stream(tunnel, remote_location)
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
        let tunnel = self.setup_tunnel(client_stream).await?;
        self.handler
            .setup_client_udp_bidirectional(tunnel, target)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::async_stream::testing::TestStream;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    const GOOD_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nPAYLOAD";

    /// Hands the stream back, after recording the bytes that reached it.
    #[derive(Debug)]
    struct RecordingHandler {
        received: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl TcpClientHandler for RecordingHandler {
        async fn setup_client_tcp_stream(
            &self,
            mut client_stream: Box<dyn AsyncStream>,
            _remote_location: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            let mut got = vec![0u8; 7];
            // Bounded for the same reason as on the server side.
            tokio::time::timeout(Duration::from_secs(2), client_stream.read_exact(&mut got))
                .await
                .map_err(|_| std::io::Error::other("the tunnel's first payload never arrived"))??;
            *self.received.lock().unwrap() = got;
            Ok(TcpClientSetupResult {
                client_stream,
                early_data: None,
            })
        }
    }

    fn target() -> ResolvedLocation {
        ResolvedLocation::new(NetLocation::from_str("example.com:443", None).unwrap())
    }

    fn client(
        host: Option<&str>,
        headers: Option<Vec<(&str, &str)>>,
        received: Arc<Mutex<Vec<u8>>>,
    ) -> HttpUpgradeTcpClientHandler {
        HttpUpgradeTcpClientHandler::new(
            host.map(String::from),
            Some("/download".to_string()),
            headers.map(|hs| {
                hs.into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            }),
            Box::new(RecordingHandler { received }),
        )
    }

    /// Byte for byte, including order. sing-box applies Connection and Upgrade
    /// over the top of the configured headers, so they come last.
    #[tokio::test]
    async fn the_request_is_what_the_reference_sends() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(
            Some("cdn.example.com"),
            Some(vec![("X-Secret", "value")]),
            received,
        );
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let n = far.read(&mut request).await.unwrap();
        request.truncate(n);
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /download HTTP/1.1\r\nHost: cdn.example.com\r\nX-Secret: value\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        );

        far.write_all(GOOD_RESPONSE).await.unwrap();
        task.await.unwrap().unwrap();
    }

    /// The server refuses a request carrying one, so sending it would make
    /// every connection fail.
    #[tokio::test]
    async fn no_websocket_key_is_sent() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received);
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let n = far.read(&mut request).await.unwrap();
        let request = String::from_utf8(request[..n].to_vec()).unwrap();
        assert!(
            !request.to_lowercase().contains("sec-websocket"),
            "request carried a websocket header: {request}"
        );

        far.write_all(GOOD_RESPONSE).await.unwrap();
        task.await.unwrap().unwrap();
    }

    /// Same defect as on the server side, seen from the other end.
    #[tokio::test]
    async fn the_payload_after_the_header_block_reaches_the_inner_handler() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received.clone());
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let _ = far.read(&mut request).await.unwrap();
        far.write_all(GOOD_RESPONSE).await.unwrap();

        task.await.unwrap().unwrap();
        assert_eq!(&*received.lock().unwrap(), b"PAYLOAD");
    }

    async fn response_is_rejected(response: &'static [u8]) -> String {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received);
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let _ = far.read(&mut request).await.unwrap();
        far.write_all(response).await.unwrap();

        match task.await.unwrap() {
            Ok(_) => panic!("the client accepted a response it should have refused"),
            Err(e) => e.to_string(),
        }
    }

    #[tokio::test]
    async fn a_non_101_response_is_an_error_that_quotes_it() {
        let message =
            response_is_rejected(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        assert!(message.contains("404 Not Found"), "got {message}");
    }

    #[tokio::test]
    async fn a_response_without_the_upgrade_headers_is_an_error() {
        let message = response_is_rejected(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n",
        )
        .await;
        assert!(message.to_lowercase().contains("upgrade"), "got {message}");
    }

    /// UDP-over-TCP is the inner protocol's business; this transport only
    /// reports what the thing it wraps can do.
    #[test]
    fn udp_support_is_the_inner_handlers_answer() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(None, None, received);
        assert!(!handler.supports_udp_over_tcp());
    }

    /// Go writes Host from the request field, so a header of that name in the
    /// configuration is ignored, and Connection and Upgrade are overwritten.
    /// Ours must not emit any of the three twice.
    #[tokio::test]
    async fn configured_headers_cannot_forge_the_upgrade() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = client(
            Some("real.example.com"),
            Some(vec![
                ("Host", "forged.example.com"),
                ("Connection", "keep-alive"),
                ("Upgrade", "h2c"),
            ]),
            received,
        );
        let (near, mut far) = duplex(8192);

        let task = tokio::spawn(async move {
            handler
                .setup_client_tcp_stream(Box::new(TestStream(near)), target())
                .await
        });

        let mut request = vec![0u8; 512];
        let n = far.read(&mut request).await.unwrap();
        request.truncate(n);
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /download HTTP/1.1\r\nHost: real.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        );

        far.write_all(GOOD_RESPONSE).await.unwrap();
        task.await.unwrap().unwrap();
    }
}
