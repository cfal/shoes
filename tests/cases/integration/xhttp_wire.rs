use std::{io, net::SocketAddr, time::Duration};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::json;
use shoes_test_support::{
    process::ProcessGuard,
    test_fixture::start_shoes_server,
    test_servers::{TestServer, start_tcp_stream_echo_server},
    xray,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    task::JoinSet,
};

use super::fixture::{POST_BYTES, Result, port};

struct WireServer {
    address: SocketAddr,
    _process: (ProcessGuard, tempfile::NamedTempFile),
    _echo: TestServer,
}

impl WireServer {
    async fn start() -> Result<Self> {
        let echo = start_tcp_stream_echo_server("0.0.0.0", 0).await?;
        let remote = port();
        let ready = port();
        let process = start_shoes_server(&serde_yaml::to_string(&json!([
            {"address":format!("0.0.0.0:{remote}"),"protocol":{"type":"xhttp",
                "path":"/wire","host":"front.test","mode":"packet-up",
                "sc_max_each_post_bytes":POST_BYTES,
                "limits":{"packet_timeout_secs":2,"max_session_buffered_bytes":65536,
                    "max_buffered_bytes":131072,"max_sessions":2,"max_pending_sessions":2},
                "protocol":{"type":"forward","target":format!("127.0.0.1:{}",echo.local_addr().port())}}},
            {"address":format!("0.0.0.0:{ready}"),"protocol":{"type":"socks"}}
        ]))?)?;
        xray::wait_socks(([127, 0, 0, 1], ready).into()).await?;
        Ok(Self {
            address: ([127, 0, 0, 1], remote).into(),
            _process: process,
            _echo: echo,
        })
    }

    async fn request(
        &self,
        tasks: &mut JoinSet<()>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Response<Incoming>> {
        self.request_headers(tasks, method, path, body, "front.test", true)
            .await
    }

    async fn request_headers(
        &self,
        tasks: &mut JoinSet<()>,
        method: &str,
        path: &str,
        body: &[u8],
        host: &str,
        padding: bool,
    ) -> Result<Response<Incoming>> {
        let socket = tokio::net::TcpStream::connect(self.address).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
        tasks.spawn(async move {
            let _ = connection.await;
        });
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host);
        if padding {
            request = request.header(
                "referer",
                format!("https://front.test/?x_padding={}", "X".repeat(100)),
            );
        }
        Ok(tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(request.body(Full::new(Bytes::copy_from_slice(body)))?),
        )
        .await??)
    }
}

async fn read_bytes(body: &mut Incoming, length: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while data.len() < length {
            let frame = body
                .frame()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))??;
            if let Ok(bytes) = frame.into_data() {
                data.extend_from_slice(&bytes);
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(data)
}

#[tokio::test]
async fn reordered_packets_duplicates_and_download_ownership() -> Result {
    let server = WireServer::start().await?;
    let mut tasks = JoinSet::new();
    for (sequence, data, expected) in [
        (1, b"second".as_slice(), StatusCode::OK),
        (1, b"second", StatusCode::OK),
        (1, b"conflict", StatusCode::CONFLICT),
        (0, b"first", StatusCode::OK),
    ] {
        assert_eq!(
            server
                .request(&mut tasks, "POST", &format!("/wire/order/{sequence}"), data)
                .await?
                .status(),
            expected
        );
    }
    let download = server
        .request(&mut tasks, "GET", "/wire/order", b"")
        .await?;
    assert_eq!(download.status(), StatusCode::OK);
    let mut body = download.into_body();
    assert_eq!(read_bytes(&mut body, 11).await?, b"firstsecond");
    assert_eq!(
        server
            .request(&mut tasks, "GET", "/wire/order", b"")
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        server
            .request(&mut tasks, "POST", "/wire/order/2", b"tail")
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(read_bytes(&mut body, 4).await?, b"tail");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), body.frame())
            .await
            .is_err(),
        "duplicate bytes or unexpected EOF"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_requests_do_not_consume_session_admission() -> Result {
    let server = WireServer::start().await?;
    let mut tasks = JoinSet::new();
    for attempt in 0..3 {
        for (method, path, host, padding, data, expected) in [
            (
                "GET",
                "/wrong/session",
                "front.test",
                true,
                Vec::new(),
                StatusCode::NOT_FOUND,
            ),
            (
                "GET",
                "/wire/session",
                "wrong.test",
                true,
                Vec::new(),
                StatusCode::NOT_FOUND,
            ),
            (
                "GET",
                "/wire/session",
                "front.test",
                false,
                Vec::new(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "POST",
                "/wire/session/0",
                "front.test",
                true,
                vec![0; POST_BYTES + 1],
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                "POST",
                "/wire/",
                "front.test",
                true,
                Vec::new(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "POST",
                "/wire/gap/1024",
                "front.test",
                true,
                b"too far ahead".to_vec(),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let path = path
                .replace("session", &format!("session{attempt}"))
                .replace("gap", &format!("gap{attempt}"));
            let response = server
                .request_headers(&mut tasks, method, &path, &data, host, padding)
                .await?;
            assert_eq!(response.status(), expected, "{method} {path} host={host}");
            if expected == StatusCode::NOT_FOUND {
                assert!(!response.headers().contains_key("x-accel-buffering"));
                assert!(!response.headers().contains_key("content-type"));
            }
        }
    }
    assert_eq!(
        server
            .request(&mut tasks, "POST", "/wire/healthy/0", b"alive")
            .await?
            .status(),
        StatusCode::OK
    );
    let mut body = server
        .request(&mut tasks, "GET", "/wire/healthy", b"")
        .await?
        .into_body();
    assert_eq!(read_bytes(&mut body, 5).await?, b"alive");
    Ok(())
}

#[tokio::test]
async fn slow_packet_body_outlives_idle_timeout_but_stalled_body_releases_admission() -> Result {
    let server = WireServer::start().await?;
    let mut tasks = JoinSet::new();
    let download = server.request(&mut tasks, "GET", "/wire/slow", b"").await?;
    assert_eq!(download.status(), StatusCode::OK);
    let mut body = download.into_body();
    let data = super::payload(20 * 1024, 81);
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut upload = tokio::net::TcpStream::connect(server.address).await?;
        let headers = format!(
            "POST /wire/slow/0 HTTP/1.1\r\n\
             Host: front.test\r\n\
             Referer: /?x_padding={}\r\n\
             Content-Length: {}\r\n\r\n",
            "X".repeat(100),
            data.len(),
        );
        upload.write_all(headers.as_bytes()).await?;
        let start = tokio::time::Instant::now();
        for chunk in data.chunks(1024) {
            upload.write_all(chunk).await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(start.elapsed() > Duration::from_secs(2));
        let mut line = String::new();
        BufReader::new(upload).read_line(&mut line).await?;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        assert_eq!(read_bytes(&mut body, data.len()).await?, data);

        // Repeat more times than the pending-session limit, without a download.
        for id in 0..3 {
            let mut stalled = tokio::net::TcpStream::connect(server.address).await?;
            let request = format!(
                "POST /wire/stalled{id}/0 HTTP/1.1\r\n\
                 Host: front.test\r\n\
                 Referer: /?x_padding={}\r\n\
                 Content-Length: 4096\r\n\r\nx",
                "X".repeat(100),
            );
            stalled.write_all(request.as_bytes()).await?;
            let mut line = String::new();
            tokio::time::timeout(
                Duration::from_secs(4),
                BufReader::new(stalled).read_line(&mut line),
            )
            .await??;
            assert!(line.starts_with("HTTP/1.1 408"), "{line}");
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}
