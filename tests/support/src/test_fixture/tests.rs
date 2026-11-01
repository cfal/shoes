use super::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn fixture(port: u16) -> BuiltFixture {
    BuiltFixture {
        _tun_route: None,
        _guards: Vec::new(),
        _local_servers: Vec::new(),
        _config_files: Vec::new(),
        _certs: Vec::new(),
        _tun_handles: Vec::new(),
        entry_ip: "127.0.0.1".into(),
        entry_port: port,
        local_server_ip: Some("127.0.0.1".into()),
        local_server_port: Some(port),
        local_server_protocol: Some(LocalServerProtocol::Http),
        tun_interface: None,
        tun_virtual_server_ip: None,
    }
}

#[tokio::test]
async fn local_success_helpers_reject_http_errors_with_nonempty_bodies() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for streaming in [false, true] {
            for (status, succeeds) in [("200 OK", true), ("502 Bad Gateway", false)] {
                let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
                let fixture = fixture(listener.local_addr().unwrap().port());
                let body = b"a complete nonempty response";
                let ((), result) = tokio::join!(
                    async {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            assert!(request.len() < 8192);
                            request.push(stream.read_u8().await.unwrap());
                        }
                        let headers = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let mut response = headers.into_bytes();
                        response.extend_from_slice(body);
                        stream.write_all(&response).await.unwrap();
                        stream.shutdown().await.unwrap();
                    },
                    AssertUnwindSafe(async {
                        if streaming {
                            fixture
                                .test_local_server_streaming("/", false, 5)
                                .await
                                .unwrap();
                        } else {
                            assert_eq!(fixture.test_local_server("/", false).await.unwrap(), body);
                        }
                    })
                    .catch_unwind()
                );
                if succeeds {
                    assert!(result.is_ok(), "streaming={streaming}: success rejected");
                } else {
                    let panic = result.expect_err("HTTP 502 must not satisfy a success helper");
                    let message = panic.downcast_ref::<String>().unwrap();
                    assert!(
                        message.contains("curl failed with exit code: Some(22)"),
                        "{message}"
                    );
                }
            }
        }
    })
    .await
    .expect("local HTTP helper regression timed out");
}
