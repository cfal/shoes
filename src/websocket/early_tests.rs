use super::*;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Context;
use std::time::Duration;

use futures::task::{ArcWake, waker};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::async_stream::AsyncPing;
use crate::async_stream::test_streams::FlushGatedStream;
use crate::client_proxy_selector::ClientProxySelector;

const BAD_REQUEST_RESPONSE: &str =
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn handshake_options(max: usize, header: Option<&str>) -> Arc<ClientHandshake> {
    Arc::new(ClientHandshake {
        authority: "example.test:80".into(),
        matching_path: Some("/ws".into()),
        matching_headers: Some(FxHashMap::from_iter([(
            "Host".into(),
            "example.test".into(),
        )])),
        ping_type: WebsocketPingType::PingFrame,
        early_data: EarlyData::new(max, header),
    })
}

fn request(path: &str, extra: &str) -> Vec<u8> {
    format!(
        concat!(
            "GET {path} HTTP/1.1\r\n",
            "Host: example.test\r\n",
            "Connection: Upgrade\r\n",
            "Upgrade: websocket\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "{extra}\r\n",
        ),
        path = path,
        extra = extra,
    )
    .into_bytes()
}

fn early_request(header: Option<&str>, encoded: &str) -> Vec<u8> {
    match header {
        Some(name) => request("/ws", &format!("{name}: {encoded}\r\n")),
        None => request(&format!("/ws{encoded}"), ""),
    }
}

#[tokio::test]
async fn parsed_headers_preserve_first_colon_and_case_insensitive_duplicates() {
    let (mut peer, server) = tokio::io::duplex(8192);
    peer.write_all(&request(
        "/ws",
        "X-Value: first:value\r\nx-VALUE:  final:value  \r\n",
    ))
    .await
    .unwrap();
    let mut server: Box<dyn AsyncStream> = Box::new(server);
    let parsed = ParsedHttpData::parse(&mut server).await.unwrap();
    assert_eq!(parsed.headers["x-value"], "first:value, final:value");
    assert_eq!(parsed.duplicates, HashSet::from(["x-value".into()]));

    peer.write_all(&request("/ws", "missing separator\r\n"))
        .await
        .unwrap();
    let error = ParsedHttpData::parse(&mut server).await.err().unwrap();
    assert_eq!(error.to_string(), "invalid http header line");
}

#[tokio::test]
async fn parsed_header_block_limit_is_inclusive() {
    for size in [MAX_HTTP, MAX_HTTP + 1] {
        let mut extra = format!("X-Pad: {}\r\n", "x".repeat(3991)).repeat(8);
        let remaining = size - request("/ws", &extra).len();
        extra.push_str(&format!(
            "X-Rest: {}\r\n",
            "x".repeat(remaining - "X-Rest: \r\n".len())
        ));
        let bytes = request("/ws", &extra);
        assert_eq!(bytes.len(), size);

        let (mut peer, server) = tokio::io::duplex(65536);
        peer.write_all(&bytes).await.unwrap();
        let mut server: Box<dyn AsyncStream> = Box::new(server);
        let result = ParsedHttpData::parse(&mut server).await;
        if size == MAX_HTTP {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.err().unwrap().to_string(),
                "http header block is too long"
            );
        }
    }
}

#[tokio::test]
async fn parsed_line_length_and_count_limits_are_exclusive() {
    for header_line in [false, true] {
        for length in [MAX_LINE - 1, MAX_LINE] {
            let bytes = if header_line {
                request("/ws", &format!("X-Pad: {}\r\n", "x".repeat(length - 7)))
            } else {
                request(&format!("/{}", "x".repeat(length - 14)), "")
            };
            assert_eq!(
                bytes
                    .split(|b| *b == b'\n')
                    .map(|line| line.len().saturating_sub(1))
                    .max(),
                Some(length)
            );
            let (mut peer, server) = tokio::io::duplex(8192);
            peer.write_all(&bytes).await.unwrap();
            let mut server: Box<dyn AsyncStream> = Box::new(server);
            let result = ParsedHttpData::parse(&mut server).await;
            if length < MAX_LINE {
                assert!(result.is_ok(), "header_line={header_line}, length={length}");
            } else {
                assert_eq!(
                    result.err().unwrap().to_string(),
                    "http request line is too long"
                );
            }
        }
    }
    for count in [MAX_HTTP_LINES - 1, MAX_HTTP_LINES] {
        let bytes = request("/ws", &"X-Pad: x\r\n".repeat(count - 6));
        let (mut peer, server) = tokio::io::duplex(8192);
        peer.write_all(&bytes).await.unwrap();
        let mut server: Box<dyn AsyncStream> = Box::new(server);
        let result = ParsedHttpData::parse(&mut server).await;
        if count < MAX_HTTP_LINES {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.err().unwrap().to_string(),
                "http request is too long"
            );
        }
    }
}

async fn accept(
    mut peer: Box<dyn AsyncStream>,
    max: usize,
    header: Option<&str>,
    expected: &[u8],
) -> WebsocketStream {
    let parsed = ParsedHttpData::parse(&mut peer).await.unwrap();
    let encoded = URL_SAFE_NO_PAD.encode(&expected[..expected.len().min(max)]);
    if let Some(header) = header {
        assert_eq!(parsed.first_line, "GET /ws HTTP/1.1");
        assert_eq!(
            parsed.headers.get(&header.to_ascii_lowercase()),
            (!encoded.is_empty()).then_some(&encoded)
        );
    } else {
        assert_eq!(parsed.first_line, format!("GET /ws{encoded} HTTP/1.1"));
    }
    let key = create_websocket_key_response(parsed.headers["sec-websocket-key"].clone());
    let response = format!(
        concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: {key}\r\n\r\n",
        ),
        key = key,
    );
    peer.write_all(response.as_bytes()).await.unwrap();
    peer.flush().await.unwrap();
    WebsocketStream::new(
        peer,
        false,
        WebsocketPingType::Disabled,
        parsed.stream_reader.unparsed_data(),
    )
}

#[derive(Debug)]
struct PassThrough(u16);

#[async_trait]
impl TcpServerHandler for PassThrough {
    async fn setup_server_stream(
        &self,
        stream: Box<dyn AsyncStream>,
    ) -> io::Result<TcpServerSetupResult> {
        Ok(TcpServerSetupResult::TcpForward {
            stream,
            remote_location: crate::address::NetLocation::from_ip_addr(
                "127.0.0.1".parse().unwrap(),
                self.0,
            ),
            need_initial_flush: false,
            connection_success_response: None,
            connection_failure_response: None,
            initial_remote_data: None,
            proxy_selector: Arc::new(ClientProxySelector::new(vec![])),
        })
    }
}

fn target(path: &str, max: usize, header: Option<&str>) -> WebsocketServerTarget {
    WebsocketServerTarget {
        matching_path: Some(path.into()),
        matching_headers: None,
        early_data: EarlyData::new(max, header),
        ping_type: WebsocketPingType::Disabled,
        handler: Box::new(PassThrough(80)),
    }
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x82, 126];
    bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[tokio::test]
async fn early_prefix_is_owned_and_split_exactly_once_for_all_carriers() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for header in [None, Some("X-Early-Data"), Some("Sec-WebSocket-Protocol")] {
            for length in [1, 2, 31, 32, 33, 70_000] {
                let (client, peer) = tokio::io::duplex(37);
                let mut stream = EarlyWebsocketStream::new(
                    Box::new(FlushGatedStream::new(client)),
                    handshake_options(32, header),
                );
                let original: Vec<_> = (0..length).map(|i| (i * 131 + 255) as u8).collect();
                let mut caller_buffer = original.clone();
                let n = stream.write(&caller_buffer).await.unwrap();
                assert_eq!(n, length.min(32));
                caller_buffer.fill(0);
                let expected = original.clone();
                let task = tokio::spawn(async move {
                    let mut ws = accept(Box::new(peer), 32, header, &expected).await;
                    let mut tail = vec![0; expected.len() - n];
                    ws.read_exact(&mut tail).await.unwrap();
                    assert_eq!(tail, expected[n..]);
                    ws.write_all(b"reply").await.unwrap();
                    ws.flush().await.unwrap();
                });
                stream.write_all(&original[n..]).await.unwrap();
                stream.flush().await.unwrap();
                let mut reply = [0; 5];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"reply");
                task.await.unwrap();
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn largest_validated_carriers_round_trip_above_the_automatic_cap() {
    for header in [None, Some("X-Early-Data"), Some("Sec-WebSocket-Protocol")] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let headers = HashMap::from_iter([("Host".into(), "example.test".into())]);
            let max = (2049..MAX_LINE)
                .rev()
                .find(|max| {
                    crate::websocket::validate_early_data(
                        Some("/ws"),
                        Some(&headers),
                        *max,
                        header,
                        false,
                    )
                    .is_ok()
                })
                .unwrap();
            crate::websocket::validate_early_data(Some("/ws"), None, max, header, true).unwrap();
            let (client, server) = tokio::io::duplex(65536);
            let mut client =
                EarlyWebsocketStream::new(Box::new(client), handshake_options(max, header));
            let payload: Vec<_> = (0..max + 1).map(|i| (i * 131 + 255) as u8).collect();
            assert_eq!(client.write(&payload).await.unwrap(), max);
            let handler = WebsocketTcpServerHandler::new(vec![target("/ws", max, header)]);
            let (result, sent) =
                tokio::join!(handler.setup_server_stream(Box::new(server)), async {
                    client.write_all(&payload[max..]).await.unwrap();
                    client.flush().await
                });
            sent.unwrap();
            let TcpServerSetupResult::TcpForward { mut stream, .. } = result.unwrap() else {
                panic!()
            };
            let mut received = vec![0; payload.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
            assert!(futures::poll!(Box::pin(stream.read_u8())).is_pending());
        })
        .await
        .unwrap_or_else(|_| panic!("carrier={header:?} timed out"));
    }
}

#[tokio::test]
async fn server_prefix_precedes_coalesced_frames_and_echoes_only_protocol_header() {
    for (max, header) in [
        (32, None),
        (32, Some("X-Early-Data")),
        (32, Some("Sec-WebSocket-Protocol")),
        (0, Some("Sec-WebSocket-Protocol")),
    ] {
        for length in [0, 1, 2, 31, 32, 2048] {
            if max > 0 && length > max {
                continue;
            }
            let prefix: Vec<_> = (0..length).map(|i| (i * 131 + 255) as u8).collect();
            let encoded = URL_SAFE_NO_PAD.encode(&prefix);
            let mut wire = early_request(header, &encoded);
            // More than the old 16 KiB frame buffer, but within the HTTP reader's read-ahead.
            let tail = vec![0xa5; 24000];
            wire.extend(frame(&tail));
            let (mut peer, server) = tokio::io::duplex(65536);
            peer.write_all(&wire).await.unwrap();
            let handler = WebsocketTcpServerHandler::new(vec![target(
                "/ws",
                max,
                header.filter(|_| max > 0),
            )]);
            let result = handler
                .setup_server_stream(Box::new(FlushGatedStream::new(server)))
                .await
                .unwrap();
            let TcpServerSetupResult::TcpForward {
                mut stream,
                need_initial_flush,
                ..
            } = result
            else {
                panic!()
            };
            assert!(need_initial_flush);
            let mut peer: Box<dyn AsyncStream> = Box::new(peer);
            let response =
                tokio::time::timeout(Duration::from_secs(5), ParsedHttpData::parse(&mut peer))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("upgrade timed out: max={max}, header={header:?}, length={length}")
                    })
                    .unwrap();
            assert_eq!(
                response.headers.get("sec-websocket-protocol"),
                (header == Some("Sec-WebSocket-Protocol") && length > 0).then_some(&encoded)
            );
            assert_eq!(stream.read(&mut []).await.unwrap(), 0);
            let expected = [prefix, tail].concat();
            tokio::time::timeout(Duration::from_secs(5), async {
                for byte in expected {
                    assert_eq!(stream.read_u8().await.unwrap(), byte);
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("prefix read timed out: max={max}, header={header:?}, length={length}")
            });
            assert!(futures::poll!(Box::pin(stream.read_u8())).is_pending());
        }
    }
}

#[tokio::test]
async fn malformed_early_data_is_rejected_before_upgrade_without_fallback() {
    for encoded in [
        "a", "YQ=", "YQ==", "+w", "/w", "YR", "YQ,Yg", "Y Q", "YQ?x=1", "YWJjZGU",
    ] {
        for header in [None, Some("X-Early-Data"), Some("Sec-WebSocket-Protocol")] {
            let (mut peer, server) = tokio::io::duplex(8192);
            peer.write_all(&early_request(header, encoded))
                .await
                .unwrap();
            let handler = WebsocketTcpServerHandler::new(vec![target("/ws", 4, header)]);
            assert!(
                handler.setup_server_stream(Box::new(server)).await.is_err(),
                "{encoded}"
            );
            let mut response = String::new();
            peer.read_to_string(&mut response).await.unwrap();
            assert_eq!(
                response,
                if header.is_none() && encoded == "Y Q" {
                    BAD_REQUEST_RESPONSE
                } else {
                    ""
                }
            );
        }
    }
    for (header, extra, expected_response) in [
        (
            "X-Early-Data",
            "X-Early-Data: YQ\r\nx-early-data: Yg\r\n",
            "",
        ),
        (
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Protocol: YQ\r\nsec-websocket-protocol: Yg\r\n",
            "",
        ),
        (
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Protocol: YQ\r\nHost: other.test\r\n",
            BAD_REQUEST_RESPONSE,
        ),
        (
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Protocol: YQ\r\nSec-WebSocket-Key: duplicate\r\n",
            BAD_REQUEST_RESPONSE,
        ),
    ] {
        let (mut peer, server) = tokio::io::duplex(8192);
        peer.write_all(&request("/ws", extra)).await.unwrap();
        assert!(
            WebsocketTcpServerHandler::new(vec![target("/ws", 4, Some(header))])
                .setup_server_stream(Box::new(server))
                .await
                .is_err()
        );
        let mut response = String::new();
        peer.read_to_string(&mut response).await.unwrap();
        assert_eq!(response, expected_response);
    }
}

#[tokio::test]
async fn early_data_does_not_bypass_upgrade_validation() {
    let valid = String::from_utf8(request("/ws", "Sec-WebSocket-Protocol: YQ\r\n")).unwrap();
    for max in [0, 32] {
        for invalid in [
            valid.replace("HTTP/1.1", "HTTP/1.0"),
            valid.replace("Host: example.test\r\n", ""),
            valid.replace(
                "Host: example.test",
                "Host: example.test\r\nHost: other.test",
            ),
            valid.replace("Connection: Upgrade\r\n", ""),
            valid.replace("dGhlIHNhbXBsZSBub25jZQ==", "invalid"),
        ] {
            let (mut peer, server) = tokio::io::duplex(8192);
            peer.write_all(invalid.as_bytes()).await.unwrap();
            let error = WebsocketTcpServerHandler::new(vec![target(
                "/ws",
                max,
                (max > 0).then_some("Sec-WebSocket-Protocol"),
            )])
            .setup_server_stream(Box::new(FlushGatedStream::new(server)))
            .await
            .err()
            .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "400 Bad Request");
            let mut response = String::new();
            peer.read_to_string(&mut response).await.unwrap();
            assert_eq!(response, BAD_REQUEST_RESPONSE);
        }
    }
}

#[tokio::test]
async fn overlapping_targets_reject_explicit_early_data_but_plain_routing_stays_first_match() {
    for (first_max, second_max) in [(0, 0), (32, 0), (0, 32)] {
        let (mut peer, server) = tokio::io::duplex(8192);
        peer.write_all(&request("/ws", "")).await.unwrap();
        let mut second = target("/ws", second_max, None);
        second.handler = Box::new(PassThrough(81));
        let handler = WebsocketTcpServerHandler::new(vec![target("/ws", first_max, None), second]);
        let result = handler.setup_server_stream(Box::new(server)).await;
        if first_max == 0 && second_max == 0 {
            let TcpServerSetupResult::TcpForward {
                remote_location, ..
            } = result.unwrap()
            else {
                panic!("expected first target's TCP destination")
            };
            assert_eq!(remote_location.port(), 80);
        } else {
            assert!(result.is_err());
        }
    }
    let (mut peer, server) = tokio::io::duplex(8192);
    peer.write_all(&request("/wsYQ", "")).await.unwrap();
    let handler =
        WebsocketTcpServerHandler::new(vec![target("/ws", 32, None), target("/wsYQ", 0, None)]);
    assert!(handler.setup_server_stream(Box::new(server)).await.is_err());
}

#[tokio::test]
async fn structural_matching_precedes_decoding_and_only_candidates_are_ambiguous() {
    for excluded_by in [None, Some("path"), Some("header")] {
        let mut first = target("/ws", 32, None);
        if excluded_by == Some("path") {
            first.matching_path = Some("/other".into());
        } else if excluded_by == Some("header") {
            first.matching_headers =
                Some(FxHashMap::from_iter([("x-route".into(), "other".into())]));
        }
        let (mut peer, server) = tokio::io::duplex(8192);
        // The suffix matches structurally but is not canonical base64url.
        let mut bytes = request("/ws/admin", "");
        bytes.extend(frame(b"tail"));
        peer.write_all(&bytes).await.unwrap();
        let result = WebsocketTcpServerHandler::new(vec![first, target("/ws/admin", 0, None)])
            .setup_server_stream(Box::new(server))
            .await;
        if excluded_by.is_none() {
            assert_eq!(
                result.err().unwrap().to_string(),
                "ambiguous WebSocket early data target"
            );
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        } else {
            let TcpServerSetupResult::TcpForward { mut stream, .. } = result.unwrap() else {
                panic!()
            };
            let mut received = [0; 4];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&received, b"tail");
        }
    }
}

#[tokio::test]
async fn server_factory_preserves_mixed_case_selectors_and_explicit_carrier_limits() {
    use crate::tcp::tcp_server_handler_factory::create_tcp_server_handler;
    use serde_json::json;

    for (max, token) in [(0, "chat"), (0, "YQ"), (4, "YQ"), (4, "YWJjZGU")] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut selected = json!({"matching_path": "/ws", "max_early_data": max,
                "protocol": {"type": "forward", "targets": "127.0.0.1:81"}});
            let header = if max == 0 {
                selected["matching_headers"] = json!({"Sec-WebSocket-Protocol": token});
                "Sec-WebSocket-Protocol"
            } else {
                selected["early_data_header_name"] = "X-Early".into();
                "x-EARLY"
            };
            let config = json!({"type": "ws", "targets": [selected,
                {"matching_path": if max == 0 { "/ws" } else { "/other" },
                    "protocol": {"type": "forward", "targets": "127.0.0.1:80"}}
            ]});
            let resolver: Arc<dyn crate::resolver::Resolver> =
                Arc::new(crate::resolver::NativeResolver::new());
            let handler = create_tcp_server_handler(
                serde_json::from_value(config).unwrap(),
                &Arc::new(ClientProxySelector::new(vec![])),
                &resolver,
                None,
            )
            .unwrap();
            let (mut peer, server) = tokio::io::duplex(8192);
            let mut bytes = request(
                "/ws",
                &format!("{header}: {token}\r\nX-Other: a\r\nx-other: b\r\n"),
            );
            bytes.extend(frame(b"tail"));
            peer.write_all(&bytes).await.unwrap();
            let result = handler.setup_server_stream(Box::new(server)).await;
            if token == "YWJjZGU" {
                assert_eq!(
                    result.err().unwrap().to_string(),
                    "WebSocket early data exceeds configured limit"
                );
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                return;
            }
            let TcpServerSetupResult::TcpForward {
                mut stream,
                remote_location,
                ..
            } = result.unwrap()
            else {
                panic!()
            };
            assert_eq!(remote_location.port(), 81);
            let expected = if max == 0 {
                b"tail".as_slice()
            } else {
                b"atail"
            };
            let mut received = vec![0; expected.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
            assert!(futures::poll!(Box::pin(stream.read_u8())).is_pending());
            let mut peer: Box<dyn AsyncStream> = Box::new(peer);
            let response = ParsedHttpData::parse(&mut peer).await.unwrap();
            assert!(!response.headers.contains_key("sec-websocket-protocol"));
        })
        .await
        .unwrap_or_else(|_| panic!("max={max}, token={token} timed out"));
    }
}

#[tokio::test]
async fn duplicate_matching_header_is_rejected_before_upgrade() {
    for max in [0, 32] {
        let (mut peer, server) = tokio::io::duplex(8192);
        peer.write_all(&request(
            "/ws",
            "Sec-WebSocket-Protocol: YQ\r\nX-Match: other\r\nx-match: selected\r\n",
        ))
        .await
        .unwrap();
        let mut selected = target("/ws", max, None);
        selected.matching_headers = Some(FxHashMap::from_iter([(
            "x-match".into(),
            "other, selected".into(),
        )]));
        let error = WebsocketTcpServerHandler::new(vec![selected])
            .setup_server_stream(Box::new(server))
            .await
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "duplicate WebSocket handshake header");
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn automatic_early_data_rejects_invalid_oversized_and_duplicate_headers_before_upgrade() {
    let oversized = URL_SAFE_NO_PAD.encode(vec![0; 2049]);
    let mut extras: Vec<_> = [
        "a", "YQ=", "YQ==", "+w", "/w", "YR", "binary", "a, b", "Y Q", &oversized,
    ]
    .into_iter()
    .map(|value| (format!("Sec-WebSocket-Protocol: {value}\r\n"), ""))
    .collect();
    for (first, last) in [("YQ", "Yg"), ("YQ", ""), ("", "YQ"), ("", "")] {
        extras.push((
            format!("Sec-WebSocket-Protocol: {first}\r\nsEc-WeBsOcKeT-pRoToCoL: {last}\r\n"),
            "",
        ));
    }
    for (duplicate, expected_response) in [
        ("Host: other.test", BAD_REQUEST_RESPONSE),
        ("Sec-WebSocket-Key: duplicate", BAD_REQUEST_RESPONSE),
        ("Connection: Upgrade", ""),
        ("Upgrade: websocket", ""),
        ("Sec-WebSocket-Version: 13", BAD_REQUEST_RESPONSE),
        ("Content-Length: 0\r\ncontent-length: 0", ""),
        (
            "Transfer-Encoding: chunked\r\ntransfer-encoding: chunked",
            "",
        ),
    ] {
        extras.push((
            format!("Sec-WebSocket-Protocol: YQ\r\n{duplicate}\r\n"),
            expected_response,
        ));
    }
    for catch_all in [false, true] {
        for (extra, expected_response) in &extras {
            let (mut peer, server) = tokio::io::duplex(8192);
            peer.write_all(&request("/ws", extra)).await.unwrap();
            let mut selected = target("/ws", 0, None);
            if catch_all {
                selected.matching_path = None;
            }
            assert!(
                WebsocketTcpServerHandler::new(vec![selected])
                    .setup_server_stream(Box::new(server))
                    .await
                    .is_err(),
                "{extra}"
            );
            let mut response = String::new();
            peer.read_to_string(&mut response).await.unwrap();
            assert_eq!(response, *expected_response);
        }
    }
}

#[tokio::test]
async fn automatic_routing_preserves_static_selectors_and_rejects_ambiguous_data() {
    for selector_first in [None, Some(true), Some(false)] {
        for extra in [
            "",
            "Sec-WebSocket-Protocol: \r\n",
            "Sec-WebSocket-Protocol: chat\r\n",
            "Sec-WebSocket-Protocol: YQ\r\n",
            "Sec-WebSocket-Protocol: YQ\r\nsec-websocket-protocol: \r\n",
            "Sec-WebSocket-Protocol: \r\nsec-websocket-protocol: \r\n",
        ] {
            let mut targets = vec![target("/ws", 0, None), target("/ws", 0, None)];
            targets[1].matching_path = None;
            if let Some(first) = selector_first {
                let selected = &mut targets[usize::from(!first)];
                selected.matching_headers = Some(FxHashMap::from_iter([(
                    "sec-websocket-protocol".into(),
                    "chat".into(),
                )]));
                selected.handler = Box::new(PassThrough(81));
            }
            let plain = extra.is_empty() || extra == "Sec-WebSocket-Protocol: \r\n";
            let static_token = extra == "Sec-WebSocket-Protocol: chat\r\n";
            let selected_static = selector_first == Some(true) && static_token;
            let ambiguous = !plain
                && (selector_first.is_none() || (selector_first == Some(false) && static_token));
            let duplicate = extra.contains("sec-websocket-protocol:");
            let (mut peer, server) = tokio::io::duplex(8192);
            let mut bytes = request("/ws", extra);
            bytes.extend(frame(b"tail"));
            peer.write_all(&bytes).await.unwrap();
            let result = WebsocketTcpServerHandler::new(targets)
                .setup_server_stream(Box::new(server))
                .await;
            if ambiguous || duplicate {
                let error = result.err().unwrap();
                assert_eq!(
                    error.to_string(),
                    if ambiguous {
                        "ambiguous WebSocket early data target"
                    } else {
                        "duplicate WebSocket handshake header"
                    }
                );
                assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
                continue;
            }
            let TcpServerSetupResult::TcpForward {
                mut stream,
                remote_location,
                ..
            } = result.unwrap()
            else {
                panic!()
            };
            assert_eq!(
                remote_location.port(),
                if selected_static { 81 } else { 80 }
            );
            let expected = if plain || selected_static {
                b"tail".as_slice()
            } else {
                b"atail"
            };
            let mut received = vec![0; expected.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
                .await
                .unwrap_or_else(|_| {
                    panic!("selector_first={selector_first:?}, extra={extra:?} timed out")
                })
                .unwrap();
            assert_eq!(received, expected);
            let mut peer: Box<dyn AsyncStream> = Box::new(peer);
            let response = ParsedHttpData::parse(&mut peer).await.unwrap();
            assert_eq!(
                response
                    .headers
                    .get("sec-websocket-protocol")
                    .map(String::as_str),
                (!plain && !selected_static).then_some("YQ")
            );
        }
    }
}

#[tokio::test]
async fn empty_operations_preserve_early_data_and_first_operations_can_upgrade_without_it() {
    for operation in ["read", "flush", "shutdown", "ping"] {
        let (client, mut peer) = tokio::io::duplex(8192);
        let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(32, None));
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        assert_eq!(stream.read(&mut []).await.unwrap(), 0);
        assert!(futures::poll!(Box::pin(peer.read(&mut [0]))).is_pending());
        let task = tokio::spawn(async move {
            let mut ws = accept(Box::new(peer), 32, None, &[]).await;
            ws.write_all(b"banner").await.unwrap();
            ws.flush().await.unwrap();
            if operation == "shutdown" {
                assert_eq!(ws.read(&mut [0]).await.unwrap(), 0);
            }
            ws
        });
        match operation {
            "flush" => stream.flush().await.unwrap(),
            "shutdown" => stream.shutdown().await.unwrap(),
            "ping" => {
                std::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_ping(cx))
                    .await
                    .unwrap();
            }
            _ => (),
        }
        let mut banner = [0; 6];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"banner");
        task.await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_write_never_sends_unacknowledged_bytes() {
    let (client, peer) = tokio::io::duplex(17);
    let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(32, None));
    assert_eq!(stream.write(b"accepted").await.unwrap(), 8);
    assert!(futures::poll!(Box::pin(stream.write(b"cancelled"))).is_pending());
    let task = tokio::spawn(async move {
        let mut ws = accept(Box::new(peer), 32, None, b"accepted").await;
        let mut received = Vec::new();
        ws.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"replacement");
    });
    stream.write_all(b"replacement").await.unwrap();
    stream.shutdown().await.unwrap();
    task.await.unwrap();
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelled_reader_does_not_steal_handshake_writer_wakeup() {
    for read_first in [false, true] {
        let (client, mut peer) = tokio::io::duplex(1);
        let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(32, None));
        stream.write_all(b"early").await.unwrap();
        let reader = Arc::new(WakeCount::default());
        let writer = Arc::new(WakeCount::default());
        let rw = waker(reader.clone());
        let ww = waker(writer.clone());
        if !read_first {
            assert!(
                Pin::new(&mut stream)
                    .poll_flush(&mut Context::from_waker(&ww))
                    .is_pending()
            );
        }
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut Context::from_waker(&rw), &mut ReadBuf::new(&mut [0]))
                .is_pending()
        );
        if read_first {
            assert!(
                Pin::new(&mut stream)
                    .poll_flush(&mut Context::from_waker(&ww))
                    .is_pending()
            );
        }
        let first = peer.read_u8().await.unwrap();
        assert!(reader.0.load(Ordering::SeqCst) > 0);
        assert!(writer.0.load(Ordering::SeqCst) > 0);
        let task = tokio::spawn(async move {
            let peer = PrependStream::new(peer, Some(vec![first].into_boxed_slice()));
            accept(Box::new(peer), 32, None, b"early").await;
        });
        tokio::time::timeout(Duration::from_secs(5), stream.flush())
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn independently_scheduled_split_halves_finish_upgrades_and_failures() {
    use std::future::Future;
    use tokio::sync::oneshot;

    async fn notify_first_pending<F: Future>(
        operation: F,
        pending: oneshot::Sender<()>,
    ) -> F::Output {
        let mut operation = Box::pin(operation);
        let mut pending = Some(pending);
        std::future::poll_fn(|cx| {
            let result = operation.as_mut().poll(cx);
            if result.is_pending()
                && let Some(sender) = pending.take()
            {
                sender.send(()).unwrap();
            }
            result
        })
        .await
    }

    for case in ["success", "bad-status", "eof", "timeout", "cancel-reader"] {
        let (client, peer) = tokio::io::duplex(8192);
        let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(32, None));
        stream.write_all(b"early").await.unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        let (reader_pending, reader_ready) = oneshot::channel();
        let (writer_pending, writer_ready) = oneshot::channel();
        let reader = tokio::spawn(async move {
            let mut banner = [0; 6];
            notify_first_pending(read.read_exact(&mut banner), reader_pending).await?;
            assert_eq!(&banner, b"banner");
            io::Result::Ok(())
        });
        let writer = tokio::spawn(async move {
            notify_first_pending(write.write_all(b"tail"), writer_pending).await?;
            write.shutdown().await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            reader_ready.await.unwrap();
            writer_ready.await.unwrap();
        })
        .await
        .unwrap();
        if case == "cancel-reader" {
            reader.abort();
        }
        let mut peer: Box<dyn AsyncStream> = Box::new(peer);
        let mut websocket = None;
        let mut silent_peer = None;
        if matches!(case, "success" | "cancel-reader") {
            let mut ws =
                tokio::time::timeout(Duration::from_secs(5), accept(peer, 32, None, b"early"))
                    .await
                    .unwrap();
            ws.write_all(b"banner").await.unwrap();
            ws.flush().await.unwrap();
            websocket = Some(ws);
        } else {
            let request =
                tokio::time::timeout(Duration::from_secs(5), ParsedHttpData::parse(&mut peer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(request.first_line, "GET /wsZWFybHk HTTP/1.1");
            match case {
                "bad-status" => peer
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await
                    .unwrap(),
                "timeout" => tokio::time::advance(crate::util::STREAM_SETUP_TIMEOUT).await,
                _ => (),
            }
            if case == "timeout" {
                silent_peer = Some(peer);
            } else {
                drop(peer);
            }
        }
        // A deadline around the task handles cannot rescue a lost operation wakeup.
        tokio::time::timeout(Duration::from_secs(5), async {
            let read = reader.await;
            let write = writer.await.unwrap();
            if matches!(case, "success" | "cancel-reader") {
                if case == "cancel-reader" {
                    assert!(read.unwrap_err().is_cancelled());
                } else {
                    read.unwrap().unwrap();
                }
                write.unwrap();
                let mut tail = Vec::new();
                websocket
                    .as_mut()
                    .unwrap()
                    .read_to_end(&mut tail)
                    .await
                    .unwrap();
                assert_eq!(tail, b"tail");
            } else {
                let read = read.unwrap().unwrap_err();
                let write = write.unwrap_err();
                assert_eq!(read.kind(), write.kind(), "{case}");
                assert_eq!(read.to_string(), write.to_string(), "{case}");
                if case == "timeout" {
                    assert_eq!(read.kind(), io::ErrorKind::TimedOut);
                }
                if case == "bad-status" {
                    assert_eq!(read.to_string(), "Bad websocket response status");
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("split upgrade {case} timed out"));
        drop(silent_peer);
    }
}

#[tokio::test(start_paused = true)]
async fn idle_time_and_noop_operations_do_not_start_the_upgrade_deadline() {
    let (client, mut peer) = tokio::io::duplex(8192);
    let mut options = handshake_options(32, Some("Sec-WebSocket-Protocol"));
    Arc::get_mut(&mut options).unwrap().ping_type = WebsocketPingType::Disabled;
    let mut stream = EarlyWebsocketStream::new(Box::new(client), options);
    assert_eq!(
        stream
            .write_vectored(&[io::IoSlice::new(&[])])
            .await
            .unwrap(),
        0
    );
    assert!(
        !std::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_ping(cx))
            .await
            .unwrap()
    );
    tokio::time::advance(crate::util::STREAM_SETUP_TIMEOUT + Duration::from_secs(1)).await;
    assert!(futures::poll!(Box::pin(peer.read_u8())).is_pending());
    stream.write_all(b"early").await.unwrap();
    let (result, _peer) = tokio::join!(
        stream.flush(),
        accept(Box::new(peer), 32, Some("Sec-WebSocket-Protocol"), b"early")
    );
    result.unwrap();
}

#[tokio::test(start_paused = true)]
async fn upgrade_deadline_and_failures_are_sticky() {
    let (client, _peer) = tokio::io::duplex(8192);
    let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(32, None));
    stream.write_all(b"early").await.unwrap();
    tokio::time::advance(crate::util::STREAM_SETUP_TIMEOUT + Duration::from_secs(1)).await;
    assert!(matches!(
        futures::poll!(Box::pin(stream.flush())),
        std::task::Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::TimedOut
    ));
    assert_eq!(
        stream.write(b"later").await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        stream.read(&mut [0]).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        stream.shutdown().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test]
async fn client_rejects_bad_status_accept_and_subprotocol_but_accepts_absent_or_exact_echo() {
    for case in [
        "status",
        "version",
        "accept",
        "missing-accept",
        "protocol",
        "duplicate",
        "duplicate-protocol",
        "eof",
        "none",
        "echo",
    ] {
        let (client, peer) = tokio::io::duplex(65536);
        let mut stream = EarlyWebsocketStream::new(
            Box::new(client),
            handshake_options(32, Some("Sec-WebSocket-Protocol")),
        );
        stream.write_all(b"early").await.unwrap();
        let task = tokio::spawn(async move {
            let mut peer: Box<dyn AsyncStream> = Box::new(peer);
            let parsed = ParsedHttpData::parse(&mut peer).await.unwrap();
            if case == "eof" {
                return;
            }
            let accept = if case == "accept" {
                "wrong".into()
            } else {
                create_websocket_key_response(parsed.headers["sec-websocket-key"].clone())
            };
            let status = if case == "status" { "1010" } else { "101" };
            let extra = match case {
                "protocol" => "Sec-WebSocket-Protocol: wrong\r\n".into(),
                "duplicate" => format!("Sec-WebSocket-Accept: {accept}\r\n"),
                "duplicate-protocol" => format!(
                    "Sec-WebSocket-Protocol: {}\r\n",
                    parsed.headers["sec-websocket-protocol"]
                )
                .repeat(2),
                "echo" => format!(
                    "Sec-WebSocket-Protocol: {}\r\n",
                    parsed.headers["sec-websocket-protocol"]
                ),
                _ => String::new(),
            };
            let version = if case == "version" {
                "HTTP/2"
            } else {
                "HTTP/1.1"
            };
            let accept_header = if case == "missing-accept" {
                String::new()
            } else {
                format!("Sec-WebSocket-Accept: {accept}\r\n")
            };
            let mut response = format!(
                concat!(
                    "{version} {status} Switching Protocols\r\n",
                    "Upgrade: websocket\r\n",
                    "Connection: Upgrade\r\n",
                    "{accept_header}",
                    "{extra}\r\n",
                ),
                status = status,
                version = version,
                accept_header = accept_header,
                extra = extra,
            )
            .into_bytes();
            response.extend(frame(&vec![0x33; 24000]));
            peer.write_all(&response).await.unwrap();
        });
        if matches!(case, "none" | "echo") {
            stream.flush().await.unwrap();
            let mut received = vec![0; 24000];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
                .await
                .unwrap_or_else(|_| panic!("response read timed out: {case}"))
                .unwrap();
            assert_eq!(received, vec![0x33; 24000]);
        } else {
            let first = stream.flush().await.unwrap_err().to_string();
            let expected = match case {
                "status" | "version" => "Bad websocket response status",
                "accept" => "incorrect websocket key response",
                "missing-accept" => "missing websocket key response",
                "protocol" => "unexpected WebSocket subprotocol",
                "duplicate" | "duplicate-protocol" => "duplicate WebSocket response header",
                "eof" => "EOF while reading",
                _ => unreachable!(),
            };
            assert!(first.contains(expected), "{case}: {first}");
            assert_eq!(stream.flush().await.unwrap_err().to_string(), first);
            assert_eq!(stream.write(b"later").await.unwrap_err().to_string(), first);
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn eager_client_rejects_bad_status_and_duplicate_response_headers() {
    for case in [
        "status",
        "accept",
        "duplicate-accept",
        "duplicate-protocol",
        "valid",
    ] {
        let (client, peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpClientHandler {
            handshake: handshake_options(0, None),
            handler: Box::new(crate::port_forward_handler::PortForwardClientHandler),
        };
        let task = tokio::spawn(async move {
            let mut peer: Box<dyn AsyncStream> = Box::new(peer);
            let parsed = ParsedHttpData::parse(&mut peer).await.unwrap();
            assert_eq!(parsed.first_line, "GET /ws HTTP/1.1");
            assert!(!parsed.headers.contains_key("sec-websocket-protocol"));
            let accept = if case == "accept" {
                "wrong".into()
            } else {
                create_websocket_key_response(parsed.headers["sec-websocket-key"].clone())
            };
            let status = if case == "status" { "1010" } else { "101" };
            let extra = match case {
                "duplicate-accept" => format!("Sec-WebSocket-Accept: {accept}\r\n"),
                "duplicate-protocol" => "Sec-WebSocket-Protocol: chat\r\n".repeat(2),
                _ => String::new(),
            };
            let response = format!(
                "HTTP/1.1 {status} Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
            );
            peer.write_all(response.as_bytes()).await.unwrap();
            peer
        });
        let result = handler.setup_client_stream_common(Box::new(client)).await;
        if case == "valid" {
            assert!(result.is_ok());
        } else {
            let expected = match case {
                "status" => "Bad websocket response status",
                "accept" => "incorrect websocket key response",
                _ => "duplicate WebSocket response header",
            };
            assert_eq!(result.err().unwrap().to_string(), expected);
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn eager_and_early_clients_validate_upgrade_tokens_and_preserve_read_ahead() {
    for max in [0, 32] {
        for (headers, expected_error) in [
            ("", Some("missing or invalid WebSocket Upgrade header")),
            (
                "Connection: Upgrade\r\n",
                Some("missing or invalid WebSocket Upgrade header"),
            ),
            (
                "Upgrade: h2c\r\nConnection: Upgrade\r\n",
                Some("missing or invalid WebSocket Upgrade header"),
            ),
            (
                "Upgrade: websocket-extra\r\nConnection: Upgrade\r\n",
                Some("missing or invalid WebSocket Upgrade header"),
            ),
            (
                "Upgrade: \r\nConnection: Upgrade\r\n",
                Some("missing or invalid WebSocket Upgrade header"),
            ),
            (
                "Upgrade: websocket\r\n",
                Some("missing or invalid WebSocket Connection header"),
            ),
            (
                "Upgrade: websocket\r\nConnection: keep-alive\r\n",
                Some("missing or invalid WebSocket Connection header"),
            ),
            (
                "Upgrade: websocket\r\nConnection: not-upgrade\r\n",
                Some("missing or invalid WebSocket Connection header"),
            ),
            (
                "Upgrade: websocket\r\nConnection: \r\n",
                Some("missing or invalid WebSocket Connection header"),
            ),
            ("Upgrade: websocket\r\nConnection: Upgrade\r\n", None),
            (
                "uPgRaDe: h2c, WeBsOcKeT\r\ncOnNeCtIoN: keep-alive, UpGrAdE\r\n",
                None,
            ),
            (
                "Upgrade: h2c\r\nupgrade: websocket\r\nConnection: keep-alive\r\nconnection: Upgrade\r\n",
                None,
            ),
        ] {
            tokio::time::timeout(Duration::from_secs(3), async {
                let (client, peer) = tokio::io::duplex(8192);
                let handler = WebsocketTcpClientHandler {
                    handshake: handshake_options(max, Some("Sec-WebSocket-Protocol")),
                    handler: Box::new(crate::port_forward_handler::PortForwardClientHandler),
                };
                let task = async move {
                    let mut peer: Box<dyn AsyncStream> = Box::new(peer);
                    let parsed = ParsedHttpData::parse(&mut peer).await.unwrap();
                    assert_eq!(
                        parsed.headers.get("sec-websocket-protocol").map(String::as_str),
                        (max > 0).then_some("ZWFybHk")
                    );
                    let accept =
                        create_websocket_key_response(parsed.headers["sec-websocket-key"].clone());
                    let mut response = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {accept}\r\n{headers}\r\n"
                    )
                    .into_bytes();
                    response.extend(frame(b"reply"));
                    peer.write_all(&response).await.unwrap();
                    peer
                };
                let client = async {
                    let mut stream = handler
                        .setup_client_stream_common(Box::new(FlushGatedStream::new(client)))
                        .await?;
                    if max > 0 {
                        stream.write_all(b"early").await?;
                        stream.flush().await?;
                    }
                    let mut reply = [0; 5];
                    stream.read_exact(&mut reply).await?;
                    assert_eq!(&reply, b"reply");
                    Ok::<_, io::Error>(())
                };
                let (result, _peer) = tokio::join!(client, task);
                match expected_error {
                    Some(expected) => assert_eq!(result.unwrap_err().to_string(), expected),
                    None => result.unwrap(),
                }
            })
            .await
            .unwrap_or_else(|_| panic!("upgrade timed out: max={max}, headers={headers:?}"));
        }
    }
}

#[test]
fn early_stream_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<EarlyWebsocketStream>();
}

#[derive(Debug)]
struct ReadFirstClient;

#[async_trait]
impl TcpClientHandler for ReadFirstClient {
    async fn setup_client_tcp_stream(
        &self,
        mut stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> io::Result<TcpClientSetupResult> {
        let mut banner = vec![0; 6];
        stream.read_exact(&mut banner).await?;
        Ok(TcpClientSetupResult {
            client_stream: stream,
            early_data: Some(banner),
        })
    }
}

#[tokio::test]
async fn read_first_inner_setup_and_destination_early_data_are_preserved() {
    for header in [None, Some("Sec-WebSocket-Protocol")] {
        let (client, peer) = tokio::io::duplex(8192);
        let handler = WebsocketTcpClientHandler {
            handshake: handshake_options(32, header),
            handler: Box::new(ReadFirstClient),
        };
        let task = tokio::spawn(async move {
            let mut peer = accept(Box::new(peer), 32, header, &[]).await;
            peer.write_all(b"banner").await.unwrap();
            peer.flush().await.unwrap();
            peer
        });
        let location = crate::address::NetLocation::from_ip_addr("127.0.0.1".parse().unwrap(), 80);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            handler.setup_client_tcp_stream(Box::new(client), ResolvedLocation::new(location)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.early_data.as_deref(), Some(b"banner".as_slice()));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn automatic_and_explicit_servers_prepend_data_only_after_valid_upgrade() {
    for (max, extra) in [
        (32, ""),
        (32, "Sec-WebSocket-Protocol: \r\n"),
        (32, "Sec-WebSocket-Protocol: YQ\r\n"),
        (0, ""),
        (0, "Sec-WebSocket-Protocol: \r\n"),
        (0, "Host: other.test\r\n"),
        (0, "Sec-WebSocket-Protocol: \r\nHost: other.test\r\n"),
        (0, "Sec-WebSocket-Protocol: YQ\r\n"),
    ] {
        let (mut peer, server) = tokio::io::duplex(8192);
        let mut bytes = request("/ws", extra);
        bytes.extend(frame(b"framed"));
        peer.write_all(&bytes).await.unwrap();
        let handler = WebsocketTcpServerHandler::new(vec![target(
            "/ws",
            max,
            (max > 0).then_some("Sec-WebSocket-Protocol"),
        )]);
        let result = handler.setup_server_stream(Box::new(server)).await;
        if extra.contains("Host:") {
            let error = result.err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "400 Bad Request");
            let mut response = String::new();
            peer.read_to_string(&mut response).await.unwrap();
            assert_eq!(response, BAD_REQUEST_RESPONSE);
            continue;
        }
        let TcpServerSetupResult::TcpForward { mut stream, .. } = result.unwrap() else {
            panic!()
        };
        let has_prefix = extra.contains("YQ");
        let expected = if has_prefix {
            b"aframed".as_slice()
        } else {
            b"framed"
        };
        let mut data = vec![0; expected.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut data))
            .await
            .unwrap_or_else(|_| panic!("prefix read timed out: max={max}, extra={extra:?}"))
            .unwrap();
        assert_eq!(data, expected);
        let mut peer: Box<dyn AsyncStream> = Box::new(peer);
        let response = ParsedHttpData::parse(&mut peer).await.unwrap();
        assert_eq!(
            response
                .headers
                .get("sec-websocket-protocol")
                .map(String::as_str),
            has_prefix.then_some("YQ")
        );
    }
}

#[tokio::test]
async fn automatic_reception_prevents_standard_header_loss_but_not_other_carrier_mismatches() {
    use crate::port_forward_handler::{PortForwardClientHandler, PortForwardServerHandler};

    tokio::time::timeout(Duration::from_secs(5), async {
        for (header, server_max, server_header, catch_all) in [
            (Some("X-Early-Data"), 0, None, false),
            (Some("Sec-WebSocket-Protocol"), 0, None, false),
            (Some("Sec-WebSocket-Protocol"), 0, None, true),
            (Some("X-Early-Data"), 2048, Some("X-Other"), false),
            (None, 0, None, true),
            (None, 2048, Some("X-Early-Data"), true),
            (
                Some("Sec-WebSocket-Protocol"),
                2048,
                Some("X-Early-Data"),
                false,
            ),
            (Some("Sec-WebSocket-Protocol"), 2048, None, false),
        ] {
            let (client, server) = tokio::io::duplex(8192);
            let location =
                crate::address::NetLocation::from_ip_addr("127.0.0.1".parse().unwrap(), 80);
            let client_handler = WebsocketTcpClientHandler {
                handshake: handshake_options(2048, header),
                handler: Box::new(PortForwardClientHandler),
            };
            let mut server_target = target("/ws", server_max, server_header);
            if catch_all {
                server_target.matching_path = None;
            }
            server_target.handler = Box::new(PortForwardServerHandler::new(
                vec![location.clone()],
                Arc::new(ClientProxySelector::new(vec![])),
            ));
            let server_handler = WebsocketTcpServerHandler::new(vec![server_target]);
            let mut client = client_handler
                .setup_client_tcp_stream(Box::new(client), ResolvedLocation::new(location))
                .await
                .unwrap()
                .client_stream;
            let task = tokio::spawn(async move {
                let TcpServerSetupResult::TcpForward { mut stream, .. } = server_handler
                    .setup_server_stream(Box::new(server))
                    .await
                    .unwrap()
                else {
                    panic!()
                };
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                received
            });
            let payload = [vec![0xa5; 2048], b"tail".to_vec()].concat();
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            let received = task.await.unwrap();
            if header == Some("Sec-WebSocket-Protocol") && server_max == 0 {
                assert_eq!(received, payload);
            } else {
                assert_eq!(received, b"tail");
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vectored_first_write_and_empty_slices_follow_partial_write_contract() {
    let (client, peer) = tokio::io::duplex(1024);
    let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(3, None));
    let n = stream
        .write_vectored(&[
            io::IoSlice::new(b""),
            io::IoSlice::new(b"abcdef"),
            io::IoSlice::new(b"later"),
        ])
        .await
        .unwrap();
    assert_eq!(n, 3);
    let task = tokio::spawn(async move { accept(Box::new(peer), 3, None, b"abc").await });
    stream.flush().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn dropping_pending_upgrade_closes_transport() {
    let (client, mut peer) = tokio::io::duplex(1);
    let mut stream = EarlyWebsocketStream::new(Box::new(client), handshake_options(32, None));
    stream.write_all(b"early").await.unwrap();
    assert!(futures::poll!(Box::pin(stream.flush())).is_pending());
    drop(stream);
    let mut data = Vec::new();
    peer.read_to_end(&mut data).await.unwrap();
    assert_eq!(&data, b"G");
}

struct TaggedStream {
    inner: tokio::io::DuplexStream,
    flow: Arc<crate::control::flows::FlowEntry>,
}

impl AsyncRead for TaggedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for TaggedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl AsyncPing for TaggedStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}
impl AsyncStream for TaggedStream {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        Some("127.0.0.1:4321".parse().unwrap())
    }

    fn flow(&self) -> Option<&Arc<crate::control::flows::FlowEntry>> {
        Some(&self.flow)
    }
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        Some("127.0.0.1:1234".parse().unwrap())
    }
}

#[tokio::test]
async fn transport_metadata_survives_upgrade_and_prefix_wrapping() {
    use crate::control::flows::{FlowCounters, FlowEntry, FlowMetadata};
    let flow = Arc::new(FlowEntry {
        id: "test".into(),
        generation: 1,
        start: String::new(),
        metadata: FlowMetadata::default(),
        chains: vec![],
        rule_payload: String::new(),
        counters: FlowCounters::default(),
        cancel: tokio_util::sync::CancellationToken::new(),
        notes: None,
    });
    let (inner, peer) = tokio::io::duplex(8192);
    let mut stream = EarlyWebsocketStream::new(
        Box::new(TaggedStream {
            inner,
            flow: flow.clone(),
        }),
        handshake_options(32, None),
    );
    let check = |stream: &dyn AsyncStream| {
        assert_eq!(stream.local_addr(), Some("127.0.0.1:4321".parse().unwrap()));
        assert_eq!(stream.peer_addr(), Some("127.0.0.1:1234".parse().unwrap()));
        assert!(Arc::ptr_eq(stream.flow().unwrap(), &flow));
        #[cfg(target_os = "linux")]
        assert!(stream.plain_tcp().is_none());
    };
    check(&stream);
    stream.write_all(b"early").await.unwrap();
    check(&stream);
    let task = tokio::spawn(async move { accept(Box::new(peer), 32, None, b"early").await });
    stream.flush().await.unwrap();
    check(&stream);
    check(&PrependStream::new(
        stream,
        Some(Box::from(b"prefix".as_slice())),
    ));
    task.await.unwrap();

    let (inner, _peer) = tokio::io::duplex(8192);
    let ws = WebsocketStream::new(
        Box::new(TaggedStream {
            inner,
            flow: flow.clone(),
        }),
        false,
        WebsocketPingType::Disabled,
        &[],
    );
    check(&PrependStream::new(
        ws,
        Some(Box::from(b"prefix".as_slice())),
    ));
}
