use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    client::Client,
    connector::Security,
    stream::{Body, Memory, Tasks, pipe},
};
use crate::{
    address::NetLocation,
    async_stream::AsyncStream,
    config::xhttp::{XhttpClientConfig, XhttpMode, XhttpVersion},
    resources::Budget,
    tcp::carrier_dialer::{CarrierDialer, RouteKey},
};

#[derive(Debug)]
struct Dialer {
    address: SocketAddr,
    key: RouteKey,
    opens: AtomicUsize,
}

#[async_trait]
impl CarrierDialer for Dialer {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }
    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(
            tokio::net::TcpStream::connect(self.address).await?,
        ))
    }
}

fn client(version: XhttpVersion) -> Arc<Client> {
    let config: XhttpClientConfig = serde_json::from_value(serde_json::json!({
        "mode":"stream-one", "limits":{"response_header_timeout_secs":1},
        "pool":{"max_connections":2,"idle_timeout_secs":1},
        "protocol":{"type":"socks"}
    }))
    .unwrap();
    configured_client(config, version, XhttpMode::StreamOne)
}

fn configured_client(
    config: XhttpClientConfig,
    version: XhttpVersion,
    mode: XhttpMode,
) -> Arc<Client> {
    Arc::new(
        Client::new(
            config,
            NetLocation::from_str("localhost:80", None).unwrap(),
            "localhost".into(),
            version,
            mode,
            Security::Plain,
        )
        .unwrap(),
    )
}

async fn echo_peer(version: XhttpVersion, drain: bool) -> (SocketAddr, Tasks) {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    let tasks = Tasks::new();
    tasks.spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = tokio::select! {
                accepted = listener.accept() => accepted.unwrap(),
                _ = connections.join_next(), if !connections.is_empty() => continue,
            };
            connections.spawn(async move {
                if version == XhttpVersion::H1 {
                    let service = hyper::service::service_fn(
                        |request: Request<hyper::body::Incoming>| async {
                            let mut incoming = request.into_body();
                            // Headers deliberately wait for the client's inner handshake.
                            let first = incoming
                                .frame()
                                .await
                                .unwrap()
                                .unwrap()
                                .into_data()
                                .unwrap();
                            let memory =
                                Memory::new(Arc::new(Budget::new(Some(1024 * 1024))), 1024 * 1024);
                            let (mut write, read) = pipe(memory);
                            let tasks = Arc::new(Tasks::new());
                            tasks.spawn(async move {
                                write.write_all(&first).await.unwrap();
                                super::carrier::receive_hyper(incoming, write, None).await;
                            });
                            Ok::<_, io::Error>(Response::new(Body::stream(read).with_guard(tasks)))
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .half_close(true)
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                } else {
                    let mut connection = h2::server::handshake(stream).await.unwrap();
                    let mut requests = tokio::task::JoinSet::new();
                    loop {
                        let request = tokio::select! {
                            request = connection.accept() => request,
                            _ = requests.join_next(), if !requests.is_empty() => continue,
                        };
                        let Some(Ok((request, mut respond))) = request else {
                            break;
                        };
                        if drain {
                            connection.graceful_shutdown();
                        }
                        requests.spawn(async move {
                            let mut incoming = request.into_body();
                            let Some(Ok(first)) = incoming.data().await else {
                                return;
                            };
                            incoming
                                .flow_control()
                                .release_capacity(first.len())
                                .unwrap();
                            let Ok(mut send) = respond.send_response(Response::new(()), false)
                            else {
                                return;
                            };
                            if send.send_data(first, false).is_err() {
                                return;
                            }
                            while let Some(Ok(data)) = incoming.data().await {
                                incoming
                                    .flow_control()
                                    .release_capacity(data.len())
                                    .unwrap();
                                if send.send_data(data, false).is_err() {
                                    return;
                                }
                            }
                            let _ = send.send_data(Bytes::new(), true);
                        });
                    }
                }
            });
        }
    });
    (address, tasks)
}

#[tokio::test]
async fn delayed_headers_half_close_and_pool_isolation() {
    for version in [XhttpVersion::H1, XhttpVersion::H2] {
        let (address, _server) = echo_peer(version, false).await;
        let client = client(version);
        let first = Arc::new(Dialer {
            address,
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let second = Arc::new(Dialer {
            address,
            key: RouteKey(vec![2]),
            opens: AtomicUsize::new(0),
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut survivor = client.open(first.clone()).await.unwrap();
            survivor.write_all(b"ok\0\xff").await.unwrap();
            survivor.read_exact(&mut [0; 4]).await.unwrap();
            for dialer in [first.clone(), first.clone(), second.clone()] {
                let mut stream = client.open(dialer).await.unwrap();
                stream.write_all(b"data: raw bytes\n\n").await.unwrap();
                stream.shutdown().await.unwrap();
                let mut result = Vec::new();
                stream.read_to_end(&mut result).await.unwrap();
                assert_eq!(result, b"data: raw bytes\n\n");
            }
            survivor.write_all(b"still alive").await.unwrap();
            let mut result = [0; 11];
            survivor.read_exact(&mut result).await.unwrap();
            assert_eq!(&result, b"still alive");
            survivor.shutdown().await.unwrap();
            assert_eq!(survivor.read(&mut [0; 1]).await.unwrap(), 0);
        })
        .await
        .unwrap();
        assert_eq!(
            first.opens.load(Ordering::Relaxed),
            if version == XhttpVersion::H1 { 3 } else { 1 }
        );
        assert_eq!(second.opens.load(Ordering::Relaxed), 1);
        let weak = Arc::downgrade(&client);
        drop(client);
        tokio::task::yield_now().await;
        assert!(weak.upgrade().is_none());
    }
}

#[tokio::test]
async fn h2_streaming_early_responses_preserve_download_tails() {
    for mode in [XhttpMode::StreamOne, XhttpMode::StreamUp] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
            let tasks = Tasks::new();
            let expected: Vec<_> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
            let response_bytes = expected.clone();
            tasks.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::Builder::new()
                    .initial_window_size(1024)
                    .handshake(socket)
                    .await
                    .unwrap();
                let requests = Tasks::new();
                let uploaded = tokio_util::sync::CancellationToken::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let uploaded = uploaded.clone();
                    let response_bytes = response_bytes.clone();
                    requests.spawn(async move {
                        let post = request.method() == http::Method::POST;
                        let mut incoming = request.into_body();
                        if post {
                            assert_eq!(incoming.data().await.unwrap().unwrap(), &[7; 1024][..]);
                            uploaded.cancel();
                        } else {
                            uploaded.cancelled().await;
                        }
                        let upload_only = post && mode == XhttpMode::StreamUp;
                        let mut send = respond
                            .send_response(Response::new(()), upload_only)
                            .unwrap();
                        if !upload_only {
                            send.send_data(Bytes::from(response_bytes), true).unwrap();
                        }
                        // Dropping the unread POST queues NO_ERROR after its response.
                    });
                }
            });
            let config = serde_json::from_value(serde_json::json!({
                "limits":{"max_buffered_bytes":65536,"max_session_buffered_bytes":65536},
                "protocol":{"type":"socks"}
            }))
            .unwrap();
            let client = configured_client(config, XhttpVersion::H2, mode);
            let dialer = Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            });
            let mut stream = client.open(dialer.clone()).await.unwrap();
            stream.write_all(&[7; 2048]).await.unwrap();
            stream.write.closed().await;
            let mut actual = Vec::new();
            stream.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, expected);
            stream._tasks.wait().await;
            assert!(stream.write_all(b"after response").await.is_err());
            assert_eq!(dialer.opens.load(Ordering::Relaxed), 1);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn idle_routes_are_evicted_and_failed_dials_do_not_fill_the_pool() {
    let (address, _server) = echo_peer(XhttpVersion::H2, false).await;
    let client = client(XhttpVersion::H2);
    let dial = |key, address| {
        Arc::new(Dialer {
            address,
            key: RouteKey(vec![key]),
            opens: AtomicUsize::new(0),
        })
    };
    let unavailable = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let bad_address = ([127, 0, 0, 1], unavailable.local_addr().unwrap().port()).into();
    drop(unavailable);
    assert!(client.open(dial(99, bad_address)).await.is_err());
    tokio::time::timeout(Duration::from_secs(5), async {
        for key in 0..6 {
            let dialer = dial(key, address);
            let mut stream = client.open(dialer.clone()).await.unwrap();
            stream.write_all(b"route").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"route");
            assert_eq!(dialer.opens.load(Ordering::Relaxed), 1);
            drop(stream);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn carrier_idle_timeout_starts_after_the_last_session_finishes() {
    let (address, _server) = echo_peer(XhttpVersion::H2, false).await;
    let client = client(XhttpVersion::H2);
    let dialer = Arc::new(Dialer {
        address,
        key: RouteKey(vec![1]),
        opens: AtomicUsize::new(0),
    });
    let mut first = client.open(dialer.clone()).await.unwrap();
    first.write_all(b"a").await.unwrap();
    assert_eq!(first.read_u8().await.unwrap(), b'a');
    tokio::time::sleep(Duration::from_millis(1100)).await;
    first.shutdown().await.unwrap();
    assert_eq!(first.read(&mut [0; 1]).await.unwrap(), 0);
    drop(first);
    tokio::task::yield_now().await;
    let second = client.open(dialer.clone()).await.unwrap();
    assert_eq!(dialer.opens.load(Ordering::Relaxed), 1);
    drop(second);
}

#[tokio::test]
async fn draining_carriers_keep_their_physical_pool_slots_until_tails_finish() {
    let (address, _server) = echo_peer(XhttpVersion::H2, true).await;
    let config = serde_json::from_value(serde_json::json!({
        "pool":{"max_connections":1},"protocol":{"type":"socks"}
    }))
    .unwrap();
    let client = configured_client(config, XhttpVersion::H2, XhttpMode::StreamOne);
    let dialer = Arc::new(Dialer {
        address,
        key: RouteKey(vec![1]),
        opens: AtomicUsize::new(0),
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut first = client.open(dialer.clone()).await.unwrap();
        first.write_all(b"a").await.unwrap();
        assert_eq!(first.read_u8().await.unwrap(), b'a');
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(client.open(dialer.clone()).await.is_err());
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 1);
        first.write_all(b"tail").await.unwrap();
        first.shutdown().await.unwrap();
        let mut tail = Vec::new();
        first.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"tail");
        drop(first);
        tokio::task::yield_now().await;
        let second = client.open(dialer.clone()).await.unwrap();
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 2);
        drop(second);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_goaway_retires_carrier_without_closing_active_response() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (address, _server) = echo_peer(XhttpVersion::H2, true).await;
        let memory = Memory::new(Arc::new(Budget::new(Some(1024 * 1024))), 1024 * 1024);
        let tasks = Tasks::new();
        let carrier = super::carrier::Carrier::tcp(
            Box::new(tokio::net::TcpStream::connect(address).await.unwrap()),
            XhttpVersion::H2,
            8192,
        )
        .await
        .unwrap();
        let (mut writer, reader) = pipe(memory.clone());
        writer.write_all(b"first").await.unwrap();
        let mut response = carrier
            .request(
                Request::post("http://localhost/")
                    .body(Body::stream(reader))
                    .unwrap(),
                memory,
                &tasks,
                Duration::from_secs(1),
            )
            .await
            .unwrap()
            .into_body();
        assert_eq!(response.read_u8().await.unwrap(), b'f');
        while !carrier.closed() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        writer.write_all(b" tail").await.unwrap();
        writer.shutdown().await.unwrap();
        let mut tail = Vec::new();
        response.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"irst tail");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_and_delayed_response_errors_reach_reader() {
    for respond in [true, false] {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0; 8192];
            assert!(stream.read(&mut header).await.unwrap() > 0);
            if respond {
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
            std::future::pending::<()>().await;
        });
        let client = client(XhttpVersion::H1);
        let mut stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        stream.write_all(b"handshake").await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        if respond {
            assert!(error.to_string().contains("403"), "{error}");
        } else {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }
}

#[tokio::test]
async fn client_download_does_not_reserve_the_same_bytes_twice() {
    for global_limit in [16384, 65536] {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
            let tasks = Tasks::new();
            tasks.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((_, mut respond))) = connection.accept().await {
                    let mut send = respond.send_response(Response::new(()), false).unwrap();
                    send.send_data(Bytes::from(vec![42; 16384]), true).unwrap();
                }
            });
            let config = serde_json::from_value(serde_json::json!({
                "limits":{"max_buffered_bytes":global_limit,
                    "max_session_buffered_bytes": if global_limit == 16384 {65536} else {16384}},
                "protocol":{"type":"socks"}
            }))
            .unwrap();
            let client = configured_client(config, XhttpVersion::H2, XhttpMode::StreamOne);
            let mut stream = client
                .open(Arc::new(Dialer {
                    address,
                    key: RouteKey(vec![1]),
                    opens: AtomicUsize::new(0),
                }))
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![42; 16384]);
        })
        .await
        .expect("download must progress at an exact one-frame byte budget");
    }
}

#[tokio::test]
async fn sent_packet_releases_bytes_before_acknowledgement() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let (download, mut downloads) = tokio::sync::mpsc::channel(1);
            let mut uploads = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                if request.method() == http::Method::GET {
                    download
                        .send(respond.send_response(Response::new(()), false).unwrap())
                        .await
                        .unwrap();
                    continue;
                }
                let send = downloads.recv().await.unwrap();
                uploads.spawn(async move {
                    let mut body = request.into_body();
                    let mut size = 0;
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        size += data.len();
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    assert_eq!(size, 16384);
                    super::carrier::send_h2(
                        Body::Chunks([Bytes::from(vec![7; 512 * 1024])].into()),
                        send,
                    )
                    .await
                    .unwrap();
                    respond.send_response(Response::new(()), true).unwrap();
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_max_each_post_bytes":16384,
            "limits":{"max_buffered_bytes":16384,"max_session_buffered_bytes":16384},
            "protocol":{"type":"socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        let (mut read, mut write) = tokio::io::split(stream);
        let ((), bytes) = tokio::join!(
            async {
                write.write_all(&[42; 16384]).await.unwrap();
                write.shutdown().await.unwrap();
            },
            async {
                let mut bytes = Vec::new();
                read.read_to_end(&mut bytes).await.unwrap();
                bytes
            }
        );
        assert_eq!(bytes, vec![7; 512 * 1024]);
    })
    .await
    .expect("download before the POST acknowledgement must not deadlock");
}

#[tokio::test]
async fn packet_upload_pipelines_written_requests_before_acknowledgement() {
    for (request_limit, byte_limit, depth, hold_head_only) in [
        (9, 4 * 1024 * 1024, 30, false),
        (128, 8 * 1024, 30, false),
        (128, 4 * 1024 * 1024, 8, true),
    ] {
        tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let (seen, mut received) = tokio::sync::mpsc::channel(16);
        let release = tokio_util::sync::CancellationToken::new();
        let released = release.clone();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut uploads = tokio::task::JoinSet::new();
            let mut downloads = Vec::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                if request.method() == http::Method::GET {
                    downloads.push(respond.send_response(Response::new(()), false).unwrap());
                    continue;
                }
                let seen = seen.clone();
                let released = released.clone();
                uploads.spawn(async move {
                    assert_eq!(request.headers()[http::header::CONTENT_LENGTH], "1024");
                    let sequence: usize = request
                        .uri()
                        .path()
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        bytes.extend_from_slice(&chunk);
                    }
                    assert_eq!(bytes, vec![sequence as u8; 1024]);
                    seen.send(sequence).await.unwrap();
                        if !hold_head_only || sequence == 0 {
                            released.cancelled().await;
                        }
                    respond.send_response(Response::new(()), true).unwrap();
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_max_each_post_bytes":1024, "sc_min_posts_interval_ms":1,
                "packet_pipeline_depth":depth,
            "limits":{"max_requests_per_session":request_limit, "max_session_buffered_bytes":byte_limit},
            "pool":{"max_connections":1}, "protocol":{"type":"socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let mut stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        for sequence in 0..9 {
            stream.write_all(&[sequence; 1024]).await.unwrap();
        }
        for sequence in 0..8 {
            assert_eq!(received.recv().await.unwrap(), sequence);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), received.recv())
                .await
                .is_err()
        );
        release.cancel();
        assert_eq!(received.recv().await.unwrap(), 8);
        stream.shutdown().await.unwrap();
    })
    .await
    .expect("packet sending must pipeline until its explicit request or byte bound");
    }
}

#[tokio::test]
async fn client_aggregate_packet_limit_releases_capacity_after_session_cancellation() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let (seen, mut received) = tokio::sync::mpsc::channel(8);
        let release = tokio_util::sync::CancellationToken::new();
        let released = release.clone();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut uploads = tokio::task::JoinSet::new();
            let mut downloads = Vec::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                if request.method() == http::Method::GET {
                    downloads.push(respond.send_response(Response::new(()), false).unwrap());
                    continue;
                }
                let seen = seen.clone();
                let released = released.clone();
                uploads.spawn(async move {
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        bytes.extend_from_slice(&chunk);
                    }
                    seen.send(bytes).await.unwrap();
                    released.cancelled().await;
                    let _ = respond.send_response(Response::new(()), true);
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_max_each_post_bytes": 1024,
            "sc_min_posts_interval_ms": 1,
            "limits": {"max_requests": 2},
            "pool": {"max_connections": 1},
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let dialer = Arc::new(Dialer {
            address,
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let mut first = client.open(dialer.clone()).await.unwrap();
        let mut second = client.open(dialer).await.unwrap();
        first.write_all(&[1; 1024]).await.unwrap();
        assert_eq!(received.recv().await.unwrap(), [1; 1024]);
        second.write_all(&[2; 2048]).await.unwrap();
        assert_eq!(received.recv().await.unwrap(), [2; 1024]);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), received.recv())
                .await
                .is_err()
        );
        drop(first);
        assert_eq!(received.recv().await.unwrap(), [2; 1024]);
        release.cancel();
        second.shutdown().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_lanes_reacquire_after_h2_goaway() {
    for sessions in [1, 4] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
            let tasks = Tasks::new();
            let (seen, mut received) = tokio::sync::mpsc::channel(8);
            let retire = tokio_util::sync::CancellationToken::new();
            let retired = retire.clone();
            tasks.spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                let mut index = 0;
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    let index = {
                        let current = index;
                        index += 1;
                        current
                    };
                    let seen = seen.clone();
                    let retired = retired.clone();
                    connections.spawn(async move {
                        let mut connection = h2::server::handshake(socket).await.unwrap();
                        let mut downloads = Vec::new();
                        let mut uploads = tokio::task::JoinSet::new();
                        let mut draining = false;
                        loop {
                            let request = tokio::select! {
                                _ = retired.cancelled(), if index == 0 && !draining => {
                                    connection.graceful_shutdown();
                                    draining = true;
                                    continue;
                                },
                                request = connection.accept() => request,
                            };
                            let Some(Ok((request, mut respond))) = request else {
                                break;
                            };
                            if request.method() == http::Method::GET {
                                downloads
                                    .push(respond.send_response(Response::new(()), false).unwrap());
                                continue;
                            }
                            let seen = seen.clone();
                            uploads.spawn(async move {
                                let path = request.uri().path().to_owned();
                                let mut body = request.into_body();
                                let mut bytes = Vec::new();
                                while let Some(data) = body.data().await {
                                    let data = data.unwrap();
                                    bytes.extend_from_slice(&data);
                                    body.flow_control().release_capacity(data.len()).unwrap();
                                }
                                respond.send_response(Response::new(()), true).unwrap();
                                seen.send((index, path, bytes)).await.unwrap();
                            });
                        }
                    });
                }
            });
            let config = serde_json::from_value(serde_json::json!({
                "sc_max_each_post_bytes":1,"sc_min_posts_interval_ms":1,
                "pool":{"max_connections":2},"protocol":{"type":"socks"}
            }))
            .unwrap();
            let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
            let dialer = Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            });
            let mut streams = Vec::new();
            for _ in 0..sessions {
                let mut stream = client.open(dialer.clone()).await.unwrap();
                stream.write_all(b"a").await.unwrap();
                streams.push(stream);
            }
            let mut paths = std::collections::BTreeSet::new();
            for _ in 0..sessions {
                let (index, path, bytes) = received.recv().await.unwrap();
                assert_eq!(index, 0);
                assert_eq!(bytes, b"a");
                paths.insert(path.strip_suffix("/0").unwrap().to_owned());
            }
            retire.cancel();
            tokio::time::sleep(Duration::from_millis(200)).await;
            for stream in &mut streams {
                stream.write_all(b"b").await.unwrap();
            }
            for _ in 0..sessions {
                let (index, path, bytes) = received.recv().await.unwrap();
                assert_eq!(index, 1);
                assert_eq!(bytes, b"b");
                assert!(paths.remove(path.strip_suffix("/1").unwrap()));
            }
            assert!(paths.is_empty());
            assert_eq!(dialer.opens.load(Ordering::Relaxed), 2);
        })
        .await
        .expect("retired packet lanes must reuse one exact-route replacement");
    }
}

#[tokio::test]
async fn h2_header_timeout_retires_the_carrier() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
    let tasks = Tasks::new();
    tasks.spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                let mut pending = Vec::new();
                while let Some(Ok(request)) = connection.accept().await {
                    pending.push(request);
                }
            });
        }
    });
    let client = client(XhttpVersion::H2);
    let dialer = Arc::new(Dialer {
        address,
        key: RouteKey(vec![1]),
        opens: AtomicUsize::new(0),
    });
    for _ in 0..2 {
        let mut stream = client.open(dialer.clone()).await.unwrap();
        stream.shutdown().await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
    assert_eq!(dialer.opens.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn client_accepts_server_padding_wider_than_its_own_range() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(|_: Request<hyper::body::Incoming>| async {
                Ok::<_, io::Error>(
                    Response::builder()
                        .header("x-padding", "X".repeat(20000))
                        .body(Body::Chunks([Bytes::from_static(b"ok")].into()))
                        .unwrap(),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .half_close(true)
                .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                .await;
        });
        let client = client(XhttpVersion::H1);
        let mut stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"ok");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_bursts_release_opportunistic_request_lanes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let (seen, mut received) = tokio::sync::mpsc::channel(3);
        let release = tokio_util::sync::CancellationToken::new();
        let released = release.clone();
        tasks.spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::Builder::new()
                .max_concurrent_streams(4)
                .handshake::<_, Bytes>(stream)
                .await
                .unwrap();
            let mut downloads = Vec::new();
            let mut uploads = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                if request.method() == http::Method::GET {
                    downloads.push(
                        respond
                            .send_response(Response::<()>::new(()), false)
                            .unwrap(),
                    );
                    continue;
                }
                let seen = seen.clone();
                let released = released.clone();
                uploads.spawn(async move {
                    let mut body = request.into_body();
                    while let Some(chunk) = body.data().await {
                        body.flow_control()
                            .release_capacity(chunk.unwrap().len())
                            .unwrap();
                    }
                    seen.send(()).await.unwrap();
                    released.cancelled().await;
                    respond.send_response(Response::new(()), true).unwrap();
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_max_each_post_bytes":16384, "sc_min_posts_interval_ms":1,
            "limits":{"max_requests_per_connection":4},
            "pool":{"max_connections":1}, "protocol":{"type":"socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let dialer = Arc::new(Dialer {
            address,
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let mut first = client.open(dialer.clone()).await.unwrap();
        first.write_all(&[42; 3 * 16384]).await.unwrap();
        for _ in 0..3 {
            received.recv().await.unwrap();
        }
        assert!(client.open(dialer.clone()).await.is_err());
        release.cancel();
        let second = loop {
            if let Ok(stream) = client.open(dialer.clone()).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 1);
        drop((first, second));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_shutdown_preserves_an_active_download_tail() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for slow_reader in [false, true] {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
            let tasks = Tasks::new();
            let uploaded = tokio_util::sync::CancellationToken::new();
            tasks.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                let mut requests = tokio::task::JoinSet::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let uploaded = uploaded.clone();
                    requests.spawn(async move {
                        if request.method() == http::Method::GET {
                            let mut send = respond.send_response(Response::new(()), false).unwrap();
                            uploaded.cancelled().await;
                            if slow_reader {
                                send.send_data(Bytes::from(vec![42; 96 * 1024]), true)
                                    .unwrap();
                                return;
                            }
                            for index in 0..8 {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                if send
                                    .send_data(Bytes::from(vec![index; 1024]), index == 7)
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        } else {
                            let mut body = request.into_body();
                            while let Some(data) = body.data().await {
                                body.flow_control()
                                    .release_capacity(data.unwrap().len())
                                    .unwrap();
                            }
                            respond.send_response(Response::new(()), true).unwrap();
                            uploaded.cancel();
                        }
                    });
                }
            });
            let config = serde_json::from_value(serde_json::json!({
                "download_idle_timeout_secs": 1,
                "protocol":{"type":"socks"}
            }))
            .unwrap();
            let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
            let mut stream = client
                .open(Arc::new(Dialer {
                    address,
                    key: RouteKey(vec![1]),
                    opens: AtomicUsize::new(0),
                }))
                .await
                .unwrap();
            stream.write_all(b"request").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            if slow_reader {
                let mut buffer = [0; 4096];
                loop {
                    let size = stream.read(&mut buffer).await.unwrap();
                    if size == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..size]);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                assert_eq!(bytes.len(), 96 * 1024);
                assert!(bytes.iter().all(|byte| *byte == 42));
            } else {
                stream.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes.len(), 8192);
                for (index, chunk) in bytes.chunks(1024).enumerate() {
                    assert!(chunk.iter().all(|byte| *byte == index as u8));
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_download_idle_timeout_starts_after_upload_and_resets_on_progress() {
    tokio::time::timeout(Duration::from_secs(6), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let (download, ready) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut download = Some(download);
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                assert_eq!(request.method(), http::Method::GET);
                download
                    .take()
                    .unwrap()
                    .send(respond.send_response(Response::new(()), false).unwrap())
                    .unwrap();
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "download_idle_timeout_secs": 1,
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let mut stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        let mut download = ready.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(1200), stream.read_u8())
                .await
                .is_err(),
            "an open upload must not start the tail timer"
        );
        stream.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(600), stream.read_u8())
                .await
                .is_err()
        );
        download.send_data(Bytes::from_static(b"x"), false).unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'x');
        assert!(
            tokio::time::timeout(Duration::from_millis(600), stream.read_u8())
                .await
                .is_err(),
            "download progress must extend the deadline"
        );
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(stream);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_shutdown_waits_for_acknowledgement() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let (seen, received) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let mut packet = Some((seen, released));
            let mut downloads = Vec::new();
            let mut uploads = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                if request.method() == http::Method::GET {
                    downloads.push(respond.send_response(Response::new(()), false).unwrap());
                    continue;
                }
                let (seen, released) = packet.take().unwrap();
                uploads.spawn(async move {
                    let mut body = request.into_body();
                    let mut data = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        data.extend_from_slice(&chunk);
                    }
                    seen.send(data).unwrap();
                    released.await.unwrap();
                    respond.send_response(Response::new(()), true).unwrap();
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "limits":{"max_sessions":1, "packet_timeout_secs":1, "response_header_timeout_secs":1}, "protocol":{"type":"socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let dialer = Arc::new(Dialer {
            address,
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let mut stream = client.open(dialer.clone()).await.unwrap();
        stream.write_all(b"pending packet").await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), stream.flush())
            .await
            .expect("flush must not wait for the remote acknowledgement")
            .unwrap();
        let mut shutdown = Box::pin(stream.shutdown());
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert_eq!(received.await.unwrap(), b"pending packet");
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(futures::poll!(&mut shutdown).is_pending());
        release.send(()).unwrap();
        shutdown.as_mut().await.unwrap();
        drop(shutdown);
        assert!(tokio::time::timeout(Duration::from_millis(1200), stream.read(&mut [0; 1]))
            .await
            .is_err());
        drop(stream);
        let next = loop {
            if let Ok(stream) = client.open(dialer.clone()).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        drop(next);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn h1_packet_upload_inactivity_and_deferred_ack() {
    use super::carrier::{Carrier, Timeouts};

    for stalled in [false, true] {
        let (client, mut peer) = tokio::io::duplex(4096);
        let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H1, 8192)
            .await
            .unwrap();
        let budget = Arc::new(Budget::new(Some(128 * 1024)));
        let memory = Memory::new(budget.clone(), 128 * 1024);
        let chunks = (0..64)
            .map(|_| memory.copy(&[b'x'; 1024]).unwrap())
            .collect();
        let tasks = Arc::new(Tasks::new());
        let request = Request::post("http://localhost/packet/0")
            .body(Body::Chunks(chunks))
            .unwrap();
        let reservation = carrier.reserve().await.unwrap();
        let post = tokio::spawn({
            let carrier = carrier.clone();
            let tasks = tasks.clone();
            async move {
                carrier
                    .request_reserved(
                        request,
                        memory,
                        &tasks,
                        Timeouts::packet(Duration::from_millis(100), Duration::from_secs(1)),
                        reservation,
                    )
                    .await
            }
        });
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(peer.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(headers)
                .unwrap()
                .to_ascii_lowercase()
                .contains("content-length: 65536")
        );
        if stalled {
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        }
        let started = tokio::time::Instant::now();
        for _ in 0..if stalled { 32 } else { 64 } {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut bytes = [0; 1024];
            peer.read_exact(&mut bytes).await.unwrap();
            assert!(bytes.iter().all(|byte| *byte == b'x'));
            assert!(!post.is_finished());
        }
        if stalled {
            let error = post.await.unwrap().err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() > Duration::from_secs(3));
            assert!(carrier.closed());
            let mut tail = Vec::new();
            peer.read_to_end(&mut tail).await.unwrap();
            assert!(
                tail.iter().all(|byte| *byte == b'x'),
                "request must not replay"
            );
        } else {
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(
                !post.is_finished(),
                "FIN disarms the packet timer, not just the header timer"
            );
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let mut response = post.await.unwrap().unwrap().into_body();
            assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
        }
        tokio::task::yield_now().await;
        assert_eq!(budget.snapshot().active, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn h1_abandoned_packet_fails_without_waiting_for_inactivity() {
    use super::carrier::{Carrier, Timeouts};

    for status in [200, 413] {
        let (client, mut peer) = tokio::io::duplex(1024);
        let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H1, 8192)
            .await
            .unwrap();
        let memory = Memory::new(Arc::new(Budget::new(Some(128 * 1024))), 128 * 1024);
        let tasks = Arc::new(Tasks::new());
        let chunks = (0..4)
            .map(|_| memory.copy(&[0; 16 * 1024]).unwrap())
            .collect();
        let reservation = carrier.reserve().await.unwrap();
        let post = tokio::spawn({
            let tasks = tasks.clone();
            let carrier = carrier.clone();
            async move {
                carrier
                    .request_reserved(
                        Request::post("http://localhost/packet/0")
                            .body(Body::Chunks(chunks))
                            .unwrap(),
                        memory,
                        &tasks,
                        Timeouts::packet(Duration::from_secs(1), Duration::from_secs(300)),
                        reservation,
                    )
                    .await
            }
        });
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(peer.read_u8().await.unwrap());
        }
        peer.write_all(format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await
            .unwrap();
        if status == 200 {
            drop(peer);
        }
        let error = tokio::time::timeout(Duration::from_secs(1), post)
            .await
            .unwrap()
            .unwrap()
            .err()
            .unwrap();
        assert_ne!(error.kind(), io::ErrorKind::TimedOut);
        if status == 413 {
            assert!(error.to_string().contains("413"));
        }
        assert!(carrier.closed());
    }
}

#[tokio::test(start_paused = true)]
async fn h2_packet_fin_is_on_the_last_payload_frame() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let tasks = Tasks::new();
    let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
    tasks.spawn(async move {
        connection.await.unwrap();
    });
    peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let (_response, send) = sender
        .send_request(
            Request::post("https://localhost/packet/0")
                .header("content-length", 2048)
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    tasks.spawn(async move {
        super::carrier::send_h2(
            Body::Chunks(vec![Bytes::from(vec![42; 1024]), Bytes::from(vec![42; 1024])].into()),
            send,
        )
        .await
        .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut received = 0;
        loop {
            let mut header = [0; 9];
            peer.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            let mut payload = vec![0; length];
            peer.read_exact(&mut payload).await.unwrap();
            if header[3] == 0 {
                assert!(payload.iter().all(|byte| *byte == 42));
                received += length;
                if received == 2048 {
                    assert_ne!(header[4] & 1, 0, "final DATA must carry END_STREAM");
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn h2_packet_upload_inactivity_and_early_or_deferred_ack() {
    use super::carrier::{Carrier, Timeouts};

    for stalled in [false, true] {
        let (client, peer) = tokio::io::duplex(4096);
        let server_tasks = Tasks::new();
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        server_tasks.spawn(async move {
            let mut connection: h2::server::Connection<_, Bytes> = h2::server::Builder::new()
                .initial_window_size(1024)
                .handshake(peer)
                .await
                .unwrap();
            while let Some(request) = connection.accept().await {
                requests.send(request.unwrap()).unwrap();
            }
        });
        let carrier = Carrier::tcp(Box::new(client), XhttpVersion::H2, 8192)
            .await
            .unwrap();
        let tasks = Arc::new(Tasks::new());
        let budget = Arc::new(Budget::new(Some(128 * 1024)));
        let memory = Memory::new(budget.clone(), 128 * 1024);
        let chunks = (0..4)
            .map(|_| memory.copy(&[b'x'; 16 * 1024]).unwrap())
            .collect();
        let request = Request::post("https://localhost/packet/0")
            .body(Body::Chunks(chunks))
            .unwrap();
        let reservation = carrier.reserve().await.unwrap();
        let post = tokio::spawn({
            let tasks = tasks.clone();
            let carrier = carrier.clone();
            async move {
                carrier
                    .request_reserved(
                        request,
                        memory,
                        &tasks,
                        Timeouts::packet(Duration::from_millis(100), Duration::from_secs(1)),
                        reservation,
                    )
                    .await
            }
        });
        let (request, mut respond) = received.recv().await.unwrap();
        let mut body = request.into_body();
        if stalled {
            respond.send_response(Response::new(()), true).unwrap();
        }
        let started = tokio::time::Instant::now();
        let mut total = 0;
        while total < if stalled { 32 * 1024 } else { 64 * 1024 } {
            let data = body.data().await.unwrap().unwrap();
            assert!(data.iter().all(|byte| *byte == b'x'));
            total += data.len();
            tokio::time::sleep(Duration::from_millis(100)).await;
            body.flow_control().release_capacity(data.len()).unwrap();
            assert!(!post.is_finished());
        }
        if stalled {
            let error = post.await.unwrap().err().unwrap();
            assert_eq!(
                error.kind(),
                io::ErrorKind::TimedOut,
                "early response must not disarm upload watchdog"
            );
            assert!(started.elapsed() > Duration::from_secs(3));
            while let Some(data) = body.data().await {
                if let Err(error) = data {
                    assert_eq!(error.reason(), Some(h2::Reason::CANCEL));
                    break;
                }
            }
        } else {
            while let Some(data) = body.data().await {
                assert!(data.unwrap().is_empty());
            }
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(!post.is_finished());
            respond.send_response(Response::new(()), true).unwrap();
            let mut response = post.await.unwrap().unwrap().into_body();
            assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
        }
        tokio::task::yield_now().await;
        assert!(received.try_recv().is_err(), "request must not replay");
        assert_eq!(budget.snapshot().active, 0);
        let fresh = Tasks::new();
        let memory = Memory::new(budget.clone(), 128 * 1024);
        let probe = carrier.request(
            Request::get("https://localhost/probe")
                .body(Body::Empty)
                .unwrap(),
            memory,
            &fresh,
            Duration::from_secs(1),
        );
        let reply = async {
            let (_, mut respond) = received.recv().await.unwrap();
            respond.send_response(Response::new(()), true).unwrap();
        };
        let (response, ()) = tokio::join!(probe, reply);
        assert_eq!(
            response
                .unwrap()
                .into_body()
                .read(&mut [0; 1])
                .await
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn h1_waiting_packet_ack_does_not_consume_another_sessions_connections() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let (seen, mut received) = tokio::sync::mpsc::channel(8);
        let release = tokio_util::sync::CancellationToken::new();
        let released = release.clone();
        tasks.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                let released = released.clone();
                connections.spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: Request<hyper::body::Incoming>| {
                            let seen = seen.clone();
                            let released = released.clone();
                            async move {
                                if request.method() == http::Method::GET {
                                    let memory =
                                        Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
                                    let (writer, reader) = pipe(memory);
                                    return Ok::<_, io::Error>(Response::new(
                                        Body::stream(reader).with_guard(writer),
                                    ));
                                }
                                let data = request.into_body().collect().await.unwrap().to_bytes();
                                seen.send(data).await.unwrap();
                                released.cancelled().await;
                                Ok(Response::new(Body::Empty))
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_max_each_post_bytes": 1024,
            "sc_min_posts_interval_ms": 1,
            "pool": {"max_h1_connections": 4},
            "protocol": {"type": "socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H1, XhttpMode::PacketUp);
        let dialer = Arc::new(Dialer {
            address,
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let mut first = client.open(dialer.clone()).await.unwrap();
        first.write_all(&[1; 3072]).await.unwrap();
        assert_eq!(received.recv().await.unwrap().as_ref(), &[1; 1024]);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), received.recv())
                .await
                .is_err()
        );
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 2);
        let mut second = client.open(dialer.clone()).await.unwrap();
        second.write_all(&[2; 1024]).await.unwrap();
        assert_eq!(received.recv().await.unwrap().as_ref(), &[2; 1024]);
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 4);
        release.cancel();
        tokio::try_join!(first.shutdown(), second.shutdown()).unwrap();
        for _ in 0..2 {
            assert_eq!(received.recv().await.unwrap().as_ref(), &[1; 1024]);
        }
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 4);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h1_packet_connection_close_redials_without_replaying_packets() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let received = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let packets = received.clone();
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                let (socket, _) = tokio::select! {
                    accepted = listener.accept() => accepted.unwrap(),
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                let packets = packets.clone();
                connections.spawn(async move {
                    let service = hyper::service::service_fn(
                        move |request: Request<hyper::body::Incoming>| {
                            let packets = packets.clone();
                            async move {
                                if request.method() == http::Method::GET {
                                    let memory =
                                        Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
                                    let (writer, reader) = pipe(memory);
                                    return Ok::<_, io::Error>(Response::new(
                                        Body::stream(reader).with_guard(writer),
                                    ));
                                }
                                let path = request.uri().path().to_owned();
                                let data = request.into_body().collect().await.unwrap().to_bytes();
                                packets.lock().push((path, data));
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                Ok(Response::builder()
                                    .header("connection", "close")
                                    .body(Body::Empty)
                                    .unwrap())
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        let config =
            serde_json::from_value(serde_json::json!({"protocol":{"type":"socks"}})).unwrap();
        let client = configured_client(config, XhttpVersion::H1, XhttpMode::PacketUp);
        let dialer = Arc::new(Dialer {
            address,
            key: RouteKey(vec![1]),
            opens: AtomicUsize::new(0),
        });
        let mut stream = client.open(dialer.clone()).await.unwrap();
        for byte in 0..3 {
            stream.write_all(&[byte]).await.unwrap();
            stream.flush().await.unwrap();
            while received.lock().len() <= byte as usize {
                tokio::task::yield_now().await;
            }
        }
        stream.shutdown().await.unwrap();
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 4);
        let received = received.lock();
        assert_eq!(received.len(), 3);
        for (sequence, (path, bytes)) in received.iter().enumerate() {
            assert!(path.ends_with(&format!("/{sequence}")));
            assert_eq!(bytes.as_ref(), &[sequence as u8]);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tiny_writes_bound_packet_fragments_without_losing_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
        let tasks = Tasks::new();
        let packets = Arc::new(parking_lot::Mutex::new(std::collections::BTreeMap::new()));
        let received = packets.clone();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut downloads = Vec::new();
            let mut uploads = tokio::task::JoinSet::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                if request.method() == http::Method::GET {
                    downloads.push(respond.send_response(Response::new(()), false).unwrap());
                    continue;
                }
                let sequence: usize = request
                    .uri()
                    .path()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                let received = received.clone();
                uploads.spawn(async move {
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    let mut fragments = 0;
                    while let Some(data) = body.data().await {
                        let data = data.unwrap();
                        fragments += 1;
                        bytes.extend_from_slice(&data);
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    assert!(
                        fragments <= 2 * bytes.len().div_ceil(super::stream::CHUNK),
                        "uncoalesced packet: {fragments} fragments for {} bytes",
                        bytes.len()
                    );
                    received.lock().insert(sequence, bytes);
                    respond.send_response(Response::new(()), true).unwrap();
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_min_posts_interval_ms":100, "protocol":{"type":"socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
        let mut stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        let payload: Vec<u8> = (0..2048).map(|index| (index % 251) as u8).collect();
        for byte in &payload {
            stream.write_u8(*byte).await.unwrap();
        }
        stream.shutdown().await.unwrap();
        let packets = packets.lock();
        assert!(packets.values().any(|packet| packet.len() > 64));
        assert_eq!(
            packets.values().flatten().copied().collect::<Vec<_>>(),
            payload
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn packet_pacing_stages_more_than_one_pipe_without_serializing_flushes() {
    tokio::time::timeout(Duration::from_secs(8), async {
        for (size, count) in [(16 * 1024, 64), (1200, 256)] {
            let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
            let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
            let packets = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let received = packets.clone();
            let tasks = Tasks::new();
            tasks.spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(socket).await.unwrap();
                let mut downloads = Vec::new();
                let mut requests = tokio::task::JoinSet::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    if request.method() == http::Method::GET {
                        downloads.push(respond.send_response(Response::new(()), false).unwrap());
                        continue;
                    }
                    let received = received.clone();
                    requests.spawn(async move {
                        let mut body = request.into_body();
                        let mut size = 0;
                        while let Some(data) = body.data().await {
                            let data = data.unwrap();
                            assert!(data.iter().all(|byte| *byte == 42));
                            size += data.len();
                            body.flow_control().release_capacity(data.len()).unwrap();
                        }
                        received.lock().push(size);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        respond.send_response(Response::new(()), true).unwrap();
                    });
                }
            });
            let config = serde_json::from_value(serde_json::json!({
                "sc_min_posts_interval_ms":if size == 1200 { 1000 } else { 100 },
                "limits":{"max_session_buffered_bytes": 1200000},
                "protocol":{"type":"socks"}
            }))
            .unwrap();
            let client = configured_client(config, XhttpVersion::H2, XhttpMode::PacketUp);
            let mut stream = client
                .open(Arc::new(Dialer {
                    address,
                    key: RouteKey(vec![1]),
                    opens: AtomicUsize::new(0),
                }))
                .await
                .unwrap();
            let data = vec![42; size];
            for _ in 0..count {
                stream.write_all(&data).await.unwrap();
                stream.flush().await.unwrap();
            }
            stream.shutdown().await.unwrap();
            let packets = packets.lock();
            assert_eq!(packets.iter().sum::<usize>(), size * count);
            let threshold = if size == 1200 { 64 * size } else { 64 * 1024 };
            assert!(packets.iter().any(|size| *size > threshold), "{packets:?}");
            assert!(packets.len() < 10, "{packets:?}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn split_requests_share_service_across_listener_addresses() {
    use crate::{
        client_proxy_selector::ClientProxySelector,
        config::ServerProxyConfig,
        resolver::{NativeResolver, Resolver},
        tcp::{
            tcp_handler::TcpServerSetupResult,
            tcp_server_handler_factory::{HandlerServices, create_tcp_server_handler_shared},
        },
    };
    let selector = Arc::new(ClientProxySelector::new(vec![]));
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let config: ServerProxyConfig =
        serde_json::from_value(serde_json::json!({"type":"xhttp","protocol":{"type":"socks"}}))
            .unwrap();
    let mut services = HandlerServices::default();
    let tasks = Tasks::new();
    let mut carriers = Vec::new();
    for ip in ["0.0.0.0", "::"] {
        let handler = create_tcp_server_handler_shared(
            config.clone(),
            &selector,
            &resolver,
            Some(ip.parse().unwrap()),
            &mut services,
        )
        .unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        tasks.spawn(async move {
            let TcpServerSetupResult::Session(run) =
                handler.setup_server_stream(Box::new(server)).await.unwrap()
            else {
                panic!("expected XHTTP session");
            };
            run.await;
        });
        carriers.push(
            super::carrier::Carrier::tcp(Box::new(client), XhttpVersion::H1, 8192)
                .await
                .unwrap(),
        );
    }
    let memory = Memory::new(Arc::new(Budget::new(Some(1024 * 1024))), 1024 * 1024);
    let request = |method: &str, path: &str, body| {
        Request::builder()
            .method(method)
            .uri(format!("http://localhost/{path}"))
            .header(
                "referer",
                format!("https://localhost/?x_padding={}", "X".repeat(100)),
            )
            .body(body)
            .unwrap()
    };
    let mut ack = carriers[0]
        .request(
            request(
                "POST",
                "shared/0",
                Body::Chunks([Bytes::from_static(&[5, 1, 0])].into()),
            ),
            memory.clone(),
            &tasks,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .into_body();
    assert_eq!(ack.read(&mut [0; 1]).await.unwrap(), 0);
    let mut down = carriers[1]
        .request(
            request("GET", "shared", Body::Empty),
            memory,
            &tasks,
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .into_body();
    let mut greeting = [0; 2];
    tokio::time::timeout(Duration::from_secs(1), down.read_exact(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(greeting, [5, 0]);
}

pub(super) async fn quic_pair(
    limit: u32,
) -> (
    crate::tcp::carrier_dialer::QuicCarrier,
    quinn::Connection,
    quinn::Endpoint,
) {
    quic_pair_with_window(limit, None).await
}

async fn quic_pair_with_window(
    limit: u32,
    window: Option<u32>,
) -> (
    crate::tcp::carrier_dialer::QuicCarrier,
    quinn::Connection,
    quinn::Endpoint,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut server_config = quinn::ServerConfig::with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_bidi_streams(limit.into());
    if let Some(window) = window {
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .stream_receive_window(window.into());
    }
    let server = quinn::Endpoint::server(server_config, "0.0.0.0:0".parse().unwrap()).unwrap();
    let mut client = crate::quic_endpoint::QuicEndpoint::new(
        None,
        std::net::UdpSocket::bind("0.0.0.0:0").unwrap(),
        0,
    )
    .unwrap();
    client.set_default_client_config(
        quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
    );
    let client = Arc::new(client);
    let address = ([127, 0, 0, 1], server.local_addr().unwrap().port()).into();
    let (outgoing, incoming) = tokio::join!(client.connect(address, "localhost").unwrap(), async {
        server.accept().await.unwrap().await.unwrap()
    });
    (
        crate::tcp::carrier_dialer::QuicCarrier {
            connection: outgoing.unwrap(),
            _endpoint: client,
        },
        incoming,
        server,
    )
}

async fn h3_peer(
    limit: u32,
) -> (
    Arc<super::carrier::Carrier>,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
    quinn::Endpoint,
) {
    let (outgoing, incoming, server) = quic_pair(limit).await;
    let carrier = super::carrier::Carrier::quic(outgoing, 8192).await.unwrap();
    let driver = h3::server::builder()
        .build(h3_quinn::Connection::new(incoming))
        .await
        .unwrap();
    (carrier, driver, server)
}

#[tokio::test]
async fn h3_packet_fin_does_not_write_frames_after_the_payload() {
    async fn varint(stream: &mut quinn::RecvStream) -> u64 {
        let first = stream.read_u8().await.unwrap();
        let mut value = u64::from(first & 0x3f);
        for _ in 1..(1 << (first >> 6)) {
            value = (value << 8) | u64::from(stream.read_u8().await.unwrap());
        }
        value
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let (outgoing, incoming, _endpoint) = quic_pair(1).await;
        let carrier = super::carrier::Carrier::quic(outgoing, 8192).await.unwrap();
        let tasks = Arc::new(Tasks::new());
        let memory = Memory::new(Arc::new(Budget::new(Some(4096))), 4096);
        let reservation = carrier.reserve().await.unwrap();
        let workers = tasks.clone();
        tasks.spawn(async move {
            let _ = carrier
                .request_reserved(
                    Request::post("https://localhost/packet/0")
                        .header("content-length", 1024)
                        .body(Body::Chunks([Bytes::from(vec![42; 1024])].into()))
                        .unwrap(),
                    memory,
                    &workers,
                    super::carrier::Timeouts::packet(
                        Duration::from_secs(1),
                        Duration::from_secs(1),
                    ),
                    reservation,
                )
                .await;
        });
        let (_response, mut request) = incoming.accept_bi().await.unwrap();
        assert_eq!(varint(&mut request).await, 1, "HEADERS");
        let mut headers = vec![0; varint(&mut request).await as usize];
        request.read_exact(&mut headers).await.unwrap();
        assert_eq!(varint(&mut request).await, 0, "DATA");
        assert_eq!(varint(&mut request).await, 1024);
        let mut payload = [0; 1024];
        request.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [42; 1024]);
        let tail = request.read_to_end(1024).await.unwrap();
        assert!(tail.is_empty(), "post-payload HTTP/3 frames: {tail:?}");
        tasks.cancel.cancel();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_packet_upload_inactivity_and_early_or_deferred_ack() {
    use super::carrier::{Carrier, Timeouts};

    tokio::time::timeout(Duration::from_secs(20), async {
        for stalled in [false, true] {
            let (outgoing, incoming, _endpoint) = quic_pair_with_window(2, Some(8192)).await;
            let carrier = Carrier::quic(outgoing, 8192).await.unwrap();
            let mut driver: h3::server::Connection<_, Bytes> = h3::server::builder()
                .build(h3_quinn::Connection::new(incoming))
                .await
                .unwrap();
            let server_tasks = Tasks::new();
            let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
            server_tasks.spawn(async move {
                while let Ok(Some(resolver)) = driver.accept().await {
                    requests
                        .send(resolver.resolve_request().await.unwrap())
                        .ok()
                        .unwrap();
                }
            });
            let tasks = Arc::new(Tasks::new());
            let budget = Arc::new(Budget::new(Some(256 * 1024)));
            let memory = Memory::new(budget.clone(), 256 * 1024);
            let chunks = (0..8)
                .map(|_| memory.copy(&[b'x'; 16 * 1024]).unwrap())
                .collect();
            let request = Request::post("https://localhost/packet/0")
                .body(Body::Chunks(chunks))
                .unwrap();
            let reservation = carrier.reserve().await.unwrap();
            let post = tokio::spawn({
                let tasks = tasks.clone();
                let carrier = carrier.clone();
                async move {
                    carrier
                        .request_reserved(
                            request,
                            memory,
                            &tasks,
                            Timeouts::packet(Duration::from_secs(1), Duration::from_secs(1)),
                            reservation,
                        )
                        .await
                }
            });
            let (_, mut stream) = received.recv().await.unwrap();
            if stalled {
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            }
            let started = tokio::time::Instant::now();
            let mut total = 0;
            while total < if stalled { 64 * 1024 } else { 128 * 1024 } {
                use bytes::Buf;
                let data = stream.recv_data().await.unwrap().unwrap();
                assert!(data.chunk().iter().all(|byte| *byte == b'x'));
                total += data.remaining();
                let paced = Duration::from_secs_f64(total as f64 / (32.0 * 1024.0));
                tokio::time::sleep_until(started + paced).await;
                assert!(!post.is_finished(), "stalled={stalled}, received={total}");
            }
            assert!(started.elapsed() > Duration::from_secs(1));
            if stalled {
                let error = post.await.unwrap().err().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                while stream.recv_data().await.is_ok_and(|data| data.is_some()) {}
            } else {
                assert!(stream.recv_data().await.unwrap().is_none());
                tokio::time::sleep(Duration::from_millis(2100)).await;
                assert!(!post.is_finished());
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
                let mut response = post.await.unwrap().unwrap().into_body();
                assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
            }
            tokio::task::yield_now().await;
            assert!(received.try_recv().is_err(), "request must not replay");
            assert_eq!(budget.snapshot().active, 0);
            let fresh = Tasks::new();
            let memory = Memory::new(budget.clone(), 256 * 1024);
            let probe = carrier.request(
                Request::get("https://localhost/probe")
                    .body(Body::Empty)
                    .unwrap(),
                memory,
                &fresh,
                Duration::from_secs(1),
            );
            let reply = async {
                let (_, mut stream) = received.recv().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            };
            let (response, ()) = tokio::join!(probe, reply);
            assert_eq!(
                response
                    .unwrap()
                    .into_body()
                    .read(&mut [0; 1])
                    .await
                    .unwrap(),
                0
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_stalled_packet_replacement_keeps_polling_other_acknowledgements() {
    struct Stalled {
        first: parking_lot::Mutex<Option<crate::tcp::carrier_dialer::QuicCarrier>>,
        key: RouteKey,
        opened: tokio::sync::Notify,
    }
    impl std::fmt::Debug for Stalled {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Stalled").finish_non_exhaustive()
        }
    }
    #[async_trait]
    impl CarrierDialer for Stalled {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
        async fn open_quic(&self) -> io::Result<crate::tcp::carrier_dialer::QuicCarrier> {
            if let Some(first) = self.first.lock().take() {
                return Ok(first);
            }
            self.opened.notify_one();
            std::future::pending().await
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let (outgoing, incoming, _endpoint) = quic_pair(3).await;
        let dialer = Arc::new(Stalled {
            first: parking_lot::Mutex::new(Some(outgoing)),
            key: RouteKey(vec![1]),
            opened: tokio::sync::Notify::new(),
        });
        let acknowledge = tokio_util::sync::CancellationToken::new();
        let reject = tokio_util::sync::CancellationToken::new();
        let ack = acknowledge.clone();
        let failure = reject.clone();
        let (seen, mut requests) = tokio::sync::mpsc::channel(3);
        let peer = Tasks::new();
        peer.spawn(async move {
            let mut driver: h3::server::Connection<_, Bytes> = h3::server::builder()
                .build(h3_quinn::Connection::new(incoming))
                .await
                .unwrap();
            let mut handlers = tokio::task::JoinSet::new();
            while let Ok(Some(resolver)) = driver.accept().await {
                let ack = ack.clone();
                let failure = failure.clone();
                let seen = seen.clone();
                handlers.spawn(async move {
                    let Ok((request, stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let (mut send, receive) = stream.split();
                    let status = if request.method() == http::Method::GET {
                        seen.send(None).await.unwrap();
                        http::StatusCode::OK
                    } else {
                        let sequence = request.uri().path().rsplit('/').next().unwrap();
                        let sequence = sequence.parse::<u64>().unwrap();
                        seen.send(Some(sequence)).await.unwrap();
                        if sequence == 0 {
                            ack.cancelled().await;
                            http::StatusCode::OK
                        } else {
                            failure.cancelled().await;
                            http::StatusCode::INTERNAL_SERVER_ERROR
                        }
                    };
                    send.send_response(Response::builder().status(status).body(()).unwrap())
                        .await
                        .unwrap();
                    if request.method() != http::Method::GET {
                        send.finish().await.unwrap();
                    }
                    // Unread upload bodies keep the peer's three bidi streams occupied.
                    let _receive = receive;
                    let _send = send;
                    std::future::pending::<()>().await;
                });
            }
        });
        let config = serde_json::from_value(serde_json::json!({
            "sc_max_each_post_bytes":1,"pool":{"max_connections":2},
            "protocol":{"type":"socks"}
        }))
        .unwrap();
        let client = configured_client(config, XhttpVersion::H3, XhttpMode::PacketUp);
        let mut stream = client.open(dialer.clone()).await.unwrap();
        assert_eq!(requests.recv().await.unwrap(), None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"a").await.unwrap();
        assert_eq!(requests.recv().await.unwrap(), Some(0));
        stream.write_all(b"b").await.unwrap();
        assert_eq!(requests.recv().await.unwrap(), Some(1));
        acknowledge.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.write_all(b"c").await.unwrap();
        dialer.opened.notified().await;
        reject.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .expect("packet acknowledgement was blocked by an unrelated dial")
            .unwrap_err();
        assert!(error.to_string().contains("500"), "{error}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_unused_stream_reservations_reset_without_transmitting_requests() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (carrier, mut driver, _endpoint) = h3_peer(1).await;
        let reservation = carrier.try_reserve().unwrap().unwrap();
        assert!(carrier.try_reserve().unwrap().is_none());
        let seen = Arc::new(AtomicUsize::new(0));
        let requests = seen.clone();
        let tasks = Tasks::new();
        tasks.spawn(async move {
            while let Ok(Some(resolver)) = driver.accept().await {
                if let Ok((_, mut stream)) = resolver.resolve_request().await {
                    requests.fetch_add(1, Ordering::Relaxed);
                    stream.send_response(Response::new(())).await.unwrap();
                    stream.finish().await.unwrap();
                }
            }
        });
        drop(reservation);
        let reservation = tokio::time::timeout(Duration::from_secs(1), carrier.reserve())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen.load(Ordering::Relaxed), 0);
        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
        let mut response = carrier
            .request_reserved(
                Request::get("https://localhost/")
                    .body(Body::Empty)
                    .unwrap(),
                memory,
                &tasks,
                super::carrier::Timeouts::headers(Duration::from_secs(1)),
                reservation,
            )
            .await
            .unwrap()
            .into_body();
        assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(seen.load(Ordering::Relaxed), 1);
        assert!(!carrier.closed());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_empty_data_preserves_request_and_response_bodies() {
    use bytes::Buf;

    tokio::time::timeout(Duration::from_secs(5), async {
        for payload in [b"".as_slice(), b"tail".as_slice()] {
            for trailers in [false, true] {
                let (carrier, mut driver, _endpoint) = h3_peer(1).await;
                let tasks = Tasks::new();
                let (received, receipt) = tokio::sync::oneshot::channel();
                tasks.spawn(async move {
                    let resolver = driver.accept().await.unwrap().unwrap();
                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                    let mut request_body = Vec::new();
                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                        request_body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                    }
                    received.send(request_body).unwrap();
                    stream.send_response(Response::new(())).await.unwrap();
                    for data in [
                        Bytes::new(),
                        Bytes::new(),
                        Bytes::from_static(payload),
                        Bytes::new(),
                    ] {
                        stream.send_data(data).await.unwrap();
                    }
                    if trailers {
                        let mut headers = http::HeaderMap::new();
                        headers.insert("x-test", "done".parse().unwrap());
                        stream.send_trailers(headers).await.unwrap();
                    } else {
                        stream.finish().await.unwrap();
                    }
                    let _ = driver.accept().await;
                });
                let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
                let mut response = carrier
                    .request(
                        Request::post("https://localhost/")
                            .body(Body::Chunks(
                                [
                                    Bytes::new(),
                                    Bytes::new(),
                                    Bytes::from_static(payload),
                                    Bytes::new(),
                                ]
                                .into(),
                            ))
                            .unwrap(),
                        memory,
                        &tasks,
                        Duration::from_secs(1),
                    )
                    .await
                    .unwrap()
                    .into_body();
                assert_eq!(receipt.await.unwrap(), payload);
                let mut response_body = Vec::new();
                response.read_to_end(&mut response_body).await.unwrap();
                assert_eq!(response_body, payload);
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_goaway_preserves_active_response_and_refuses_new_reservations() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (carrier, mut driver, _endpoint) = h3_peer(2).await;
        let release = tokio_util::sync::CancellationToken::new();
        let released = release.clone();
        let tasks = Tasks::new();
        tasks.spawn(async move {
            let resolver = driver.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.send_data(Bytes::from_static(b"head")).await.unwrap();
            driver.shutdown(0).await.unwrap();
            tokio::select! {
                _ = driver.accept() => panic!("connection ended before its response tail"),
                _ = released.cancelled() => {},
            }
            stream.send_data(Bytes::from_static(b"tail")).await.unwrap();
            stream.finish().await.unwrap();
            let _ = driver.accept().await;
        });
        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
        let mut response = carrier
            .request(
                Request::get("https://localhost/")
                    .body(Body::Empty)
                    .unwrap(),
                memory,
                &tasks,
                Duration::from_secs(1),
            )
            .await
            .unwrap()
            .into_body();
        let mut head = [0; 4];
        response.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"head");
        while !carrier.closed() {
            tokio::task::yield_now().await;
        }
        assert!(carrier.try_reserve().unwrap().is_none());
        release.cancel();
        let mut tail = Vec::new();
        response.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"tail");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h3_idle_upload_observes_stop_sending_without_closing_the_carrier() {
    let (carrier, mut driver, _endpoint) = h3_peer(2).await;
    let peer = Tasks::new();
    peer.spawn(async move {
        let resolver = driver.accept().await.unwrap().unwrap();
        let (_, stream) = resolver.resolve_request().await.unwrap();
        let (mut send, mut receive) = stream.split();
        send.send_response(Response::new(())).await.unwrap();
        receive.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        let _send = send;
        let _ = driver.accept().await;
    });
    let tasks = Tasks::new();
    let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
    let (_writer, reader) = pipe(memory.clone());
    let _response = carrier
        .request(
            Request::post("https://localhost/")
                .body(Body::stream(reader))
                .unwrap(),
            memory,
            &tasks,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(12), tasks.cancel.cancelled())
        .await
        .unwrap();
    assert!(!carrier.closed());
}

#[tokio::test]
async fn split_allocation_rolls_back_without_partial_batch_deadlock() {
    let (address, _server) = echo_peer(XhttpVersion::H2, false).await;
    let config = serde_json::from_value(serde_json::json!({
        "pool":{"max_connections":2},"limits":{"max_requests_per_connection":1},
        "protocol":{"type":"socks"}
    }))
    .unwrap();
    let client = configured_client(config, XhttpVersion::H2, XhttpMode::StreamUp);
    let dialer = Arc::new(Dialer {
        address,
        key: RouteKey(vec![1]),
        opens: AtomicUsize::new(0),
    });
    let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client.open(dialer.clone()), client.open(dialer.clone()))
    })
    .await
    .unwrap();
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(dialer.opens.load(Ordering::Relaxed), 2);
    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(10)).await;
    let next = client.open(dialer.clone()).await.unwrap();
    assert_eq!(dialer.opens.load(Ordering::Relaxed), 2);
    drop(next);
}

#[tokio::test]
async fn stalled_route_dials_do_not_block_other_routes_or_leak_slots_on_cancel() {
    #[derive(Debug)]
    struct Stalled {
        key: RouteKey,
        opened: tokio::sync::Notify,
    }
    #[async_trait]
    impl CarrierDialer for Stalled {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            self.opened.notify_one();
            std::future::pending().await
        }
    }
    let (address, _server) = echo_peer(XhttpVersion::H2, false).await;
    let config = serde_json::from_value(serde_json::json!({
        "pool":{"max_connections":2},"protocol":{"type":"socks"}
    }))
    .unwrap();
    let client = configured_client(config, XhttpVersion::H2, XhttpMode::StreamUp);
    let stalled = Arc::new(Stalled {
        key: RouteKey(vec![0]),
        opened: tokio::sync::Notify::new(),
    });
    let bad = {
        let client = client.clone();
        let stalled = stalled.clone();
        tokio::spawn(async move { client.open(stalled).await })
    };
    stalled.opened.notified().await;
    let dialer = Arc::new(Dialer {
        address,
        key: RouteKey(vec![1]),
        opens: AtomicUsize::new(0),
    });
    let good = tokio::time::timeout(Duration::from_secs(1), client.open(dialer))
        .await
        .unwrap()
        .unwrap();
    bad.abort();
    let _ = bad.await;
    let dialer = Arc::new(Dialer {
        address,
        key: RouteKey(vec![2]),
        opens: AtomicUsize::new(0),
    });
    let next = tokio::time::timeout(Duration::from_secs(1), client.open(dialer))
        .await
        .unwrap()
        .unwrap();
    drop(good);
    drop(next);
}

#[tokio::test]
async fn h3_response_timeout_does_not_replay_the_request() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (carrier, mut driver, _endpoint) = h3_peer(2).await;
        let seen = Arc::new(AtomicUsize::new(0));
        let received = seen.clone();
        let peer = Tasks::new();
        peer.spawn(async move {
            let mut unanswered = None;
            while let Ok(Some(resolver)) = driver.accept().await {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                if received.fetch_add(1, Ordering::Relaxed) == 0 {
                    unanswered = Some(stream);
                } else {
                    unanswered.take();
                    stream.send_response(Response::new(())).await.unwrap();
                    stream.finish().await.unwrap();
                }
            }
        });
        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
        let tasks = Tasks::new();
        let error = carrier
            .request(
                Request::post("https://localhost/packet/0")
                    .body(Body::Empty)
                    .unwrap(),
                memory.clone(),
                &tasks,
                Duration::from_millis(100),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(seen.load(Ordering::Relaxed), 1);
        let mut response = carrier
            .request(
                Request::get("https://localhost/new")
                    .body(Body::Empty)
                    .unwrap(),
                memory,
                &tasks,
                Duration::from_secs(1),
            )
            .await
            .unwrap()
            .into_body();
        assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(seen.load(Ordering::Relaxed), 2);
    })
    .await
    .unwrap();
}
