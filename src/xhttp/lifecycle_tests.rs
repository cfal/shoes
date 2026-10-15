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
    Arc::new(
        Client::new(
            config,
            NetLocation::from_str("localhost:80", None).unwrap(),
            "localhost".into(),
            version,
            XhttpMode::StreamOne,
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
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    connections.spawn(async move {
                        if version == XhttpVersion::H1 {
                            let service = hyper::service::service_fn(|request: Request<hyper::body::Incoming>| async {
                                let mut incoming = request.into_body();
                                // Headers deliberately wait for the client's inner handshake.
                                let first = incoming.frame().await.unwrap().unwrap().into_data().unwrap();
                                let memory = Memory::new(Arc::new(Budget::new(Some(1024*1024))), 1024*1024);
                                let (mut write, read) = pipe(memory);
                                let tasks = Arc::new(Tasks::new());
                                tasks.spawn(async move {
                                    write.write_all(&first).await.unwrap();
                                    super::carrier::receive_hyper(incoming, write).await;
                                });
                                Ok::<_, io::Error>(Response::new(Body::stream(read).with_guard(tasks)))
                            });
                            let _ = hyper::server::conn::http1::Builder::new().half_close(true).serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
                        } else {
                            let mut connection = h2::server::handshake(stream).await.unwrap();
                            let mut requests = tokio::task::JoinSet::new();
                            loop {
                                tokio::select! {
                                    request = connection.accept() => {
                                        let Some(Ok((request, mut respond))) = request else { break; };
                                        if drain { connection.graceful_shutdown(); }
                                        requests.spawn(async move {
                                            let mut incoming = request.into_body();
                                            let Some(Ok(first)) = incoming.data().await else { return; };
                                            incoming.flow_control().release_capacity(first.len()).unwrap();
                                            let Ok(mut send) = respond.send_response(Response::new(()), false) else { return; };
                                            if send.send_data(first, false).is_err() { return; }
                                            while let Some(Ok(data)) = incoming.data().await {
                                                incoming.flow_control().release_capacity(data.len()).unwrap();
                                                if send.send_data(data, false).is_err() { return; }
                                            }
                                            let _ = send.send_data(Bytes::new(), true);
                                        });
                                    }
                                    _ = requests.join_next(), if !requests.is_empty() => {}
                                }
                            }
                        }
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
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
        let config =
            serde_json::from_value(serde_json::json!({"protocol":{"type":"socks"}})).unwrap();
        let client = Arc::new(
            Client::new(
                config,
                NetLocation::from_str("localhost:80", None).unwrap(),
                "localhost".into(),
                XhttpVersion::H2,
                XhttpMode::PacketUp,
                Security::Plain,
            )
            .unwrap(),
        );
        let mut stream = client
            .open(Arc::new(Dialer {
                address,
                key: RouteKey(vec![1]),
                opens: AtomicUsize::new(0),
            }))
            .await
            .unwrap();
        stream.write_all(b"pending packet").await.unwrap();
        let mut shutdown = Box::pin(stream.shutdown());
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert_eq!(received.await.unwrap(), b"pending packet");
        assert!(futures::poll!(&mut shutdown).is_pending());
        release.send(()).unwrap();
        shutdown.await.unwrap();
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
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let packets = packets.clone();
                        connections.spawn(async move {
                            let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                                let packets = packets.clone();
                                async move {
                                    if request.method() == http::Method::GET {
                                        let memory = Memory::new(Arc::new(Budget::new(Some(1024))), 1024);
                                        let (writer, reader) = pipe(memory);
                                        return Ok::<_, io::Error>(Response::new(Body::stream(reader).with_guard(writer)));
                                    }
                                    let path = request.uri().path().to_owned();
                                    let data = request.into_body().collect().await.unwrap().to_bytes();
                                    packets.lock().push((path, data));
                                    Ok(Response::builder().header("connection", "close").body(Body::Empty).unwrap())
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(hyper_util::rt::TokioIo::new(socket), service).await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        let config = serde_json::from_value(serde_json::json!({"protocol":{"type":"socks"}})).unwrap();
        let client = Arc::new(Client::new(
            config,
            NetLocation::from_str("localhost:80", None).unwrap(),
            "localhost".into(),
            XhttpVersion::H1,
            XhttpMode::PacketUp,
            Security::Plain,
        ).unwrap());
        let dialer = Arc::new(Dialer {
            address, key: RouteKey(vec![1]), opens: AtomicUsize::new(0),
        });
        let mut stream = client.open(dialer.clone()).await.unwrap();
        for byte in 0..3 {
            stream.write_all(&[byte]).await.unwrap();
            stream.flush().await.unwrap();
        }
        stream.shutdown().await.unwrap();
        assert_eq!(dialer.opens.load(Ordering::Relaxed), 4);
        let received = received.lock();
        assert_eq!(received.len(), 3);
        for (sequence, (path, bytes)) in received.iter().enumerate() {
            assert!(path.ends_with(&format!("/{sequence}")));
            assert_eq!(bytes.as_ref(), &[sequence as u8]);
        }
    }).await.unwrap();
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
                Body::Full(Some(Bytes::from_static(&[5, 1, 0]))),
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
