use std::{sync::Arc, time::Duration};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    client_proxy_chain::{ClientProxyChain, InitialHopEntry},
    config::{ClientConfig, Config},
    resolver::{NativeResolver, Resolver},
    tcp::{proxy_connector_impl::ProxyConnectorImpl, socket_connector_impl::SocketConnectorImpl},
};

#[tokio::test]
async fn all_modes_and_carriers_exchange_data_before_upload_eof() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let echo = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let target = format!("127.0.0.1:{}", echo.local_addr().unwrap().port());
    let mut echo_tasks = tokio::task::JoinSet::new();
    echo_tasks.spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = echo.accept() => {
                    let (mut socket, _) = result.unwrap();
                    clients.spawn(async move {
                        let (mut read, mut write) = socket.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });
    let half_close = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let half_close_target = format!("127.0.0.1:{}", half_close.local_addr().unwrap().port());
    let (received, mut uploads) = tokio::sync::mpsc::channel(1);
    echo_tasks.spawn(async move {
        while let Ok((mut socket, _)) = half_close.accept().await {
            socket.write_all(b"fin").await.unwrap();
            socket.shutdown().await.unwrap();
            let mut upload = Vec::new();
            socket.read_to_end(&mut upload).await.unwrap();
            received.send(upload).await.unwrap();
        }
    });
    let sink = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let sink_target = format!("127.0.0.1:{}", sink.local_addr().unwrap().port());
    let (finished, mut transfers) = tokio::sync::mpsc::channel(1);
    echo_tasks.spawn(async move {
        while let Ok((mut socket, _)) = sink.accept().await {
            let mut total = 0;
            let mut buffer = [0; 16 * 1024];
            while total < 8 * 1024 * 1024 {
                let size = socket.read(&mut buffer).await.unwrap();
                assert_ne!(size, 0, "packet upload was cut off after {total} bytes");
                assert!(buffer[..size].iter().all(|byte| *byte == 83));
                total += size;
                tokio::time::sleep(Duration::from_millis(4)).await;
            }
            finished.send(total).await.unwrap();
            let _ = socket.read(&mut buffer).await;
        }
    });
    for (version, peer_limit, local_limit) in [
        ("h1", 128, 128),
        ("h2", 128, 128),
        ("h3", 128, 128),
        ("h2", 1, 128),
        ("h3", 1, 128),
        ("h2", 128, 1),
        ("h3", 128, 1),
    ] {
        for mode in ["packet-up", "stream-up", "stream-one"] {
            eprintln!(
                "testing {version} {mode}, peer limit {peer_limit}, local limit {local_limit}"
            );
            let reserved = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
            let port = reserved.local_addr().unwrap().port();
            let address = format!("127.0.0.1:{port}");
            let server_protocol = json!({"type":"xhttp", "path":"/tunnel", "http_version":version,
                "matching_headers":{"X-Tunnel-Key":"test-secret"}, "close_on_error":true,
                "limits":{"max_requests_per_connection":peer_limit},
                "protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}});
            let concurrent_packets =
                version == "h3" && peer_limit == 1 && local_limit == 128 && mode == "packet-up";
            let client_protocol = json!({"type":"xhttp", "path":"/tunnel", "http_version":version, "mode":mode,
                "headers":{"x-tunnel-key":"test-secret"},
                "limits":{"max_requests_per_connection":local_limit}, "pool":{"max_connections":if concurrent_packets { 3 } else { 2 }},
                "protocol":{"type":"vless","user_id":"550e8400-e29b-41d4-a716-446655440000"}});
            let (server_value, client_value) = if version == "h3" {
                (
                    json!({"address":format!("0.0.0.0:{port}"), "transport":"quic", "quic_settings":{"cert":certificate.cert.pem(),"key":certificate.signing_key.serialize_pem()}, "protocol":server_protocol}),
                    json!({"address":address,"transport":"quic","quic_settings":{"verify":false,"sni_hostname":"localhost"},"protocol":client_protocol}),
                )
            } else {
                (
                    json!({"address":format!("0.0.0.0:{port}"),"protocol":{"type":"tls","default_target":{"cert":certificate.cert.pem(),"key":certificate.signing_key.serialize_pem(),"protocol":server_protocol}}}),
                    json!({"address":address,"protocol":{"type":"tls","verify":false,"sni_hostname":"localhost","protocol":client_protocol}}),
                )
            };
            let configs: Vec<Config> = serde_json::from_value(json!([server_value])).unwrap();
            let server = crate::config::create_server_configs(configs)
                .unwrap()
                .configs
                .into_iter()
                .next()
                .unwrap();
            drop(reserved);
            let handles = crate::tcp::tcp_server::start_servers(server, resolver.clone())
                .await
                .unwrap();
            let config: ClientConfig = serde_json::from_value(client_value.clone()).unwrap();
            let socket = SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
            let proxy = ProxyConnectorImpl::from_config(config, resolver.clone())
                .unwrap()
                .unwrap();
            let chain = ClientProxyChain::new(
                vec![InitialHopEntry::Proxy {
                    socket: Arc::new(socket),
                    proxy: Box::new(proxy),
                }],
                vec![],
            );
            let (chain, upstream_handles) = if version != "h3" {
                let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                let configs = serde_json::from_value(
                    json!([{"address":format!("0.0.0.0:{port}"),"protocol":{"type":"socks"}}]),
                )
                .unwrap();
                let server = crate::config::create_server_configs(configs)
                    .unwrap()
                    .configs
                    .remove(0);
                drop(listener);
                let handles = crate::tcp::tcp_server::start_servers(server, resolver.clone())
                    .await
                    .unwrap();
                let upstream: ClientConfig = serde_json::from_value(
                    json!({"address":format!("127.0.0.1:{port}"),"protocol":{"type":"socks"}}),
                )
                .unwrap();
                let socket =
                    SocketConnectorImpl::from_config(&upstream, Some(&upstream.address)).unwrap();
                let proxy = ProxyConnectorImpl::from_config(upstream, resolver.clone())
                    .unwrap()
                    .unwrap();
                let config: ClientConfig = serde_json::from_value(client_value).unwrap();
                let xhttp = ProxyConnectorImpl::from_config(config, resolver.clone())
                    .unwrap()
                    .unwrap();
                (
                    ClientProxyChain::new(
                        vec![InitialHopEntry::Proxy {
                            socket: Arc::new(socket),
                            proxy: Box::new(proxy),
                        }],
                        vec![vec![Box::new(xhttp)]],
                    ),
                    handles,
                )
            } else {
                (chain, vec![])
            };
            tokio::time::timeout(Duration::from_secs(15), async {
                let connect = async |target: crate::address::ResolvedLocation| {
                    loop {
                        match chain.connect_tcp(target.clone(), &resolver).await {
                            Ok(connection) => break connection.client_stream,
                            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                                // Stream drop cancels workers asynchronously, including pool leases.
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                            Err(error) => panic!("{error}"),
                        }
                    }
                };
                for _ in 0..2 {
                    let target = crate::address::NetLocation::from_str(&target, None)
                        .unwrap()
                        .into();
                    let mut stream = connect(target).await;
                    for marker in [42, 43] {
                        let payload = vec![marker; 32 * 1024];
                        stream.write_all(&payload).await.unwrap();
                        stream.flush().await.unwrap();
                        let mut response = vec![0; payload.len()];
                        stream.read_exact(&mut response).await.unwrap();
                        assert_eq!(response, payload);
                    }
                    stream.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    if mode == "packet-up" {
                        assert!(
                            tokio::time::timeout(
                                Duration::from_millis(50),
                                stream.read_to_end(&mut tail)
                            )
                            .await
                            .is_err()
                        );
                    } else {
                        stream.read_to_end(&mut tail).await.unwrap();
                    }
                    assert!(tail.is_empty());
                }
                if concurrent_packets {
                    let destination = crate::address::NetLocation::from_str(&target, None).unwrap();
                    let mut first = chain
                        .connect_tcp(destination.clone().into(), &resolver)
                        .await
                        .unwrap()
                        .client_stream;
                    first.write_all(b"a").await.unwrap();
                    assert_eq!(first.read_u8().await.unwrap(), b'a');
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let mut second = chain
                        .connect_tcp(destination.into(), &resolver)
                        .await
                        .unwrap()
                        .client_stream;
                    second.write_all(b"b").await.unwrap();
                    assert_eq!(second.read_u8().await.unwrap(), b'b');
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    first.write_all(b"c").await.unwrap();
                    assert_eq!(first.read_u8().await.unwrap(), b'c');
                    second.write_all(b"d").await.unwrap();
                    assert_eq!(second.read_u8().await.unwrap(), b'd');
                    tokio::try_join!(first.shutdown(), second.shutdown()).unwrap();
                    let (mut first_tail, mut second_tail) = (Vec::new(), Vec::new());
                    assert!(
                        tokio::time::timeout(Duration::from_millis(50), async {
                            tokio::try_join!(
                                first.read_to_end(&mut first_tail),
                                second.read_to_end(&mut second_tail),
                            )
                        })
                        .await
                        .is_err()
                    );
                    assert!(first_tail.is_empty() && second_tail.is_empty());
                    drop((first, second));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                // H1 stream-one ends its connection with the response, not an independent FIN.
                if mode != "packet-up" && !(mode == "stream-one" && version == "h1") {
                    let target = crate::address::NetLocation::from_str(&half_close_target, None)
                        .unwrap()
                        .into();
                    let mut stream = connect(target).await;
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, b"fin");
                    let payload = vec![71; 2 * 1024 * 1024];
                    stream.write_all(&payload).await.unwrap();
                    stream.shutdown().await.unwrap();
                    assert_eq!(uploads.recv().await.unwrap(), payload);
                }
                if mode == "packet-up" {
                    let target = crate::address::NetLocation::from_str(&sink_target, None)
                        .unwrap()
                        .into();
                    let mut stream = connect(target).await;
                    stream.write_all(&vec![83; 8 * 1024 * 1024]).await.unwrap();
                    stream.shutdown().await.unwrap();
                    assert_eq!(transfers.recv().await.unwrap(), 8 * 1024 * 1024);
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{version} {mode} stalled"));
            drop(chain);
            for handle in handles.into_iter().chain(upstream_handles) {
                handle.abort();
                let _ = handle.await;
            }
        }
    }
}
