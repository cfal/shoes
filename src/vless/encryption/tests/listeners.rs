use std::{io, sync::Arc, time::Duration};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    fixture_settings,
    transports::{Tasks, echo, request},
};
use crate::{
    async_stream::AsyncStream, config::ServerConfig, resolver::NativeResolver,
    vless::encryption::ClientEncryption,
};

const LIMIT: Duration = Duration::from_secs(10);
const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

async fn port() -> u16 {
    TcpListener::bind("0.0.0.0:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn listen(config: serde_json::Value) -> Tasks {
    let config: ServerConfig = serde_json::from_value(config).unwrap();
    Tasks(
        crate::tcp::tcp_server::start_servers(
            crate::config::Config::Server(config),
            Arc::new(NativeResolver::new()),
        )
        .await
        .unwrap(),
    )
}

async fn exchange(stream: &mut (impl AsyncStream + ?Sized), target: u16) -> io::Result<()> {
    stream.write_all(&request(target, 1, false)).await?;
    stream.write_all(b"scope").await?;
    stream.flush().await?;
    let mut reply = [0; 7];
    stream.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"\0\0scope");
    Ok(())
}

#[tokio::test]
async fn simultaneous_resumed_replays_across_bind_addresses_reach_destination_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::{sync::Barrier, task::JoinSet};

    timeout(LIMIT, async {
        let (encryption, decryption) = fixture_settings("random", true, &[32]);
        let client = ClientEncryption::new(&encryption).unwrap();
        let port = port().await;
        let mut listeners = listen(json!({
            "addresses":[format!("127.0.0.1:{port}"),format!("127.0.0.2:{port}")],
            "protocol":{"type":"vless","user_id":UUID,"decryption":decryption}
        }))
        .await;
        let target = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let mut destination = Tasks(vec![tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    result = target.accept() => {
                        let (mut stream, _) = result.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        tasks.spawn(async move {
                            let (mut r, mut w) = stream.split();
                            let _ = tokio::io::copy(&mut r, &mut w).await;
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        })]);
        let mut warm = client
            .handshake(TcpStream::connect(("127.0.0.1", port)).await.unwrap())
            .await
            .unwrap();
        exchange(&mut warm, target_port).await.unwrap();
        drop(warm);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        // Capture an unspent resumed flight, then race its identical bytes on both listeners.
        let (a, mut b) = tokio::io::duplex(8192);
        let mut resumed = client.handshake(a).await.unwrap();
        assert!(resumed.is_resumed());
        resumed
            .write_all(&request(target_port, 1, false))
            .await
            .unwrap();
        resumed.write_all(b"scope").await.unwrap();
        resumed.shutdown().await.unwrap();
        drop(resumed);
        let mut flight = Vec::new();
        b.read_to_end(&mut flight).await.unwrap();
        let barrier = Arc::new(Barrier::new(16));
        let mut tasks = JoinSet::new();
        for i in 0..16 {
            let barrier = barrier.clone();
            let flight = flight.clone();
            tasks.spawn(async move {
                let mut stream =
                    TcpStream::connect((if i % 2 == 0 { "127.0.0.1" } else { "127.0.0.2" }, port))
                        .await
                        .unwrap();
                barrier.wait().await;
                stream.write_all(&flight).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                // A rejected flight may reset TCP with unread application bytes.
                // Wait for EOF/reset, not just the server's initial random prefix.
                if let Err(error) = stream.read_to_end(&mut response).await {
                    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        // A final echo drains the accept queue before the duplicate-count assertion.
        let mut sentinel = TcpStream::connect(("127.0.0.1", target_port))
            .await
            .unwrap();
        sentinel.write_all(b"done").await.unwrap();
        sentinel.read_exact(&mut [0; 4]).await.unwrap();
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
        listeners.stop().await;
        destination.stop().await;
    })
    .await
    .unwrap();
}

#[derive(Debug)]
struct Carrier;

#[async_trait::async_trait]
impl crate::tcp::tcp_handler::TcpClientHandler for Carrier {
    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        _: crate::address::ResolvedLocation,
    ) -> io::Result<crate::tcp::tcp_handler::TcpClientSetupResult> {
        Ok(crate::tcp::tcp_handler::TcpClientSetupResult {
            client_stream: stream,
            early_data: None,
        })
    }
}

#[tokio::test]
async fn native_tickets_are_shared_across_bind_ips_but_isolated_by_sni_and_websocket_path() {
    use crate::{
        address::{Address, NetLocation, ResolvedLocation},
        tcp::tcp_handler::TcpClientHandler,
        tls_client_handler::TlsClientHandler,
        websocket::WebsocketTcpClientHandler,
    };
    timeout(LIMIT, async {
        for tls in [false, true] {
            let (encryption, decryption) = fixture_settings("native", true, &[32]);
            let client = ClientEncryption::new(&encryption).unwrap();
            let cert =
                rcgen::generate_simple_self_signed(vec!["a.local".into(), "b.local".into()]).unwrap();
            let protocol = json!({"type":"vless","user_id":UUID,"decryption":decryption});
            let outer = if tls {
                let target = json!({"cert":cert.cert.pem(),"key":cert.signing_key.serialize_pem(),"protocol":protocol});
                json!({"type":"tls","tls_targets":{"a.local":target,"b.local":target}})
            } else {
                json!({"type":"websocket","targets":[
                    {"matching_path":"/a","protocol":protocol},
                    {"matching_path":"/b","protocol":protocol}
                ]})
            };
            let port = port().await;
            let mut listeners = listen(json!({
                "addresses":[format!("127.0.0.1:{port}"),format!("127.0.0.2:{port}")],"protocol":outer
            }))
            .await;
            let (target, mut destination) = echo().await;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.cert.der().clone()).unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = Arc::new(
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            for (scope, ip, resumed, rejected) in [
                ("a", 1, false, false),
                ("a", 2, true, false),
                ("b", 1, true, true),
                ("b", 1, false, false),
                ("b", 2, true, false),
                ("a", 2, true, true),
                ("a", 1, false, false),
            ] {
                let wrapper: Box<dyn TcpClientHandler> = if tls {
                    Box::new(TlsClientHandler::new(
                        config.clone(),
                        None,
                        format!("{scope}.local").try_into().unwrap(),
                        Box::new(Carrier),
                    ))
                } else {
                    Box::new(WebsocketTcpClientHandler::new(
                        Some(format!("/{scope}")),
                        None,
                        Default::default(),
                        Box::new(Carrier),
                    ))
                };
                let socket = TcpStream::connect((std::net::Ipv4Addr::new(127, 0, 0, ip), port))
                    .await
                    .unwrap();
                let location = ResolvedLocation::new(NetLocation::new(
                    Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    target,
                ));
                let carrier = wrapper
                    .setup_client_tcp_stream(Box::new(socket), location)
                    .await
                    .unwrap()
                    .client_stream;
                let mut stream = client.handshake(carrier).await.unwrap();
                assert_eq!(stream.is_resumed(), resumed);
                assert_eq!(
                    exchange(&mut stream, target).await.is_err(),
                    rejected,
                    "tls={tls}, scope={scope}, ip={ip}"
                );
            }
            listeners.stop().await;
            destination.stop().await;
        }
    })
    .await
    .unwrap();
}
