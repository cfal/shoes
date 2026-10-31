use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::h2_multi_stream::H2MultiStream;
use crate::async_stream::AsyncStream;
use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
use crate::config::{ResolvedClientConfig, ResolvedConfig, ResolvedRuleActionConfig};
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp::proxy_connector_impl::create_proxy_connector;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;

struct Prefix {
    config: Value,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<(usize, String)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Prefix {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn prefix(tag: u8, tls: bool) -> Prefix {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let count = connections.clone();
    let recorded = requests.clone();
    let tls = tls.then(|| {
        let cert = rcgen::generate_simple_self_signed(vec!["naive.invalid".into()]).unwrap();
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                        .into(),
                )
                .unwrap(),
        )
    });
    let task = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    let connection = count.fetch_add(1, Ordering::SeqCst);
                    let requests = recorded.clone();
                    let tls = tls.clone();
                    peers.spawn(async move {
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            request.push(stream.read_u8().await.unwrap());
                            assert!(request.len() < 8192);
                        }
                        assert!(request.starts_with(b"CONNECT naive.invalid:443 HTTP/1.1\r\n"));
                        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                        if let Some(tls) = tls {
                            if let Ok(stream) = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await {
                                serve_h2(stream, requests, connection, tag).await;
                            }
                        } else {
                            // Wait for the client preface so H2 SETTINGS cannot be
                            // mistaken for early data in the preceding HTTP response.
                            if stream.peek(&mut [0; 1]).await.unwrap() == 0 {
                                return;
                            }
                            serve_h2(stream, requests, connection, tag).await;
                        }
                    });
                }
                completed = peers.join_next(), if !peers.is_empty() => {
                    completed.unwrap().unwrap();
                }
            }
        }
    });
    Prefix {
        config: json!({"address": address.to_string(), "protocol": {"type": "http"}}),
        connections,
        requests,
        task,
    }
}

async fn serve_h2<S>(
    stream: S,
    requests: Arc<Mutex<Vec<(usize, String)>>>,
    connection: usize,
    tag: u8,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut h2) = h2::server::handshake(stream).await else {
        return;
    };
    let mut echoes = tokio::task::JoinSet::new();
    while let Some(incoming) = h2.accept().await {
        let Ok((request, mut respond)) = incoming else {
            break;
        };
        requests
            .lock()
            .unwrap()
            .push((connection, request.uri().to_string()));
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        echoes.spawn(async move {
            let mut stream = H2MultiStream::new(send, request.into_body());
            stream.write_u8(tag).await.unwrap();
            stream.flush().await.unwrap();
            let mut buffer = [0; 64];
            while let Ok(size) = stream.read(&mut buffer).await {
                if size == 0 {
                    break;
                }
                if stream.write_all(&buffer[..size]).await.is_err() {
                    return;
                }
                stream.flush().await.unwrap();
            }
            let _ = stream.shutdown().await;
        });
    }
}

fn naive(tls: bool) -> Value {
    let protocol =
        json!({"type": "naive", "username": "user", "password": "pass", "padding": false});
    json!({
        "address": "naive.invalid:443",
        "protocol": if tls {
            json!({"type": "tls", "verify": false, "protocol": protocol})
        } else {
            protocol
        }
    })
}

fn resolver() -> Arc<dyn Resolver> {
    Arc::new(NativeResolver::new())
}

fn flat_chain(prefixes: &[&Prefix], tls: bool) -> ClientProxyChain {
    let initial = prefixes
        .iter()
        .map(|prefix| {
            let config: ResolvedClientConfig =
                crate::config::test_support::from_json(prefix.config.clone()).unwrap();
            InitialHopEntry::Proxy {
                socket: Arc::new(
                    SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap(),
                ),
                proxy: create_proxy_connector(config, resolver()).unwrap().unwrap(),
            }
        })
        .collect();
    let naive = create_proxy_connector(
        crate::config::test_support::from_json(naive(tls)).unwrap(),
        resolver(),
    )
    .unwrap()
    .unwrap();
    ClientProxyChain::new(initial, vec![vec![naive]])
}

async fn open(chain: &ClientProxyChain, tag: u8) -> Box<dyn AsyncStream> {
    let target = crate::address::NetLocation::from_str("destination.invalid:80", None).unwrap();
    let mut stream = chain
        .connect_tcp(target.into(), &resolver())
        .await
        .unwrap()
        .client_stream;
    assert_eq!(
        stream.read_u8().await.unwrap(),
        tag,
        "new tunnel used the wrong prefix"
    );
    stream
}

async fn echo(stream: &mut Box<dyn AsyncStream>) {
    stream.write_all(b"still-alive").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 11];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"still-alive");
}

#[tokio::test]
async fn flat_round_robin_keeps_naive_prefixes_isolated() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for tls in [false, true] {
            let a = prefix(b'A', tls).await;
            let b = prefix(b'B', tls).await;
            let chain = flat_chain(&[&a, &b], tls);
            let mut first = open(&chain, b'A').await;
            let mut second = open(&chain, b'B').await;
            let mut third = open(&chain, b'A').await;
            echo(&mut first).await;
            echo(&mut second).await;
            echo(&mut third).await;
            assert_eq!(a.connections.load(Ordering::SeqCst), 2);
            assert_eq!(b.connections.load(Ordering::SeqCst), 1);
            assert_eq!(
                a.requests
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|r| r.0)
                    .collect::<Vec<_>>(),
                [0, 1]
            );
            assert_eq!(
                b.requests
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|r| r.0)
                    .collect::<Vec<_>>(),
                [0]
            );
            drop(chain);
            echo(&mut first).await;
            echo(&mut second).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn composed_naive_prefix_selection_preserves_live_tunnels() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for kind in ["round-robin", "selector"] {
            let a = prefix(b'A', true).await;
            let b = prefix(b'B', true).await;
            let mut validated = crate::config::create_server_configs(serde_json::from_value(json!([
                {"clash_api_address": "127.0.0.1:0", "secret": "test"},
                {"client_group": "prefix", "type": kind, "client_chains": [
                    {"name": "a", "chain": [a.config]},
                    {"name": "b", "chain": [b.config]}
                ]},
                {"address": "127.0.0.1:0", "protocol": {"type": "socks"},
                 "rules": [{"mask": "0.0.0.0/0", "action": "allow", "client_chain": ["prefix", naive(true)]}]}
            ])).unwrap()).unwrap();
            let ResolvedConfig::Server(server) = validated.configs.remove(0) else { panic!() };
            let ResolvedRuleActionConfig::Allow { client_chains, .. } =
                server.rules.into_vec().remove(0).action else { panic!() };
            let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
                client_chains.into_vec().remove(0).hops, resolver(),
            ).unwrap();
            let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
            owner.activate(validated.catalog.take().unwrap().selection).unwrap();
            let mut first = open(&chain, b'A').await;
            if kind == "selector" { owner.select("prefix", "b").unwrap(); }
            let mut second = open(&chain, b'B').await;
            if kind == "selector" {
                let mut warm = open(&chain, b'B').await;
                echo(&mut warm).await;
                owner.select("prefix", "a").unwrap();
            }
            let mut third = open(&chain, b'A').await;
            assert_eq!(a.connections.load(Ordering::SeqCst), 2);
            assert_eq!(b.connections.load(Ordering::SeqCst), 1);
            echo(&mut first).await;
            echo(&mut second).await;
            echo(&mut third).await;
        }
    }).await.unwrap();
}
