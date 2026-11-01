use super::*;
use crate::control::runtime::{ControlService, Generation};
use serde_json::json;
use shoes_test_support::measure::{process_usage, settle};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;

const CLEANUP: Duration = Duration::from_secs(5);

async fn peer(marker: Option<u8>) -> (SocketAddr, AbortOnDropHandle<()>) {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = ([127, 0, 0, 1], listener.local_addr().unwrap().port()).into();
    let task = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    socket.set_nodelay(true).unwrap();
                    sessions.spawn(async move {
                        let mut greeting = [0; 3];
                        socket.read_exact(&mut greeting).await?;
                        assert_eq!(greeting, [5, 1, 0]);
                        socket.write_all(&[5, 0]).await?;
                        let mut header = [0; 3];
                        socket.read_exact(&mut header).await?;
                        assert_eq!(header, [5, 1, 0]);
                        let target = crate::socks_handler::read_location_direct(&mut socket).await?;
                        socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                        if let Some(marker) = marker {
                            let mut bytes = [0; 4];
                            while socket.read_exact(&mut bytes).await.is_ok() {
                                if bytes == *b"HEAD" {
                                    let mut head = bytes.to_vec();
                                    while !head.ends_with(b"\r\n\r\n") { head.push(socket.read_u8().await?); }
                                    socket.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
                                    break;
                                }
                                assert_eq!(bytes, *b"ping");
                                socket.write_all(&[marker, b'i', b'n', b'g']).await?;
                            }
                        } else {
                            let address = target.to_socket_addr_nonblocking().expect("literal fixture target");
                            assert!(address.ip().is_loopback());
                            let mut onward = TcpStream::connect(address).await?;
                            onward.set_nodelay(true)?;
                            tokio::io::copy_bidirectional(&mut socket, &mut onward).await?;
                        }
                        Ok::<_, io::Error>(())
                    });
                }
                result = sessions.join_next(), if !sessions.is_empty() => {
                    if let Err(error) = result.unwrap().unwrap() {
                        assert!(matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe), "{error}");
                    }
                }
            }
        }
    });
    (address, AbortOnDropHandle::new(task))
}

fn build(
    id: u64,
    east: SocketAddr,
    west: SocketAddr,
    relay: SocketAddr,
) -> (Arc<Generation>, ClientProxyChain) {
    let proxy = |name: &str, address: SocketAddr| json!({"name":name,"address":address.to_string(),"protocol":{"type":"socks"}});
    let mut validated = crate::config::create_server_configs(serde_json::from_value(json!([
        {"client_group":"east","client_chain":proxy("east-leaf",east)},
        {"client_group":"west","client_chain":proxy("west-leaf",west)},
        {"client_group":"relay","client_chain":proxy("relay-leaf",relay)},
        {"client_group":"manual","type":"selector","client_chains":[{"chain":["east"]},{"name":"via-west","chain":["relay","west"]}]},
        {"client_group":"auto","type":"url-test","url":"http://192.0.2.1/","interval":1,"timeout":1000,"lazy":false,
         "client_chains":[{"chain":["manual"]},{"chain":["east"]}]},
        {"address":"0.0.0.0:0","protocol":{"type":"socks"},"rules":[{"mask":"0.0.0.0/0","action":"allow","client_chain":"manual"}]}
    ])).unwrap()).unwrap();
    let crate::config::ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!()
    };
    let crate::config::ResolvedRuleActionConfig::Allow { client_chains, .. } =
        &server.rules.iter().next().unwrap().action
    else {
        panic!()
    };
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let chain = crate::tcp::chain_builder::try_build_client_proxy_chain(
        client_chains.iter().next().unwrap().hops.clone(),
        resolver.clone(),
    )
    .unwrap();
    (
        Arc::new(Generation {
            id,
            catalog: validated.catalog.take().unwrap(),
            rules: Vec::new(),
            probes: crate::control::probes::ProbeState::new(resolver, Vec::new()),
            leaf_udp_support: Default::default(),
        }),
        chain,
    )
}

async fn echo(stream: &mut dyn crate::async_stream::AsyncStream, marker: u8) {
    timeout(CLEANUP, async {
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut bytes = [0; 4];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [marker, b'i', b'n', b'g']);
    })
    .await
    .unwrap();
}

fn sample() -> (usize, usize, usize, usize) {
    let resources = crate::resources::snapshot();
    (
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks(),
        process_usage(std::process::id()).unwrap().fds,
        resources.connections.active,
        resources.streams.active,
    )
}

#[test]
fn path_lifecycle_churn_releases_generations_tasks_and_sockets() {
    const NAME: &str = "client_proxy_chain::lifecycle_tests::path_lifecycle_churn_releases_generations_tasks_and_sockets";
    if std::env::var_os("SHOES_PATH_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("SHOES_PATH_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        print!("{stdout}");
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success());
        assert!(stdout.contains("test result: ok. 1 passed;"));
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(Duration::from_secs(360), exercise()).await.unwrap();
        });
}

async fn exercise() {
    let (east, _east) = peer(Some(b'E')).await;
    let (west, _west) = peer(Some(b'W')).await;
    let (relay, _relay) = peer(None).await;
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let target: ResolvedLocation = NetLocation::from_str("192.0.2.100:80", None)
        .unwrap()
        .into();
    let downstream: Arc<dyn ProxyConnector> =
        crate::tcp::proxy_connector_impl::create_proxy_connector(
            crate::config::test_support::from_json(json!({
                "address": "192.0.2.100:80", "protocol": {"type": "socks"}
            }))
            .unwrap(),
            resolver.clone(),
        )
        .unwrap()
        .unwrap()
        .into();
    let baseline = sample();
    for cycle in 0..12 {
        let mut service = ControlService::new(Default::default()).unwrap();
        let mut old = Vec::new();
        let mut pinned = Vec::new();
        let mut retired = Vec::new();
        let mut selections = Vec::new();
        for index in 0..4 {
            let (generation, chain) = build(index + 1, east, west, relay);
            service.runtime.begin_activation(&generation).await.unwrap();
            service.runtime.publish(generation.clone()).await.unwrap();
            service.runtime.resume().await.unwrap();
            assert!(
                retired
                    .iter()
                    .all(|generation: &std::sync::Weak<Generation>| generation.upgrade().is_none())
            );
            assert!(selections.iter().all(
                |selection: &std::sync::Weak<crate::control::selection::SelectionView>| {
                    selection.upgrade().is_none()
                }
            ));
            retired.push(Arc::downgrade(&generation));
            selections.push(Arc::downgrade(&generation.catalog.selection));
            for turn in 0..16 {
                let (member, marker) = if turn % 2 == 0 {
                    ("east", b'E')
                } else {
                    ("via-west", b'W')
                };
                service
                    .runtime
                    .select(generation.id, "manual".into(), member.into())
                    .await
                    .unwrap();
                let mut stream = chain
                    .connect_tcp(target.clone(), &resolver)
                    .await
                    .unwrap()
                    .client_stream;
                echo(stream.as_mut(), marker).await;
                if turn < 2 {
                    old.push((stream, marker));
                    let mut route = chain.select(false).unwrap().selected_route(&resolver);
                    // The excluded downstream hop leaves the entire selected path in the prefix.
                    route.subsequent.push(downstream.clone());
                    pinned.push((route.prefix(target.clone()), marker));
                }
                if turn == 2 {
                    for (prefix, marker) in &pinned {
                        let mut stream = prefix.open_stream().await.unwrap();
                        echo(stream.as_mut(), *marker).await;
                    }
                }
            }
            // Publication retires control ownership; established transports still work.
            for (stream, marker) in &mut old {
                echo(stream.as_mut(), *marker).await;
            }
            settle(
                "automatic recovery after selector burst",
                CLEANUP,
                || generation.catalog.selection.automatic.0["auto"].health("manual"),
                |health| *health == "healthy",
            )
            .await;
            let weak = Arc::downgrade(chain.composition().unwrap());
            drop(chain);
            assert!(weak.upgrade().is_none());
            for (prefix, marker) in &pinned {
                let mut stream = prefix.open_stream().await.unwrap();
                echo(stream.as_mut(), *marker).await;
            }
        }
        drop((old, pinned));
        service.shutdown().await;
        drop(service);
        assert!(
            retired
                .iter()
                .all(|generation| generation.upgrade().is_none())
        );
        assert!(
            selections
                .iter()
                .all(|selection| selection.upgrade().is_none())
        );
        let restored = settle("path churn cleanup", CLEANUP, sample, |value| {
            *value == baseline
        })
        .await;
        let rss = process_usage(std::process::id()).unwrap().rss_kib;
        println!(
            "PATH_LIFECYCLE,cycle={cycle},tasks_fds_connections_streams={restored:?},rss_kib={rss}"
        );
    }
}
