use super::*;
use crate::{
    address::NetLocationMask,
    client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry},
    client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule},
    resolver::{NativeResolver, Resolver},
    tcp::{
        proxy_connector::ProxyConnector,
        proxy_connector_impl::ProxyConnectorImpl,
        socket_connector_impl::SocketConnectorImpl,
        tcp_handler::{TcpServerHandler, TcpServerSetupResult},
        tcp_server_handler_factory::create_tcp_server_handler,
    },
};
use serde_json::json;
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinSet,
};

#[tokio::test]
async fn h1_stream_one_reuses_a_live_carrier_for_tcp_and_uot() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for disable_reuse in [false, true] {
            check_reuse(disable_reuse).await;
        }
    })
    .await
    .expect("AnyTLS-over-XHTTP exchange stalled");
}

async fn check_reuse(disable_reuse: bool) {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let selector = Arc::new(ClientProxySelector::new(vec![ConnectRule::new(
        vec![NetLocationMask::ANY],
        ConnectAction::new_allow(
            None,
            ClientChainGroup::new(vec![ClientProxyChain::new(
                vec![InitialHopEntry::Direct(Arc::new(
                    SocketConnectorImpl::new_tcp(None, true),
                ))],
                vec![],
            )]),
        ),
    )]));
    let server: Arc<dyn TcpServerHandler> = create_tcp_server_handler(
        crate::config::test_support::from_json(json!({
            "type": "xhttp",
            "http_version": "h1",
            "path": "/anytls",
            "protocol": {
                "type": "anytls",
                "users": [{"name": "test", "password": "test"}],
                "padding_scheme": ["stop=1", "0=0-0"]
            }
        }))
        .unwrap(),
        &selector,
        &resolver,
        None,
    )
    .unwrap()
    .into();
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dialer = Arc::new(NetworkDialer {
        address: address.clone(),
        calls: AtomicUsize::new(0),
        key: RouteKey(vec![1]),
    });
    let config = crate::config::test_support::from_json(json!({
        "address": address,
        "protocol": {
            "type": "xhttp",
            "http_version": "h1",
            "mode": "stream-one",
            "path": "/anytls",
            "protocol": {
                "type": "anytls",
                "password": "test",
                "disable_reuse": disable_reuse,
                "padding_scheme": ["stop=1", "0=0-0"]
            }
        }
    }))
    .unwrap();
    let proxy = ProxyConnectorImpl::from_config(config, resolver)
        .unwrap()
        .unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                socket = listener.accept() => {
                    let (socket, _) = socket.unwrap();
                    count.fetch_add(1, Ordering::Relaxed);
                    let server = server.clone();
                    sessions.spawn(async move {
                        let result = server.setup_server_stream(Box::new(socket)).await.unwrap();
                        let TcpServerSetupResult::Session(run) = result else {
                            panic!("expected XHTTP session");
                        };
                        run.await;
                    });
                }
                result = sessions.join_next(), if !sessions.is_empty() => {
                    result.unwrap().unwrap();
                }
            }
        }
    });
    let echo = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let tcp_target: ResolvedLocation = NetLocation::from_str(
        &format!("127.0.0.1:{}", echo.local_addr().unwrap().port()),
        None,
    )
    .unwrap()
    .into();
    tasks.spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                socket = echo.accept() => {
                    let (mut socket, _) = socket.unwrap();
                    clients.spawn(async move {
                        let (mut reader, mut writer) = socket.split();
                        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
                    });
                }
                result = clients.join_next(), if !clients.is_empty() => {
                    result.unwrap().unwrap();
                }
            }
        }
    });
    let echo = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let udp_target: ResolvedLocation = NetLocation::from_str(
        &format!("127.0.0.1:{}", echo.local_addr().unwrap().port()),
        None,
    )
    .unwrap()
    .into();
    tasks.spawn(async move {
        let mut buffer = [0; 2048];
        loop {
            let (size, source) = echo.recv_from(&mut buffer).await.unwrap();
            assert_eq!(echo.send_to(&buffer[..size], source).await.unwrap(), size);
        }
    });
    let exchange = async {
        for marker in 0..4 {
            let mut tcp = proxy
                .connect_tcp_with_dialer(dialer.clone(), &tcp_target)
                .await
                .unwrap()
                .client_stream;
            let payload = vec![marker; 8192];
            tcp.write_all(&payload).await.unwrap();
            tcp.flush().await.unwrap();
            let mut response = vec![0; payload.len()];
            tcp.read_exact(&mut response).await.unwrap();
            assert_eq!(response, payload);
            tcp.shutdown().await.unwrap();
        }
        let mut udp = proxy
            .connect_udp_with_dialer(dialer.clone(), udp_target)
            .await
            .unwrap();
        for marker in 0..4 {
            let payload = [marker; 32];
            let mut bytes = [0; 64];
            assert_message_echo(&mut *udp, &payload, &mut bytes).await;
        }
        let expected = if disable_reuse { 5 } else { 1 };
        assert_eq!(accepted.load(Ordering::Relaxed), expected);
        assert_eq!(dialer.calls.load(Ordering::Relaxed), expected);
        let mut busy = proxy
            .connect_tcp_with_dialer(dialer.clone(), &tcp_target)
            .await
            .unwrap()
            .client_stream;
        busy.write_all(b"busy").await.unwrap();
        let mut response = [0; 4];
        busy.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"busy");
        assert_eq!(accepted.load(Ordering::Relaxed), expected + 1);
        udp.shutdown_message().await.unwrap();
        busy.shutdown().await.unwrap();
    };
    tokio::select! {
        () = exchange => {}
        result = tasks.join_next() => panic!("fixture ended early: {result:?}"),
    }
    tasks.shutdown().await;
}
