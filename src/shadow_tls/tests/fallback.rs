use super::*;
use crate::address::Address;
use crate::client_proxy_chain::InitialHopEntry;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ClientConfig;
use crate::port_forward_handler::PortForwardServerHandler;
use crate::resolver::NativeResolver;
use crate::tcp::socket_connector_impl::SocketConnectorImpl;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn authentication_fallback_preserves_preread_and_live_bytes() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let mut client =
            rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let location = NetLocation::new(
            Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            listener.local_addr().unwrap().port(),
        );
        let target = ShadowTlsServerTarget::new(
            "secret".into(),
            ShadowTlsServerTargetHandshake::new_remote(
                location.clone(),
                ClientProxyChain::new(
                    vec![InitialHopEntry::Direct(Arc::new(
                        SocketConnectorImpl::from_config(&ClientConfig::default(), None).unwrap(),
                    ))],
                    Vec::new(),
                ),
            ),
            Box::new(PortForwardServerHandler::new(
                vec![location],
                Arc::new(ClientProxySelector::new(Vec::new())),
            )),
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let (io, mut peer) = tokio::io::duplex(65536);
        let mut flight = hello.clone();
        flight.extend_from_slice(b"early");
        peer.write_all(&flight).await.unwrap();
        let mut io: Box<dyn AsyncStream> = Box::new(io);
        let parsed = read_client_hello(&mut io).await.unwrap();
        assert_eq!(parsed.client_reader.unparsed_data(), b"early");
        assert_eq!(
            validate_shadowtls_client_hello(&parsed, &target.initial_hmac)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let result = setup_shadowtls_server_stream(io, &target, parsed, &resolver)
            .await
            .unwrap();
        let TcpServerSetupResult::Session(session) = result else {
            panic!("expected fallback session");
        };
        let remote = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            socket.read_to_end(&mut received).await.unwrap();
            let mut expected = flight;
            expected.extend_from_slice(b"-live");
            assert_eq!(received, expected);
            socket.write_all(b"reply").await.unwrap();
            socket.shutdown().await.unwrap();
        };
        let client = async {
            peer.write_all(b"-live").await.unwrap();
            peer.shutdown().await.unwrap();
            let mut reply = Vec::new();
            peer.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"reply");
        };
        tokio::join!(session, remote, client);
    })
    .await
    .expect("fallback stalled");
}
