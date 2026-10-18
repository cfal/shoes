use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use super::{
    ShadowTlsServerTarget, ShadowTlsServerTargetHandshake, read_client_hello,
    setup_shadowtls_server_stream,
};
use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::async_stream::test_streams::FlushGatedStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::{NativeResolver, Resolver};
use crate::rustls_config_util::{try_create_client_config, try_create_server_config};
use crate::shadow_tls::ShadowTlsClientHandler;
use crate::socks_handler::{SocksTcpClientHandler, SocksTcpServerHandler};
use crate::tcp::tcp_handler::{TcpClientHandler, TcpServerSetupResult};

const PASSWORD: &str = "test-password";

/// Runs the shoes ShadowTLS client against a local-handshake server, with SOCKS inside,
/// over transports that send only on flush, so every handshake step must flush.
#[tokio::test]
async fn socks_inside_local_handshake_completes_over_flush_gated_transport() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_config = Arc::new(
        try_create_server_config(
            certificate.cert.pem().as_bytes(),
            certificate.signing_key.serialize_pem().as_bytes(),
            vec![],
            &[],
            &[],
            &Default::default(),
        )
        .unwrap(),
    );
    let client_config = Arc::new(
        try_create_client_config(false, vec![], vec![], true, None, true, &Default::default())
            .unwrap(),
    );
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let destination = NetLocation::from_str("example.com:443", None).unwrap();

    for auth_info in [None, Some(("user".to_string(), "pass".to_string()))] {
        let target = ShadowTlsServerTarget::new(
            PASSWORD.to_string(),
            ShadowTlsServerTargetHandshake::new_local(server_config.clone()),
            Box::new(SocksTcpServerHandler::new(
                auth_info.clone(),
                false,
                "0.0.0.0".parse().unwrap(),
                Arc::new(ClientProxySelector::new(vec![])),
                resolver.clone(),
            )),
        );
        let client_handler = ShadowTlsClientHandler::new(
            PASSWORD.to_string(),
            client_config.clone(),
            "localhost".try_into().unwrap(),
            Box::new(SocksTcpClientHandler::new(auth_info)),
        );

        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let client_destination = destination.clone();
        let client = tokio::spawn(async move {
            client_handler
                .setup_client_tcp_stream(
                    Box::new(FlushGatedStream::new(client_stream)),
                    client_destination.into(),
                )
                .await
        });

        let server = async {
            let mut server_stream: Box<dyn AsyncStream> =
                Box::new(FlushGatedStream::new(server_stream));
            let client_hello = read_client_hello(&mut server_stream).await?;
            setup_shadowtls_server_stream(server_stream, &target, client_hello, &resolver).await
        };
        let TcpServerSetupResult::TcpForward {
            remote_location,
            stream: mut tunnel,
            connection_success_response: Some(response),
            ..
        } = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("handshake stalled")
            .unwrap()
        else {
            panic!("expected TCP forwarding with a deferred CONNECT reply");
        };
        assert_eq!(remote_location, destination);

        // The TCP server sends the CONNECT reply once the upstream connection is set up.
        tunnel.write_all(&response).await.unwrap();
        tunnel.flush().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("CONNECT reply stalled")
            .unwrap()
            .unwrap();
    }
}
