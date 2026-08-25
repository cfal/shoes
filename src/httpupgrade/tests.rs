//! Client against server, both driven the way the factories drive them.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::{HttpUpgradeServerTarget, HttpUpgradeTcpClientHandler, HttpUpgradeTcpServerHandler};
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::async_stream::testing::TestStream;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};

/// Stands in for the wrapped proxy protocol: hands the tunnel straight back.
#[derive(Debug)]
struct PassthroughClient;

#[async_trait]
impl TcpClientHandler for PassthroughClient {
    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        _remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }
}

/// Echoes everything it is sent, so the test can prove the tunnel carries bytes
/// in both directions once the handshake is done.
#[derive(Debug)]
struct EchoServer {
    task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[async_trait]
impl TcpServerHandler for EchoServer {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            while let Ok(n) = server_stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if server_stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        *self.task.lock().unwrap() = Some(handle);
        Ok(TcpServerSetupResult::AlreadyHandled)
    }
}

#[tokio::test]
async fn a_tunnel_carries_bytes_in_both_directions() {
    let (client_side, server_side) = duplex(65536);

    let server = HttpUpgradeTcpServerHandler::new(vec![HttpUpgradeServerTarget {
        matching_path: Some("/download".to_string()),
        matching_headers: None,
        handler: Box::new(EchoServer {
            task: Arc::new(Mutex::new(None)),
        }),
    }]);

    let server_task = tokio::spawn(async move {
        server
            .setup_server_stream(Box::new(TestStream(server_side)))
            .await
    });

    let client = HttpUpgradeTcpClientHandler::new(
        Some("cdn.example.com".to_string()),
        Some("/download".to_string()),
        None,
        Box::new(PassthroughClient),
    );

    let mut result = client
        .setup_client_tcp_stream(
            Box::new(TestStream(client_side)),
            ResolvedLocation::new(NetLocation::from_str("example.com:443", None).unwrap()),
        )
        .await
        .unwrap();

    assert!(server_task.await.unwrap().is_ok());

    result.client_stream.write_all(b"ping").await.unwrap();
    result.client_stream.flush().await.unwrap();

    let mut got = [0u8; 4];
    result.client_stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
}
