//! The `TcpForward` half of connection handling, shared by the TCP and QUIC
//! servers. Both transports reach the same place once the inbound protocol has
//! been parsed: a destination, a stream carrying application data, and a proxy
//! selector to route it with.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::util::write_all;

/// Everything `TcpServerSetupResult::TcpForward` carries, plus the resolver.
pub struct ForwardRequest {
    pub remote_location: NetLocation,
    pub server_stream: Box<dyn AsyncStream>,
    pub server_need_initial_flush: bool,
    pub connection_success_response: Option<Box<[u8]>>,
    pub initial_remote_data: Option<Box<[u8]>>,
    pub proxy_selector: Arc<ClientProxySelector>,
    pub resolver: Arc<dyn Resolver>,
}

pub async fn forward_tcp(request: ForwardRequest) -> std::io::Result<()> {
    let ForwardRequest {
        remote_location,
        mut server_stream,
        server_need_initial_flush,
        connection_success_response,
        initial_remote_data,
        proxy_selector,
        resolver,
    } = request;

    let judged: ResolvedLocation = remote_location.clone().into();

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_tcp_stream(&mut server_stream, proxy_selector, resolver, judged),
    );

    let mut client_stream = match setup_client_stream_future.await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => {
            // Must have been blocked.
            let _ = server_stream.shutdown().await;
            return Ok(());
        }
        Ok(Err(e)) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup client stream to {remote_location}: {e}"),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {remote_location} timed out: {elapsed}"),
            ));
        }
    };

    if let Some(data) = connection_success_response {
        write_all(&mut server_stream, &data).await?;
        // server_need_initial_flush should be set to true by the handler if
        // it's needed.
    }

    let client_need_initial_flush = match initial_remote_data {
        Some(data) => {
            write_all(&mut client_stream, &data).await?;
            true
        }
        None => false,
    };

    let copy_result = copy_bidirectional(
        &mut server_stream,
        &mut client_stream,
        server_need_initial_flush,
        client_need_initial_flush,
    )
    .await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

/// Judge the destination and open the client side of the connection.
///
/// Takes a `ResolvedLocation` rather than a `NetLocation` so that a caller
/// which already knows the address — after sniffing, for instance — can keep
/// it attached to the name.
pub async fn setup_client_tcp_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    remote_location: ResolvedLocation,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_selector
        .judge(remote_location, &resolver)
        .await?;

    match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let TcpClientSetupResult {
                client_stream,
                early_data,
            } = chain_group.connect_tcp(remote_location, &resolver).await?;

            if let Some(data) = early_data {
                write_all(server_stream, &data).await?;
                server_stream.flush().await?;
            }

            Ok(Some(client_stream))
        }
        ConnectDecision::Block => Ok(None),
    }
}
