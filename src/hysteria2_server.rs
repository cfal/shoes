use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{pin_mut, select, FutureExt};
use log::error;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
use crate::copy_bidirectional::copy_bidirectional;
use crate::copy_bidirectional_message::copy_bidirectional_message;
use crate::copy_multidirectional_message::copy_multidirectional_message;
use crate::quic_stream::QuicStream;
use crate::resolver::{NativeResolver, Resolver};
use crate::tcp_client_connector::TcpClientConnector;
use crate::tcp_server::setup_client_stream;

async fn process_hysteria2_connection(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    password: &'static str,
    conn: quinn::Incoming,
) -> std::io::Result<()> {
    let connection = conn.await?;

    // we unfortunately need to keep the h3 connection around because it closes the underlying
    // connection on drop, see
    // https://github.com/hyperium/h3/blob/dbf2523d26e115f096b66cdd8a6f68127a17a156/h3/src/server/connection.rs#L427
    let h3_quinn_connection = h3_quinn::Connection::new(connection.clone());
    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_quinn_connection)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    auth_hysteria2_connection(&mut h3_conn, password).await?;

    let udp_future = {
        let connection = connection.clone();
        let client_proxy_selector = client_proxy_selector.clone();
        let resolver = resolver.clone();
        run_hysteria2_udp_loop(connection, client_proxy_selector, resolver)
    };

    let tcp_future = run_hysteria2_tcp_loop(connection, client_proxy_selector, resolver);

    // Pin the futures since select! requires them to be pinned
    pin_mut!(udp_future);
    pin_mut!(tcp_future);

    select! {
        tcp_result = tcp_future.fuse() => tcp_result,
        udp_result = udp_future.fuse() => udp_result,
    }
}

fn validate_auth_request<T>(req: http::Request<T>, password: &str) -> std::io::Result<()> {
    if req.uri() != "https://hysteria/auth" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid uri",
        ));
    }
    if req.method() != "POST" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid method",
        ));
    }

    let headers = req.headers();
    let auth_value = match headers.get("hysteria-auth") {
        Some(h) => h,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "missing auth header",
            ));
        }
    };
    let auth_str = auth_value
        .to_str()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    if auth_str != password {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "missing host header",
        ));
    }

    Ok(())
}

async fn auth_hysteria2_connection(
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    password: &str,
) -> std::io::Result<()> {
    loop {
        match h3_conn
            .accept()
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
        {
            Some((req, mut stream)) => {
                match validate_auth_request(req, password) {
                    Ok(()) => {
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::from_u16(233).unwrap())
                            // TODO: handle udp
                            .header("Hysteria-UDP", "false")
                            .header("Hysteria-CC-RX", "0")
                            // TODO: randomize padding
                            .header("Hysteria-Padding", "test")
                            .body(())
                            .unwrap();

                        stream
                            .send_response(resp)
                            .await
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                        stream
                            .finish()
                            .await
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                        return Ok(());
                    }
                    Err(e) => {
                        error!("Received non-hysteria2 auth http3 request: {}", e);
                        let resp = http::Response::builder()
                            .status(http::status::StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        stream
                            .send_response(resp)
                            .await
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                        stream
                            .finish()
                            .await
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                    }
                }
            }
            // indicating no more streams to be received
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "no streams",
                ));
            }
        }
    }
}

async fn run_hysteria2_udp_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    // TODO: Implement UDP support for hysteria2 protocol
    std::future::pending::<()>().await;
    Ok(())
}
async fn run_hysteria2_tcp_loop(
    connection: quinn::Connection,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    loop {
        let (send_stream, recv_stream) = match connection.accept_bi().await {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                // TODO: should this be an error?
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Connection closed",
                ));
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to accept bidirectional stream: {}", e),
                ));
            }
            Ok(s) => s,
        };
        let cloned_selector = client_proxy_selector.clone();
        let cloned_resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = process_hysteria2_tcp_stream(
                cloned_selector,
                cloned_resolver,
                send_stream,
                recv_stream,
            )
            .await
            {
                error!("Failed to process streams: {}", e);
            }
        });
    }
}

async fn process_hysteria2_tcp_stream(
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
    resolver: Arc<dyn Resolver>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> std::io::Result<()> {
    // TODO: read_exact is shown as non-cancellable, switch to a state machine?
    let tcp_request_id = read_varint(&mut recv).await?;
    if tcp_request_id != 0x401 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid tcp request id",
        ));
    }
    let address_length = read_varint(&mut recv).await?;
    let mut address_bytes = vec![0u8; address_length as usize];
    recv.read_exact(&mut address_bytes)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let padding_length = read_varint(&mut recv).await?;
    // TODO: this could be big, don't allocate
    let mut padding_bytes = vec![0u8; padding_length as usize];
    recv.read_exact(&mut padding_bytes)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let address = std::string::String::from_utf8(address_bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let remote_location = NetLocation::from_str(&address, None)?;

    // TODO: add message or padding
    // [uint8] Status (0x00 = OK, 0x01 = Error)
    // [varint] Message length
    // [bytes] Message string
    // [varint] Padding length
    // [bytes] Random padding
    send.write_all(&[0u8, 0u8, 0u8])
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let mut server_stream: Box<dyn AsyncStream> = Box::new(QuicStream::from(send, recv));

    let setup_client_stream_future = timeout(
        Duration::from_secs(60),
        setup_client_stream(
            &mut server_stream,
            client_proxy_selector,
            resolver,
            remote_location.clone(),
        ),
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
                format!(
                    "failed to setup client stream to {}: {}",
                    remote_location, e
                ),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup to {} timed out: {}", remote_location, elapsed),
            ));
        }
    };

    let server_need_initial_flush = false;
    let client_need_initial_flush = false;
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

async fn read_varint(recv: &mut quinn::RecvStream) -> std::io::Result<u64> {
    let mut first_byte = [0u8];
    recv.read_exact(&mut first_byte)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let length = (first_byte[0] >> 6) & 0b11; // Get top two bits
    let mut value: u64 = (first_byte[0] & 0b00111111) as u64; // Remaining bits of the first byte

    let num_bytes = match length {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid num bytes value",
            ))
        }
    };

    if num_bytes > 1 {
        let mut remaining_bytes = vec![0u8; num_bytes - 1];
        recv.read_exact(&mut remaining_bytes).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read remaining bytes: {}", e),
            )
        })?;

        for byte in remaining_bytes {
            value <<= 8; // Shift left by 8 bits for each subsequent byte
            value |= byte as u64; // Add the next byte
        }
    }

    Ok(value)
}

pub async fn run_hysteria2_server(
    bind_address: SocketAddr,
    server_config: Arc<rustls::ServerConfig>,
    password: String,
    client_proxy_selector: Arc<ClientProxySelector<TcpClientConnector>>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let quic_server_config: quinn::crypto::rustls::QuicServerConfig = server_config
        .try_into()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

    // Previously we set server_config.transport, but that seems to break when testing
    // against the hysteria2 client:
    //   Arc::get_mut(&mut server_config.transport)
    //     .unwrap()
    //     .max_concurrent_bidi_streams(1024_u32.into())
    //     .max_concurrent_uni_streams(0_u8.into())
    //     .keep_alive_interval(Some(Duration::from_secs(15)))
    //     .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));

    let endpoint = quinn::Endpoint::server(server_config, bind_address)?;

    // TODO: hash password instead of passing directly
    let hysteria2_password: &'static str = Box::leak(password.into_boxed_str());

    while let Some(conn) = endpoint.accept().await {
        let cloned_selector = client_proxy_selector.clone();
        let cloned_resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = process_hysteria2_connection(
                cloned_selector,
                cloned_resolver,
                hysteria2_password,
                conn,
            )
            .await
            {
                error!("Connection ended with error: {}", e);
            }
        });
    }

    Ok(())
}
