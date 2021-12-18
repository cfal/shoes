use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::address::Location;
use crate::async_stream::AsyncStream;
use crate::async_tls::{AsyncTlsAcceptor, AsyncTlsFactory};
use crate::client_proxy::ClientProxy;
use crate::client_proxy_provider::{ClientProxyProvider, ProxyAction};
use crate::config::{ServerConfig, ServerTlsConfig};
use crate::copy_bidirectional::copy_bidirectional;
use crate::protocol_handler::{ClientSetupResult, ServerSetupResult, TcpServerHandler};
use crate::resolver::{NativeResolver, Resolver};

const BUFFER_SIZE: usize = 8192;
const ALWAYS_RESOLVE_HOSTNAMES: bool = true;

async fn run_tcp_server(
    bind_address: SocketAddr,
    tls_acceptor: Option<Arc<Box<dyn AsyncTlsAcceptor>>>,
    client_proxy_provider: Arc<ClientProxyProvider>,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
) -> std::io::Result<()> {
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

    let listener = tokio::net::TcpListener::bind(bind_address).await.unwrap();

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept failed: {:?}", e);
                continue;
            }
        };

        let cloned_acceptor = tls_acceptor.clone();
        let cloned_provider = client_proxy_provider.clone();
        let cloned_cache = resolver.clone();
        let cloned_handler = server_handler.clone();
        tokio::spawn(async move {
            if let Err(e) = process_stream(
                stream,
                cloned_acceptor,
                cloned_handler,
                cloned_provider,
                cloned_cache,
            )
            .await
            {
                error!("{}:{} finished with error: {:?}", addr.ip(), addr.port(), e);
            } else {
                debug!("{}:{} finished successfully", addr.ip(), addr.port());
            }
        });
    }
}

async fn setup_server_stream(
    stream: tokio::net::TcpStream,
    tls_acceptor: Option<Arc<Box<dyn AsyncTlsAcceptor>>>,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
) -> std::io::Result<ServerSetupResult> {
    let server_stream = if let Some(acceptor) = tls_acceptor {
        acceptor.accept(stream).await?
    } else {
        Box::new(stream)
    };

    server_handler.setup_server_stream(server_stream).await
}

async fn process_stream(
    stream: tokio::net::TcpStream,
    tls_acceptor: Option<Arc<Box<dyn AsyncTlsAcceptor>>>,
    server_handler: Arc<Box<dyn TcpServerHandler>>,
    client_proxy_provider: Arc<ClientProxyProvider>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<()> {
    let setup_server_stream_future = timeout(
        Duration::from_secs(60),
        setup_server_stream(stream, tls_acceptor, server_handler),
    );

    let ServerSetupResult {
        mut server_stream,
        remote_location,
        override_proxy_provider,
        initial_remote_data,
    } = match setup_server_stream_future.await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return Err(std::io::Error::new(
                e.kind(),
                format!("failed to setup server stream: {}", e),
            ));
        }
        Err(elapsed) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("server setup timed out: {}", elapsed),
            ));
        }
    };

    let selected_proxy_provider = override_proxy_provider.unwrap_or(client_proxy_provider);

    let setup_client_stream_future = timeout(
        Duration::from_secs(15),
        setup_client_stream(
            &mut server_stream,
            selected_proxy_provider,
            resolver,
            remote_location,
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
                format!("failed to setup client stream: {}", e),
            ));
        }
        Err(elapsed) => {
            let _ = server_stream.shutdown().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("client setup timed out: {}", elapsed),
            ));
        }
    };

    if let Some(data) = initial_remote_data {
        client_stream.write_all(&data).await?;
        client_stream.flush().await?;
    }

    let copy_result = copy_bidirectional(&mut server_stream, &mut client_stream, BUFFER_SIZE).await;

    let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());

    copy_result?;
    Ok(())
}

async fn setup_client_stream(
    server_stream: &mut Box<dyn AsyncStream>,
    client_proxy_provider: Arc<ClientProxyProvider>,
    resolver: Arc<dyn Resolver>,
    remote_location: Location,
) -> std::io::Result<Option<Box<dyn AsyncStream>>> {
    let action = client_proxy_provider
        .get_action(remote_location, &resolver)
        .await?;

    match action {
        ProxyAction::Connect {
            client_proxy,
            mut remote_location,
        } => {
            let client_stream = match client_proxy {
                Some(ClientProxy {
                    location: proxy_location,
                    tls_connector,
                    client_handler,
                }) => {
                    let proxy_addr = resolver.resolve_location(&proxy_location).await?;
                    let client_stream = tokio::net::TcpStream::connect(proxy_addr).await?;

                    let client_stream = if let Some(connector) = tls_connector {
                        let domain = proxy_location.address().hostname().unwrap_or("example.com");
                        connector.connect(domain, client_stream).await?
                    } else {
                        Box::new(client_stream)
                    };

                    // TODO: make this configurable
                    if ALWAYS_RESOLVE_HOSTNAMES {
                        if let Some(hostname) = remote_location.address().hostname() {
                            let ip_addr = resolver.resolve_host(hostname).await?[0];
                            remote_location =
                                Location::from_ip_addr(ip_addr, remote_location.port());
                        }
                    }

                    let ClientSetupResult { client_stream } = client_handler
                        .setup_client_stream(server_stream, client_stream, remote_location)
                        .await?;

                    client_stream
                }
                None => {
                    let remote_addr = resolver.resolve_location(&remote_location).await?;
                    let client_stream = tokio::net::TcpStream::connect(remote_addr).await?;
                    Box::new(client_stream)
                }
            };
            Ok(Some(client_stream))
        }
        ProxyAction::Block => Ok(None),
    }
}

pub async fn start_tcp_server(
    config: ServerConfig,
    tls_factory: Arc<dyn AsyncTlsFactory>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let ServerConfig {
        bind_address,
        server_protocols: _,
        server_proxy_config,
        tls_config,
        proxies,
        rules,
    } = config;

    let tls_acceptor = if let Some(config) = tls_config {
        let ServerTlsConfig {
            cert_path,
            key_path,
        } = config;

        let mut cert_file = File::open(&cert_path).await?;
        let mut cert_bytes = vec![];
        cert_file.read_to_end(&mut cert_bytes).await?;

        let mut key_file = File::open(&key_path).await?;
        let mut key_bytes = vec![];
        key_file.read_to_end(&mut key_bytes).await?;

        let acceptor = tls_factory.create_acceptor(&cert_bytes, &key_bytes);

        Some(Arc::new(acceptor))
    } else {
        None
    };

    let client_proxy_provider = Arc::new(ClientProxyProvider::new(proxies, rules, &tls_factory));

    println!("Starting TCP server at {}", &bind_address);

    let tcp_handler: Arc<Box<dyn TcpServerHandler>> = Arc::new(server_proxy_config.clone().into());

    Ok(Some(tokio::spawn(async move {
        run_tcp_server(
            bind_address,
            tls_acceptor,
            client_proxy_provider,
            tcp_handler,
        )
        .await
        .unwrap();
    })))
}
