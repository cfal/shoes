//! Hyper-based NaiveProxy service
//!
//! This module provides a hyper-based HTTP/2 server for NaiveProxy connections.
//! It handles CONNECT requests with padding support and built-in static file fallback.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::TokioIo;
use log::debug;
use parking_lot::Mutex;
use rand::RngExt;
use tokio::task::JoinSet;
use tokio_util::io::ReaderStream;

use crate::address::{Address, NetLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_selector::ClientProxySelector;
use crate::copy_bidirectional::copy_bidirectional_with_sizes;
use crate::crypto::CryptoTlsStream;
use crate::resolver::Resolver;
use crate::routing::{ServerStream, run_udp_routing};
use crate::socks_handler::read_location_direct;
use crate::tcp::tcp_handler::TcpServerSetupResult;
use crate::tcp::tcp_server::run_udp_copy;
use crate::tls_server_handler::NaiveConfig;
use crate::uot::{UOT_V1_MAGIC_ADDRESS, UOT_V2_MAGIC_ADDRESS, UotV1ServerStream, UotV2Stream};

use tokio::io::AsyncReadExt;

use super::naive_padding_stream::{
    NaivePaddingStream, PaddingDirection, PaddingType, generate_padding_header,
    parse_padding_type_request,
};
use super::user_lookup::UserLookup;

/// Wrapper for hyper's upgraded stream that implements AsyncStream.
///
/// This is needed because `TokioIo<Upgraded>` doesn't implement `AsyncStream`
/// (which requires `Sync`), but we need `AsyncStream` for UoT stream wrappers.
struct HyperUpgradedStream(Mutex<TokioIo<hyper::upgrade::Upgraded>>);

impl tokio::io::AsyncRead for HyperUpgradedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(self.0.get_mut()).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;

    #[tokio::test]
    async fn connection_executor_cancels_children_without_a_reference_cycle() {
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let executor = ConnectionExecutor(Arc::downgrade(&tasks));
        let marker = Arc::new(());
        let owned = marker.clone();
        hyper::rt::Executor::execute(&executor, async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        drop(tasks);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&marker), 1);
        assert!(executor.0.upgrade().is_none());
    }

    #[tokio::test]
    async fn large_get_is_chunked_and_head_has_no_body() {
        let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let file = std::fs::File::create(dir.path().join("large.bin")).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        let root = Some(dir.path().to_path_buf());
        let head = serve_fallback("/large.bin", &root, true).await.unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()["content-length"], "67108864");
        assert!(
            head.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        let mut get = serve_fallback("/large.bin", &root, false).await.unwrap();
        let chunk = get
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(chunk.len(), 16 * 1024);
        assert_eq!(
            get.body().size_hint().exact(),
            Some(64 * 1024 * 1024 - 16 * 1024)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fallback_rejects_symlink_escape() {
        let dir = tempfile::tempdir_in(std::env::var_os("HOME").unwrap()).unwrap();
        let root = dir.path().join("public");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(dir.path().join("secret"), b"private").unwrap();
        std::os::unix::fs::symlink(dir.path().join("secret"), root.join("escape")).unwrap();
        let response = serve_fallback("/escape", &Some(root), false).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

impl tokio::io::AsyncWrite for HyperUpgradedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(self.0.get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(self.0.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(self.0.get_mut()).poll_shutdown(cx)
    }
}

impl crate::async_stream::AsyncPing for HyperUpgradedStream {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<bool>> {
        std::task::Poll::Ready(Ok(false))
    }
}

impl AsyncStream for HyperUpgradedStream {}

#[derive(Clone)]
struct ConnectionExecutor(Weak<Mutex<JoinSet<()>>>);

impl<F> hyper::rt::Executor<F> for ConnectionExecutor
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    fn execute(&self, future: F) {
        if let Some(tasks) = self.0.upgrade() {
            let mut tasks = tasks.lock();
            while tasks.try_join_next().is_some() {}
            tasks.spawn(async move {
                let _ = future.await;
            });
        }
    }
}

/// Service configuration for hyper NaiveProxy handler
struct NaiveServiceConfig {
    users: Arc<UserLookup>,
    fallback_path: Option<PathBuf>,
    resolver: Arc<dyn Resolver>,
    proxy_selector: Arc<ClientProxySelector>,
    udp_enabled: bool,
    padding_enabled: bool,
    executor: ConnectionExecutor,
    slots: Arc<crate::resources::Budget>,
}

fn empty_body() -> BoxBody<Bytes, io::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

struct FileBody {
    reader: ReaderStream<tokio::io::Take<tokio::fs::File>>,
    remaining: u64,
    _permit: crate::resources::BudgetPermit,
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match std::task::ready!(Pin::new(&mut self.reader).poll_next(cx)) {
            Some(Ok(bytes)) => {
                self.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            None if self.remaining != 0 => {
                self.remaining = 0;
                Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fallback file truncated",
                ))))
            }
            result => Poll::Ready(result.map(|r| r.map(Frame::data))),
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// Run the hyper-based NaiveProxy service
///
/// This is an internal function called by `setup_naive_server_stream` after
/// determining the HTTP version to use.
pub(super) async fn run_naive_hyper_service<IO: AsyncStream + 'static>(
    tls_stream: CryptoTlsStream<IO>,
    naive_cfg: &NaiveConfig,
    effective_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    use_h2: bool,
) -> io::Result<TcpServerSetupResult> {
    let io = TokioIo::new(tls_stream);
    let tasks = Arc::new(Mutex::new(JoinSet::new()));
    let executor = ConnectionExecutor(Arc::downgrade(&tasks));

    let service_config = Arc::new(NaiveServiceConfig {
        users: naive_cfg.users.clone(),
        fallback_path: naive_cfg.fallback_path.clone(),
        resolver,
        proxy_selector: effective_selector,
        udp_enabled: naive_cfg.udp_enabled,
        padding_enabled: naive_cfg.padding_enabled,
        executor: executor.clone(),
        slots: Arc::new(crate::resources::Budget::new(
            crate::resources::limits().max_streams_per_connection,
        )),
    });

    if use_h2 {
        // HTTP/2 for NaiveProxy clients
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let _tasks = tasks;
            let service = hyper::service::service_fn(move |req| {
                let config = service_config.clone();
                async move { naive_service(req, config).await }
            });

            // H2 settings tuned for reasonable throughput without excessive memory
            // Reference naiveproxy uses ~64KB default, we use 256 KB for better throughput
            const WINDOW_SIZE: u32 = 256 * 1024; // 256 KB (was 16 MB)
            const MAX_FRAME_SIZE: u32 = 16 * 1024;

            let result = hyper::server::conn::http2::Builder::new(executor)
                .auto_date_header(false)
                .initial_stream_window_size(WINDOW_SIZE)
                .initial_connection_window_size(WINDOW_SIZE)
                .max_frame_size(MAX_FRAME_SIZE)
                .max_concurrent_streams(
                    crate::resources::limits()
                        .max_streams_per_connection
                        .map(|limit| limit as u32),
                )
                .serve_connection(io, service)
                .await;

            if let Err(e) = result {
                debug!("Naive HTTP/2 connection error: {}", e);
            }
        })))
    } else {
        // HTTP/1.1 for browsers and censors - serve static files only, no proxy
        let fallback_path = naive_cfg.fallback_path.clone();
        Ok(TcpServerSetupResult::Session(Box::pin(async move {
            let service = hyper::service::service_fn(move |req| {
                let path = fallback_path.clone();
                async move { http1_fallback_service(req, path).await }
            });

            let result = hyper::server::conn::http1::Builder::new()
                .auto_date_header(false)
                .serve_connection(io, service)
                .await;

            if let Err(e) = result {
                debug!("Naive HTTP/1.1 fallback error: {}", e);
            }
        })))
    }
}

/// HTTP/1.1 fallback service - only serves static files, no proxy functionality
async fn http1_fallback_service(
    req: Request<Incoming>,
    fallback_path: Option<PathBuf>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    match *req.method() {
        Method::GET | Method::HEAD => {
            let path = req.uri().path();
            let is_head = req.method() == Method::HEAD;
            debug!("NaiveProxy HTTP/1.1: serving fallback for {}", path);
            serve_fallback(path, &fallback_path, is_head).await
        }
        Method::OPTIONS => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("allow", "GET, HEAD, OPTIONS")
            .body(empty_body())
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty_body())
            .unwrap()),
    }
}

/// Main NaiveProxy service handler for HTTP/2 (hyper)
async fn naive_service(
    mut req: Request<Incoming>,
    config: Arc<NaiveServiceConfig>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    match *req.method() {
        Method::CONNECT => {}
        Method::GET | Method::HEAD => {
            let is_head = req.method() == Method::HEAD;
            debug!(
                "NaiveProxy HTTP/2: serving fallback for {}",
                req.uri().path()
            );
            return serve_fallback(req.uri().path(), &config.fallback_path, is_head).await;
        }
        Method::OPTIONS => {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("allow", "GET, HEAD, OPTIONS")
                .body(empty_body())
                .unwrap());
        }
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    }

    // Return 400 for anything that might reveal proxy support
    let has_padding = req.headers().get("padding").is_some();
    if !has_padding && config.padding_enabled {
        debug!("NaiveProxy: missing padding header, returning 400");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty_body())
            .unwrap());
    }

    let username = match req.headers().get("proxy-authorization") {
        Some(auth) => match auth.to_str().ok().and_then(|s| config.users.validate(s)) {
            Some(user) => user.to_string(),
            None => {
                debug!("NaiveProxy: invalid credentials, returning 400");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(empty_body())
                    .unwrap());
            }
        },
        None => {
            debug!("NaiveProxy: missing auth header, returning 400");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };

    let destination = match parse_connect_destination(&req) {
        Some(dest) => dest,
        None => {
            log::warn!("NaiveProxy: invalid CONNECT destination");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap());
        }
    };

    debug!("[{}] NaiveProxy CONNECT to {}", username, destination);

    let padding_type = if config.padding_enabled && has_padding {
        if let Some(types) = req.headers().get("padding-type-request") {
            let types_str = types.to_str().unwrap_or("1");
            parse_padding_type_request(types_str)
                .into_iter()
                .find(|&t| t == PaddingType::Variant1)
                .unwrap_or(PaddingType::Variant1)
        } else {
            PaddingType::Variant1
        }
    } else {
        PaddingType::None
    };

    let Some(permits) = config
        .slots
        .acquire(1)
        .and_then(|local| crate::resources::try_stream().map(|global| (local, global)))
    else {
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(empty_body())
            .unwrap());
    };

    // Get upgrade future before moving the request
    let on_upgrade = hyper::upgrade::on(&mut req);
    let resolver = config.resolver.clone();
    let proxy_selector = config.proxy_selector.clone();
    let udp_enabled = config.udp_enabled;

    hyper::rt::Executor::execute(&config.executor, async move {
        let _permits = permits;
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = HyperUpgradedStream(Mutex::new(TokioIo::new(upgraded)));

                if padding_type != PaddingType::None {
                    let stream =
                        NaivePaddingStream::new(io, PaddingDirection::Server, padding_type);
                    if let Err(e) = handle_naive_stream(
                        stream,
                        destination,
                        resolver,
                        proxy_selector,
                        udp_enabled,
                        &username,
                    )
                    .await
                    {
                        debug!("NaiveProxy tunnel error: {}", e);
                    }
                } else if let Err(e) = handle_naive_stream(
                    io,
                    destination,
                    resolver,
                    proxy_selector,
                    udp_enabled,
                    &username,
                )
                .await
                {
                    debug!("NaiveProxy tunnel error: {}", e);
                }
            }
            Err(e) => {
                debug!("NaiveProxy upgrade failed: {}", e);
            }
        }
    });

    let mut response = Response::builder().status(StatusCode::OK);

    if padding_type != PaddingType::None {
        let padding_len = rand::rng().random_range(30..=62);
        response = response.header("padding", generate_padding_header(padding_len));
        response = response.header("padding-type-reply", (padding_type as u8).to_string());
    }

    Ok(response.body(empty_body()).unwrap())
}

fn parse_connect_destination(req: &Request<Incoming>) -> Option<NetLocation> {
    let authority = req.uri().authority()?;
    NetLocation::from_authority(authority.as_str(), None).ok()
}

/// Serve static files or return 401 Unauthorized
async fn serve_fallback(
    uri_path: &str,
    fallback_path: &Option<PathBuf>,
    is_head: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Infallible> {
    let Some(base_path) = fallback_path else {
        // Return 401 instead of 407 to avoid revealing proxy
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(empty_body())
            .unwrap());
    };
    let Some(permit) = crate::resources::try_stream() else {
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(empty_body())
            .unwrap());
    };

    // Sanitize path to prevent directory traversal
    let request_path = uri_path.trim_start_matches('/');
    let mut file_path = base_path.clone();

    for component in std::path::Path::new(request_path).components() {
        match component {
            std::path::Component::Normal(c) => file_path.push(c),
            std::path::Component::ParentDir => {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(empty_body())
                    .unwrap());
            }
            _ => {}
        }
    }

    if tokio::fs::metadata(&file_path)
        .await
        .is_ok_and(|m| m.is_dir())
    {
        file_path.push("index.html");
    }

    let open = async {
        let root = tokio::fs::canonicalize(base_path).await?;
        let path = tokio::fs::canonicalize(&file_path).await?;
        if !path.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fallback path escapes root",
            ));
        }
        let metadata = tokio::fs::metadata(&path).await?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "not a regular file",
            ));
        }
        let file = if is_head {
            None
        } else {
            Some(tokio::fs::File::open(path).await?)
        };
        Ok((file, metadata.len()))
    };
    match open.await {
        Ok((file, length)) => {
            let mime = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();

            let body = if is_head {
                empty_body()
            } else {
                FileBody {
                    reader: ReaderStream::with_capacity(file.unwrap().take(length), 16 * 1024),
                    remaining: length,
                    _permit: permit,
                }
                .boxed()
            };

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", mime)
                .header("content-length", length)
                .body(body)
                .unwrap())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(empty_body())
            .unwrap()),
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(empty_body())
            .unwrap()),
    }
}

/// Handle a single NaiveProxy stream after setup
///
/// This handles both TCP and UDP-over-TCP (UoT) connections.
async fn handle_naive_stream<S: AsyncStream + 'static>(
    mut stream: S,
    remote_location: NetLocation,
    resolver: Arc<dyn Resolver>,
    proxy_selector: Arc<ClientProxySelector>,
    udp_enabled: bool,
    user_name: &str,
) -> io::Result<()> {
    use crate::client_proxy_selector::ConnectDecision;

    if let Address::Hostname(host) = remote_location.address() {
        if host == UOT_V1_MAGIC_ADDRESS {
            if !udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            debug!("NaiveProxy stream (user: {}): UoT V1 mode", user_name);
            let uot_stream = UotV1ServerStream::new_uot(stream);

            return run_udp_routing(
                ServerStream::Targeted(Box::new(uot_stream)),
                proxy_selector,
                resolver,
                false,
            )
            .await;
        } else if host == UOT_V2_MAGIC_ADDRESS {
            if !udp_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "UDP-over-TCP not enabled",
                ));
            }

            // UoT V2 header: destination uses SOCKS5 address format
            let (is_connect, destination) = crate::util::timeout_stream_setup(async {
                let is_connect = stream.read_u8().await?;
                let destination = read_location_direct(&mut stream).await?;
                Ok((is_connect, destination))
            })
            .await?;

            debug!(
                "NaiveProxy stream (user: {}): UoT V2 connect={} -> {}",
                user_name, is_connect, destination
            );

            if is_connect == 1 {
                let uot_v2_stream = UotV2Stream::new(stream);

                let action = crate::util::timeout_stream_setup(
                    proxy_selector.judge(destination.clone().into(), &resolver),
                )
                .await?;

                match action {
                    ConnectDecision::Allow {
                        chain_group,
                        remote_location,
                    } => {
                        let client_stream = crate::util::timeout_stream_setup(
                            chain_group.connect_udp_bidirectional(&resolver, remote_location),
                        )
                        .await?;

                        return run_udp_copy(
                            Box::new(uot_v2_stream) as Box<dyn AsyncMessageStream>,
                            client_stream,
                            false,
                            false,
                        )
                        .await;
                    }
                    ConnectDecision::Block => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "UDP blocked by rules",
                        ));
                    }
                }
            } else {
                // V2 non-connect mode (same as V1)
                let uot_stream = UotV1ServerStream::new_uot(stream);

                return run_udp_routing(
                    ServerStream::Targeted(Box::new(uot_stream)),
                    proxy_selector,
                    resolver,
                    false,
                )
                .await;
            }
        }
    }

    debug!(
        "NaiveProxy stream (user: {}): TCP -> {}",
        user_name, remote_location
    );

    let action = crate::util::timeout_stream_setup(
        proxy_selector.judge(remote_location.clone().into(), &resolver),
    )
    .await?;

    let mut client_stream: Box<dyn AsyncStream> = match action {
        ConnectDecision::Allow {
            chain_group,
            remote_location,
        } => {
            let result = crate::util::timeout_stream_setup(
                chain_group.connect_tcp(remote_location, &resolver),
            )
            .await?;
            result.client_stream
        }
        ConnectDecision::Block => {
            debug!("NaiveProxy: connection blocked by rules");
            return Ok(());
        }
    };

    // Use larger buffers for better throughput (default 8KB is too small)
    const COPY_BUF_SIZE: usize = 32 * 1024;
    let result = copy_bidirectional_with_sizes(
        &mut stream,
        &mut client_stream,
        false,
        false,
        COPY_BUF_SIZE,
        COPY_BUF_SIZE,
    )
    .await;

    futures::join!(
        crate::util::shutdown_stream(&mut stream),
        crate::util::shutdown_stream(&mut client_stream),
    );

    match result {
        Ok(()) => {
            debug!("NaiveProxy stream (user: {}): done", user_name);
            Ok(())
        }
        Err(e) => {
            debug!("NaiveProxy stream (user: {}): error: {}", user_name, e);
            Err(e)
        }
    }
}
