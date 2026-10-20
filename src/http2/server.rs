use std::{io, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, task::JoinSet};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::resolver::Resolver;
use crate::resources::{self, Budget};
use crate::tcp::ingress::PreparedTcp;

use super::stream::H2MultiStream;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

pub(crate) async fn serve(
    stream: Box<dyn AsyncStream>,
    auth_token: Option<String>,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    let limit = resources::limits().max_streams_per_connection;
    let budget = Arc::new(Budget::new(limit));
    let mut connection = crate::util::timeout_stream_setup(async {
        h2::server::Builder::new()
            .initial_window_size(super::STREAM_WINDOW)
            .initial_connection_window_size(super::CONNECTION_WINDOW)
            .max_frame_size(16 * 1024)
            .max_header_list_size(16 * 1024)
            .max_concurrent_streams(limit.unwrap_or(1024).min(u32::MAX as usize) as u32)
            .handshake(stream)
            .await
            .map_err(io::Error::other)
    })
    .await?;
    let mut tasks = JoinSet::new();
    let mut idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut shutdown_deadline = None;
    let mut auth_failed = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(shutdown_deadline.unwrap_or(idle_deadline)),
                if tasks.is_empty() => {
                if shutdown_deadline.is_some() {
                    return Ok(());
                }
                connection.graceful_shutdown();
                shutdown_deadline = Some(tokio::time::Instant::now() + crate::util::SHUTDOWN_TIMEOUT);
            }
            accepted = connection.accept() => {
                let Some(accepted) = accepted else { break };
                let (request, mut respond) = accepted.map_err(io::Error::other)?;
                if auth_failed {
                    let _ = reject(&mut respond, StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                    continue;
                }
                let target = match validate(&request, auth_token.as_deref()) {
                    Ok(target) => target,
                    Err(status) => {
                        let _ = reject(&mut respond, status);
                        if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED
                            && request.headers().contains_key(header::PROXY_AUTHORIZATION)
                        {
                            auth_failed = true;
                            connection.graceful_shutdown();
                            shutdown_deadline = Some(tokio::time::Instant::now() + crate::util::SHUTDOWN_TIMEOUT);
                        }
                        continue;
                    }
                };
                let (Some(local), Some(global)) = (budget.acquire(1), resources::try_stream()) else {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                };
                let selector = selector.clone();
                let resolver = resolver.clone();
                tasks.spawn(async move {
                    let _permits = (local, global);
                    if let Err(error) = tunnel(request, respond, target, selector, resolver).await {
                        log::debug!("HTTP/2 CONNECT stream ended: {error}");
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {
                if tasks.is_empty() {
                    idle_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                    if shutdown_deadline.is_some() {
                        shutdown_deadline = Some(tokio::time::Instant::now() + crate::util::SHUTDOWN_TIMEOUT);
                    }
                }
            }
        }
    }
    // Clean H2 completion may precede consumption of the final buffered DATA.
    let deadline = tokio::time::Instant::now() + crate::util::SHUTDOWN_TIMEOUT;
    let _ = tokio::time::timeout_at(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

fn validate<B>(request: &Request<B>, auth_token: Option<&str>) -> Result<NetLocation, StatusCode> {
    if let Some(token) = auth_token {
        let mut values = request
            .headers()
            .get_all(header::PROXY_AUTHORIZATION)
            .iter();
        let valid = values.next().is_some_and(|value| {
            let bytes = value.as_bytes();
            bytes.len() >= 6
                && bytes[..6].eq_ignore_ascii_case(b"Basic ")
                && bool::from(bytes[6..].ct_eq(token.as_bytes()))
        });
        if !valid || values.next().is_some() {
            return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        }
    }
    if request.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if request.extensions().get::<h2::ext::Protocol>().is_some()
        || request.uri().scheme().is_some()
        || request.uri().path_and_query().is_some()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let authority = request.uri().authority().ok_or(StatusCode::BAD_REQUEST)?;
    if authority.as_str().contains('@')
        || authority
            .port()
            .is_none_or(|port| !port.as_str().bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let target = NetLocation::from_authority(authority.as_str(), None)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if target.port() == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(target)
}

fn reject(respond: &mut h2::server::SendResponse<Bytes>, status: StatusCode) -> io::Result<()> {
    let mut response = Response::builder().status(status);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response = response.header(header::PROXY_AUTHENTICATE, "Basic realm=\"proxy\"");
    } else if status == StatusCode::METHOD_NOT_ALLOWED {
        response = response.header(header::ALLOW, "CONNECT");
    }
    respond
        .send_response(response.body(()).unwrap(), true)
        .map_err(io::Error::other)?;
    Ok(())
}

async fn tunnel(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    target: NetLocation,
    selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
) -> io::Result<()> {
    let prepared = match PreparedTcp::new(&selector, target, Vec::new()) {
        Ok(prepared) => prepared,
        Err(_) => return reject(&mut respond, StatusCode::BAD_GATEWAY),
    };
    if prepared.needs_sniff_read() {
        let send = respond
            .send_response(Response::new(()), false)
            .map_err(io::Error::other)?;
        let mut stream = H2MultiStream::new(send, request.into_body());
        let reset = stream.reset();
        let routed = tokio::select! {
            biased;
            _ = reset => return Ok(()),
            result = async {
                let route = crate::util::timeout_stream_setup(prepared.route(&mut stream, &selector, &resolver)).await?;
                crate::util::timeout_stream_setup(route.connect(&resolver)).await
            } => result?,
        };
        let Some(upstream) = routed.setup else {
            return Ok(());
        };
        return relay(stream, upstream, routed.prefix).await;
    }
    let mut no_read = tokio::io::empty();
    let result = tokio::select! {
        biased;
        _ = std::future::poll_fn(|cx| respond.poll_reset(cx)) => return Ok(()),
        result = async {
            let route = crate::util::timeout_stream_setup(prepared.route(&mut no_read, &selector, &resolver)).await?;
            crate::util::timeout_stream_setup(route.connect(&resolver)).await
        } => result,
    };
    let upstream = match result {
        Ok(routed) => match routed.setup {
            Some(upstream) => upstream,
            None => return reject(&mut respond, StatusCode::FORBIDDEN),
        },
        Err(error) => {
            let status = if error.kind() == io::ErrorKind::TimedOut {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            return reject(&mut respond, status);
        }
    };
    let send = respond
        .send_response(Response::new(()), false)
        .map_err(io::Error::other)?;
    relay(
        H2MultiStream::new(send, request.into_body()),
        upstream,
        Vec::new(),
    )
    .await
}

async fn relay(
    mut stream: H2MultiStream,
    mut upstream: crate::tcp::tcp_handler::TcpClientSetupResult,
    prefix: Vec<u8>,
) -> io::Result<()> {
    let reset = stream.reset();
    tokio::select! {
        biased;
        _ = reset => Ok(()),
        result = async {
            crate::util::timeout_stream_setup(async {
                if let Some(data) = upstream.early_data.take() {
                    stream.write_all(&data).await?;
                    stream.flush().await?;
                }
                if !prefix.is_empty() {
                    upstream.client_stream.write_all(&prefix).await?;
                    upstream.client_stream.flush().await?;
                }
                Ok(())
            }).await?;
            drop(prefix);
            let result = crate::copy_bidirectional::copy_bidirectional(
                &mut stream,
                &mut upstream.client_stream,
                false,
                false,
            ).await;
            if result.is_ok() {
                tokio::join!(
                    crate::util::shutdown_stream(&mut stream),
                    crate::util::shutdown_stream(&mut upstream.client_stream),
                );
            }
            result.map(|_| ())
        } => result,
    }
}
