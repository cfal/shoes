use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use log::debug;
use tokio::sync::oneshot;

use crate::address::{Address, NetLocation};
use crate::async_stream::AsyncStream;

use super::stream::H2MultiStream;

#[derive(Clone)]
pub struct H2ClientSession {
    send_request: h2::client::SendRequest<Bytes>,
    driver_handle: Arc<DriverHandle>,
}

struct DriverHandle {
    driver: tokio::task::AbortHandle,
    _drain: oneshot::Sender<()>,
    active: AtomicUsize,
    retired: Arc<AtomicBool>,
}

pub(crate) struct StreamReservation(H2ClientSession);

impl Drop for StreamReservation {
    fn drop(&mut self) {
        self.0.driver_handle.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub(crate) struct OpenError {
    pub error: h2::Error,
    pub sent: bool,
}

impl From<OpenError> for io::Error {
    fn from(error: OpenError) -> Self {
        io::Error::other(error.error)
    }
}

impl H2ClientSession {
    pub async fn new(stream: Box<dyn AsyncStream>) -> io::Result<Self> {
        const MAX_FRAME_SIZE: u32 = 16 * 1024;

        let (send_request, mut connection) = h2::client::Builder::new()
            .initial_window_size(super::STREAM_WINDOW)
            .initial_connection_window_size(super::CONNECTION_WINDOW)
            .enable_push(false)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_header_list_size(16 * 1024)
            .max_concurrent_streams(1024)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("H2 client handshake failed: {}", e)))?;

        let ping = connection.ping_pong().unwrap();
        let (drain_tx, mut drain_rx) = oneshot::channel();
        let retired = Arc::new(AtomicBool::new(false));
        let driver_retired = retired.clone();
        let abort_handle = tokio::spawn(async move {
            // Retired sessions must flush queued DATA and END_STREAM before teardown.
            let result = tokio::select! {
                result = &mut connection => Some(result.map_err(io::Error::other)),
                _ = &mut drain_rx => tokio::time::timeout(crate::util::SHUTDOWN_TIMEOUT, connection)
                    .await.ok().map(|result| result.map_err(io::Error::other)),
                result = keep_alive(ping) => {
                    debug!("HTTP/2 client session retired after keepalive failure: {result:?}");
                    driver_retired.store(true, Ordering::Relaxed);
                    // A delayed PONG stops reuse, not already-established tunnels.
                    tokio::select! {
                        result = &mut connection => Some(result.map_err(io::Error::other)),
                        _ = drain_rx => tokio::time::timeout(crate::util::SHUTDOWN_TIMEOUT, connection)
                            .await.ok().map(|result| result.map_err(io::Error::other)),
                    }
                },
            };
            if let Some(Err(e)) = result {
                debug!("HTTP/2 client connection ended: {}", e);
            }
        })
        .abort_handle();

        debug!("H2ClientSession: H2 handshake complete, session ready for multiplexing");

        Ok(Self {
            send_request,
            driver_handle: Arc::new(DriverHandle {
                driver: abort_handle,
                _drain: drain_tx,
                active: AtomicUsize::new(0),
                retired,
            }),
        })
    }

    /// Check if this session is still usable for new streams.
    pub fn is_ready(&self) -> bool {
        !self.driver_handle.retired.load(Ordering::Relaxed)
            && !self.driver_handle.driver.is_finished()
            && matches!(
                self.send_request
                    .clone()
                    .poll_ready(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            )
    }

    pub fn try_reserve(&self) -> Option<StreamReservation> {
        if !self.is_ready() {
            return None;
        }
        let limit = self.send_request.current_max_send_streams();
        let mut active = self.driver_handle.active.load(Ordering::Relaxed);
        loop {
            if active >= limit {
                return None;
            }
            match self.driver_handle.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => active = current,
            }
        }
        Some(StreamReservation(self.clone()))
    }

    pub fn reserve(&self) -> StreamReservation {
        self.driver_handle.active.fetch_add(1, Ordering::Relaxed);
        StreamReservation(self.clone())
    }

    pub fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.driver_handle, &other.driver_handle)
    }

    pub async fn open(
        &mut self,
        request: Request<()>,
    ) -> Result<(http::response::Parts, H2MultiStream), OpenError> {
        self.reserve().open(request).await
    }
}

async fn keep_alive(mut ping: h2::PingPong) -> io::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        tokio::time::timeout(Duration::from_secs(5), ping.ping(h2::Ping::opaque()))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::other)?;
    }
}

impl StreamReservation {
    pub async fn open(
        mut self,
        request: Request<()>,
    ) -> Result<(http::response::Parts, H2MultiStream), OpenError> {
        std::future::poll_fn(|cx| self.0.send_request.poll_ready(cx))
            .await
            .map_err(|error| OpenError { error, sent: false })?;
        let (response, send) = self
            .0
            .send_request
            .send_request(request, false)
            .map_err(|error| OpenError { error, sent: false })?;
        let response = response
            .await
            .map_err(|error| OpenError { error, sent: true })?;
        let (parts, recv) = response.into_parts();
        let mut stream = H2MultiStream::new(send, recv);
        stream.set_reservation(self);
        Ok((parts, stream))
    }
}

/// Format authority for CONNECT request
pub(crate) fn format_authority(location: &NetLocation) -> String {
    match location.address() {
        Address::Ipv6(addr) => format!("[{}]:{}", addr, location.port()),
        Address::Ipv4(addr) => format!("{}:{}", addr, location.port()),
        Address::Hostname(host) => format!("{}:{}", host, location.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[tokio::test(start_paused = true)]
    async fn keepalive_retires_blackholed_but_not_responsive_carriers() {
        for responsive in [false, true] {
            let (client, peer) = tokio::io::duplex(8192);
            let (ready_tx, ready_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(peer).await.unwrap();
                ready_tx.send(()).unwrap();
                if responsive {
                    while connection.accept().await.is_some() {}
                } else {
                    // Keep the transport open without processing PINGs.
                    std::future::pending::<()>().await;
                    drop(connection);
                }
            });
            let session = H2ClientSession::new(Box::new(client)).await.unwrap();
            ready_rx.await.unwrap();
            tokio::time::sleep(Duration::from_secs(36)).await;
            assert_eq!(session.is_ready(), responsive);
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn late_pong_retires_reuse_without_interrupting_an_active_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, peer) = tokio::io::duplex(8192);
        let (pause_tx, pause_rx) = oneshot::channel();
        let (paused_tx, paused_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(async move {
                let mut stream = H2MultiStream::new(send, request.into_body());
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            tokio::select! {
                _ = connection.accept() => panic!("unexpected request"),
                _ = pause_rx => {},
            }
            paused_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            while connection.accept().await.is_some() {}
        });
        let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
        let (_, mut stream) = session
            .open(
                Request::builder()
                    .method("CONNECT")
                    .uri("example.com:443")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        pause_tx.send(()).unwrap();
        paused_rx.await.unwrap();
        tokio::time::sleep(Duration::from_secs(36)).await;
        assert!(!session.is_ready());
        assert!(!session.driver_handle.driver.is_finished());
        resume_tx.send(()).unwrap();
        stream.write_all(b"tail").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"tail");
        assert!(!session.is_ready());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn unread_download_does_not_block_another_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, peer) = tokio::io::duplex(8192);
        let (filled_tx, filled_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(peer).await.unwrap();
            let mut filled = Some(filled_tx);
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = connection.accept() => {
                        let Some(Ok((request, mut respond))) = incoming else { break };
                        let send = respond.send_response(http::Response::new(()), false).unwrap();
                        let signal = filled.take();
                        tasks.spawn(async move {
                            let mut stream = H2MultiStream::new(send, request.into_body());
                            if let Some(signal) = signal {
                                stream.write_all(&vec![0; super::super::STREAM_WINDOW as usize]).await.unwrap();
                                signal.send(()).unwrap();
                                let _ = stream.read(&mut [0]).await;
                            } else {
                                stream.write_all(b"ok").await.unwrap();
                                stream.shutdown().await.unwrap();
                            }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
        let request = || {
            Request::builder()
                .method("CONNECT")
                .uri("example.com:443")
                .body(())
                .unwrap()
        };
        let (_, unread) = session.open(request()).await.unwrap();
        filled_rx.await.unwrap();
        let (_, mut second) = session.open(request()).await.unwrap();
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), second.read_to_end(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, b"ok");
        drop(unread);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(start_paused = true)]
    async fn last_owner_drain_is_bounded_when_peer_stalls() {
        let (client, _peer) = tokio::io::duplex(64);
        let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();
        drop(session.send_request.send_request(request, false).unwrap());
        let driver = session.driver_handle.driver.clone();
        drop(session);
        tokio::task::yield_now().await;
        assert!(!driver.is_finished());
        tokio::time::sleep(crate::util::SHUTDOWN_TIMEOUT + std::time::Duration::from_millis(1))
            .await;
        assert!(driver.is_finished());
    }

    #[tokio::test]
    async fn active_stream_keeps_driver_after_session_slot_is_dropped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(peer).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut stream = H2MultiStream::new(send, req.into_body());
            let echo = async {
                let mut data = [0; 4];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            };
            tokio::select! { _ = echo => {}, _ = conn.accept() => {} }
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(100), conn.accept()).await;
        });
        let mut session = H2ClientSession::new(Box::new(client)).await.unwrap();
        let weak = Arc::downgrade(&session.driver_handle);
        let (_, mut stream) = session
            .open(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri("example.com:443")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        drop(session);
        assert!(weak.upgrade().is_some());
        stream.write_all(b"test").await.unwrap();
        let mut data = [0; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut data),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&data, b"test");
        drop(stream);
        assert!(weak.upgrade().is_none());
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn test_format_authority_ipv4() {
        use std::net::Ipv4Addr;
        let loc = NetLocation::new(Address::Ipv4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(format_authority(&loc), "192.168.1.1:8080");
    }

    #[test]
    fn test_format_authority_ipv6() {
        use std::net::Ipv6Addr;
        let loc = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
        assert_eq!(format_authority(&loc), "[::1]:443");
    }

    #[test]
    fn test_format_authority_hostname() {
        let loc = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        assert_eq!(format_authority(&loc), "example.com:443");
    }
}
