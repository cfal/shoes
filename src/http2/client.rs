use std::io;
use std::sync::Arc;

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
}

impl H2ClientSession {
    pub async fn new(stream: Box<dyn AsyncStream>) -> io::Result<Self> {
        const WINDOW_SIZE: u32 = 256 * 1024;
        const MAX_FRAME_SIZE: u32 = 16 * 1024;

        let (send_request, mut connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW_SIZE)
            .initial_connection_window_size(WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_header_list_size(16 * 1024)
            .max_concurrent_streams(1024)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::other(format!("H2 client handshake failed: {}", e)))?;

        let (drain_tx, drain_rx) = oneshot::channel();
        let abort_handle = tokio::spawn(async move {
            // Retired sessions must flush queued DATA and END_STREAM before teardown.
            let result = tokio::select! {
                result = &mut connection => Some(result),
                _ = drain_rx => tokio::time::timeout(crate::util::SHUTDOWN_TIMEOUT, connection).await.ok(),
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
            }),
        })
    }

    /// Check if this session is still usable for new streams.
    pub fn is_ready(&self) -> bool {
        !self.driver_handle.driver.is_finished()
    }

    pub fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.driver_handle, &other.driver_handle)
    }

    pub async fn open(
        &mut self,
        request: Request<()>,
    ) -> io::Result<(http::response::Parts, H2MultiStream)> {
        std::future::poll_fn(|cx| self.send_request.poll_ready(cx))
            .await
            .map_err(io::Error::other)?;
        let (response, send) = self
            .send_request
            .send_request(request, false)
            .map_err(io::Error::other)?;
        let response = response.await.map_err(io::Error::other)?;
        let (parts, recv) = response.into_parts();
        let mut stream = H2MultiStream::new(send, recv);
        stream.set_session_owner(self.clone());
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
