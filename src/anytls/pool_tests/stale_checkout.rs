use super::*;
use crate::anytls::anytls_stream::STREAM_CHANNEL_BUFFER;
use crate::anytls::anytls_types::{Command, FRAME_HEADER_SIZE, Frame, FrameCodec};
use crate::tcp::carrier_dialer::{CarrierDialer, RouteKey};
use bytes::BytesMut;
use std::{
    io,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::io::{AsyncReadExt, DuplexStream};

#[derive(Debug)]
struct CloseOnTake {
    key: RouteKey,
    session: Arc<AnyTlsClientSession>,
    reusable_at_take: Arc<AtomicBool>,
}

#[async_trait]
impl CarrierDialer for CloseOnTake {
    fn route_key(&self) -> &RouteKey {
        &self.key
    }

    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        panic!("the idle route must not dial");
    }
}

impl Drop for CloseOnTake {
    fn drop(&mut self) {
        // Removing the idle entry drops its retained route after the liveness check.
        self.reusable_at_take
            .store(self.session.is_reusable(), Ordering::SeqCst);
        self.session.close();
    }
}

#[derive(Debug)]
struct Route(RouteKey);

#[async_trait]
impl CarrierDialer for Route {
    fn route_key(&self) -> &RouteKey {
        &self.0
    }

    async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
        panic!("fresh setup must use the supplied wrapped transport");
    }
}

struct Peer {
    io: DuplexStream,
    buffer: BytesMut,
}

impl Peer {
    async fn new(mut io: DuplexStream) -> Self {
        let mut auth = [0; 34];
        io.read_exact(&mut auth).await.unwrap();
        assert_eq!(&auth[32..], &[0, 0]);
        Self {
            io,
            buffer: BytesMut::new(),
        }
    }

    async fn frame(&mut self) -> Frame {
        loop {
            if let Some(frame) = FrameCodec::decode(&mut self.buffer).unwrap() {
                return frame;
            }
            assert_ne!(self.io.read_buf(&mut self.buffer).await.unwrap(), 0);
        }
    }

    async fn opened(&mut self, destination: &NetLocation) {
        assert_eq!(self.frame().await.cmd, Command::Settings);
        let syn = self.frame().await;
        assert_eq!((syn.cmd, syn.stream_id), (Command::Syn, 1));
        let target = self.frame().await;
        assert_eq!((target.cmd, target.stream_id), (Command::Psh, 1));
        assert_eq!(
            target.data.as_ref(),
            write_location_to_vec(destination).unwrap()
        );
    }
}

fn target() -> ResolvedLocation {
    NetLocation::from_str("example.org:443", None)
        .unwrap()
        .into()
}

async fn stale_handler() -> (AnyTlsClientHandler, Arc<AtomicBool>, Peer) {
    let handler = AnyTlsClientHandler::with_options(
        "test".into(),
        Arc::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap()),
        true,
        PoolOptions::default(),
    );
    let (io, peer) = tokio::io::duplex(4096);
    let session = AnyTlsClientSession::new(Box::new(io), "test", handler.padding.clone())
        .await
        .unwrap();
    let mut stream = session.open_stream(target().into_location()).await.unwrap();
    stream.flush().await.unwrap();
    let mut peer = Peer::new(peer).await;
    peer.opened(target().location()).await;
    drop(stream);
    assert_eq!(peer.frame().await.cmd, Command::Fin);
    let reusable_at_take = Arc::new(AtomicBool::new(false));
    handler.pool.release(
        session.clone(),
        Arc::new(CloseOnTake {
            key: RouteKey(vec![1]),
            session,
            reusable_at_take: reusable_at_take.clone(),
        }),
    );
    (handler, reusable_at_take, peer)
}

#[tokio::test]
async fn stale_checkout_falls_back_to_wrapped_transport_once_for_tcp_and_udp() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for udp in [false, true] {
            let (handler, reusable_at_take, mut old_peer) = stale_handler().await;
            let (io, peer) = tokio::io::duplex(4096);
            let calls = AtomicUsize::new(0);
            let wrappers = AtomicUsize::new(0);
            let transport = ClientTransport {
                route: Arc::new(Route(RouteKey(vec![1]))),
                open: Box::pin(async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Box::new(io) as Box<dyn AsyncStream>)
                }),
            }
            .wrap(|io| async {
                wrappers.fetch_add(1, Ordering::SeqCst);
                Ok(io)
            });
            if udp {
                let _stream = handler
                    .connect_client_udp(transport, target())
                    .await
                    .unwrap();
                let mut peer = Peer::new(peer).await;
                peer.opened(&AnyTlsClientHandler::udp_destination()).await;
                let mut request = vec![1];
                request.extend(write_location_to_vec(target().location()).unwrap());
                let mut received = Vec::new();
                while received.len() < request.len() {
                    let frame = peer.frame().await;
                    assert_eq!((frame.cmd, frame.stream_id), (Command::Psh, 1));
                    received.extend_from_slice(&frame.data);
                }
                assert_eq!(received, request);
            } else {
                let mut stream = handler
                    .connect_client_tcp(transport, target())
                    .await
                    .unwrap();
                stream.client_stream.flush().await.unwrap();
                let mut peer = Peer::new(peer).await;
                peer.opened(target().location()).await;
            }
            assert!(reusable_at_take.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(wrappers.load(Ordering::SeqCst), 1);
            let mut remaining = Vec::new();
            old_peer.io.read_to_end(&mut remaining).await.unwrap();
            assert!(remaining.is_empty());
            assert!(old_peer.buffer.is_empty());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stale_checkout_propagates_fresh_dial_failure_without_retrying_again() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for udp in [false, true] {
            let (handler, reusable_at_take, _peer) = stale_handler().await;
            let calls = AtomicUsize::new(0);
            let transport = ClientTransport {
                route: Arc::new(Route(RouteKey(vec![1]))),
                open: Box::pin(async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "fresh dial",
                    ))
                }),
            };
            let error = if udp {
                handler.connect_client_udp(transport, target()).await.err()
            } else {
                handler.connect_client_tcp(transport, target()).await.err()
            }
            .unwrap();
            assert!(reusable_at_take.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(error.to_string(), "fresh dial");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pooled_open_error_after_syn_admission_never_dials_fresh() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for udp in [false, true] {
            let handler = AnyTlsClientHandler::with_options(
                "test".into(),
                Arc::new(PaddingFactory::new(b"stop=1\n0=0-0").unwrap()),
                true,
                PoolOptions::default(),
            );
            let (io, peer) = tokio::io::duplex(4096);
            let session = AnyTlsClientSession::new(Box::new(io), "test", handler.padding.clone())
                .await
                .unwrap();
            let mut stream = session.open_stream(target().into_location()).await.unwrap();
            stream.flush().await.unwrap();
            let mut peer = Peer::new(peer).await;
            peer.opened(target().location()).await;
            assert!(peer.buffer.is_empty());

            // Reading only the header leaves the writer blocked on this oversized body.
            stream.write_all(&[7; 32000]).await.unwrap();
            peer.io
                .read_exact(&mut [0; FRAME_HEADER_SIZE])
                .await
                .unwrap();
            for _ in 0..STREAM_CHANNEL_BUFFER - 1 {
                stream.write_all(b"queued").await.unwrap();
            }
            peer.io
                .write_all(&Frame::control(Command::Fin, 1).encode())
                .await
                .unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            let route = Arc::new(Route(RouteKey(vec![1])));
            handler.pool.release(session.clone(), route.clone());

            let fresh_dials = AtomicUsize::new(0);
            let transport = ClientTransport {
                route: route.clone(),
                open: Box::pin(async {
                    fresh_dials.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "unexpected fresh dial",
                    ))
                }),
            };
            let mut opening = Box::pin(async {
                if udp {
                    handler
                        .connect_client_udp(transport, target())
                        .await
                        .map(|_| ())
                } else {
                    handler
                        .connect_client_tcp(transport, target())
                        .await
                        .map(|_| ())
                }
            });
            // The sole free queue slot admits SYN; the destination PSH must wait.
            assert!(futures::poll!(&mut opening).is_pending());
            peer.io.shutdown().await.unwrap();
            let error = opening.await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(error.to_string(), "Session writer closed");
            assert_eq!(fresh_dials.load(Ordering::SeqCst), 0);
            assert!(!session.is_reusable());
            assert!(handler.pool.take(route.route_key()).is_none());
            drop(stream);
        }
    })
    .await
    .unwrap();
}
