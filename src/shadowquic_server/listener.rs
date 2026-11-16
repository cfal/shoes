//! JLS Quinn has distinct runtime traits; share shoes' retirement tracker and lifecycle policy.
use super::quic;
use quic::Runtime;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, DropGuard};

pub(super) struct Listener {
    pub endpoint: quic::Endpoint,
    _retired: DropGuard,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"listener stopped");
    }
}
pub(super) fn bind(
    config: quic::ServerConfig,
    socket: std::net::UdpSocket,
) -> io::Result<Listener> {
    let (release, released) = oneshot::channel();
    let retired = CancellationToken::new();
    let socket = ReleaseSocket {
        inner: quic::TokioRuntime.wrap_udp_socket(socket)?,
        release: Arc::new(release),
    };
    let runtime = Arc::new(ListenerRuntime {
        started: AtomicBool::new(false),
        retired: retired.clone(),
    });
    let endpoint = quic::Endpoint::new_with_abstract_socket(
        quic::EndpointConfig::default(),
        Some(config),
        Box::new(socket),
        runtime,
    )?;
    crate::listener_tasks::register_quic_retirement(released);
    Ok(Listener {
        endpoint,
        _retired: retired.drop_guard(),
    })
}
#[derive(Debug)]
struct ListenerRuntime {
    started: AtomicBool,
    retired: CancellationToken,
}
impl Runtime for ListenerRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quic::AsyncTimer>> {
        quic::TokioRuntime.new_timer(deadline)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if self.started.swap(true, Ordering::Relaxed) {
            quic::TokioRuntime.spawn(future);
            return;
        }
        let mut driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(future));
        let retired = self.retired.clone();
        tokio::spawn(async move {
            tokio::select! { _ = &mut driver => {}, _ = async { retired.cancelled().await; tokio::time::sleep(Duration::from_secs(1)).await; } => {} }
        });
    }
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Box<dyn quic::AsyncUdpSocket>> {
        quic::TokioRuntime.wrap_udp_socket(socket)
    }
}
#[derive(Debug)]
struct ReleaseSocket {
    inner: Box<dyn quic::AsyncUdpSocket>,
    release: Arc<oneshot::Sender<()>>,
}
impl quic::AsyncUdpSocket for ReleaseSocket {
    fn create_sender(&self) -> Pin<Box<dyn quic::UdpSender>> {
        Box::pin(ReleaseSender {
            inner: self.inner.create_sender(),
            _release: self.release.clone(),
        })
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [io::IoSliceMut<'_>],
        meta: &mut [quic::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, buffers, meta)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
#[derive(Debug)]
struct ReleaseSender {
    inner: Pin<Box<dyn quic::UdpSender>>,
    _release: Arc<oneshot::Sender<()>>,
}
impl quic::UdpSender for ReleaseSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &quic::udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_send(transmit, cx)
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
}
