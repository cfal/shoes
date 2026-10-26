use std::cell::RefCell;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::resources::BudgetPermit;
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::AbortOnDropHandle;

const LISTENER_CLOSE_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct ListenerRuntime {
    endpoint_started: AtomicBool,
    retired: CancellationToken,
}

impl Runtime for ListenerRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(deadline)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        // Quinn 0.11 spawns the endpoint driver synchronously before exposing the
        // endpoint. Later spawns are connection drivers; recheck this on upgrades.
        if self.endpoint_started.swap(true, Ordering::Relaxed) {
            quinn::TokioRuntime.spawn(future);
            return;
        }
        let mut driver = AbortOnDropHandle::new(tokio::spawn(future));
        let retired = self.retired.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = &mut driver => {},
                _ = async {
                    retired.cancelled().await;
                    tokio::time::sleep(LISTENER_CLOSE_GRACE).await;
                } => {},
            }
            // Dropping the endpoint driver closes its connection-event channels.
            // Connection drivers then terminate and wake application waiters.
        });
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        quinn::TokioRuntime.now()
    }
}

tokio::task_local! {
    static CONNECTION_MEMORY: RefCell<Option<BudgetPermit>>;
}

/// Quinn replaces connection pollers on rebind, so this wrapper deliberately
/// exposes no rebinding API. Reload creates fresh endpoints instead.
#[derive(Debug)]
pub(crate) struct QuicEndpoint {
    inner: quinn::Endpoint,
    // Transport windows belong to this endpoint, not the latest config generation.
    memory_bytes: usize,
    _driver_retirement: Option<DropGuard>,
}

impl QuicEndpoint {
    pub fn new(
        config: Option<quinn::ServerConfig>,
        socket: std::net::UdpSocket,
        memory_bytes: usize,
    ) -> io::Result<Self> {
        Self::with_release(config, socket, memory_bytes, None)
    }

    pub fn listen(
        config: quinn::ServerConfig,
        socket: std::net::UdpSocket,
        memory_bytes: usize,
    ) -> io::Result<(Self, oneshot::Receiver<()>)> {
        let (release, released) = oneshot::channel();
        let endpoint = Self::with_release(Some(config), socket, memory_bytes, Some(release))?;
        Ok((endpoint, released))
    }

    fn with_release(
        config: Option<quinn::ServerConfig>,
        socket: std::net::UdpSocket,
        memory_bytes: usize,
        release: Option<oneshot::Sender<()>>,
    ) -> io::Result<Self> {
        let (runtime, retirement): (Arc<dyn Runtime>, _) = if release.is_some() {
            let retired = CancellationToken::new();
            let runtime = ListenerRuntime {
                endpoint_started: AtomicBool::new(false),
                retired: retired.clone(),
            };
            (Arc::new(runtime), Some(retired.drop_guard()))
        } else {
            (Arc::new(quinn::TokioRuntime), None)
        };
        let socket = MemorySocket {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
            endpoint_memory: None,
            _release: release,
        };
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            config,
            Arc::new(socket),
            runtime,
        )
        .map(|inner| Self {
            inner,
            memory_bytes,
            _driver_retirement: retirement,
        })
    }

    pub fn set_default_client_config(&mut self, config: quinn::ClientConfig) {
        self.inner.set_default_client_config(config);
    }

    pub fn connect(&self, address: SocketAddr, name: &str) -> io::Result<quinn::Connecting> {
        let memory = crate::resources::try_quic_memory(self.memory_bytes)
            .ok_or_else(|| crate::resources::quic_memory_exhausted(self.memory_bytes))?;
        self.connect_with_memory(address, name, memory)
    }

    fn connect_with_memory(
        &self,
        address: SocketAddr,
        name: &str,
        memory: BudgetPermit,
    ) -> io::Result<quinn::Connecting> {
        CONNECTION_MEMORY.sync_scope(RefCell::new(Some(memory)), || {
            self.inner.connect(address, name).map_err(io::Error::other)
        })
    }

    pub async fn accept(&self) -> Option<Incoming> {
        self.inner.accept().await.map(|inner| Incoming {
            inner,
            memory_bytes: self.memory_bytes,
        })
    }

    pub fn close(&self, code: quinn::VarInt, reason: &[u8]) {
        self.inner.close(code, reason);
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    #[cfg(test)]
    async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

pub(crate) struct Incoming {
    inner: quinn::Incoming,
    memory_bytes: usize,
}

impl Incoming {
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    pub fn refuse(self) {
        self.inner.refuse();
    }

    pub fn accept(self) -> io::Result<quinn::Connecting> {
        let Some(memory) = crate::resources::try_quic_memory(self.memory_bytes) else {
            let error = crate::resources::quic_memory_exhausted(self.memory_bytes);
            self.refuse();
            return Err(error);
        };
        self.accept_with_memory(memory)
    }

    fn accept_with_memory(self, memory: BudgetPermit) -> io::Result<quinn::Connecting> {
        CONNECTION_MEMORY.sync_scope(RefCell::new(Some(memory)), || {
            self.inner.accept().map_err(io::Error::from)
        })
    }
}

/// For a dedicated single-connection endpoint, such as Hickory's H3 client.
/// Pooled endpoints must reserve each connection through QuicEndpoint instead.
pub(crate) fn socket_with_memory(
    socket: std::net::UdpSocket,
    memory: BudgetPermit,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    Ok(Arc::new(MemorySocket {
        inner: quinn::TokioRuntime.wrap_udp_socket(socket)?,
        endpoint_memory: Some(memory),
        _release: None,
    }))
}

#[derive(Debug)]
struct MemorySocket {
    inner: Arc<dyn AsyncUdpSocket>,
    endpoint_memory: Option<BudgetPermit>,
    // Field order signals retirement only after the native socket has been dropped.
    _release: Option<oneshot::Sender<()>>,
}

impl AsyncUdpSocket for MemorySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        if self.endpoint_memory.is_some() {
            return self.inner.clone().create_io_poller();
        }
        // Quinn creates one poller synchronously inside connect/accept. Its State
        // drops protocol stream/datagram buffers before dropping this poller,
        // including when application handles survive driver completion.
        let memory = CONNECTION_MEMORY.with(|memory| {
            memory
                .borrow_mut()
                .take()
                .expect("QUIC memory reserved once per connection")
        });
        Box::pin(MemoryPoller {
            inner: self.inner.clone().create_io_poller(),
            _memory: memory,
            _socket: self,
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct MemoryPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    _memory: BudgetPermit,
    // The delegated poller owns a socket reference and must drop before the release signal.
    _socket: Arc<MemorySocket>,
}

impl UdpPoller for MemoryPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.as_mut().poll_writable(cx)
    }
}

#[cfg(test)]
pub(crate) use tests::test_endpoints;

#[cfg(test)]
mod tests;
