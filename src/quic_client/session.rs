use std::{collections::HashMap, io, sync::Arc, time::Duration};

use tokio::sync::watch;
use tokio_util::task::AbortOnDropHandle;

use super::{Protocol, hysteria2, tuic, udp};
use crate::tcp::carrier_dialer::{CarrierDialer, QuicCarrier, RouteKey};

pub(super) const SETUP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
struct Failure(Arc<io::Error>);

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

type Outcome = Option<Result<Arc<Generation>, Failure>>;

struct Slot {
    result: watch::Receiver<Outcome>,
    _init: AbortOnDropHandle<()>,
}

#[derive(Default)]
pub(super) struct Pool {
    slots: Arc<parking_lot::Mutex<HashMap<RouteKey, Slot>>>,
}

impl Pool {
    pub async fn get(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        protocol: Protocol,
        udp: bool,
    ) -> io::Result<Arc<Generation>> {
        let mut receiver = {
            let mut slots = self.slots.lock();
            slots.retain(|_, slot| match &*slot.result.borrow() {
                Some(Ok(generation)) => {
                    generation.connection().close_reason().is_none()
                        && (!udp || !generation.registry.lock().exhausted())
                }
                Some(Err(_)) => false,
                None => !slot._init.is_finished(),
            });
            let slot = slots.entry(dialer.route_key().clone()).or_insert_with(|| {
                let (sender, result) = watch::channel(None);
                let slots = Arc::downgrade(&self.slots);
                let key = dialer.route_key().clone();
                let init = tokio::spawn(async move {
                    let result =
                        tokio::time::timeout(SETUP_TIMEOUT, Generation::open(dialer, protocol))
                            .await
                            .unwrap_or_else(|_| {
                                Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "QUIC client setup timed out",
                                ))
                            })
                            .map(Arc::new)
                            .map_err(|error| Failure(Arc::new(error)));
                    let closed = result.as_ref().ok().map(|generation| (generation.connection().clone(), Arc::downgrade(generation)));
                    let _ = sender.send(Some(result));
                    drop(sender);
                    if let Some((connection, generation)) = closed {
                        connection.closed().await;
                        if let Some(slots) = slots.upgrade() {
                            let mut slots = slots.lock();
                            let matches = slots.get(&key).is_some_and(|slot| {
                                matches!(&*slot.result.borrow(), Some(Ok(current)) if Arc::downgrade(current).ptr_eq(&generation))
                            });
                            if matches { slots.remove(&key); }
                        }
                    }
                });
                Slot {
                    result,
                    _init: AbortOnDropHandle::new(init),
                }
            });
            slot.result.clone()
        };
        loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                return result.map_err(|error| io::Error::new(error.0.kind(), error));
            }
            receiver.changed().await.map_err(|_| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "QUIC client retired")
            })?;
        }
    }
}

pub(super) struct Generation {
    carrier: QuicCarrier,
    pub protocol: Protocol,
    pub udp_enabled: bool,
    pub registry: Arc<parking_lot::Mutex<udp::Registry>>,
    pub dissociate: Option<tokio::sync::mpsc::Sender<tuic::Dissociate>>,
    tasks: Vec<AbortOnDropHandle<()>>,
    initialized: bool,
    // Retains pointer-based route identities for the entire pooled lifetime.
    _dialer: Arc<dyn CarrierDialer>,
}

impl Generation {
    async fn open(dialer: Arc<dyn CarrierDialer>, protocol: Protocol) -> io::Result<Self> {
        let carrier = dialer.open_quic().await?;
        let maximum = match &protocol {
            Protocol::Hysteria2(_) => u32::MAX as u64,
            Protocol::Tuic(_) => u16::MAX as u64,
        };
        let mut generation = Self {
            carrier,
            protocol,
            udp_enabled: false,
            registry: Arc::new(parking_lot::Mutex::new(udp::Registry::new(maximum))),
            dissociate: None,
            tasks: Vec::new(),
            initialized: false,
            _dialer: dialer,
        };
        match &generation.protocol {
            Protocol::Hysteria2(config) => {
                let (enabled, task) =
                    hysteria2::authenticate(generation.connection(), config).await?;
                generation.udp_enabled = config.udp_enabled && enabled;
                generation.tasks.push(task);
            }
            Protocol::Tuic(config) => {
                tuic::authenticate(generation.connection(), config).await?;
                if generation.connection().max_datagram_size().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "TUIC requires QUIC datagrams for heartbeat",
                    ));
                }
                generation.udp_enabled = config.udp_enabled;
                generation
                    .tasks
                    .push(AbortOnDropHandle::new(tokio::spawn(tuic::heartbeat(
                        generation.connection().clone(),
                        config.heartbeat_interval_secs,
                    ))));
                let (sender, receiver) = tokio::sync::mpsc::channel(64);
                generation.dissociate = Some(sender);
                generation
                    .tasks
                    .push(AbortOnDropHandle::new(tokio::spawn(tuic::dissociate_loop(
                        generation.connection().clone(),
                        receiver,
                    ))));
            }
        }
        generation
            .tasks
            .push(AbortOnDropHandle::new(tokio::spawn(udp::receive(
                generation.connection().clone(),
                generation.registry.clone(),
                generation.protocol.clone(),
            ))));
        generation.initialized = true;
        Ok(generation)
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.carrier.connection
    }
}

impl Drop for Generation {
    fn drop(&mut self) {
        self.registry.lock().close();
        if self.initialized
            && self.connection().close_reason().is_none()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            // Retiring a route must not discard FIN/data already accepted by
            // Quinn. One bounded drain task per generation retains its endpoint
            // and protocol drivers, rather than spawning a task per stream.
            let connection = self.connection().clone();
            let endpoint = self.carrier._endpoint.clone();
            let tasks = std::mem::take(&mut self.tasks);
            runtime.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
                connection.close(0u32.into(), b"client retired");
                drop((tasks, endpoint));
            });
            return;
        }
        self.carrier
            .connection
            .close(0u32.into(), b"client retired");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        async_stream::AsyncStream,
        config::quic_client::{Hysteria2ClientConfig, Secret},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Stalled {
        key: RouteKey,
        started: AtomicUsize,
        done: tokio::sync::Notify,
    }
    #[derive(Debug)]
    struct Panics(RouteKey);
    #[async_trait::async_trait]
    impl CarrierDialer for Panics {
        fn route_key(&self) -> &RouteKey {
            &self.0
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
        async fn open_quic(&self) -> io::Result<QuicCarrier> {
            panic!("test initializer panic")
        }
    }

    #[tokio::test]
    async fn panicked_initializers_do_not_poison_routes() {
        let pool = Pool::default();
        assert!(
            pool.get(Arc::new(Panics(RouteKey(vec![1]))), protocol(), false)
                .await
                .is_err()
        );
        let dialer = Arc::new(Stalled {
            key: RouteKey(vec![1]),
            started: AtomicUsize::new(0),
            done: tokio::sync::Notify::new(),
        });
        let mut retry = Box::pin(pool.get(dialer.clone(), protocol(), false));
        assert!(futures::poll!(&mut retry).is_pending());
        tokio::task::yield_now().await;
        assert_eq!(dialer.started.load(Ordering::SeqCst), 1);
    }
    #[async_trait::async_trait]
    impl CarrierDialer for Stalled {
        fn route_key(&self) -> &RouteKey {
            &self.key
        }
        async fn open_stream(&self) -> io::Result<Box<dyn AsyncStream>> {
            unreachable!()
        }
        async fn open_quic(&self) -> io::Result<QuicCarrier> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.done.notified().await;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test auth rejected",
            ))
        }
    }
    fn protocol() -> Protocol {
        Protocol::Hysteria2(Hysteria2ClientConfig {
            password: Secret("test".into()),
            obfs: None,
            hopping: None,
            udp_enabled: true,
        })
    }

    #[tokio::test]
    async fn cancellation_does_not_cancel_shared_initialization_and_failures_retry() {
        let pool = Arc::new(Pool::default());
        let dialer = Arc::new(Stalled {
            key: RouteKey(vec![1]),
            started: AtomicUsize::new(0),
            done: tokio::sync::Notify::new(),
        });
        let mut first = Box::pin(pool.get(dialer.clone(), protocol(), false));
        assert!(futures::poll!(&mut first).is_pending());
        tokio::task::yield_now().await;
        drop(first);
        let mut second = Box::pin(pool.get(dialer.clone(), protocol(), false));
        assert!(futures::poll!(&mut second).is_pending());
        assert_eq!(dialer.started.load(Ordering::SeqCst), 1);
        dialer.done.notify_one();
        assert_eq!(
            second.await.err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut third = Box::pin(pool.get(dialer.clone(), protocol(), false));
        assert!(futures::poll!(&mut third).is_pending());
        tokio::task::yield_now().await;
        assert_eq!(dialer.started.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn initialization_has_a_deadline_even_without_waiters() {
        let pool = Pool::default();
        let dialer = Arc::new(Stalled {
            key: RouteKey(vec![1]),
            started: AtomicUsize::new(0),
            done: tokio::sync::Notify::new(),
        });
        assert_eq!(
            pool.get(dialer, protocol(), false)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
