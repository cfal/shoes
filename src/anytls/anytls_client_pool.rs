use std::{collections::VecDeque, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::time::Instant;

use super::anytls_client_session::AnyTlsClientSession;
use crate::tcp::carrier_dialer::{CarrierDialer, RouteKey};

#[derive(Clone, Copy, Debug)]
pub struct PoolOptions {
    pub idle_session_check_interval_secs: u32,
    pub idle_session_timeout_secs: u32,
    pub min_idle_session: usize,
    pub disable_reuse: bool,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            idle_session_check_interval_secs: 30,
            idle_session_timeout_secs: 30,
            min_idle_session: 0,
            disable_reuse: false,
        }
    }
}

fn interval(seconds: u32) -> Duration {
    Duration::from_secs(if seconds <= 5 { 30 } else { seconds.into() })
}

struct IdleSession {
    session: Arc<AnyTlsClientSession>,
    since: Instant,
    // Retain connector identities for as long as their pointer-based key is cached.
    route: Arc<dyn CarrierDialer>,
}

#[derive(Default)]
struct PoolState {
    idle: VecDeque<IdleSession>,
    reaper: Option<tokio::task::AbortHandle>,
}

pub(super) struct SessionPool {
    options: PoolOptions,
    state: Mutex<PoolState>,
}

impl SessionPool {
    pub fn new(options: PoolOptions) -> Arc<Self> {
        Arc::new(Self {
            options,
            state: Mutex::new(PoolState::default()),
        })
    }

    pub fn take(&self, route: &RouteKey) -> Option<Arc<AnyTlsClientSession>> {
        let mut state = self.state.lock();
        let mut index = 0;
        while index < state.idle.len() {
            let idle = &state.idle[index];
            if !idle.session.is_reusable() {
                let idle = state.idle.remove(index).unwrap();
                // close() never calls back into the pool.
                idle.session.close();
            } else if idle.route.route_key() == route {
                return Some(state.idle.remove(index).unwrap().session);
            } else {
                index += 1;
            }
        }
        None
    }

    pub fn release(
        self: &Arc<Self>,
        session: Arc<AnyTlsClientSession>,
        route: Arc<dyn CarrierDialer>,
    ) {
        // Each checkout opens exactly one stream; only its idempotent terminal
        // transition may release it. Idle sessions have no active streams.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            session.close();
            return;
        };
        if self.options.disable_reuse || !session.is_reusable() {
            session.close();
            return;
        }
        let mut state = self.state.lock();
        state.idle.push_front(IdleSession {
            session,
            route,
            since: Instant::now(),
        });
        if state.reaper.is_none() {
            let weak = Arc::downgrade(self);
            let check_interval = interval(self.options.idle_session_check_interval_secs);
            state.reaper = Some(
                runtime
                    .spawn(async move {
                        loop {
                            tokio::time::sleep(check_interval).await;
                            let Some(pool) = weak.upgrade() else { return };
                            if !pool.reap() {
                                return;
                            }
                        }
                    })
                    .abort_handle(),
            );
        }
    }

    fn reap(&self) -> bool {
        let mut state = self.state.lock();
        state.idle.retain(|idle| {
            if idle.session.is_reusable() {
                true
            } else {
                idle.session.close();
                false
            }
        });
        let timeout = interval(self.options.idle_session_timeout_secs);
        while state.idle.len() > self.options.min_idle_session
            && state
                .idle
                .back()
                .is_some_and(|idle| idle.since.elapsed() > timeout)
        {
            state.idle.pop_back().unwrap().session.close();
        }
        if state.idle.is_empty() {
            state.reaper = None;
            false
        } else {
            true
        }
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if let Some(reaper) = state.reaper.take() {
            reaper.abort();
        }
        for idle in state.idle.drain(..) {
            idle.session.close();
        }
    }
}

/// A cancelled or failed open must never return a partially initialized session.
pub(super) struct OpeningSession {
    pub session: Arc<AnyTlsClientSession>,
    armed: bool,
}

impl Drop for OpeningSession {
    fn drop(&mut self) {
        if self.armed {
            self.session.close();
        }
    }
}

impl OpeningSession {
    pub fn new(session: Arc<AnyTlsClientSession>) -> Self {
        Self {
            session,
            armed: true,
        }
    }

    pub fn disarm(mut self) {
        self.armed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_intervals_use_the_reference_default() {
        for (seconds, expected) in [(0, 30), (1, 30), (5, 30), (6, 6), (30, 30)] {
            assert_eq!(interval(seconds), Duration::from_secs(expected));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_prunes_dead_sessions_below_the_retention_floor() {
        #[derive(Debug)]
        struct Route(RouteKey);

        #[async_trait::async_trait]
        impl CarrierDialer for Route {
            fn route_key(&self) -> &RouteKey {
                &self.0
            }
            async fn open_stream(
                &self,
            ) -> std::io::Result<Box<dyn crate::async_stream::AsyncStream>> {
                panic!("reaping must not dial");
            }
        }

        let pool = SessionPool::new(PoolOptions {
            idle_session_check_interval_secs: 6,
            idle_session_timeout_secs: 6,
            min_idle_session: 2,
            disable_reuse: false,
        });
        let (transport, _peer) = tokio::io::duplex(4096);
        let session = AnyTlsClientSession::new(
            Box::new(transport),
            "test",
            Arc::new(parking_lot::RwLock::new(Arc::new(
                crate::anytls::PaddingFactory::new(b"stop=1\n0=0-0").unwrap(),
            ))),
        )
        .await
        .unwrap();
        let route = Arc::new(Route(RouteKey(vec![1])));
        let retained_route = Arc::downgrade(&route);
        pool.release(session.clone(), route);
        assert_eq!(pool.state.lock().idle.len(), 1);
        assert!(pool.state.lock().reaper.is_some());
        session.close();
        tokio::time::sleep(Duration::from_secs(7)).await;
        let state = pool.state.lock();
        assert!(state.idle.is_empty());
        assert!(state.reaper.is_none());
        assert!(retained_route.upgrade().is_none());
    }
}
