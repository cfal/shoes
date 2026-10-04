use std::future::Future;
use std::time::Duration;

use tokio::task::JoinSet;

pub(crate) struct QuicListener(pub quinn::Endpoint);

impl std::ops::Deref for QuicListener {
    type Target = quinn::Endpoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for QuicListener {
    fn drop(&mut self) {
        // Keep established connections alive without queuing new handshakes on an old endpoint.
        self.0.set_server_config(None);
    }
}

/// Accepted connections may drain after reload, but cannot outlive its deadline.
pub(crate) struct ListenerTasks {
    tasks: JoinSet<()>,
    grace: Duration,
}

impl ListenerTasks {
    pub fn new() -> Self {
        let seconds = match std::env::var("SHOES_RELOAD_GRACE_SECS") {
            Ok(value) => match value.parse::<u64>() {
                Ok(seconds) if seconds <= 86400 => seconds,
                _ => {
                    log::warn!("Invalid SHOES_RELOAD_GRACE_SECS; using 300 seconds");
                    300
                }
            },
            Err(_) => 300,
        };
        Self::with_grace(Duration::from_secs(seconds))
    }

    fn with_grace(grace: Duration) -> Self {
        Self {
            tasks: JoinSet::new(),
            grace,
        }
    }

    pub fn spawn(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.tasks.spawn(future);
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub async fn join_next(&mut self) {
        if let Some(Err(error)) = self.tasks.join_next().await {
            log::warn!("Connection task failed: {error}");
        }
    }
}

impl Drop for ListenerTasks {
    fn drop(&mut self) {
        if self.tasks.is_empty() || self.grace.is_zero() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut tasks = std::mem::take(&mut self.tasks);
        let deadline = tokio::time::Instant::now() + self.grace;
        runtime.spawn(async move {
            let drained = tokio::time::timeout_at(deadline, async {
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        log::warn!("Draining connection task failed: {error}");
                    }
                }
            })
            .await;
            if drained.is_err() {
                log::info!(
                    "Reload grace expired; cancelling {} connections",
                    tasks.len()
                );
                tasks.shutdown().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    #[tokio::test(start_paused = true)]
    async fn reload_preserves_active_work_then_cancels_stalled_connections() {
        let marker = Arc::new(());
        let owned = marker.clone();
        let mut tasks = ListenerTasks::with_grace(Duration::from_secs(300));
        let (tx, rx) = oneshot::channel();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            tx.send(()).unwrap();
        });
        tasks.spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        drop(tasks);
        tokio::time::advance(Duration::from_secs(61)).await;
        rx.await.unwrap();
        assert_eq!(Arc::strong_count(&marker), 2);
        tokio::time::advance(Duration::from_secs(240)).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[tokio::test]
    async fn zero_grace_cancels_immediately() {
        let marker = Arc::new(());
        let owned = marker.clone();
        let mut tasks = ListenerTasks::with_grace(Duration::ZERO);
        tasks.spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        });
        drop(tasks);
        tokio::task::yield_now().await;
        assert_eq!(Arc::strong_count(&marker), 1);
    }
}
