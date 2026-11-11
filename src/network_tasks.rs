use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio_util::task::TaskTracker;

tokio::task_local! {
    static CURRENT: NetworkTasks;
}

#[derive(Debug, Default)]
struct State {
    cancelled: bool,
    next_id: u64,
    tasks: HashMap<u64, Option<AbortHandle>>,
}

/// One underlay lifetime, shared across ordinary configuration reloads.
#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkTasks {
    untracked: bool,
    state: Arc<Mutex<State>>,
    tracker: TaskTracker,
    pub(crate) cancelled: tokio_util::sync::CancellationToken,
}

#[derive(Default)]
pub(crate) struct NetworkLifetime(NetworkTasks);

impl NetworkLifetime {
    pub fn untracked() -> Self {
        Self(NetworkTasks {
            untracked: true,
            ..NetworkTasks::default()
        })
    }
}

impl std::ops::Deref for NetworkLifetime {
    type Target = NetworkTasks;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NetworkLifetime {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct Registration {
    state: Weak<Mutex<State>>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state.lock().tasks.remove(&self.id);
        }
    }
}

impl NetworkTasks {
    pub fn current() -> Option<Self> {
        CURRENT.try_with(Clone::clone).ok()
    }

    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        if self.untracked {
            future.await
        } else {
            CURRENT.scope(self.clone(), future).await
        }
    }

    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (id, future) = self.clone().guard(future);
        let task = self.tracker.spawn(future);
        self.attach(id, task.abort_handle());
        task
    }

    fn guard<F: Future>(self, future: F) -> (u64, impl Future<Output = F::Output>) {
        let registration = self.register();
        let id = registration.id;
        let cancelled = self.cancelled.clone();
        let future = CURRENT.scope(self, async move {
            let _registration = registration;
            if cancelled.is_cancelled() {
                std::future::pending::<()>().await;
            }
            future.await
        });
        (id, future)
    }

    fn register(&self) -> Registration {
        let mut state = self.state.lock();
        let id = state.next_id;
        state.next_id += 1;
        state.tasks.insert(id, None);
        Registration {
            state: Arc::downgrade(&self.state),
            id,
        }
    }

    fn attach(&self, id: u64, task: AbortHandle) {
        let mut state = self.state.lock();
        if state.cancelled {
            task.abort();
        }
        // Spawning into a stopped runtime can synchronously destroy the registration.
        if let Some(slot) = state.tasks.get_mut(&id) {
            *slot = Some(task);
        }
    }

    /// Tracks drivers that must process endpoint closure rather than being aborted.
    pub fn spawn_completion<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tracker.spawn(CURRENT.scope(self.clone(), future));
    }

    pub fn cancel(&self) {
        self.cancelled.cancel();
        let mut state = self.state.lock();
        state.cancelled = true;
        for task in state.tasks.values().flatten() {
            task.abort();
        }
        self.tracker.close();
    }

    pub async fn wait(&self) {
        self.tracker.wait().await;
    }
}

pub(crate) fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match NetworkTasks::current() {
        Some(context) => context.spawn(future),
        None => tokio::spawn(future),
    }
}

pub(crate) fn spawn_in<F>(tasks: &mut JoinSet<F::Output>, future: F) -> AbortHandle
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let Some(context) = NetworkTasks::current() else {
        return tasks.spawn(future);
    };
    let (id, future) = context.clone().guard(future);
    let task = tasks.spawn(context.tracker.track_future(future));
    context.attach(id, task.clone());
    task
}

pub(crate) fn inherit<F: Future>(future: F) -> impl Future<Output = F::Output> {
    let context = NetworkTasks::current();
    async move {
        match context {
            Some(context) => context.scope(future).await,
            None => future.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unmanaged_work_does_not_register_a_network_lifetime() {
        let network = NetworkLifetime::untracked();
        let mut task = None;
        network
            .scope(async {
                assert!(NetworkTasks::current().is_none());
                task = Some(spawn(async { NetworkTasks::current().is_none() }));
            })
            .await;
        network.cancel();
        assert!(task.unwrap().await.unwrap());
        assert!(network.state.lock().tasks.is_empty());
    }

    #[tokio::test]
    async fn reset_cancels_descendants_and_rejects_late_spawns() {
        let context = NetworkTasks::default();
        let (ready, started) = tokio::sync::oneshot::channel();
        let owned = Arc::new(());
        let retained = owned.clone();
        let parent = context.spawn(async move {
            spawn(async move {
                let _retained = retained;
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            });
        });
        parent.await.unwrap();
        started.await.unwrap();
        context.cancel();
        context.wait().await;
        assert_eq!(Arc::strong_count(&owned), 1);
        assert!(context.spawn(async { 1 }).await.unwrap_err().is_cancelled());
        context.wait().await;
        assert!(context.state.lock().tasks.is_empty());
        assert_eq!(spawn(async { 2 }).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn join_set_cancellation_releases_registrations_and_blocks_late_work() {
        let network = NetworkLifetime::default();
        let mut tasks = JoinSet::new();
        network
            .scope(async {
                spawn_in(&mut tasks, std::future::pending::<()>());
            })
            .await;
        network.cancel();
        network.wait().await;
        assert!(tasks.join_next().await.unwrap().unwrap_err().is_cancelled());
        network
            .scope(async {
                spawn_in(&mut tasks, async { panic!("retired work ran") });
            })
            .await;
        network.wait().await;
        assert!(tasks.join_next().await.unwrap().unwrap_err().is_cancelled());
        assert!(network.state.lock().tasks.is_empty());
    }

    #[tokio::test]
    async fn completion_drivers_survive_cancellation_and_are_awaited() {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let network = NetworkTasks::default();
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let (finished, done) = tokio::sync::oneshot::channel();
            network.spawn_completion(async move {
                let current = NetworkTasks::current().unwrap();
                started.send(()).unwrap();
                released.await.unwrap();
                assert!(current.cancelled.is_cancelled());
                assert!(spawn(async { 1 }).await.unwrap_err().is_cancelled());
                finished.send(()).unwrap();
            });
            ready.await.unwrap();
            network.cancel();
            let mut wait = Box::pin(network.wait());
            assert!(futures::poll!(&mut wait).is_pending());
            release.send(()).unwrap();
            wait.await;
            done.await.expect("completion driver was aborted");
            assert!(network.state.lock().tasks.is_empty());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn inherited_cleanup_survives_owner_drop_while_descendants_are_cancelled() {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let network = NetworkLifetime::default();
            let context = network.0.clone();
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let mut cleanup = None;
            network
                .scope(async {
                    cleanup = Some(tokio::spawn(inherit(async move {
                        let child = spawn(std::future::pending::<()>());
                        started.send(()).unwrap();
                        released.await.unwrap();
                        assert!(NetworkTasks::current().unwrap().cancelled.is_cancelled());
                        assert!(child.await.unwrap_err().is_cancelled());
                        assert!(spawn(async { 1 }).await.unwrap_err().is_cancelled());
                    })));
                })
                .await;
            let cleanup = cleanup.unwrap();
            ready.await.unwrap();
            drop(network);
            context.wait().await;
            assert!(
                !cleanup.is_finished(),
                "inherited cleanup must not be aborted"
            );
            release.send(()).unwrap();
            cleanup.await.unwrap();
            context.wait().await;
            assert!(context.state.lock().tasks.is_empty());
        })
        .await
        .unwrap();
    }

    #[test]
    fn stopped_runtime_destroys_registrations_without_locking_recursively() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        drop(runtime);
        let _entered = handle.enter();
        let network = NetworkTasks::default();
        drop(network.spawn(async {}));
        assert!(network.state.lock().tasks.is_empty());
    }
}
