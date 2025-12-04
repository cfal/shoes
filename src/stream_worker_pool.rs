//! A worker pool for processing futures without spawning per-future tasks.
//!
//! This module provides a way to process many futures concurrently without spawning
//! a separate tokio task for each one. Instead, a fixed number of worker tasks are
//! spawned, and each worker uses `FuturesUnordered` to poll multiple futures.
//!
//! This is designed to solve the Quinn connection driver starvation issue documented
//! in QUINN_HANG_BUG.md - when too many tasks are spawned via `tokio::spawn`, Quinn's
//! `ConnectionDriver` task gets starved by tokio's scheduler, causing connection
//! timeouts and hangs.
//!
//! By limiting the number of spawned tasks to a fixed pool size (e.g., 4-8 workers),
//! the connection driver has much less competition for scheduler time.

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::{debug, error};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Type alias for boxed futures that the worker pool processes.
/// Returns `std::io::Result<()>` to match copy_bidirectional and other copy utilities.
pub type BoxedFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

/// A pool of worker tasks that process futures without spawning per-future tasks.
///
/// Each worker maintains a `FuturesUnordered` and receives new futures via a channel.
/// This drastically reduces the number of spawned tasks compared to spawning one
/// task per stream/future.
///
/// Uses type-erased boxed futures to allow submitting different future types to
/// the same pool.
pub struct StreamWorkerPool {
    /// Senders to each worker, for round-robin distribution
    senders: Vec<mpsc::UnboundedSender<BoxedFuture>>,
    /// Counter for round-robin distribution
    next_worker: AtomicUsize,
}

impl StreamWorkerPool {
    /// Create a new worker pool with the specified number of workers.
    ///
    /// Each worker is spawned as a tokio task and will process futures sent to it
    /// using `FuturesUnordered` for concurrent (but not parallel) execution within
    /// each worker.
    ///
    /// # Arguments
    /// * `num_workers` - Number of worker tasks to spawn. Recommended: 4-8 for
    ///   typical QUIC proxy workloads. More workers = more parallelism but more
    ///   task competition with Quinn's driver.
    pub fn new(num_workers: usize) -> Self {
        assert!(num_workers > 0, "must have at least one worker");

        let mut senders = Vec::with_capacity(num_workers);

        for worker_id in 0..num_workers {
            let (tx, rx) = mpsc::unbounded_channel::<BoxedFuture>();
            senders.push(tx);

            tokio::spawn(worker_loop(worker_id, rx));
        }

        Self {
            senders,
            next_worker: AtomicUsize::new(0),
        }
    }

    /// Submit a future to be processed by a worker.
    ///
    /// The future is distributed to workers using round-robin scheduling.
    /// The future should return `std::io::Result<()>` to match copy_bidirectional
    /// and other copy utilities. Errors are logged by the worker.
    ///
    /// Returns `true` if the future was successfully submitted, `false` if
    /// the worker channel is closed (worker task has terminated).
    pub fn submit<F>(&self, future: F) -> bool
    where
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        // Round-robin distribution
        let worker_idx = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        self.senders[worker_idx].send(Box::pin(future)).is_ok()
    }

    /// Returns the number of workers in the pool.
    pub fn num_workers(&self) -> usize {
        self.senders.len()
    }
}

/// The worker loop that processes futures from the channel.
async fn worker_loop(worker_id: usize, mut rx: mpsc::UnboundedReceiver<BoxedFuture>) {
    let mut futures: FuturesUnordered<BoxedFuture> = FuturesUnordered::new();
    let mut yield_counter: u8 = 0;

    loop {
        // Use biased select to prioritize polling existing futures over accepting new ones.
        // This is critical because FuturesUnordered only polls futures when they have
        // wake-up notifications, and newly pushed futures need an initial poll to register
        // their wakers. By prioritizing futures.next(), we ensure existing work progresses
        // and new futures get their initial poll before we accept more work.
        tokio::select! {
            biased;

            // Poll existing futures first (higher priority)
            Some(result) = futures.next(), if !futures.is_empty() => {
                // Log errors from completed futures
                if let Err(e) = result {
                    error!("Stream worker {worker_id}: {e}");
                }
            }
            // Accept new futures from the channel (lower priority)
            Some(future) = rx.recv() => {
                futures.push(future);
            }
            // Channel closed and no more futures to process
            else => {
                if futures.is_empty() {
                    debug!("Worker {worker_id} shutting down: channel closed and no pending futures");
                    break;
                }
            }
        }

        // Periodic yield to give other tasks (especially Quinn's driver) a chance to run.
        yield_counter = yield_counter.wrapping_add(1);
        if yield_counter == 0 {
            tokio::task::yield_now().await;
        }
    }
}

/// A shared worker pool that can be cloned and used from multiple tasks.
///
/// This is a convenience wrapper around `Arc<StreamWorkerPool>`.
#[derive(Clone)]
pub struct SharedWorkerPool {
    inner: Arc<StreamWorkerPool>,
}

impl SharedWorkerPool {
    /// Create a new shared worker pool with the specified number of workers.
    pub fn new(num_workers: usize) -> Self {
        Self {
            inner: Arc::new(StreamWorkerPool::new(num_workers)),
        }
    }

    /// Submit a future to be processed by a worker.
    pub fn submit<F>(&self, future: F) -> bool
    where
        F: Future<Output = io::Result<()>> + Send + 'static,
    {
        self.inner.submit(future)
    }

    /// Returns the number of workers in the pool.
    pub fn num_workers(&self) -> usize {
        self.inner.num_workers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    #[tokio::test]
    async fn test_worker_pool_basic() {
        let pool = StreamWorkerPool::new(4);
        let counter = Arc::new(AtomicU32::new(0));

        // Submit 100 futures
        for _ in 0..100 {
            let counter = counter.clone();
            pool.submit(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
        }

        // Give workers time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 100);
    }

    #[tokio::test]
    async fn test_worker_pool_concurrent() {
        let pool = StreamWorkerPool::new(4);
        let counter = Arc::new(AtomicU32::new(0));
        let max_concurrent = Arc::new(AtomicU32::new(0));
        let current_concurrent = Arc::new(AtomicU32::new(0));

        // Submit futures that take some time
        for _ in 0..20 {
            let counter = counter.clone();
            let max_concurrent = max_concurrent.clone();
            let current_concurrent = current_concurrent.clone();
            pool.submit(async move {
                let current = current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;
                max_concurrent.fetch_max(current, Ordering::Relaxed);

                tokio::time::sleep(Duration::from_millis(10)).await;

                current_concurrent.fetch_sub(1, Ordering::Relaxed);
                counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            });
        }

        // Wait for completion
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 20);
        // With 4 workers, we should see some concurrency
        assert!(max_concurrent.load(Ordering::Relaxed) > 1);
    }

    #[tokio::test]
    async fn test_shared_worker_pool() {
        let pool = SharedWorkerPool::new(2);
        let counter = Arc::new(AtomicU32::new(0));

        // Clone and use from multiple "tasks"
        let pool2 = pool.clone();
        let counter2 = counter.clone();

        pool.submit({
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        });

        pool2.submit(async move {
            counter2.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_worker_pool_error_handling() {
        let pool = StreamWorkerPool::new(2);
        let success_counter = Arc::new(AtomicU32::new(0));
        let error_counter = Arc::new(AtomicU32::new(0));

        // Submit a mix of successful and failing futures
        for i in 0..10 {
            let success_counter = success_counter.clone();
            let error_counter = error_counter.clone();
            pool.submit(async move {
                if i % 2 == 0 {
                    success_counter.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                } else {
                    error_counter.fetch_add(1, Ordering::Relaxed);
                    Err(io::Error::new(io::ErrorKind::Other, "test error"))
                }
            });
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // All futures should complete, regardless of success/failure
        assert_eq!(success_counter.load(Ordering::Relaxed), 5);
        assert_eq!(error_counter.load(Ordering::Relaxed), 5);
    }
}
