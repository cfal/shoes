//! Activity tracking for h2mux connection idle timeout detection.
//!
//! Tracks the last time activity occurred on a connection to support idle timeout.
//! Uses atomic operations for lock-free performance.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Timeout constants matching sing-mux behavior.
///
/// IDLE_TIMEOUT is set to 60s (2x sing-mux's 30s) for extra margin. Our server
/// wraps the connection with ActivityTrackedStream so that ALL HTTP/2 frames
/// (including PING, SETTINGS, WINDOW_UPDATE) count as activity.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const PING_INTERVAL: Duration = Duration::from_secs(30);
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);
pub const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Grace period after graceful shutdown before forcing connection close.
/// Allows in-flight streams to complete while preventing indefinite hangs.
pub const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Tracks connection activity for idle timeout detection.
///
/// Clone is cheap (Arc-based) and all clones share the same activity state.
/// Safe to use from multiple tasks concurrently.
#[derive(Clone)]
pub struct ActivityTracker {
    /// Milliseconds since `created` when last activity occurred.
    /// Using u64 milliseconds rather than Instant for atomic storage.
    last_activity_ms: Arc<AtomicU64>,
    /// Reference point for time calculations.
    created: Instant,
}

impl ActivityTracker {
    /// Create a new tracker. Initial state is "just had activity".
    pub fn new() -> Self {
        Self {
            last_activity_ms: Arc::new(AtomicU64::new(0)),
            created: Instant::now(),
        }
    }

    /// Record that activity occurred. Call this on stream open, read, or write.
    #[inline]
    pub fn record_activity(&self) {
        let now_ms = self.created.elapsed().as_millis() as u64;
        self.last_activity_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Get duration since last activity.
    #[inline]
    pub fn idle_duration(&self) -> Duration {
        let last_ms = self.last_activity_ms.load(Ordering::Relaxed);
        let now_ms = self.created.elapsed().as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }

    /// Check if connection has been idle longer than threshold.
    #[inline]
    pub fn is_idle(&self, threshold: Duration) -> bool {
        self.idle_duration() >= threshold
    }
}

impl Default for ActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_activity_tracker_initial_state() {
        let tracker = ActivityTracker::new();
        // Initially not idle (just created)
        assert!(!tracker.is_idle(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn test_activity_tracker_becomes_idle() {
        let tracker = ActivityTracker::new();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tracker.is_idle(Duration::from_millis(40)));
        assert!(!tracker.is_idle(Duration::from_millis(100)));
    }

    #[tokio::test]
    async fn test_activity_tracker_reset() {
        let tracker = ActivityTracker::new();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tracker.is_idle(Duration::from_millis(40)));

        tracker.record_activity();
        assert!(!tracker.is_idle(Duration::from_millis(40)));
    }

    #[tokio::test]
    async fn test_activity_tracker_clone_shares_state() {
        let tracker1 = ActivityTracker::new();
        let tracker2 = tracker1.clone();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tracker1.is_idle(Duration::from_millis(40)));
        assert!(tracker2.is_idle(Duration::from_millis(40)));

        // Activity on one clone affects the other
        tracker1.record_activity();
        assert!(!tracker2.is_idle(Duration::from_millis(40)));
    }
}
