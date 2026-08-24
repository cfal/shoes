//! Counters a host displays.
//!
//! Deliberately thin. The figure a GUI server list really wants is bytes per
//! configured outbound, and there is no key to hang that on: outbound client
//! configs in `src/config/types/client.rs` carry no name or label field, so
//! the only candidate is an address, which is neither stable across config
//! edits nor meaningful to show a user. Adding outbound labels is a config
//! schema change that reaches mobile, and it belongs in its own spec rather
//! than arriving through the back door of a stats module.

/// A point-in-time reading of the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
}

/// Read the counters.
pub fn snapshot() -> StatsSnapshot {
    // The byte counters live behind cfg(unix) with the TUN module. On Windows
    // there is no tunnel to count yet, and a host still wants a snapshot.
    #[cfg(unix)]
    let (upload_bytes, download_bytes) = crate::tun::traffic::get_traffic_counters();
    #[cfg(not(unix))]
    let (upload_bytes, download_bytes) = (0, 0);

    #[cfg(unix)]
    let active_connections = crate::tun::traffic::active_connections();
    #[cfg(not(unix))]
    let active_connections = 0;

    StatsSnapshot {
        upload_bytes,
        download_bytes,
        active_connections,
    }
}

// cfg(unix) as well as cfg(test): these drive the counter through
// tun::traffic, and the tun module does not exist on Windows. The
// cfg(not(unix)) arms of `snapshot` are covered by the Windows CI job
// compiling this module, not by these.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::tun::traffic::{
        COUNTER_TEST_LOCK, connection_closed, connection_opened, reset_active_connections,
    };

    /// The count has to come back down, or a host shows a number that only
    /// ever grows and means nothing after an hour.
    #[test]
    fn test_the_count_rises_and_falls() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        reset_active_connections();
        assert_eq!(snapshot().active_connections, 0);

        connection_opened();
        connection_opened();
        assert_eq!(snapshot().active_connections, 2);

        connection_closed();
        assert_eq!(snapshot().active_connections, 1);

        connection_closed();
        assert_eq!(snapshot().active_connections, 0);
    }

    /// The stack cleans up on paths that can run more than once for the same
    /// socket, so an unmatched close must floor at zero rather than wrap.
    #[test]
    fn test_an_unmatched_close_floors_at_zero() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        reset_active_connections();

        connection_closed();
        assert_eq!(snapshot().active_connections, 0);
    }
}
