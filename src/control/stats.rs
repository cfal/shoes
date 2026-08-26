//! Counters a host displays.
//!
//! Two layers. `upload_bytes` and `download_bytes` are process-wide totals
//! measured at the TUN edge (`crate::tun::traffic`), so in server mode, where
//! nothing increments them, they stay at zero. `outbounds` is measured at the
//! outbound instead (`crate::outbound_stats`) and is populated in every mode.
//!
//! The two will not agree to the byte: the TUN-edge counter also sees the
//! sniffed prefix and anything a connection wrote before it failed. The
//! difference is explainable, not zero.
//!
//! Outbound naming is specified in
//! `docs/superpowers/specs/2026-08-26-named-outbounds-design.md`.

/// A point-in-time reading of the counters.
///
/// Not `Copy`: `outbounds` is a `Vec`, one entry per configured server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
    /// One entry per configured outbound, sorted by name. Installed when the
    /// service starts, so a host lists every server at zero before any
    /// traffic flows.
    pub outbounds: Vec<crate::outbound_stats::OutboundStats>,
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
        outbounds: crate::outbound_stats::snapshot_all(),
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

    #[test]
    fn the_snapshot_carries_every_installed_outbound() {
        let _registry = crate::outbound_stats::REGISTRY_TEST_LOCK.lock().unwrap();
        crate::outbound_stats::reset_for_test();

        crate::outbound_stats::register("Amsterdam", "ams1.example:443")
            .unwrap()
            .add_download(4096);
        crate::outbound_stats::register("Frankfurt", "fra1.example:443").unwrap();

        let snap = snapshot();
        let names: Vec<&str> = snap.outbounds.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, vec!["Amsterdam", "Frankfurt"]);
        assert_eq!(snap.outbounds[0].download_bytes, 4096);
    }
}
