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
    // The byte counters live with the TUN module, which exists on Unix and
    // Windows. On anything else there is no tunnel to count, and a host
    // still wants a snapshot.
    #[cfg(any(unix, windows))]
    let (upload_bytes, download_bytes) = crate::tun::traffic::get_traffic_counters();
    #[cfg(not(any(unix, windows)))]
    let (upload_bytes, download_bytes) = (0, 0);

    #[cfg(any(unix, windows))]
    let active_connections = crate::tun::traffic::active_connections();
    #[cfg(not(any(unix, windows)))]
    let active_connections = 0;

    StatsSnapshot {
        upload_bytes,
        download_bytes,
        active_connections,
        outbounds: crate::outbound_stats::snapshot_all(),
    }
}

impl StatsSnapshot {
    /// The snapshot as one line of JSON, for the FFI.
    ///
    /// Hand-written rather than serde_json: the library has no JSON
    /// dependency, and a serializer for four integers and a list of
    /// four-field records would cost more download bytes than the feature it
    /// serves. The shape is documented on `shoes_get_stats` in
    /// `include/shoes.h`; adding a key is a compatible change, renaming one
    /// is not.
    pub fn to_json(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(96 + 96 * self.outbounds.len());
        // write! into a String cannot fail; the Results are discarded on that
        // basis rather than unwrapped.
        let _ = write!(
            out,
            "{{\"upload_bytes\":{},\"download_bytes\":{},\"active_connections\":{},\"outbounds\":[",
            self.upload_bytes, self.download_bytes, self.active_connections
        );
        for (i, o) in self.outbounds.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            write_json_string(&mut out, &o.name);
            let _ = write!(
                out,
                ",\"upload_bytes\":{},\"download_bytes\":{},\"active_connections\":{}}}",
                o.upload_bytes, o.download_bytes, o.active_connections
            );
        }
        out.push_str("]}");
        out
    }
}

/// Append `s` as a JSON string literal, quotes included.
///
/// RFC 8259 section 7: the quote and the backslash are escaped, control
/// characters below U+0020 are escaped, and everything else -- including
/// non-ASCII -- is emitted as it stands, which is valid because the output is
/// UTF-8. U+0000 is a control character and so becomes six ASCII bytes, which
/// is what lets the C caller put the result through `CString::new`.
fn write_json_string(out: &mut String, s: &str) {
    use std::fmt::Write as _;

    out.push('"');
    for c in s.chars() {
        match c {
            '\"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// any(unix, windows) as well as cfg(test): these drive the counter through
// tun::traffic, and the tun module exists exactly there. The remaining
// cfg(not(any(unix, windows))) arms of `snapshot` are covered by nothing
// that runs, only by review.
#[cfg(all(test, any(unix, windows)))]
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

        let mut set = crate::outbound_stats::OutboundSet::default();
        set.insert("Amsterdam", "ams1.example:443").unwrap();
        set.insert("Frankfurt", "fra1.example:443").unwrap();
        crate::outbound_stats::install(&set);
        crate::outbound_stats::lookup("Amsterdam").add_download(4096);

        let snap = snapshot();
        let names: Vec<&str> = snap.outbounds.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names, vec!["Amsterdam", "Frankfurt"]);
        assert_eq!(snap.outbounds[0].download_bytes, 4096);
    }
}

#[cfg(test)]
mod json_tests {
    use super::*;
    use crate::outbound_stats::OutboundStats;

    fn outbound(name: &str, up: u64, down: u64, conns: usize) -> OutboundStats {
        OutboundStats {
            name: name.to_string(),
            upload_bytes: up,
            download_bytes: down,
            active_connections: conns,
        }
    }

    /// The zero document is what a host sees before `start`. Byte-exact,
    /// because a host may well compare against a literal to detect "nothing
    /// yet".
    #[test]
    fn a_zero_snapshot_is_the_documented_literal() {
        let snap = StatsSnapshot {
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            outbounds: Vec::new(),
        };
        assert_eq!(
            snap.to_json(),
            r#"{"upload_bytes":0,"download_bytes":0,"active_connections":0,"outbounds":[]}"#
        );
    }

    /// Asymmetric values so a transposition fails; u64::MAX so a cast to a
    /// narrower type fails.
    #[test]
    fn every_field_round_trips_through_a_real_parser() {
        let snap = StatsSnapshot {
            upload_bytes: 7,
            download_bytes: u64::MAX,
            active_connections: 3,
            outbounds: vec![
                outbound("Frankfurt", 11, 22, 1),
                outbound("Amsterdam", 33, 44, 2),
            ],
        };
        let v: serde_json::Value = serde_json::from_str(&snap.to_json()).unwrap();

        assert_eq!(v["upload_bytes"], 7);
        assert_eq!(v["download_bytes"], u64::MAX);
        assert_eq!(v["active_connections"], 3);
        let outs = v["outbounds"].as_array().unwrap();
        assert_eq!(outs.len(), 2);
        // Input order, not re-sorted: snapshot() already sorts by name and
        // the serializer must not have an opinion of its own.
        assert_eq!(outs[0]["name"], "Frankfurt");
        assert_eq!(outs[0]["upload_bytes"], 11);
        assert_eq!(outs[0]["download_bytes"], 22);
        assert_eq!(outs[0]["active_connections"], 1);
        assert_eq!(outs[1]["name"], "Amsterdam");
        assert_eq!(outs[1]["active_connections"], 2);
    }

    /// Every character class JSON cannot carry raw, built by code point so
    /// that this file contains no control characters of its own: quote,
    /// backslash, the four with short escapes, two that need the six-byte
    /// form, and multi-byte UTF-8 which must pass through untouched.
    fn hostile_name() -> String {
        let mut name = String::from("quote:\" backslash:");
        name.push(char::from(0x5c));
        name.push_str(" lf:");
        name.push(char::from(0x0a));
        name.push_str(" tab:");
        name.push(char::from(0x09));
        name.push_str(" cr:");
        name.push(char::from(0x0d));
        name.push_str(" bs:");
        name.push(char::from(0x08));
        name.push_str(" ff:");
        name.push(char::from(0x0c));
        name.push_str(" soh:");
        name.push(char::from(0x01));
        name.push_str(" us:");
        name.push(char::from(0x1f));
        name.push_str(" latin1:");
        name.push(char::from(0xe9));
        name.push_str(" astral:");
        name.push(char::from_u32(0x1f980).unwrap());
        name
    }

    /// Names come from user config, so this is the one place a bad escape
    /// becomes a malformed document on a phone.
    #[test]
    fn a_hostile_name_survives_escaping() {
        let name = hostile_name();
        let snap = StatsSnapshot {
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            outbounds: vec![outbound(&name, 0, 0, 0)],
        };
        let v: serde_json::Value = serde_json::from_str(&snap.to_json()).unwrap();
        assert_eq!(v["outbounds"][0]["name"], name);
    }

    /// The C side hands this to CString::new, which rejects an interior NUL.
    /// The escaper must have already turned it into six ASCII bytes.
    #[test]
    fn an_interior_nul_is_escaped_not_emitted() {
        let name = format!("a{}b", char::from(0x00));
        let snap = StatsSnapshot {
            upload_bytes: 0,
            download_bytes: 0,
            active_connections: 0,
            outbounds: vec![outbound(&name, 0, 0, 0)],
        };
        let json = snap.to_json();
        assert!(!json.as_bytes().contains(&0), "raw NUL in {json:?}");

        let expected = format!("a{}u0000b", char::from(0x5c));
        assert!(json.contains(&expected), "{json}");

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["outbounds"][0]["name"], name);
    }
}
