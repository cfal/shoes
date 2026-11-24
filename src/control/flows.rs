use crate::atomic::AtomicU64;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::connection_notes::{ConnectionNotes, MAX_FLOWS, Note};
use crate::address::{NetLocation, ResolvedLocation};

/// Inbound scopes whose closed-flow totals are retained, shared across reloads.
pub const MAX_SCOPE_TOTALS: usize = 16_384;

#[derive(Debug, Default)]
pub struct FlowCounters {
    upload: AtomicU64,
    download: AtomicU64,
}

impl FlowCounters {
    pub fn upload(&self, bytes: usize) {
        self.upload.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn download(&self, bytes: usize) {
        self.download.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn totals(&self) -> (u64, u64) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub registry: Arc<FlowRegistry>,
    pub generation: u64,
    pub inbound: String,
    pub scope: String,
    pub protocol: String,
}

#[derive(Debug, Default)]
pub struct FlowInfo {
    pub source: Option<std::net::SocketAddr>,
    pub original: Option<NetLocation>,
    pub restored_host: Option<String>,
    pub sniff_host: Option<String>,
    pub sniff_protocol: Option<crate::rules::Protocol>,
    pub fake_dns: bool,
    pub notes: Option<Arc<ConnectionNotes>>,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub protocol: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    pub source_port: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    pub destination_port: String,
    pub host: String,
    pub sniff_host: String,
    pub sniff_protocol: String,
    pub dns_mode: String,
    pub inbound_name: String,
    pub process: String,
    pub process_path: String,
    pub remote_destination: String,
    pub shoes_original_destination: String,
}

#[derive(Debug)]
pub struct FlowEntry {
    pub id: String,
    pub generation: u64,
    pub start: String,
    pub metadata: FlowMetadata,
    pub scope: String,
    pub chains: Vec<String>,
    pub rule_payload: String,
    pub counters: FlowCounters,
    pub cancel: CancellationToken,
    pub notes: Option<Arc<ConnectionNotes>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub id: String,
    pub start: String,
    pub metadata: FlowMetadata,
    pub chains: Vec<String>,
    pub provider_chains: Vec<String>,
    pub rule: &'static str,
    pub rule_payload: String,
    pub upload: u64,
    pub download: u64,
    pub shoes_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<Note>>,
}

/// Cumulative payload bytes of the open and closed flows of one inbound scope.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ScopeTotals {
    pub inbound: String,
    pub scope: String,
    pub upload: u64,
    pub download: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionsSnapshot {
    #[serde(skip)]
    pub sequence: u64,
    pub upload_total: u64,
    pub download_total: u64,
    pub memory: u64,
    pub connections: Vec<ConnectionSnapshot>,
    pub shoes_scope_totals: Vec<ScopeTotals>,
}

#[derive(Debug, Default)]
struct RegistryState {
    snapshot_sequence: u64,
    entries: BTreeMap<String, Arc<FlowEntry>>,
    closed_upload: u64,
    closed_download: u64,
    // Inbound, then scope: a close looks its scope up without allocating.
    closed_scopes: BTreeMap<String, BTreeMap<String, (u64, u64)>>,
    closed_scope_count: usize,
}

impl RegistryState {
    fn close_scope(&mut self, inbound: &str, scope: &str, upload: u64, download: u64) {
        if let Some(totals) = self
            .closed_scopes
            .get_mut(inbound)
            .and_then(|scopes| scopes.get_mut(scope))
        {
            totals.0 += upload;
            totals.1 += download;
            return;
        }
        // Idle flows need no entry, and a full table keeps only the process totals.
        if (upload, download) == (0, 0) || self.closed_scope_count == MAX_SCOPE_TOTALS {
            return;
        }
        self.closed_scopes
            .entry(inbound.into())
            .or_default()
            .insert(scope.into(), (upload, download));
        self.closed_scope_count += 1;
    }
}

#[derive(Debug, Default)]
pub struct FlowRegistry {
    state: Mutex<RegistryState>,
    notes_slots: Option<Arc<tokio::sync::Semaphore>>,
}

#[derive(Debug)]
pub struct FlowGuard {
    registry: Arc<FlowRegistry>,
    pub entry: Arc<FlowEntry>,
}

impl FlowContext {
    pub fn register(
        &self,
        network: &str,
        target: &ResolvedLocation,
        chains: Vec<String>,
        rule_payload: &str,
        info: FlowInfo,
    ) -> FlowGuard {
        let destination: &NetLocation = target.location();
        let hostname = destination.address().hostname();
        let entry = Arc::new(FlowEntry {
            id: crate::uuid_util::generate_uuid(),
            generation: self.generation,
            start: chrono::Utc::now().to_rfc3339(),
            metadata: FlowMetadata {
                network: network.into(),
                source_ip: info
                    .source
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_default(),
                source_port: info
                    .source
                    .map(|addr| addr.port().to_string())
                    .unwrap_or_default(),
                protocol: self.protocol.clone(),
                destination_ip: target
                    .resolved_addr()
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_else(|| {
                        if hostname.is_none() {
                            destination.address().to_string()
                        } else {
                            String::new()
                        }
                    }),
                destination_port: destination.port().to_string(),
                host: info
                    .restored_host
                    .unwrap_or_else(|| hostname.unwrap_or("").to_owned()),
                sniff_host: info.sniff_host.unwrap_or_default(),
                sniff_protocol: info.sniff_protocol.map_or("", |p| p.as_str()).into(),
                remote_destination: destination.to_string(),
                shoes_original_destination: info
                    .original
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                inbound_name: self.inbound.clone(),
                dns_mode: if info.fake_dns { "fake-ip" } else { "normal" }.into(),
                ..Default::default()
            },
            scope: self.scope.clone(),
            chains: if chains.is_empty() {
                vec!["DIRECT".into()]
            } else {
                chains
            },
            rule_payload: format!("{} ({}): {}", self.inbound, self.scope, rule_payload),
            counters: FlowCounters::default(),
            cancel: CancellationToken::new(),
            notes: info.notes,
        });
        self.registry
            .state
            .lock()
            .entries
            .insert(entry.id.clone(), entry.clone());
        FlowGuard {
            registry: self.registry.clone(),
            entry,
        }
    }
}

impl FlowRegistry {
    pub fn new(connection_notes: bool) -> Self {
        Self {
            notes_slots: connection_notes.then(|| Arc::new(tokio::sync::Semaphore::new(MAX_FLOWS))),
            ..Default::default()
        }
    }

    pub fn notes_enabled(&self) -> bool {
        self.notes_slots.is_some()
    }

    pub fn start_notes(&self) -> Option<Arc<ConnectionNotes>> {
        let permit = self
            .notes_slots
            .as_ref()?
            .clone()
            .try_acquire_owned()
            .ok()?;
        Some(Arc::new(ConnectionNotes::new(permit)))
    }

    pub fn cancel(&self, id: &str) {
        let entry = self.state.lock().entries.get(id).cloned();
        if let Some(entry) = entry {
            entry.cancel.cancel();
        }
    }

    pub fn cancel_all(&self) {
        let entries: Vec<_> = self.state.lock().entries.values().cloned().collect();
        for entry in entries {
            entry.cancel.cancel();
        }
    }

    pub fn snapshot(&self, memory: u64) -> ConnectionsSnapshot {
        let (sequence, entries, mut upload_total, mut download_total, mut scopes) = {
            let mut state = self.state.lock();
            state.snapshot_sequence += 1;
            (
                state.snapshot_sequence,
                state
                    .entries
                    .values()
                    .map(|entry| {
                        let (upload, download) = entry.counters.totals();
                        (entry.clone(), upload, download)
                    })
                    .collect::<Vec<_>>(),
                state.closed_upload,
                state.closed_download,
                state
                    .closed_scopes
                    .iter()
                    .flat_map(|(inbound, scopes)| {
                        scopes
                            .iter()
                            .map(move |(scope, totals)| ((inbound.clone(), scope.clone()), *totals))
                    })
                    .collect::<BTreeMap<_, _>>(),
            )
        };
        // Open flows read from the same sample as the totals, so the scopes sum to them.
        for (entry, upload, download) in &entries {
            if (*upload, *download) != (0, 0) {
                let totals = scopes
                    .entry((entry.metadata.inbound_name.clone(), entry.scope.clone()))
                    .or_default();
                totals.0 += upload;
                totals.1 += download;
            }
        }
        let connections = entries
            .into_iter()
            .map(|(entry, upload, download)| {
                upload_total += upload;
                download_total += download;
                ConnectionSnapshot {
                    id: entry.id.clone(),
                    start: entry.start.clone(),
                    metadata: entry.metadata.clone(),
                    chains: entry.chains.clone(),
                    provider_chains: Vec::new(),
                    rule: "Shoes",
                    rule_payload: entry.rule_payload.clone(),
                    upload,
                    download,
                    shoes_generation: entry.generation,
                    notes: entry.notes.as_ref().map(|notes| notes.snapshot()),
                }
            })
            .collect();
        ConnectionsSnapshot {
            sequence,
            upload_total,
            download_total,
            memory,
            connections,
            shoes_scope_totals: scopes
                .into_iter()
                .map(|((inbound, scope), (upload, download))| ScopeTotals {
                    inbound,
                    scope,
                    upload,
                    download,
                })
                .collect(),
        }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock();
        if state.entries.remove(&self.entry.id).is_some() {
            let (upload, download) = self.entry.counters.totals();
            state.closed_upload += upload;
            state.closed_download += download;
            state.close_scope(
                &self.entry.metadata.inbound_name,
                &self.entry.scope,
                upload,
                download,
            );
        }
    }
}

#[cfg(test)]
pub(crate) fn test_guard() -> FlowGuard {
    FlowContext {
        registry: Arc::new(FlowRegistry::default()),
        generation: 1,
        inbound: "test".into(),
        scope: "root".into(),
        protocol: "Socks5".into(),
    }
    .register(
        "tcp",
        &NetLocation::from_str("test.example:443", None)
            .unwrap()
            .into(),
        vec!["DIRECT".into()],
        "all",
        FlowInfo::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_notes_are_optional_and_disappear_with_active_connections() {
        use super::super::connection_notes::Phase;
        for enabled in [false, true] {
            let registry = Arc::new(FlowRegistry::new(enabled));
            let context = FlowContext {
                registry: registry.clone(),
                generation: 7,
                inbound: "test".into(),
                scope: "root".into(),
                protocol: "Socks5".into(),
            };
            let notes = registry.start_notes();
            let weak = notes.as_ref().map(Arc::downgrade);
            if let Some(notes) = &notes {
                notes.event(Phase::Routing, format_args!("fixture rule"));
            }
            assert!(registry.snapshot(0).connections.is_empty());
            let guard = context.register(
                "tcp",
                &NetLocation::from_str("fixture.test:443", None)
                    .unwrap()
                    .into(),
                vec!["DIRECT".into()],
                "all",
                FlowInfo {
                    notes,
                    ..Default::default()
                },
            );
            guard.entry.counters.upload(13);
            guard.entry.counters.download(27);
            let snapshot = serde_json::to_value(registry.snapshot(0)).unwrap();
            let connection = &snapshot["connections"][0];
            assert_eq!(connection["id"], guard.entry.id);
            assert_eq!(connection["shoesGeneration"], 7);
            assert_eq!(connection["chains"], serde_json::json!(["DIRECT"]));
            assert_eq!(connection.get("notes").is_some(), enabled);
            if enabled {
                assert_eq!(connection["notes"][0]["text"], "fixture rule");
                assert!(connection["notes"][0]["elapsedUs"].is_u64());
            }
            registry.cancel(&guard.entry.id);
            assert!(guard.entry.cancel.is_cancelled());
            drop(guard);
            assert!(weak.is_none_or(|notes| notes.upgrade().is_none()));
            let snapshot = registry.snapshot(0);
            assert!(snapshot.connections.is_empty());
            assert_eq!((snapshot.upload_total, snapshot.download_total), (13, 27));
        }
    }

    #[test]
    fn connection_notes_allow_concurrent_snapshots_and_close() {
        use super::super::connection_notes::Phase;
        let registry = Arc::new(FlowRegistry::new(true));
        let context = FlowContext {
            registry: registry.clone(),
            generation: 1,
            inbound: "test".into(),
            scope: "root".into(),
            protocol: "fixture".into(),
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..1000 {
                    registry.snapshot(0);
                }
            });
            for _ in 0..1000 {
                let notes = registry.start_notes().unwrap();
                let guard = context.register(
                    "tcp",
                    &NetLocation::from_str("fixture.test:443", None)
                        .unwrap()
                        .into(),
                    vec![],
                    "all",
                    FlowInfo {
                        notes: Some(notes.clone()),
                        ..Default::default()
                    },
                );
                notes.event(Phase::Setup, format_args!("outbound ready"));
                drop(guard);
            }
        });
        assert!(registry.snapshot(0).connections.is_empty());
    }
    #[test]
    fn sniffed_udp_protocol_is_separate_from_inbound_proxy_type() {
        let context = FlowContext {
            registry: Arc::new(FlowRegistry::default()),
            generation: 1,
            inbound: "local".into(),
            scope: "default".into(),
            protocol: "Socks5".into(),
        };
        for protocol in [
            None,
            Some(crate::rules::Protocol::Stun),
            Some(crate::rules::Protocol::Dtls),
        ] {
            let guard = context.register(
                "udp",
                &NetLocation::from_str("192.0.2.1:443", None).unwrap().into(),
                vec!["DIRECT".into()],
                "calls",
                FlowInfo {
                    sniff_protocol: protocol,
                    ..Default::default()
                },
            );
            let metadata = serde_json::to_value(&guard.entry.metadata).unwrap();
            assert_eq!(metadata["network"], "udp");
            assert_eq!(metadata["type"], "Socks5");
            assert_eq!(
                metadata["sniffProtocol"],
                protocol.map_or("", |p| p.as_str())
            );
        }
    }

    #[test]
    fn metadata_keeps_wire_restored_sniffed_and_effective_targets_separate() {
        let context = FlowContext {
            registry: Arc::new(FlowRegistry::default()),
            generation: 1,
            inbound: "local".into(),
            scope: "tls/default".into(),
            protocol: "Socks5".into(),
        };
        let guard = context.register(
            "tcp",
            &NetLocation::from_str("override.example:8443", None)
                .unwrap()
                .into(),
            vec!["exit".into(), "outbound".into()],
            "match all",
            FlowInfo {
                source: Some("192.0.2.1:1234".parse().unwrap()),
                original: Some(NetLocation::from_str("198.18.0.1:443", None).unwrap()),
                restored_host: Some("restored.example".into()),
                sniff_host: Some("sniffed.example".into()),
                fake_dns: true,
                ..Default::default()
            },
        );
        let metadata = &guard.entry.metadata;
        assert_eq!(metadata.source_ip, "192.0.2.1");
        assert_eq!(metadata.source_port, "1234");
        assert_eq!(metadata.shoes_original_destination, "198.18.0.1:443");
        assert_eq!(metadata.host, "restored.example");
        assert_eq!(metadata.sniff_host, "sniffed.example");
        assert_eq!(metadata.remote_destination, "override.example:8443");
        assert_eq!(metadata.dns_mode, "fake-ip");
    }
    #[test]
    fn close_transfers_totals_and_cancel_all_does_not_block_new_flows() {
        let guard = test_guard();
        let registry = guard.registry.clone();
        guard.entry.counters.upload(13);
        guard.entry.counters.download(27);
        registry.cancel_all();
        assert!(guard.entry.cancel.is_cancelled());
        let snapshot = registry.snapshot(0);
        assert_eq!((snapshot.upload_total, snapshot.download_total), (13, 27));
        assert_eq!(snapshot.connections.len(), 1);
        drop(guard);
        let snapshot = registry.snapshot(0);
        assert_eq!((snapshot.upload_total, snapshot.download_total), (13, 27));
        assert!(snapshot.connections.is_empty());
        let context = FlowContext {
            registry,
            generation: 2,
            inbound: "new".into(),
            scope: "root".into(),
            protocol: "Socks5".into(),
        };
        let new = context.register(
            "udp",
            &NetLocation::from_str("test.example:443", None)
                .unwrap()
                .into(),
            Vec::new(),
            "all",
            FlowInfo::default(),
        );
        assert!(!new.entry.cancel.is_cancelled());
    }

    fn scoped(
        registry: &Arc<FlowRegistry>,
        generation: u64,
        inbound: &str,
        scope: &str,
    ) -> FlowGuard {
        FlowContext {
            registry: registry.clone(),
            generation,
            inbound: inbound.into(),
            scope: scope.into(),
            protocol: "Vless".into(),
        }
        .register(
            "tcp",
            &NetLocation::from_str("test.example:443", None)
                .unwrap()
                .into(),
            Vec::new(),
            "all",
            FlowInfo::default(),
        )
    }

    fn scope_totals(registry: &FlowRegistry) -> Vec<(String, String, u64, u64)> {
        registry
            .snapshot(0)
            .shoes_scope_totals
            .into_iter()
            .map(|totals| (totals.inbound, totals.scope, totals.upload, totals.download))
            .collect()
    }

    #[test]
    fn scope_totals_keep_closed_flows_across_generations_and_sum_to_process_totals() {
        let registry = Arc::new(FlowRegistry::default());
        assert!(scope_totals(&registry).is_empty());

        let first = scoped(&registry, 1, "shared", "root/websocket/0");
        first.entry.counters.upload(3);
        first.entry.counters.download(5);
        let other = scoped(&registry, 1, "shared", "root/websocket/1");
        other.entry.counters.download(7);
        let dedicated = scoped(&registry, 1, "dedicated", "root");
        dedicated.entry.counters.upload(11);
        let idle = scoped(&registry, 1, "idle", "root");
        // Open flows count before any snapshot observes them closing; idle scopes are omitted.
        let expected = vec![
            ("dedicated".to_owned(), "root".to_owned(), 11, 0),
            ("shared".to_owned(), "root/websocket/0".to_owned(), 3, 5),
            ("shared".to_owned(), "root/websocket/1".to_owned(), 0, 7),
        ];
        assert_eq!(scope_totals(&registry), expected);

        // A flow that opens and closes between snapshots is still attributed.
        let brief = scoped(&registry, 1, "shared", "root/websocket/1");
        brief.entry.counters.upload(100);
        brief.entry.counters.download(200);
        drop(brief);
        drop(first);
        drop(other);
        drop(dedicated);
        drop(idle);
        // A later generation's flows in the same scope continue its totals.
        let reloaded = scoped(&registry, 2, "shared", "root/websocket/0");
        reloaded.entry.counters.upload(1000);
        let expected = vec![
            ("dedicated".to_owned(), "root".to_owned(), 11, 0),
            ("shared".to_owned(), "root/websocket/0".to_owned(), 1003, 5),
            ("shared".to_owned(), "root/websocket/1".to_owned(), 100, 207),
        ];
        assert_eq!(scope_totals(&registry), expected);

        let snapshot = registry.snapshot(0);
        let (upload, download) = snapshot
            .shoes_scope_totals
            .iter()
            .fold((0, 0), |sum, totals| {
                (sum.0 + totals.upload, sum.1 + totals.download)
            });
        assert_eq!(
            (upload, download),
            (snapshot.upload_total, snapshot.download_total)
        );
        let json = serde_json::to_value(snapshot).unwrap();
        assert_eq!(
            json["shoesScopeTotals"][1],
            serde_json::json!({
                "inbound": "shared",
                "scope": "root/websocket/0",
                "upload": 1003,
                "download": 5,
            })
        );
    }

    #[test]
    fn scope_totals_are_bounded_without_losing_process_totals() {
        let registry = Arc::new(FlowRegistry::default());
        for index in 0..MAX_SCOPE_TOTALS + 2 {
            let guard = scoped(&registry, 1, &format!("inbound-{index:05}"), "root");
            guard.entry.counters.upload(1);
        }
        let snapshot = registry.snapshot(0);
        assert_eq!(snapshot.shoes_scope_totals.len(), MAX_SCOPE_TOTALS);
        assert_eq!(snapshot.upload_total, MAX_SCOPE_TOTALS as u64 + 2);

        // A retained scope keeps counting, and an open flow of an unretained scope is
        // reported while it lasts.
        let retained = scoped(&registry, 1, "inbound-00000", "root");
        retained.entry.counters.upload(4);
        drop(retained);
        let unretained = scoped(&registry, 1, "late", "root");
        unretained.entry.counters.download(9);
        let totals = scope_totals(&registry);
        assert_eq!(totals.len(), MAX_SCOPE_TOTALS + 1);
        assert_eq!(totals[0], ("inbound-00000".into(), "root".into(), 5, 0));
        assert!(totals.contains(&("late".into(), "root".into(), 0, 9)));
        drop(unretained);
        let snapshot = registry.snapshot(0);
        assert_eq!(snapshot.shoes_scope_totals.len(), MAX_SCOPE_TOTALS);
        assert_eq!(snapshot.download_total, 9);
    }
}
