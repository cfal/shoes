use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::address::{NetLocation, ResolvedLocation};

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
    pub fake_dns: bool,
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
    pub chains: Vec<String>,
    pub rule_payload: String,
    pub counters: FlowCounters,
    pub cancel: CancellationToken,
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
}

#[derive(Debug, Default)]
struct RegistryState {
    snapshot_sequence: u64,
    entries: BTreeMap<String, Arc<FlowEntry>>,
    closed_upload: u64,
    closed_download: u64,
}

#[derive(Debug, Default)]
pub struct FlowRegistry {
    state: Mutex<RegistryState>,
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
            chains: if chains.is_empty() {
                vec!["DIRECT".into()]
            } else {
                chains
            },
            rule_payload: format!("{} ({}): {}", self.inbound, self.scope, rule_payload),
            counters: FlowCounters::default(),
            cancel: CancellationToken::new(),
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
        let (sequence, entries, mut upload_total, mut download_total) = {
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
            )
        };
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
                }
            })
            .collect();
        ConnectionsSnapshot {
            sequence,
            upload_total,
            download_total,
            memory,
            connections,
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
}
