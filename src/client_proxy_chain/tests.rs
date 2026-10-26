use super::*;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr};

use crate::address::NetLocation;
use crate::async_stream::AsyncStream;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;

/// Mock SocketConnector that fails on connect (for unit testing structure).
#[derive(Debug)]
struct MockSocketConnector;

#[async_trait]
impl SocketConnector for MockSocketConnector {
    async fn connect(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        Err(std::io::Error::other(
            "MockSocketConnector::connect not implemented",
        ))
    }

    async fn connect_udp_bidirectional(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::other(
            "MockSocketConnector::connect_udp_bidirectional not implemented",
        ))
    }

    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

#[derive(Debug)]
struct MockProxyConnector {
    location: NetLocation,
    supports_udp: bool,
}

impl MockProxyConnector {
    fn new(port: u16, supports_udp: bool) -> Self {
        Self {
            location: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            supports_udp,
        }
    }
}

#[derive(Debug)]
struct ReusableProxy {
    location: NetLocation,
    fail: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl ProxyConnector for ReusableProxy {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }
    fn supports_udp_over_tcp(&self) -> bool {
        false
    }
    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            return Err(std::io::Error::other("CONNECT rejected"));
        }
        Ok(Some(TcpClientSetupResult {
            client_stream: Box::new(tokio::io::duplex(8).0),
            early_data: Some(target.to_string().into_bytes()),
        }))
    }
    async fn setup_tcp_stream(
        &self,
        _: Box<dyn AsyncStream>,
        _: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        panic!("a warm proxy must not run cold setup")
    }
    async fn setup_udp_bidirectional(
        &self,
        _: Box<dyn AsyncStream>,
        _: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        unreachable!()
    }
}

#[tokio::test]
async fn reuse_respects_selected_entry_target_and_multihop_boundaries() {
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let warm = || InitialHopEntry::Proxy {
        socket: mock_socket(),
        proxy: Box::new(ReusableProxy {
            location: NetLocation::from_str("127.0.0.1:1080", None).unwrap(),
            fail: false,
            calls: calls.clone(),
        }),
    };
    let target: ResolvedLocation = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    let chain = ClientProxyChain::new(vec![warm(), proxy_entry(1081, false)], vec![]);
    let result = chain.connect_tcp(target.clone(), &resolver).await.unwrap();
    assert_eq!(result.early_data.unwrap(), target.to_string().as_bytes());
    // The next selected entry is cold; it must not borrow the previous entry's session.
    assert!(chain.connect_tcp(target.clone(), &resolver).await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let chain = ClientProxyChain::new(vec![warm()], vec![vec![mock_proxy(1082, false)]]);
    assert!(chain.connect_tcp(target, &resolver).await.is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn rejected_reuse_does_not_fall_back_to_a_fresh_connect() {
    let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::NativeResolver::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let chain = ClientProxyChain::new(
        vec![InitialHopEntry::Proxy {
            socket: mock_socket(),
            proxy: Box::new(ReusableProxy {
                location: NetLocation::from_str("127.0.0.1:1080", None).unwrap(),
                fail: true,
                calls: calls.clone(),
            }),
        }],
        vec![],
    );
    let target = NetLocation::from_str("example.com:443", None)
        .unwrap()
        .into();
    let error = chain.connect_tcp(target, &resolver).await.err().unwrap();
    assert_eq!(error.to_string(), "CONNECT rejected");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[async_trait]
impl ProxyConnector for MockProxyConnector {
    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.supports_udp
    }

    async fn setup_tcp_stream(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Err(std::io::Error::other(
            "MockProxyConnector::setup_tcp_stream not implemented",
        ))
    }

    async fn setup_udp_bidirectional(
        &self,
        _stream: Box<dyn AsyncStream>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::other(
            "MockProxyConnector::setup_udp_bidirectional not implemented",
        ))
    }
}

fn mock_socket() -> Arc<dyn SocketConnector> {
    Arc::new(MockSocketConnector)
}

fn mock_proxy(port: u16, supports_udp: bool) -> Box<dyn ProxyConnector> {
    Box::new(MockProxyConnector::new(port, supports_udp))
}

fn direct_entry() -> InitialHopEntry {
    InitialHopEntry::Direct(mock_socket())
}

fn proxy_entry(port: u16, supports_udp: bool) -> InitialHopEntry {
    InitialHopEntry::Proxy {
        socket: mock_socket(),
        proxy: mock_proxy(port, supports_udp),
    }
}

#[test]
fn test_initial_hop_entry_direct_supports_udp() {
    let entry = direct_entry();
    assert!(entry.supports_udp());
}

#[test]
fn test_initial_hop_entry_proxy_supports_udp() {
    let entry = proxy_entry(1080, true);
    assert!(entry.supports_udp());
}

#[test]
fn test_initial_hop_entry_proxy_no_udp() {
    let entry = proxy_entry(1080, false);
    assert!(!entry.supports_udp());
}

#[test]
fn test_chain_single_direct() {
    let chain = ClientProxyChain::new(vec![direct_entry()], vec![]);
    assert_eq!(chain.num_hops(), 1);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_single_proxy() {
    let chain = ClientProxyChain::new(vec![proxy_entry(1080, true)], vec![]);
    assert_eq!(chain.num_hops(), 1);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_single_proxy_no_udp() {
    let chain = ClientProxyChain::new(vec![proxy_entry(1080, false)], vec![]);
    assert_eq!(chain.num_hops(), 1);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_direct_with_subsequent() {
    let chain = ClientProxyChain::new(vec![direct_entry()], vec![vec![mock_proxy(1080, true)]]);
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_direct_with_subsequent_no_udp() {
    let chain = ClientProxyChain::new(vec![direct_entry()], vec![vec![mock_proxy(1080, false)]]);
    assert_eq!(chain.num_hops(), 2);
    assert!(!chain.supports_udp()); // Subsequent doesn't support UDP
}

#[test]
fn test_chain_proxy_with_subsequent() {
    let chain = ClientProxyChain::new(
        vec![proxy_entry(1080, true)],
        vec![vec![mock_proxy(1081, true)]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_mixed_initial_pool() {
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(1080, true), // VMess proxy
            proxy_entry(1081, true), // VLESS proxy
            direct_entry(),          // Direct
        ],
        vec![],
    );
    assert_eq!(chain.num_hops(), 1);
    assert!(chain.supports_udp());
    // All 3 entries support UDP (initial hop IS final hop)
    assert!(chain.udp_uses_initial_hop);
    assert_eq!(chain.udp_final_hop_indices, vec![0, 1, 2]);
}

#[test]
fn test_chain_mixed_initial_pool_partial_udp() {
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(1080, false), // No UDP
            proxy_entry(1081, true),  // Has UDP
            direct_entry(),           // Has UDP
        ],
        vec![],
    );
    assert!(chain.supports_udp());
    // Only entries 1 and 2 support UDP (initial hop IS final hop)
    assert!(chain.udp_uses_initial_hop);
    assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
}

#[test]
fn test_chain_two_subsequent_hops() {
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
    );
    assert_eq!(chain.num_hops(), 3);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_pool_at_subsequent_hop() {
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![vec![
            mock_proxy(1080, true),
            mock_proxy(1081, false),
            mock_proxy(1082, true),
        ]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp()); // At least one in pool supports UDP
}

#[test]
#[should_panic(expected = "must have at least one initial hop entry")]
fn test_chain_empty_initial_hop_panics() {
    ClientProxyChain::new(vec![], vec![]);
}

#[test]
fn test_group_single_chain() {
    let chain = ClientProxyChain::new(vec![direct_entry()], vec![]);
    let group = ClientChainGroup::new(vec![chain]);
    assert!(group.supports_udp());
}

#[test]
#[should_panic(expected = "must have at least one chain")]
fn test_group_empty_chains_panics() {
    ClientChainGroup::new(vec![]);
}

#[test]
fn test_group_mixed_udp_support() {
    let chain1 = ClientProxyChain::new(vec![proxy_entry(1080, true)], vec![]);
    let chain2 = ClientProxyChain::new(vec![proxy_entry(1081, false)], vec![]);
    let group = ClientChainGroup::new(vec![chain1, chain2]);
    assert!(group.supports_udp());
    assert_eq!(group.udp_chain_indices, vec![0]);
}

#[test]
fn test_group_all_support_udp() {
    let chain1 = ClientProxyChain::new(vec![proxy_entry(1080, true)], vec![]);
    let chain2 = ClientProxyChain::new(vec![direct_entry()], vec![]);
    let group = ClientChainGroup::new(vec![chain1, chain2]);
    assert!(group.supports_udp());
    assert_eq!(group.udp_chain_indices, vec![0, 1]);
}

#[test]
fn test_group_none_support_udp() {
    let chain1 = ClientProxyChain::new(vec![proxy_entry(1080, false)], vec![]);
    let chain2 = ClientProxyChain::new(vec![proxy_entry(1081, false)], vec![]);
    let group = ClientChainGroup::new(vec![chain1, chain2]);
    assert!(!group.supports_udp());
    assert!(group.udp_chain_indices.is_empty());
}

#[test]
fn test_pool_pairing_fix_socket_proxy_always_paired() {
    // Create a mixed pool simulating: vmess@1080, vless@1081, direct
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(1080, true),
            proxy_entry(1081, true),
            direct_entry(),
        ],
        vec![],
    );

    // Select entries multiple times and verify pairing
    // Round-robin should cycle: 0, 1, 2, 0, 1, 2, ...
    for iteration in 0..6 {
        let entry = chain.initial_hop[chain.select_indices(false).unwrap()[0]].as_ref();
        let expected_idx = iteration % 3;

        match (expected_idx, entry) {
            (0, InitialHopEntry::Proxy { proxy, .. }) => {
                // Entry 0: should be vmess proxy at port 1080
                assert_eq!(
                    proxy.proxy_location().port(),
                    1080,
                    "Iteration {}: expected proxy port 1080, got {}",
                    iteration,
                    proxy.proxy_location().port()
                );
            }
            (1, InitialHopEntry::Proxy { proxy, .. }) => {
                // Entry 1: should be vless proxy at port 1081
                assert_eq!(
                    proxy.proxy_location().port(),
                    1081,
                    "Iteration {}: expected proxy port 1081, got {}",
                    iteration,
                    proxy.proxy_location().port()
                );
            }
            (2, InitialHopEntry::Direct(_)) => {
                // Entry 2: should be direct (no proxy)
                // This is correct - direct has no proxy to mismatch
            }
            (idx, entry) => {
                panic!(
                    "Iteration {}: unexpected entry type at index {}. Entry: {:?}",
                    iteration, idx, entry
                );
            }
        }
    }
}

#[test]
fn test_pool_pairing_fix_udp_selection_also_paired() {
    // Create a mixed pool where only some support UDP
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(1080, false), // No UDP
            proxy_entry(1081, true),  // Has UDP
            direct_entry(),           // Direct always supports UDP
        ],
        vec![],
    );

    // UDP selection should only return entries 1 and 2 (initial hop IS final hop)
    assert!(chain.udp_uses_initial_hop);
    assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

    // Verify UDP selection cycles through UDP-capable entries only
    // Manually select using the new logic
    for iteration in 0..4 {
        let idx = chain
            .udp_final_hop_next_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
        let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
        let entry = &chain.initial_hop[pool_idx];
        let expected_udp_idx = iteration % 2; // 0 or 1 in udp_initial_hop_indices

        match (expected_udp_idx, entry.as_ref()) {
            (0, InitialHopEntry::Proxy { proxy, .. }) => {
                // UDP index 0 -> initial_hop[1] -> port 1081
                assert_eq!(
                    proxy.proxy_location().port(),
                    1081,
                    "UDP iteration {}: expected proxy port 1081",
                    iteration
                );
            }
            (1, InitialHopEntry::Direct(_)) => {
                // UDP index 1 -> initial_hop[2] -> direct
                // Correct!
            }
            (idx, entry) => {
                panic!(
                    "UDP iteration {}: unexpected at udp_idx {}. Entry: {:?}",
                    iteration, idx, entry
                );
            }
        }
    }
}

#[test]
fn test_udp_selection_with_subsequent_hops() {
    // Test that when udp_uses_initial_hop = false, we select:
    // - Initial hop normally (from all entries)
    // - Final hop from udp_final_hop_indices
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(1080, false), // HTTP - no UDP (but should be usable for UDP!)
            proxy_entry(1081, false), // Another HTTP
        ],
        vec![vec![
            mock_proxy(8080, false), // HTTP - no UDP (index 0)
            mock_proxy(443, true),   // VMess - has UDP (index 1)
            mock_proxy(444, true),   // VLESS - has UDP (index 2)
        ]],
    );

    assert!(!chain.udp_uses_initial_hop);
    assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);

    // Verify that initial hop selection would use all entries (indices 0 and 1)
    // We can't easily test this without calling connect_udp_bidirectional(), but we can verify
    // that the normal round-robin will cycle through both
    for i in 0..4 {
        let entry = chain.initial_hop[chain.select_indices(false).unwrap()[0]].as_ref();
        let expected_idx = i % 2;
        match (expected_idx, entry) {
            (0, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1080);
            }
            (1, InitialHopEntry::Proxy { proxy, .. }) => {
                assert_eq!(proxy.proxy_location().port(), 1081);
            }
            _ => panic!("Unexpected entry"),
        }
    }

    // Verify that final hop selection cycles through udp_final_hop_indices only
    let final_hop = chain.subsequent_hops.last().unwrap();
    for iteration in 0..6 {
        let idx = chain
            .udp_final_hop_next_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
        let pool_idx = chain.udp_final_hop_indices[idx % chain.udp_final_hop_indices.len()];
        let proxy = &final_hop[pool_idx];

        let expected_udp_idx = iteration % 2; // 0 or 1 in udp_final_hop_indices
        match expected_udp_idx {
            0 => {
                // udp_final_hop_indices[0] = 1 -> VMess at port 443
                assert_eq!(proxy.proxy_location().port(), 443);
            }
            1 => {
                // udp_final_hop_indices[1] = 2 -> VLESS at port 444
                assert_eq!(proxy.proxy_location().port(), 444);
            }
            _ => panic!("Unexpected index"),
        }
    }
}

#[test]
fn test_chain_with_subsequent_hops_uses_final_hop_indices() {
    // Test the key insight: when has subsequent hops, udp_final_hop_indices
    // points to the FINAL subsequent hop, not the initial hop
    let chain = ClientProxyChain::new(
        vec![
            proxy_entry(1080, false), // HTTP - no UDP
            proxy_entry(1081, true),  // SOCKS5 - has UDP (irrelevant!)
        ],
        vec![vec![
            mock_proxy(8080, false), // HTTP - no UDP (index 0)
            mock_proxy(443, true),   // VMess - has UDP (index 1)
            mock_proxy(444, true),   // VLESS - has UDP (index 2)
        ]],
    );

    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());

    // Key: udp_uses_initial_hop should be FALSE
    assert!(!chain.udp_uses_initial_hop);

    // udp_final_hop_indices should point to indices in the FINAL subsequent hop
    // NOT the initial hop! Only indices 1 and 2 (VMess, VLESS) support UDP
    assert_eq!(chain.udp_final_hop_indices, vec![1, 2]);
}

#[test]
fn test_chain_intermediate_hop_no_udp_final_hop_has_udp() {
    // direct -> http (no UDP) -> vmess (has UDP)
    // Should support UDP because only final hop matters
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![
            vec![mock_proxy(8080, false)], // HTTP - no UDP
            vec![mock_proxy(443, true)],   // VMess - has UDP
        ],
    );
    assert_eq!(chain.num_hops(), 3);
    assert!(chain.supports_udp()); // This was the bug - old code returned false
}

#[test]
fn test_chain_all_intermediate_no_udp_final_has_udp() {
    // direct -> http -> socks5 -> vmess
    // Three intermediate hops, none with UDP, but final has UDP
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![
            vec![mock_proxy(8080, false)], // HTTP - no UDP
            vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
            vec![mock_proxy(443, true)],   // VMess - has UDP
        ],
    );
    assert_eq!(chain.num_hops(), 4);
    assert!(chain.supports_udp()); // This was the bug - old code returned false
}

#[test]
fn test_chain_intermediate_has_udp_final_no_udp() {
    // direct -> vmess (has UDP) -> http (no UDP)
    // Should NOT support UDP because final hop doesn't
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![
            vec![mock_proxy(443, true)],   // VMess - has UDP
            vec![mock_proxy(8080, false)], // HTTP - no UDP
        ],
    );
    assert_eq!(chain.num_hops(), 3);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_pooled_final_hop_partial_udp() {
    // direct -> [http (no UDP), vmess (has UDP), vless (has UDP)]
    // Should support UDP because final hop pool has UDP-capable connectors
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![vec![
            mock_proxy(8080, false), // HTTP - no UDP
            mock_proxy(443, true),   // VMess - has UDP
            mock_proxy(444, true),   // VLESS - has UDP
        ]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(chain.supports_udp());
}

#[test]
fn test_chain_pooled_final_hop_no_udp() {
    // direct -> [http, socks5] (neither has UDP)
    // Should NOT support UDP
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![vec![
            mock_proxy(8080, false), // HTTP - no UDP
            mock_proxy(1080, false), // SOCKS5 - no UDP
        ]],
    );
    assert_eq!(chain.num_hops(), 2);
    assert!(!chain.supports_udp());
}

#[test]
fn test_chain_complex_multi_hop_mixed_udp() {
    // direct -> http (no UDP) -> socks5 (no UDP) -> [http (no), vmess (yes)]
    // Should support UDP: intermediate hops don't matter, final pool has vmess
    let chain = ClientProxyChain::new(
        vec![direct_entry()],
        vec![
            vec![mock_proxy(8080, false)], // HTTP - no UDP
            vec![mock_proxy(1080, false)], // SOCKS5 - no UDP
            vec![
                mock_proxy(8081, false), // HTTP - no UDP
                mock_proxy(443, true),   // VMess - has UDP
            ],
        ],
    );
    assert_eq!(chain.num_hops(), 4);
    assert!(chain.supports_udp()); // This was the bug - old code returned false
}
