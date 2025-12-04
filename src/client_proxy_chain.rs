//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! A `ClientProxyChain` represents an ordered sequence of proxy hops, where each hop
//! can be a pool of connectors (for round-robin selection). Traffic flows through
//! each hop in sequence to reach the final destination.
//!
//! ## Design: InitialHopEntry for Hop 0
//!
//! Hop 0 is fundamentally different from subsequent hops:
//! - **Hop 0**: Creates socket AND optionally sets up protocol (if not direct)
//! - **Hops 1+**: Only set up protocol on existing stream
//!
//! To handle mixed pools at hop 0 (e.g., direct + various proxy types), we use
//! `InitialHopEntry` which pairs socket and proxy together, ensuring they are
//! always selected atomically during round-robin.
//!
//! ## Structure
//!
//! - `initial_hop`: Pool of `InitialHopEntry` (Direct or Proxy) for hop 0
//! - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation)

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::debug;

use crate::address::NetLocation;
use crate::async_stream::AsyncMessageStream;
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;

/// Entry in the initial hop (hop 0) pool.
///
/// Each entry pairs socket creation with optional protocol setup,
/// ensuring they are always selected together during round-robin.
pub enum InitialHopEntry {
    /// Direct connection - socket only, no protocol setup.
    /// Connects directly to the next hop's proxy or final destination.
    Direct(Box<dyn SocketConnector>),

    /// Proxy connection - socket + protocol setup paired together.
    /// Socket connects to proxy_location, then protocol wraps the stream.
    Proxy {
        socket: Box<dyn SocketConnector>,
        proxy: Box<dyn ProxyConnector>,
    },
}

impl std::fmt::Debug for InitialHopEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialHopEntry::Direct(socket) => f.debug_tuple("Direct").field(socket).finish(),
            InitialHopEntry::Proxy { socket, proxy } => f
                .debug_struct("Proxy")
                .field("socket", socket)
                .field("proxy_location", &proxy.proxy_location())
                .finish(),
        }
    }
}

impl InitialHopEntry {
    /// Returns true if this entry supports UDP.
    pub fn supports_udp(&self) -> bool {
        match self {
            InitialHopEntry::Direct(_) => true, // Direct always supports UDP
            InitialHopEntry::Proxy { proxy, .. } => proxy.supports_udp_over_tcp(),
        }
    }
}

/// A chain of proxy hops with paired initial hop entries.
///
/// Structure:
/// - `initial_hop`: Pool of InitialHopEntry for hop 0 (socket + optional proxy paired)
/// - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation needed)
pub struct ClientProxyChain {
    /// Initial hop pool: each entry is either Direct or Proxy.
    /// Socket and proxy are paired and selected together.
    initial_hop: Vec<InitialHopEntry>,
    /// Round-robin index for initial hop selection.
    initial_hop_next_index: AtomicU32,

    /// Protocol connectors for subsequent hops (hops 1+).
    /// Outer vec = hops, inner vec = round-robin pool per hop.
    subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    /// Round-robin indices for each subsequent hop's pool.
    subsequent_next_indices: Vec<AtomicU32>,

    /// Indices into the FINAL hop pool for UDP-capable entries.
    /// This is either indices into initial_hop (if no subsequent hops),
    /// or indices into the last subsequent hop pool.
    udp_final_hop_indices: Vec<usize>,
    /// Round-robin index for UDP-capable final hop entries.
    udp_final_hop_next_index: AtomicU32,
    /// Flag indicating which pool udp_final_hop_indices refers to.
    /// true = udp_final_hop_indices points to initial_hop
    /// false = udp_final_hop_indices points to last subsequent hop
    udp_uses_initial_hop: bool,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientProxyChain")
            .field("initial_hop_count", &self.initial_hop.len())
            .field(
                "subsequent_hops",
                &self
                    .subsequent_hops
                    .iter()
                    .map(|h| h.len())
                    .collect::<Vec<_>>(),
            )
            .field("udp_final_hop_indices", &self.udp_final_hop_indices)
            .field("udp_uses_initial_hop", &self.udp_uses_initial_hop)
            .finish()
    }
}

impl ClientProxyChain {
    /// Create a new chain from initial hop entries and subsequent hop pools.
    ///
    /// # Arguments
    /// * `initial_hop` - Pool of InitialHopEntry for hop 0
    /// * `subsequent_hops` - Protocol connectors for hops 1+
    ///
    /// # Panics
    /// Panics if initial_hop is empty.
    pub fn new(
        initial_hop: Vec<InitialHopEntry>,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
    ) -> Self {
        assert!(
            !initial_hop.is_empty(),
            "ClientProxyChain must have at least one initial hop entry"
        );

        // Compute UDP-capable indices in the FINAL hop pool.
        // The final hop is either initial_hop (if no subsequent) or the last subsequent hop.
        // Only the hop that calls setup_udp_stream() needs UDP support.
        let (udp_final_hop_indices, udp_uses_initial_hop) = if subsequent_hops.is_empty() {
            // No subsequent hops: initial hop IS the final hop
            // Filter initial_hop for UDP-capable entries
            let indices = initial_hop
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.supports_udp())
                .map(|(i, _)| i)
                .collect();
            (indices, true)
        } else {
            // Has subsequent hops: filter the FINAL subsequent hop for UDP-capable entries
            let final_hop = subsequent_hops.last().unwrap();
            let indices = final_hop
                .iter()
                .enumerate()
                .filter(|(_, p)| p.supports_udp_over_tcp())
                .map(|(i, _)| i)
                .collect();
            (indices, false)
        };

        let subsequent_next_indices = subsequent_hops.iter().map(|_| AtomicU32::new(0)).collect();

        Self {
            initial_hop,
            initial_hop_next_index: AtomicU32::new(0),
            subsequent_hops,
            subsequent_next_indices,
            udp_final_hop_indices,
            udp_final_hop_next_index: AtomicU32::new(0),
            udp_uses_initial_hop,
        }
    }

    /// Returns the total number of hops.
    #[cfg(test)]
    pub fn num_hops(&self) -> usize {
        1 + self.subsequent_hops.len()
    }

    /// Returns true if this chain supports UDP connections.
    pub fn supports_udp(&self) -> bool {
        !self.udp_final_hop_indices.is_empty()
    }

    /// Select an initial hop entry (round-robin).
    fn select_initial_hop_entry(&self) -> &InitialHopEntry {
        if self.initial_hop.len() == 1 {
            &self.initial_hop[0]
        } else {
            let idx = self.initial_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
            &self.initial_hop[idx % self.initial_hop.len()]
        }
    }

    /// Select proxy connectors for subsequent hops (round-robin per hop).
    fn select_subsequent_proxies(&self) -> Vec<&dyn ProxyConnector> {
        self.subsequent_hops
            .iter()
            .enumerate()
            .map(|(i, hop)| {
                if hop.len() == 1 {
                    hop[0].as_ref()
                } else {
                    let idx =
                        self.subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed) as usize;
                    hop[idx % hop.len()].as_ref()
                }
            })
            .collect()
    }

    /// Connect through the chain to the remote location for TCP traffic.
    pub async fn connect_tcp(
        &self,
        remote_location: NetLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        // Select initial hop entry (socket + optional proxy paired)
        let entry = self.select_initial_hop_entry();

        // Select proxy connectors for subsequent hops
        let subsequent_proxies = self.select_subsequent_proxies();

        debug!(
            "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
            subsequent_proxies.len(),
            remote_location
        );

        // Determine first target after initial hop
        let first_subsequent_target = subsequent_proxies
            .first()
            .map(|p| p.proxy_location())
            .unwrap_or(&remote_location);

        // Connect based on initial hop type
        let mut result = match entry {
            InitialHopEntry::Direct(socket) => {
                // Socket connects to first subsequent proxy (or final target)
                debug!("Initial hop: Direct -> {}", first_subsequent_target);
                let stream = socket.connect(resolver, first_subsequent_target).await?;
                TcpClientSetupResult {
                    client_stream: stream,
                    early_data: None,
                }
            }
            InitialHopEntry::Proxy { socket, proxy } => {
                // Socket connects to this proxy's location
                debug!(
                    "Initial hop: Proxy {} -> {}",
                    proxy.proxy_location(),
                    first_subsequent_target
                );
                let stream = socket.connect(resolver, proxy.proxy_location()).await?;
                // Protocol setup targeting first subsequent proxy (or final target)
                proxy
                    .setup_tcp_stream(stream, first_subsequent_target)
                    .await?
            }
        };

        // Process subsequent hops
        for (i, proxy) in subsequent_proxies.iter().enumerate() {
            let target = subsequent_proxies
                .get(i + 1)
                .map(|p| p.proxy_location())
                .unwrap_or(&remote_location);

            debug!(
                "Subsequent hop {}/{}: {} -> {}",
                i + 1,
                subsequent_proxies.len(),
                proxy.proxy_location(),
                target
            );

            result = proxy.setup_tcp_stream(result.client_stream, target).await?;

            // Early data from intermediate hops is unexpected
            if let Some(data) = &result.early_data
                && i < subsequent_proxies.len() - 1
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Unexpected early data ({} bytes) from intermediate hop {}",
                        data.len(),
                        i + 1
                    ),
                ));
            }
        }

        debug!(
            "Chain TCP complete: {} total hop(s) to {}",
            1 + subsequent_proxies.len(),
            remote_location
        );

        Ok(result)
    }

    /// Connect for bidirectional UDP traffic through the chain.
    ///
    /// Returns an AsyncMessageStream that sends/receives UDP packets to the target.
    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        // Check if UDP is supported
        if self.udp_final_hop_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Chain does not support UDP",
            ));
        }

        if self.udp_uses_initial_hop {
            // Case 1: No subsequent hops - initial hop IS the final hop
            // Select from UDP-capable initial hop entries
            let idx = self
                .udp_final_hop_next_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = self.udp_final_hop_indices[idx % self.udp_final_hop_indices.len()];
            let entry = &self.initial_hop[pool_idx];

            debug!(
                "Chain UDP connect: 1 hop (initial IS final), target={}",
                target
            );

            match entry {
                InitialHopEntry::Direct(socket) => {
                    debug!("Chain UDP: Direct connection (native UDP)");
                    socket.connect_udp_bidirectional(resolver, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    debug!(
                        "Chain UDP: Proxy {} (UDP, no subsequent)",
                        proxy.proxy_location()
                    );
                    let stream = socket.connect(resolver, proxy.proxy_location()).await?;
                    proxy.setup_udp_bidirectional(stream, target).await
                }
            }
        } else {
            // Case 2: Has subsequent hops - select initial hop normally,
            // select intermediate hops normally, select final hop from UDP-capable

            // Select initial hop normally (ALL entries work - they just do TCP)
            let entry = self.select_initial_hop_entry();

            // Select intermediate hops normally (ALL entries work - they just do TCP)
            let intermediate_proxies: Vec<&dyn ProxyConnector> = self
                .subsequent_hops
                .iter()
                .enumerate()
                .take(self.subsequent_hops.len() - 1) // All but last
                .map(|(i, hop)| {
                    if hop.len() == 1 {
                        hop[0].as_ref()
                    } else {
                        let idx = self.subsequent_next_indices[i].fetch_add(1, Ordering::Relaxed)
                            as usize;
                        hop[idx % hop.len()].as_ref()
                    }
                })
                .collect();

            // Select final hop from UDP-capable entries
            let final_hop_pool = self.subsequent_hops.last().unwrap();
            let idx = self
                .udp_final_hop_next_index
                .fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = self.udp_final_hop_indices[idx % self.udp_final_hop_indices.len()];
            let final_proxy = final_hop_pool[pool_idx].as_ref();

            debug!(
                "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
                intermediate_proxies.len(),
                target
            );

            // Build the chain: initial -> intermediates -> final (UDP)
            match entry {
                InitialHopEntry::Direct(socket) => {
                    // Determine first target after initial hop
                    let first_target = if let Some(first) = intermediate_proxies.first() {
                        first.proxy_location()
                    } else {
                        final_proxy.proxy_location()
                    };

                    debug!("Chain UDP: Direct -> {} (TCP)", first_target);
                    let mut stream = socket.connect(resolver, first_target).await?;

                    // Process intermediate hops (all TCP)
                    for (i, proxy) in intermediate_proxies.iter().enumerate() {
                        let next_target = intermediate_proxies
                            .get(i + 1)
                            .map(|p| p.proxy_location())
                            .unwrap_or(final_proxy.proxy_location());
                        debug!(
                            "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                            i + 1,
                            intermediate_proxies.len(),
                            proxy.proxy_location(),
                            next_target
                        );
                        let result = proxy.setup_tcp_stream(stream, next_target).await?;
                        stream = result.client_stream;
                    }

                    // Final hop: UDP stream
                    debug!(
                        "Chain UDP final hop: {} (UDP)",
                        final_proxy.proxy_location()
                    );
                    final_proxy.setup_udp_bidirectional(stream, target).await
                }
                InitialHopEntry::Proxy { socket, proxy } => {
                    // Determine first target after initial hop
                    let first_target = if let Some(first) = intermediate_proxies.first() {
                        first.proxy_location()
                    } else {
                        final_proxy.proxy_location()
                    };

                    debug!(
                        "Chain UDP: Proxy {} -> {} (TCP)",
                        proxy.proxy_location(),
                        first_target
                    );
                    let stream = socket.connect(resolver, proxy.proxy_location()).await?;
                    let result = proxy.setup_tcp_stream(stream, first_target).await?;
                    let mut stream = result.client_stream;

                    // Process intermediate hops (all TCP)
                    for (i, proxy) in intermediate_proxies.iter().enumerate() {
                        let next_target = intermediate_proxies
                            .get(i + 1)
                            .map(|p| p.proxy_location())
                            .unwrap_or(final_proxy.proxy_location());
                        debug!(
                            "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                            i + 1,
                            intermediate_proxies.len(),
                            proxy.proxy_location(),
                            next_target
                        );
                        let result = proxy.setup_tcp_stream(stream, next_target).await?;
                        stream = result.client_stream;
                    }

                    // Final hop: UDP stream
                    debug!(
                        "Chain UDP final hop: {} (UDP)",
                        final_proxy.proxy_location()
                    );
                    final_proxy.setup_udp_bidirectional(stream, target).await
                }
            }
        }
    }
}

/// A group of proxy chains for round-robin selection.
pub struct ClientChainGroup {
    chains: Vec<ClientProxyChain>,
    next_tcp_index: AtomicU32,
    pub(crate) udp_chain_indices: Vec<usize>,
    next_udp_index: AtomicU32,
}

impl std::fmt::Debug for ClientChainGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientChainGroup")
            .field("chains_count", &self.chains.len())
            .field("udp_chain_indices", &self.udp_chain_indices)
            .finish()
    }
}

impl ClientChainGroup {
    pub fn new(chains: Vec<ClientProxyChain>) -> Self {
        assert!(
            !chains.is_empty(),
            "ClientChainGroup must have at least one chain"
        );

        let udp_chain_indices: Vec<usize> = chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| chain.supports_udp())
            .map(|(i, _)| i)
            .collect();

        Self {
            chains,
            next_tcp_index: AtomicU32::new(0),
            udp_chain_indices,
            next_udp_index: AtomicU32::new(0),
        }
    }

    pub async fn connect_tcp(
        &self,
        remote_location: NetLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let idx = self.next_tcp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain = &self.chains[idx % self.chains.len()];
        chain.connect_tcp(remote_location, resolver).await
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: NetLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.udp_chain_indices.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "No chains in group support UDP",
            ));
        }

        let idx = self.next_udp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain_idx = self.udp_chain_indices[idx % self.udp_chain_indices.len()];
        let chain = &self.chains[chain_idx];
        chain.connect_udp_bidirectional(resolver, target).await
    }

    #[cfg(test)]
    pub fn supports_udp(&self) -> bool {
        !self.udp_chain_indices.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::async_stream::AsyncStream;
    use crate::tcp::proxy_connector::ProxyConnector;
    use crate::tcp::socket_connector::SocketConnector;

    /// Mock SocketConnector that fails on connect (for unit testing structure).
    #[derive(Debug)]
    struct MockSocketConnector {
        id: usize,
    }

    #[async_trait]
    impl SocketConnector for MockSocketConnector {
        async fn connect(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _address: &NetLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockSocketConnector::connect not implemented",
            ))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: NetLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockSocketConnector::connect_udp_bidirectional not implemented",
            ))
        }
    }

    /// Mock ProxyConnector for testing.
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
            _target: &NetLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockProxyConnector::setup_tcp_stream not implemented",
            ))
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: NetLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockProxyConnector::setup_udp_bidirectional not implemented",
            ))
        }
    }

    fn mock_socket(id: usize) -> Box<dyn SocketConnector> {
        Box::new(MockSocketConnector { id })
    }

    fn mock_proxy(port: u16, supports_udp: bool) -> Box<dyn ProxyConnector> {
        Box::new(MockProxyConnector::new(port, supports_udp))
    }

    fn direct_entry(id: usize) -> InitialHopEntry {
        InitialHopEntry::Direct(mock_socket(id))
    }

    fn proxy_entry(id: usize, port: u16, supports_udp: bool) -> InitialHopEntry {
        InitialHopEntry::Proxy {
            socket: mock_socket(id),
            proxy: mock_proxy(port, supports_udp),
        }
    }

    #[test]
    fn test_initial_hop_entry_direct_supports_udp() {
        let entry = direct_entry(0);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_supports_udp() {
        let entry = proxy_entry(0, 1080, true);
        assert!(entry.supports_udp());
    }

    #[test]
    fn test_initial_hop_entry_proxy_no_udp() {
        let entry = proxy_entry(0, 1080, false);
        assert!(!entry.supports_udp());
    }

    #[test]
    fn test_chain_single_direct() {
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_single_proxy_no_udp() {
        let chain = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        assert_eq!(chain.num_hops(), 1);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, true)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_direct_with_subsequent_no_udp() {
        let chain =
            ClientProxyChain::new(vec![direct_entry(0)], vec![vec![mock_proxy(1080, false)]]);
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp()); // Subsequent doesn't support UDP
    }

    #[test]
    fn test_chain_proxy_with_subsequent() {
        let chain = ClientProxyChain::new(
            vec![proxy_entry(0, 1080, true)],
            vec![vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_mixed_initial_pool() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // VMess proxy
                proxy_entry(1, 1081, true), // VLESS proxy
                direct_entry(2),            // Direct
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
                proxy_entry(0, 1080, false), // No UDP
                proxy_entry(1, 1081, true),  // Has UDP
                direct_entry(2),             // Has UDP
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
            vec![direct_entry(0)],
            vec![vec![mock_proxy(1080, true)], vec![mock_proxy(1081, true)]],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pool_at_subsequent_hop() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
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
        let chain = ClientProxyChain::new(vec![direct_entry(0)], vec![]);
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
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0]);
    }

    #[test]
    fn test_group_all_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, true)], vec![]);
        let chain2 = ClientProxyChain::new(vec![direct_entry(1)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(group.supports_udp());
        assert_eq!(group.udp_chain_indices, vec![0, 1]);
    }

    #[test]
    fn test_group_none_support_udp() {
        let chain1 = ClientProxyChain::new(vec![proxy_entry(0, 1080, false)], vec![]);
        let chain2 = ClientProxyChain::new(vec![proxy_entry(1, 1081, false)], vec![]);
        let group = ClientChainGroup::new(vec![chain1, chain2]);
        assert!(!group.supports_udp());
        assert!(group.udp_chain_indices.is_empty());
    }

    #[test]
    fn test_pool_pairing_fix_socket_proxy_always_paired() {
        // Create a mixed pool simulating: vmess@1080, vless@1081, direct
        // Each with a unique socket ID matching its position
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true), // socket_id=0, proxy_port=1080
                proxy_entry(1, 1081, true), // socket_id=1, proxy_port=1081
                direct_entry(2),            // socket_id=2, no proxy
            ],
            vec![],
        );

        // Select entries multiple times and verify pairing
        // Round-robin should cycle: 0, 1, 2, 0, 1, 2, ...
        for iteration in 0..6 {
            let entry = chain.select_initial_hop_entry();
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
                proxy_entry(0, 1080, false), // socket_id=0, NO UDP
                proxy_entry(1, 1081, true),  // socket_id=1, HAS UDP, port 1081
                direct_entry(2),             // socket_id=2, HAS UDP (direct always does)
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

            match (expected_udp_idx, entry) {
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
                proxy_entry(0, 1080, false), // HTTP - no UDP (but should be usable for UDP!)
                proxy_entry(1, 1081, false), // Another HTTP
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
            let entry = chain.select_initial_hop_entry();
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
                proxy_entry(0, 1080, false), // HTTP - no UDP
                proxy_entry(1, 1081, true),  // SOCKS5 - has UDP (irrelevant!)
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
            vec![direct_entry(0)],
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
            vec![direct_entry(0)],
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
            vec![direct_entry(0)],
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
            vec![direct_entry(0)],
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
            vec![direct_entry(0)],
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
            vec![direct_entry(0)],
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
}
