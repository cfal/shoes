//! Client proxy chain implementation for multi-hop proxy connections.
//!
//! A `ClientProxyChain` represents either:
//! - An ordered sequence of proxy hops (stream chain), where each hop
//!   can be a pool of connectors (for round-robin selection)
//! - A virtual network tunnel connector (e.g., AmneziaWG) that owns its own transport
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
//! For stream chains:
//! - `initial_hop`: Pool of `InitialHopEntry` (Direct or Proxy) for hop 0
//! - `subsequent_hops`: Protocol connectors for hops 1+ (no socket creation)
//!
//! For virtual network chains:
//! - A single `VirtualNetworkConnector` that handles all connections internally

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use log::debug;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::resolver::Resolver;
use crate::tcp::proxy_connector::ProxyConnector;
use crate::tcp::socket_connector::SocketConnector;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::virtual_network_connector::VirtualNetworkConnector;

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

/// Internal kind of a proxy chain.
enum ClientProxyChainKind {
    /// Standard stream-based chain with socket connectors and proxy wrappers.
    StreamChain {
        initial_hop: Vec<InitialHopEntry>,
        initial_hop_next_index: AtomicU32,
        subsequent_hops: Vec<Vec<Box<dyn ProxyConnector>>>,
        subsequent_next_indices: Vec<AtomicU32>,
        udp_final_hop_indices: Vec<usize>,
        udp_final_hop_next_index: AtomicU32,
        udp_uses_initial_hop: bool,
    },
    /// Virtual network tunnel (e.g., AmneziaWG) that owns its own transport.
    VirtualNetwork {
        connector: Arc<dyn VirtualNetworkConnector>,
    },
}

/// A chain of proxy hops with paired initial hop entries,
/// or a virtual network tunnel connector.
pub struct ClientProxyChain {
    kind: ClientProxyChainKind,
}

impl std::fmt::Debug for ClientProxyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                subsequent_hops,
                udp_final_hop_indices,
                udp_uses_initial_hop,
                ..
            } => f
                .debug_struct("ClientProxyChain::StreamChain")
                .field("initial_hop_count", &initial_hop.len())
                .field(
                    "subsequent_hops",
                    &subsequent_hops
                        .iter()
                        .map(|h| h.len())
                        .collect::<Vec<_>>(),
                )
                .field("udp_final_hop_indices", udp_final_hop_indices)
                .field("udp_uses_initial_hop", udp_uses_initial_hop)
                .finish(),
            ClientProxyChainKind::VirtualNetwork { connector } => f
                .debug_struct("ClientProxyChain::VirtualNetwork")
                .field("connector", connector)
                .finish(),
        }
    }
}

impl ClientProxyChain {
    /// Create a new stream-based chain from initial hop entries and subsequent hop pools.
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
        let (udp_final_hop_indices, udp_uses_initial_hop) = if subsequent_hops.is_empty() {
            let indices = initial_hop
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.supports_udp())
                .map(|(i, _)| i)
                .collect();
            (indices, true)
        } else {
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
            kind: ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index: AtomicU32::new(0),
                subsequent_hops,
                subsequent_next_indices,
                udp_final_hop_indices,
                udp_final_hop_next_index: AtomicU32::new(0),
                udp_uses_initial_hop,
            },
        }
    }

    /// Create a new virtual network chain from a connector.
    pub fn new_virtual(connector: Arc<dyn VirtualNetworkConnector>) -> Self {
        Self {
            kind: ClientProxyChainKind::VirtualNetwork { connector },
        }
    }

    /// Returns the total number of hops (only meaningful for stream chains).
    #[cfg(test)]
    pub fn num_hops(&self) -> usize {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                subsequent_hops, ..
            } => 1 + subsequent_hops.len(),
            ClientProxyChainKind::VirtualNetwork { .. } => 1,
        }
    }

    /// Returns true if this chain supports UDP connections.
    pub fn supports_udp(&self) -> bool {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                udp_final_hop_indices,
                ..
            } => !udp_final_hop_indices.is_empty(),
            ClientProxyChainKind::VirtualNetwork { connector } => connector.supports_udp(),
        }
    }

    /// Returns true if this chain is "direct-only": all initial hops are Direct
    /// and there are no subsequent hops.
    pub fn is_direct_only(&self) -> bool {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                subsequent_hops,
                ..
            } => {
                if !subsequent_hops.is_empty() {
                    return false;
                }
                initial_hop
                    .iter()
                    .all(|entry| matches!(entry, InitialHopEntry::Direct(_)))
            }
            ClientProxyChainKind::VirtualNetwork { .. } => false,
        }
    }

    /// Returns the bind_interface from a direct-only chain.
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        match &self.kind {
            ClientProxyChainKind::StreamChain { initial_hop, .. } => {
                initial_hop.first().and_then(|entry| match entry {
                    InitialHopEntry::Direct(socket) => socket.bind_interface(),
                    InitialHopEntry::Proxy { .. } => None,
                })
            }
            ClientProxyChainKind::VirtualNetwork { .. } => None,
        }
    }

    /// Connect through the chain to the remote location for TCP traffic.
    pub async fn connect_tcp(
        &self,
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                subsequent_next_indices,
                ..
            } => {
                let entry = select_from_pool(initial_hop, initial_hop_next_index);
                let subsequent_proxies =
                    select_subsequent(subsequent_hops, subsequent_next_indices);

                debug!(
                    "Chain TCP connect: 1 initial + {} subsequent hop(s) -> {}",
                    subsequent_proxies.len(),
                    remote_location.location()
                );

                let first_subsequent_target: ResolvedLocation = subsequent_proxies
                    .first()
                    .map(|p| p.proxy_location().into())
                    .unwrap_or_else(|| remote_location.clone());

                let mut result = match entry {
                    InitialHopEntry::Direct(socket) => {
                        debug!(
                            "Initial hop: Direct -> {}",
                            first_subsequent_target.location()
                        );
                        let stream = socket.connect(resolver, &first_subsequent_target).await?;
                        TcpClientSetupResult {
                            client_stream: stream,
                            early_data: None,
                        }
                    }
                    InitialHopEntry::Proxy { socket, proxy } => {
                        debug!(
                            "Initial hop: Proxy {} -> {}",
                            proxy.proxy_location(),
                            first_subsequent_target.location()
                        );
                        let proxy_loc = proxy.proxy_location().into();
                        let stream = socket.connect(resolver, &proxy_loc).await?;
                        proxy
                            .setup_tcp_stream(stream, &first_subsequent_target)
                            .await?
                    }
                };

                for (i, proxy) in subsequent_proxies.iter().enumerate() {
                    let target: ResolvedLocation = subsequent_proxies
                        .get(i + 1)
                        .map(|p| p.proxy_location().into())
                        .unwrap_or_else(|| remote_location.clone());

                    debug!(
                        "Subsequent hop {}/{}: {} -> {}",
                        i + 1,
                        subsequent_proxies.len(),
                        proxy.proxy_location(),
                        target.location()
                    );

                    result = proxy
                        .setup_tcp_stream(result.client_stream, &target)
                        .await?;

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
                    remote_location.location()
                );

                Ok(result)
            }
            ClientProxyChainKind::VirtualNetwork { connector } => {
                debug!(
                    "VirtualNetwork TCP connect -> {}",
                    remote_location.location()
                );
                connector.connect_tcp(resolver, remote_location).await
            }
        }
    }

    /// Connect for bidirectional UDP traffic through the chain.
    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                subsequent_next_indices,
                udp_final_hop_indices,
                udp_final_hop_next_index,
                udp_uses_initial_hop,
            } => {
                if udp_final_hop_indices.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "Chain does not support UDP",
                    ));
                }

                if *udp_uses_initial_hop {
                    let idx = udp_final_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
                    let pool_idx =
                        udp_final_hop_indices[idx % udp_final_hop_indices.len()];
                    let entry = &initial_hop[pool_idx];

                    debug!(
                        "Chain UDP connect: 1 hop (initial IS final), target={}",
                        target.location()
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
                            let proxy_loc = proxy.proxy_location().into();
                            let stream = socket.connect(resolver, &proxy_loc).await?;
                            proxy.setup_udp_bidirectional(stream, target).await
                        }
                    }
                } else {
                    let entry = select_from_pool(initial_hop, initial_hop_next_index);

                    let intermediate_proxies: Vec<&dyn ProxyConnector> = subsequent_hops
                        .iter()
                        .enumerate()
                        .take(subsequent_hops.len() - 1)
                        .map(|(i, hop)| {
                            if hop.len() == 1 {
                                hop[0].as_ref()
                            } else {
                                let idx = subsequent_next_indices[i]
                                    .fetch_add(1, Ordering::Relaxed)
                                    as usize;
                                hop[idx % hop.len()].as_ref()
                            }
                        })
                        .collect();

                    let final_hop_pool = subsequent_hops.last().unwrap();
                    let idx = udp_final_hop_next_index.fetch_add(1, Ordering::Relaxed) as usize;
                    let pool_idx =
                        udp_final_hop_indices[idx % udp_final_hop_indices.len()];
                    let final_proxy = final_hop_pool[pool_idx].as_ref();

                    debug!(
                        "Chain UDP connect: 1 initial + {} intermediate + 1 final (UDP) hop(s), target={}",
                        intermediate_proxies.len(),
                        target.location()
                    );

                    let mut stream = match entry {
                        InitialHopEntry::Direct(socket) => {
                            let first_target: ResolvedLocation =
                                if let Some(first) = intermediate_proxies.first() {
                                    first.proxy_location().into()
                                } else {
                                    final_proxy.proxy_location().into()
                                };
                            debug!("Chain UDP: Direct -> {} (TCP)", first_target.location());
                            socket.connect(resolver, &first_target).await?
                        }
                        InitialHopEntry::Proxy { socket, proxy } => {
                            let first_target: ResolvedLocation =
                                if let Some(first) = intermediate_proxies.first() {
                                    first.proxy_location().into()
                                } else {
                                    final_proxy.proxy_location().into()
                                };
                            debug!(
                                "Chain UDP: Proxy {} -> {} (TCP)",
                                proxy.proxy_location(),
                                first_target.location()
                            );
                            let proxy_loc = proxy.proxy_location().into();
                            let raw_stream = socket.connect(resolver, &proxy_loc).await?;
                            let result =
                                proxy.setup_tcp_stream(raw_stream, &first_target).await?;
                            result.client_stream
                        }
                    };

                    for (i, proxy) in intermediate_proxies.iter().enumerate() {
                        let next_target: ResolvedLocation = intermediate_proxies
                            .get(i + 1)
                            .map(|p| p.proxy_location().into())
                            .unwrap_or_else(|| final_proxy.proxy_location().into());
                        debug!(
                            "Chain UDP intermediate hop {}/{}: {} -> {} (TCP)",
                            i + 1,
                            intermediate_proxies.len(),
                            proxy.proxy_location(),
                            next_target.location()
                        );
                        let result = proxy.setup_tcp_stream(stream, &next_target).await?;
                        stream = result.client_stream;
                    }

                    debug!(
                        "Chain UDP final hop: {} (UDP)",
                        final_proxy.proxy_location()
                    );
                    final_proxy.setup_udp_bidirectional(stream, target).await
                }
            }
            ClientProxyChainKind::VirtualNetwork { connector } => {
                debug!("VirtualNetwork UDP connect -> {}", target.location());
                connector.connect_udp_bidirectional(resolver, target).await
            }
        }
    }

    // Test helpers to access internal state for stream chains
    #[cfg(test)]
    fn as_stream_chain(
        &self,
    ) -> (
        &Vec<InitialHopEntry>,
        &AtomicU32,
        &Vec<Vec<Box<dyn ProxyConnector>>>,
        &Vec<usize>,
        &AtomicU32,
        bool,
    ) {
        match &self.kind {
            ClientProxyChainKind::StreamChain {
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                udp_final_hop_indices,
                udp_final_hop_next_index,
                udp_uses_initial_hop,
                ..
            } => (
                initial_hop,
                initial_hop_next_index,
                subsequent_hops,
                udp_final_hop_indices,
                udp_final_hop_next_index,
                *udp_uses_initial_hop,
            ),
            _ => panic!("Expected StreamChain"),
        }
    }
}

fn select_from_pool<'a>(
    pool: &'a [InitialHopEntry],
    index: &AtomicU32,
) -> &'a InitialHopEntry {
    if pool.len() == 1 {
        &pool[0]
    } else {
        let idx = index.fetch_add(1, Ordering::Relaxed) as usize;
        &pool[idx % pool.len()]
    }
}

fn select_subsequent<'a>(
    hops: &'a [Vec<Box<dyn ProxyConnector>>],
    indices: &[AtomicU32],
) -> Vec<&'a dyn ProxyConnector> {
    hops.iter()
        .enumerate()
        .map(|(i, hop)| {
            if hop.len() == 1 {
                hop[0].as_ref()
            } else {
                let idx = indices[i].fetch_add(1, Ordering::Relaxed) as usize;
                hop[idx % hop.len()].as_ref()
            }
        })
        .collect()
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
        remote_location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<TcpClientSetupResult> {
        let idx = self.next_tcp_index.fetch_add(1, Ordering::Relaxed) as usize;
        let chain = &self.chains[idx % self.chains.len()];
        chain.connect_tcp(remote_location, resolver).await
    }

    pub async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
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

    /// Returns true if all chains are direct-only.
    pub fn is_direct_only(&self) -> bool {
        self.chains.iter().all(|chain| chain.is_direct_only())
    }

    /// Returns the bind_interface if all chains are direct-only and share
    /// the same bind_interface (or all have None).
    pub fn get_bind_interface(&self) -> Option<&str> {
        if !self.is_direct_only() {
            return None;
        }
        self.chains
            .first()
            .and_then(|chain| chain.get_bind_interface())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::address::NetLocation;
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
            _address: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockSocketConnector::connect not implemented",
            ))
        }

        async fn connect_udp_bidirectional(
            &self,
            _resolver: &Arc<dyn Resolver>,
            _target: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockSocketConnector::connect_udp_bidirectional not implemented",
            ))
        }

        fn bind_interface(&self) -> Option<&str> {
            None
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
            _target: &ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "MockProxyConnector::setup_tcp_stream not implemented",
            ))
        }

        async fn setup_udp_bidirectional(
            &self,
            _stream: Box<dyn AsyncStream>,
            _target: ResolvedLocation,
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
        assert!(!chain.supports_udp());
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
                proxy_entry(0, 1080, true),
                proxy_entry(1, 1081, true),
                direct_entry(2),
            ],
            vec![],
        );
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
        let (_, _, _, udp_indices, _, udp_uses_initial) = chain.as_stream_chain();
        assert!(udp_uses_initial);
        assert_eq!(*udp_indices, vec![0, 1, 2]);
    }

    #[test]
    fn test_chain_mixed_initial_pool_partial_udp() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false),
                proxy_entry(1, 1081, true),
                direct_entry(2),
            ],
            vec![],
        );
        assert!(chain.supports_udp());
        let (_, _, _, udp_indices, _, udp_uses_initial) = chain.as_stream_chain();
        assert!(udp_uses_initial);
        assert_eq!(*udp_indices, vec![1, 2]);
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
        assert!(chain.supports_udp());
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
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, true),
                proxy_entry(1, 1081, true),
                direct_entry(2),
            ],
            vec![],
        );

        let (initial_hop, initial_hop_next_index, _, _, _, _) = chain.as_stream_chain();

        for iteration in 0..6 {
            let entry = select_from_pool(initial_hop, initial_hop_next_index);
            let expected_idx = iteration % 3;

            match (expected_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1080);
                }
                (1, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1081);
                }
                (2, InitialHopEntry::Direct(_)) => {}
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
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false),
                proxy_entry(1, 1081, true),
                direct_entry(2),
            ],
            vec![],
        );

        let (initial_hop, _, _, udp_indices, udp_next, udp_uses_initial) =
            chain.as_stream_chain();
        assert!(udp_uses_initial);
        assert_eq!(*udp_indices, vec![1, 2]);

        for iteration in 0..4 {
            let idx = udp_next.fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = udp_indices[idx % udp_indices.len()];
            let entry = &initial_hop[pool_idx];
            let expected_udp_idx = iteration % 2;

            match (expected_udp_idx, entry) {
                (0, InitialHopEntry::Proxy { proxy, .. }) => {
                    assert_eq!(proxy.proxy_location().port(), 1081);
                }
                (1, InitialHopEntry::Direct(_)) => {}
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
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false),
                proxy_entry(1, 1081, false),
            ],
            vec![vec![
                mock_proxy(8080, false),
                mock_proxy(443, true),
                mock_proxy(444, true),
            ]],
        );

        let (initial_hop, initial_hop_next, subsequent_hops, udp_indices, udp_next, udp_uses_initial) =
            chain.as_stream_chain();
        assert!(!udp_uses_initial);
        assert_eq!(*udp_indices, vec![1, 2]);

        for i in 0..4 {
            let entry = select_from_pool(initial_hop, initial_hop_next);
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

        let final_hop = subsequent_hops.last().unwrap();
        for iteration in 0..6 {
            let idx = udp_next.fetch_add(1, Ordering::Relaxed) as usize;
            let pool_idx = udp_indices[idx % udp_indices.len()];
            let proxy = &final_hop[pool_idx];

            let expected_udp_idx = iteration % 2;
            match expected_udp_idx {
                0 => assert_eq!(proxy.proxy_location().port(), 443),
                1 => assert_eq!(proxy.proxy_location().port(), 444),
                _ => panic!("Unexpected index"),
            }
        }
    }

    #[test]
    fn test_chain_with_subsequent_hops_uses_final_hop_indices() {
        let chain = ClientProxyChain::new(
            vec![
                proxy_entry(0, 1080, false),
                proxy_entry(1, 1081, true),
            ],
            vec![vec![
                mock_proxy(8080, false),
                mock_proxy(443, true),
                mock_proxy(444, true),
            ]],
        );

        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());

        let (_, _, _, udp_indices, _, udp_uses_initial) = chain.as_stream_chain();
        assert!(!udp_uses_initial);
        assert_eq!(*udp_indices, vec![1, 2]);
    }

    #[test]
    fn test_chain_intermediate_hop_no_udp_final_hop_has_udp() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)],
                vec![mock_proxy(443, true)],
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_all_intermediate_no_udp_final_has_udp() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)],
                vec![mock_proxy(1080, false)],
                vec![mock_proxy(443, true)],
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_intermediate_has_udp_final_no_udp() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(443, true)],
                vec![mock_proxy(8080, false)],
            ],
        );
        assert_eq!(chain.num_hops(), 3);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_partial_udp() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false),
                mock_proxy(443, true),
                mock_proxy(444, true),
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(chain.supports_udp());
    }

    #[test]
    fn test_chain_pooled_final_hop_no_udp() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![vec![
                mock_proxy(8080, false),
                mock_proxy(1080, false),
            ]],
        );
        assert_eq!(chain.num_hops(), 2);
        assert!(!chain.supports_udp());
    }

    #[test]
    fn test_chain_complex_multi_hop_mixed_udp() {
        let chain = ClientProxyChain::new(
            vec![direct_entry(0)],
            vec![
                vec![mock_proxy(8080, false)],
                vec![mock_proxy(1080, false)],
                vec![
                    mock_proxy(8081, false),
                    mock_proxy(443, true),
                ],
            ],
        );
        assert_eq!(chain.num_hops(), 4);
        assert!(chain.supports_udp());
    }
}
