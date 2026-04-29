//! VirtualNetworkConnector trait - Terminal outbound through a virtual network tunnel.
//!
//! This trait is used for protocols like AmneziaWG that create an L3 tunnel
//! with a virtual network stack. Unlike SocketConnector + ProxyConnector,
//! a VirtualNetworkConnector owns the entire connection lifecycle: it manages
//! its own UDP socket, encapsulation, and virtual TCP/UDP dialing.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;

/// A terminal virtual-network outbound connector.
///
/// Implementations own a long-lived tunnel (e.g., AmneziaWG) and dial
/// TCP/UDP connections through the tunnel's virtual network stack.
/// This is fundamentally different from stream-wrapping proxies.
#[async_trait]
pub trait VirtualNetworkConnector: Send + Sync + Debug {
    /// Open a TCP connection through the virtual tunnel to the target.
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Open a bidirectional UDP session through the virtual tunnel to the target.
    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>>;

    /// Whether this connector supports UDP traffic.
    fn supports_udp(&self) -> bool {
        true
    }
}
