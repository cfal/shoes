//! TerminalConnector trait - an outbound that owns its own transport.
//!
//! Most outbounds are built from a `SocketConnector` that produces a stream and
//! `ProxyConnector`s that wrap one. Some protocols cannot be expressed that way
//! because they own the transport themselves: AmneziaWG manages its own UDP
//! socket and encapsulation, and Hysteria2 and TUIC each authenticate once per
//! QUIC connection and key their UDP sessions to it.
//!
//! A `TerminalConnector` owns the whole connection lifecycle and dials TCP and
//! UDP through it. It is always the only hop in its chain.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;

#[async_trait]
pub trait TerminalConnector: Send + Sync + Debug {
    /// Open a TCP connection to the target through this outbound's transport.
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult>;

    /// Open a bidirectional UDP session to the target through this outbound's
    /// transport.
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
