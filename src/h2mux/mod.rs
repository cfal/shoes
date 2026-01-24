//! H2MUX - sing-box compatible HTTP/2 multiplexing protocol
//!
//! This module implements the h2mux protocol used by sing-box for multiplexing
//! multiple proxy streams over a single connection using HTTP/2 framing.
//!
//! ## Protocol Overview
//!
//! h2mux uses three layers:
//! 1. Session layer: Version negotiation and padding configuration
//! 2. HTTP/2 layer: Stream multiplexing via standard HTTP/2 framing
//! 3. Stream layer: Destination addressing for each logical stream
//!
//! ## Usage
//!
//! As a client handler wrapper:
//! ```ignore
//! let mux_handler = H2MuxClientHandler::new(inner_handler, mux_options);
//! ```
//!
//! As a server handler:
//! ```ignore
//! // Detected via magic destination "sp.mux.sing-box.arpa:444"
//! ```

mod activity_tracked_stream;
mod activity_tracker;
mod h2mux_client_handler;
mod h2mux_client_session;
mod h2mux_client_stream;
mod h2mux_padding;
pub mod h2mux_protocol;
mod h2mux_server_session;
mod h2mux_server_stream;
mod h2mux_stream;
mod prepend_stream;

// Re-exports for external use
pub use h2mux_client_handler::H2MuxClientHandler;
pub use h2mux_server_session::handle_h2mux_session;

// Reserved for future use (e.g., session pooling, direct stream access)
#[allow(unused_imports)]
pub use h2mux_client_session::H2MuxClientSession;
#[allow(unused_imports)]
pub use h2mux_padding::H2MuxPaddingStream;
#[allow(unused_imports)]
pub use h2mux_server_session::{H2MuxServerSession, InboundStream};
#[allow(unused_imports)]
pub use h2mux_stream::H2MuxStream;

/// Magic destination used to identify mux connections
pub const MUX_DESTINATION_HOST: &str = "sp.mux.sing-box.arpa";
pub const MUX_DESTINATION_PORT: u16 = 444;

/// Protocol identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MuxProtocol {
    Smux = 0,
    Yamux = 1,
    H2Mux = 2,
}

impl MuxProtocol {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Smux),
            1 => Some(Self::Yamux),
            2 => Some(Self::H2Mux),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "" | "h2mux" => Some(Self::H2Mux),
            "smux" => Some(Self::Smux),
            "yamux" => Some(Self::Yamux),
            _ => None,
        }
    }
}

/// Configuration options for h2mux.
/// Some fields are reserved for future connection pool management.
#[derive(Debug, Clone)]
pub struct H2MuxOptions {
    /// Protocol to use (default: H2Mux)
    pub protocol: MuxProtocol,
    /// Maximum number of concurrent streams per connection
    #[allow(dead_code)]
    pub max_streams: u32,
    /// Minimum number of streams before opening new connection
    #[allow(dead_code)]
    pub min_streams: u32,
    /// Maximum number of connections
    #[allow(dead_code)]
    pub max_connections: u32,
    /// Enable padding
    pub padding: bool,
}

impl Default for H2MuxOptions {
    fn default() -> Self {
        Self {
            protocol: MuxProtocol::H2Mux,
            max_streams: 0, // unlimited
            min_streams: 4,
            max_connections: 4,
            padding: false,
        }
    }
}
