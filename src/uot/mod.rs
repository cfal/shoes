//! SagerNet UDP-over-TCP (UoT) protocol implementation
//!
//! This module implements the sing-box UoT protocol for tunneling UDP over TCP.
//! It supports both V1 (legacy) and V2 formats.
//!
//! ## Protocol Versions
//!
//! ### UoT V1 (Legacy)
//! - Magic address: `sp.udp-over-tcp.arpa`
//! - Mode: Multi-destination (each packet includes its target address)
//! - Packet format: `[AddrParser address][length:u16be][data]`
//!
//! ### UoT V2
//! - Magic address: `sp.v2.udp-over-tcp.arpa`
//! - Request header: `[isConnect:u8][SOCKS5 address]`
//! - Two modes based on `isConnect` byte:
//!
//! #### V2 Connect Mode (isConnect=1)
//! - Single destination specified in request header
//! - Subsequent packets: `[length:u16be][data]` (no address per packet)
//! - Uses VlessMessageStream format
//!
//! #### V2 Non-Connect Mode (isConnect=0)
//! - Multi-destination mode (same as V1)
//! - Subsequent packets: `[AddrParser address][length:u16be][data]`
//!
//! ## Address Formats (IMPORTANT!)
//!
//! Two different address formats are used:
//!
//! ### SOCKS5 Format (used in V2 request header)
//! - 0x01: IPv4 (4 bytes)
//! - 0x03: Domain (1 byte length + domain)
//! - 0x04: IPv6 (16 bytes)
//!
//! ### AddrParser Format (used in V1/V2 packet payloads)
//! - 0x00: IPv4 (4 bytes)
//! - 0x01: IPv6 (16 bytes)
//! - 0x02: Domain (1 byte length + domain)

pub mod uot_common;
mod uot_v1_server_stream;

pub use uot_v1_server_stream::UotV1ServerStream;

/// UoT V2 connect mode stream - identical format to VlessMessageStream (length-prefixed u16be + data)
pub type UotV2Stream<S> = crate::vless::VlessMessageStream<S>;

/// Magic address used to signal UoT V1 mode (multi-destination)
pub const UOT_V1_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

/// Magic address used to signal UoT V2 mode (optional connect mode)
pub const UOT_V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
