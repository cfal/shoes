//! SagerNet UDP-over-TCP (UoT) protocol implementation
//!
//! This module implements the sing-box UoT protocol for tunneling UDP over TCP.
//! It supports both V1 and V2 formats.
//!
//! ## Magic Addresses
//! - V1: `sp.udp-over-tcp.arpa` - Multi-destination mode, each packet has full address
//! - V2: `sp.v2.udp-over-tcp.arpa` - Optional connect mode for single destination
//!
//! ## V1 Packet Format
//! ```text
//! | ATYP | address  | port  | length | data     |
//! | u8   | variable | u16be | u16be  | variable |
//! ```
//!
//! ## V2 Request Format
//! ```text
//! | isConnect | ATYP | address  | port  |
//! | u8        | u8   | variable | u16be |
//! ```
//!
//! If isConnect=1, subsequent packets are length-prefixed only (V2 connect mode).
//! If isConnect=0, subsequent packets use V1 format (multi-destination).
//!
//! ## ATYP Values (different from SOCKS5!)
//! - 0x00: IPv4 Address (4 bytes)
//! - 0x01: IPv6 Address (16 bytes)
//! - 0x02: Domain Name (1 byte length + domain)

mod uot_v1_stream;

pub use uot_v1_stream::UotV1Stream;

/// UoT V2 connect mode stream - identical format to VlessMessageStream (length-prefixed u16be + data)
pub type UotV2Stream = crate::vless::VlessMessageStream;

/// Magic address used to signal UoT V1 mode (multi-destination)
pub const UOT_V1_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

/// Magic address used to signal UoT V2 mode (optional connect mode)
pub const UOT_V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
