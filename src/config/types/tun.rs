//! TUN device configuration types.
//!
//! TUN (network TUNnel) devices are virtual network interfaces that operate at
//! the IP layer (Layer 3). Unlike regular server configs that bind to a
//! TCP/UDP port, TUN servers receive raw IP packets from applications.
//!
//! # Platform Differences
//!
//! - **Linux**: Creates a new TUN device with the specified name and address.
//!   Requires root privileges or `CAP_NET_ADMIN` capability.
//!
//! - **Android**: Requires a file descriptor from `VpnService.Builder.establish()`.
//!   The VPN configuration (routes, DNS, etc.) is handled by the Android VpnService.
//!
//! - **iOS**: Requires a file descriptor from `NEPacketTunnelProvider.packetFlow`.
//!   Use `packet_information: true` if using the socket FD directly.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::option_util::NoneOrSome;

use super::common::default_true;
use super::rules::RuleConfig;
use super::selection::ConfigSelection;

fn default_mtu() -> u16 {
    // Platform-specific MTU defaults based on sing-box research:
    // - iOS Network Extension: 4064 max (4096 - 32 byte UTUN_IF_HEADROOM_SIZE)
    //   Performance drops significantly above this value
    // - Android: 9000 (some devices report ENOBUFS with 65535)
    // - Other platforms: 1500 (standard Ethernet MTU)
    #[cfg(target_os = "ios")]
    return 4064;
    #[cfg(target_os = "android")]
    return 9000;
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    return 1500;
}

/// TUN device server configuration.
///
/// This is a top-level config type (not nested under ServerConfig) because TUN
/// devices are fundamentally different from TCP/UDP servers:
/// - No bind address (binds to a virtual network device, not a socket)
/// - No transport layer (receives raw IP packets)
/// - Platform-specific device creation (Linux name/address vs iOS/Android raw_fd)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    /// TUN device name (Linux only, e.g., "tun0").
    /// Ignored on iOS/Android where the device is provided via device_fd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,

    /// Raw file descriptor for the TUN device (iOS/Android).
    /// - **Android**: from `VpnService.Builder.establish()`
    /// - **iOS**: from `NEPacketTunnelProvider.packetFlow`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_fd: Option<i32>,

    /// TUN device IP address (e.g., "10.0.0.1").
    /// - **Linux**: Sets the device's IP address
    /// - **iOS/Android**: Informational only (address is set by VPN service)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,

    /// TUN device netmask (e.g., "255.255.255.0").
    /// - **Linux**: Sets the device's netmask
    /// - **iOS/Android**: Informational only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmask: Option<IpAddr>,

    /// TUN device destination/gateway (Linux only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<IpAddr>,

    /// MTU size for the TUN interface.
    /// Default: 1500
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Enable TCP connection handling.
    /// Default: true
    #[serde(default = "default_true")]
    pub tcp_enabled: bool,

    /// Enable UDP packet handling.
    /// Default: true
    #[serde(default = "default_true")]
    pub udp_enabled: bool,

    /// Enable ICMP (ping) handling.
    /// Note: ICMP requires TCP to be enabled as well.
    /// Default: true
    #[serde(default = "default_true")]
    pub icmp_enabled: bool,

    /// Routing rules for traffic coming through the TUN device.
    /// Default: Allow all traffic directly
    #[serde(
        alias = "rule",
        default,
        skip_serializing_if = "NoneOrSome::is_unspecified"
    )]
    pub rules: NoneOrSome<ConfigSelection<RuleConfig>>,
}
