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
use super::dns::DnsConfig;
use super::rules::RuleConfig;
use super::selection::ConfigSelection;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TunResourceLimits {
    pub tcp_buffer_size: usize,
    pub tcp_memory_bytes: usize,
    pub max_tcp_connections: usize,
    pub max_udp_sessions: usize,
    pub max_udp_destinations: usize,
    pub max_udp_destinations_per_session: usize,
    /// Shared outbound payload allowance across session and destination queues.
    pub max_udp_queued_bytes: usize,
}

impl Default for TunResourceLimits {
    fn default() -> Self {
        Self {
            tcp_buffer_size: 32 * 1024,
            tcp_memory_bytes: 32 * 1024 * 1024,
            max_tcp_connections: 256,
            max_udp_sessions: 64,
            max_udp_destinations: 64,
            max_udp_destinations_per_session: 16,
            max_udp_queued_bytes: 2 * 1024 * 1024,
        }
    }
}

impl TunResourceLimits {
    pub fn validate(&self) -> std::io::Result<()> {
        if !(1024..=16 * 1024 * 1024).contains(&self.tcp_buffer_size)
            || self.tcp_memory_bytes / 4 < self.tcp_buffer_size
            || self.max_tcp_connections == 0
            || self.max_udp_sessions == 0
            || self.max_udp_destinations == 0
            || self.max_udp_destinations > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_udp_destinations_per_session == 0
            || !(65535..=tokio::sync::Semaphore::MAX_PERMITS).contains(&self.max_udp_queued_bytes)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid TUN resource limits",
            ));
        }
        Ok(())
    }

    pub fn tcp_connection_limit(&self) -> usize {
        self.max_tcp_connections
            .min(self.tcp_memory_bytes / 4 / self.tcp_buffer_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_budget_counts_all_four_buffers_and_validates_limits() {
        let mut limits = TunResourceLimits::default();
        limits.tcp_memory_bytes = 8 * limits.tcp_buffer_size;
        assert_eq!(limits.tcp_connection_limit(), 2);
        limits.validate().unwrap();
        limits.tcp_memory_bytes = 1;
        assert!(limits.validate().is_err());
        limits.tcp_buffer_size = 0;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn udp_queue_budget_must_fit_a_maximum_datagram() {
        let mut limits = TunResourceLimits {
            max_udp_queued_bytes: 65535,
            ..Default::default()
        };
        limits.validate().unwrap();
        limits.max_udp_queued_bytes = 65534;
        assert!(limits.validate().is_err());
    }
}

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
    #[serde(default)]
    pub resource_limits: TunResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_information: Option<bool>,
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

    /// DNS configuration for this TUN server (optional).
    /// Can reference a dns_group by name or specify inline DNS servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
}
