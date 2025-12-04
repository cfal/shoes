//! TUN server configuration and device creation.
//!
//! # Platform-Specific Usage
//!
//! ## Linux
//! On Linux, you can create a TUN device by specifying the device name and address:
//! ```ignore
//! let config = TunServerConfig::new()
//!     .tun_name("tun0")
//!     .address("10.0.0.1".parse().unwrap())
//!     .netmask("255.255.255.0".parse().unwrap());
//! ```
//!
//! ## Android
//! On Android, you must provide the FD from `VpnService.Builder.establish()`:
//! ```ignore
//! // In Kotlin/Java:
//! // val fd = vpnService.builder.establish()?.detachFd() ?: return
//!
//! let config = TunServerConfig::new()
//!     .raw_fd(fd)
//!     .mtu(1500);
//! ```
//!
//! ## iOS
//! On iOS, you must provide the FD from `NEPacketTunnelProvider`:
//! ```ignore
//! // In Swift/Objective-C:
//! // let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
//!
//! let config = TunServerConfig::new()
//!     .raw_fd(fd)
//!     .packet_information(true)  // Set based on how you obtained the FD
//!     .mtu(1500);
//! ```

use std::net::IpAddr;

use log::info;
use tun::{Configuration as TunConfiguration, Device};

/// Configuration for the TUN server.
///
/// This struct supports all platforms (Linux, Android, iOS) with platform-specific
/// options. See module-level documentation for usage examples.
#[derive(Clone, Debug)]
pub struct TunServerConfig {
    /// MTU size for the TUN interface.
    /// Default: platform-specific (iOS: 4064, Android: 9000, others: 1500)
    pub mtu: u16,
    /// Enable TCP connection handling.
    /// Default: true
    pub tcp_enabled: bool,
    /// Enable UDP packet handling.
    /// Default: true
    pub udp_enabled: bool,
    /// Enable ICMP (ping) handling.
    /// Default: true
    pub icmp_enabled: bool,
    /// TUN device name.
    /// - **Linux**: Used to name the TUN device (e.g., "tun0")
    /// - **Android/iOS**: Ignored (device is provided via FD)
    pub tun_name: Option<String>,
    /// TUN device address.
    /// - **Linux**: Sets the device's IP address
    /// - **Android/iOS**: Informational only (address is set by VPN service)
    pub address: Option<IpAddr>,
    /// TUN device netmask.
    /// - **Linux**: Sets the device's netmask
    /// - **Android/iOS**: Informational only
    pub netmask: Option<IpAddr>,
    /// TUN device destination/gateway.
    /// - **Linux**: Sets the device's destination address
    /// - **Android/iOS**: Not used
    pub destination: Option<IpAddr>,
    /// Raw file descriptor for the TUN device.
    /// - **Linux**: Optional (if not set, creates a new TUN device)
    /// - **Android**: Required (from `VpnService.Builder.establish()`)
    /// - **iOS**: Required (from `NEPacketTunnelProvider.packetFlow`)
    pub raw_fd: Option<i32>,
    /// Whether to close the FD when the device is dropped.
    /// Default: true
    ///
    /// Set to `false` if the FD is owned by the platform (e.g., Android VpnService).
    #[allow(dead_code)] // Used on non-Linux platforms
    pub close_fd_on_drop: bool,
    /// Enable packet information header.
    /// - **iOS**: Set to `true` if using socket FD from `NEPacketTunnelProvider.packetFlow`,
    ///   `false` if using `readPackets`/`writePackets` API
    /// - **Linux/Android**: Not used
    #[allow(dead_code)] // Used on iOS
    pub packet_information: bool,
}

impl Default for TunServerConfig {
    fn default() -> Self {
        // Platform-specific MTU defaults based on sing-box research:
        // - iOS Network Extension: 4064 max (4096 - 32 byte UTUN_IF_HEADROOM_SIZE)
        //   Performance drops significantly above this value
        // - Android: 9000 (some devices report ENOBUFS with 65535)
        // - Other platforms: 1500 (standard Ethernet MTU)
        #[cfg(target_os = "ios")]
        let default_mtu = 4064;
        #[cfg(target_os = "android")]
        let default_mtu = 9000;
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        let default_mtu = 1500;

        Self {
            mtu: default_mtu,
            tcp_enabled: true,
            udp_enabled: true,
            icmp_enabled: true,
            tun_name: None,
            address: None,
            netmask: None,
            destination: None,
            raw_fd: None,
            close_fd_on_drop: true,
            packet_information: false,
        }
    }
}

impl TunServerConfig {
    /// Create a new TunServerConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the TUN device name (Linux only).
    pub fn tun_name(mut self, name: impl Into<String>) -> Self {
        self.tun_name = Some(name.into());
        self
    }

    /// Set the TUN device address (Linux only).
    pub fn address(mut self, addr: IpAddr) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the TUN device netmask (Linux only).
    pub fn netmask(mut self, mask: IpAddr) -> Self {
        self.netmask = Some(mask);
        self
    }

    /// Set the TUN device destination/gateway (Linux only).
    pub fn destination(mut self, dest: IpAddr) -> Self {
        self.destination = Some(dest);
        self
    }

    /// Set a raw file descriptor to use (iOS/Android).
    ///
    /// On iOS, this should be the FD from:
    /// ```objc
    /// int32_t tunFd = [[packetFlow valueForKeyPath:@"socket.fileDescriptor"] intValue];
    /// ```
    ///
    /// On Android, this should be the FD from `VpnService.Builder.establish()`.
    pub fn raw_fd(mut self, fd: i32) -> Self {
        self.raw_fd = Some(fd);
        self
    }

    /// Set whether to close the FD on drop.
    #[allow(dead_code)] // Used on non-Linux platforms
    pub fn close_fd_on_drop(mut self, close: bool) -> Self {
        self.close_fd_on_drop = close;
        self
    }

    /// Set whether packet information header is present (iOS only).
    ///
    /// - `true` if using socket FD from `NEPacketTunnelProvider.packetFlow`
    /// - `false` if using `readPackets`/`writePackets` API
    #[allow(dead_code)] // Used on iOS
    pub fn packet_information(mut self, pi: bool) -> Self {
        self.packet_information = pi;
        self
    }

    /// Enable or disable TCP connection handling.
    pub fn tcp_enabled(mut self, enabled: bool) -> Self {
        self.tcp_enabled = enabled;
        self
    }

    /// Enable or disable UDP packet handling.
    pub fn udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    /// Enable or disable ICMP (ping) handling.
    pub fn icmp_enabled(mut self, enabled: bool) -> Self {
        self.icmp_enabled = enabled;
        self
    }

    /// Create a synchronous TUN device from this configuration.
    ///
    /// This is used by the direct mode stack which reads/writes directly
    /// from the TUN fd using select() for event-driven I/O.
    pub fn create_sync_device(&self) -> std::io::Result<Device> {
        let mut config = TunConfiguration::default();
        config.mtu(self.mtu);

        #[cfg(target_os = "linux")]
        {
            if let Some(ref name) = self.tun_name {
                config.tun_name(name);
            }
            if let Some(addr) = self.address {
                config.address(addr);
            }
            if let Some(mask) = self.netmask {
                config.netmask(mask);
            }
            if let Some(dest) = self.destination {
                config.destination(dest);
            }
            config.platform_config(|p| {
                p.ensure_root_privileges(true);
            });
            config.up();
        }

        #[cfg(target_os = "ios")]
        {
            config.platform_config(|p| {
                p.packet_information(self.packet_information);
            });
        }

        #[cfg(target_os = "android")]
        {
            // Android requires raw_fd from VpnService.Builder.establish()
            if self.raw_fd.is_none() {
                return Err(std::io::Error::other(
                    "Android requires raw_fd from VpnService.Builder.establish()",
                ));
            }
            if let Some(addr) = self.address {
                config.address(addr);
            }
            if let Some(mask) = self.netmask {
                config.netmask(mask);
            }
        }

        if let Some(fd) = self.raw_fd {
            info!("Creating TUN device from raw FD: {}", fd);
            #[cfg(unix)]
            {
                config.raw_fd(fd);
                config.close_fd_on_drop(self.close_fd_on_drop);
            }
            #[cfg(not(unix))]
            {
                return Err(std::io::Error::other(
                    "raw_fd is only supported on Unix platforms",
                ));
            }
        }

        tun::create(&config)
            .map_err(|e| std::io::Error::other(format!("Failed to create TUN device: {}", e)))
    }
}
