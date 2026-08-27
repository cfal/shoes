//! Wintun adapter creation and configuration.
//!
//! Everything here happens once per tunnel, before the stack thread exists:
//! load `wintun.dll`, create the adapter, give it its address and MTU, and
//! start the ring-buffer session the stack thread will drive.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use log::info;
use wintun_bindings::{Adapter, Session, Wintun};

/// Ring capacity for the wintun session, in bytes per direction.
///
/// wireguard-go's value (`tun/tun_windows.go`, `StartSession(0x800000)`),
/// written by wintun's own authors. The ring is shared by every flow on the
/// tunnel — unlike the per-connection TCP buffers, it does not multiply by
/// connection count — so mobile's buffer arithmetic does not apply to it.
const RING_CAPACITY: u32 = 0x0080_0000;

/// A created wintun adapter with a running session.
///
/// Field order is drop order, and it matters: the session must end before the
/// adapter handle closes, and the adapter before the library unloads.
pub struct OpenedWintun {
    pub session: Arc<Session>,
    /// Keeps the adapter alive for the life of the tunnel; dropping the last
    /// reference deletes the adapter from the system.
    _adapter: Arc<Adapter>,
    /// Keeps `wintun.dll` loaded while anything above still calls into it.
    _wintun: Wintun,
}

/// GUID for the adapter, derived deterministically from its name.
///
/// A fixed GUID makes Windows reuse the same network profile across runs;
/// with a random one every start accumulates another "Network N" profile in
/// the registry, each with its own firewall category decision.
fn adapter_guid(name: &str) -> u128 {
    let hash = blake3::hash(format!("shoes-wintun:{name}").as_bytes());
    u128::from_le_bytes(
        hash.as_bytes()[..16]
            .try_into()
            .expect("blake3 output is 32 bytes"),
    )
}

/// Load the driver library, create and configure the adapter, and start a
/// session on it.
///
/// IPv4 by type: wintun-bindings 0.7 configures the adapter through `netsh
/// interface ipv4`, and its IPv6 arm emits parameters netsh's ipv6 context
/// does not accept, so an IPv6 adapter address cannot be expressed —
/// validate.rs refuses it at config time.
///
/// No gateway is ever passed: netsh's `gateway=` installs a system default
/// route through the adapter, and shoes configures the adapter only — routes
/// stay the host's. The config's `destination` is refused on Windows for
/// exactly that reason.
///
/// A failure after the adapter exists drops it on the way out, so a
/// half-configured adapter does not survive to shadow the next run's create.
pub fn open_wintun(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> io::Result<OpenedWintun> {
    // SAFETY: called once per tunnel start, before any wintun call; the
    // signature check below is what stands between us and a planted DLL.
    let wintun = unsafe { wintun_bindings::load() }.map_err(|e| {
        io::Error::other(format!(
            "failed to load wintun.dll: {e}. Download it from https://www.wintun.net \
             and place it next to shoes.exe or in System32"
        ))
    })?;

    let adapter =
        Adapter::create(&wintun, name, "shoes", Some(adapter_guid(name))).map_err(|e| {
            io::Error::other(format!(
                "failed to create wintun adapter '{name}': {e} \
                 (creating a wintun adapter requires Administrator)"
            ))
        })?;

    adapter
        .set_mtu(mtu as usize)
        .map_err(|e| io::Error::other(format!("failed to set MTU {mtu} on '{name}': {e}")))?;

    adapter
        .set_network_addresses_tuple(IpAddr::V4(address), IpAddr::V4(netmask), None)
        .map_err(|e| {
            io::Error::other(format!(
                "failed to assign {address}/{netmask} to '{name}': {e}"
            ))
        })?;

    let session = adapter.start_session(RING_CAPACITY).map_err(|e| {
        io::Error::other(format!("failed to start wintun session on '{name}': {e}"))
    })?;

    info!(
        "wintun adapter '{}' up: {}/{}, mtu={}, ring={} MiB",
        name,
        address,
        netmask,
        mtu,
        RING_CAPACITY / (1024 * 1024)
    );

    Ok(OpenedWintun {
        session,
        _adapter: adapter,
        _wintun: wintun,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The GUID decides which Windows network profile the adapter lands in,
    /// so it must be stable for a name and distinct across names.
    #[test]
    fn test_adapter_guid_is_stable_and_distinct() {
        assert_eq!(adapter_guid("shoes0"), adapter_guid("shoes0"));
        assert_ne!(adapter_guid("shoes0"), adapter_guid("shoes1"));
    }
}
