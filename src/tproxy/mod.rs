//! Linux transparent proxy (TPROXY) inbound.
//!
//! Accepts TCP and UDP traffic redirected via `iptables -j TPROXY` / `nftables`
//! and `ip rule`. The original destination is recovered from the kernel
//! (TCP: `getsockname` on the IP_TRANSPARENT-bound listener; UDP:
//! `IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` ancillary data).
//!
//! Linux-only.

pub mod cmsg;
pub mod listener;
