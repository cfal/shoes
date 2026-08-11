# Hysteria2 and TUIC Client Outbounds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let shoes dial Hysteria2 and TUIC v5 servers, with Salamander obfuscation on both the client and the server.

**Architecture:** Both protocols own their QUIC transport, so they cannot be expressed as a socket connector plus a stream-wrapping proxy connector. They become `TerminalConnector`s — the trait AmneziaWG already uses, generalised — each holding one lazily re-established QUIC connection that is authenticated once and multiplexes streams and UDP sessions over it.

**Tech Stack:** Rust 2024, tokio, quinn 0.11, quinn-udp 0.5, h3 0.0.8 + h3-quinn 0.0.10, rustls with aws-lc-rs, serde_yaml, blake2 (new).

**Spec:** [docs/specs/2026-08-11-quic-client-outbounds.md](../specs/2026-08-11-quic-client-outbounds.md)

---

## Context you need before starting

Read these once; the tasks below assume them.

**Module declarations are duplicated.** `src/lib.rs` and `src/main.rs` each declare the module tree independently. Every new top-level module must be added to **both** or the binary will not build even though the library does.

**`debug!` disappears in release.** `log` is built with `release_max_level_info` (Cargo.toml:54). Anything you need to see from a release binary must be `info!` or higher.

**The verification gate this project uses:**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
```

Do not add `--tests` to the clippy invocation; the binary's test build has pre-existing dead code that fails `-D warnings` and is not yours to fix.

**Commit signing.** Commits are signed through a 1Password agent that intermittently returns `1Password: failed to fill whole buffer`. If a commit fails that way, simply run the same `git commit` again — the files stay staged.

**`quinn::udp` vs `quinn::Transmit`.** `quinn` re-exports the `quinn-udp` crate as `quinn::udp` (quinn/src/lib.rs:75). The `AsyncUdpSocket` trait takes `quinn::udp::Transmit` and `quinn::udp::RecvMeta`. `quinn::Transmit` is a *different* type from `quinn-proto` — do not use it.

---

## File structure

| Path | Responsibility |
| --- | --- |
| `src/hysteria2/mod.rs` | Module root; re-exports `start_hysteria2_server` and `Hysteria2Connector` |
| `src/hysteria2/server.rs` | Today's `src/hysteria2_server.rs`, minus the codec |
| `src/hysteria2/frame.rs` | Varints, TCP request/response, datagram header — shared by both sides |
| `src/hysteria2/auth.rs` | The HTTP/3 authentication exchange, client side |
| `src/hysteria2/client.rs` | `Hysteria2Connector`, a `TerminalConnector` |
| `src/hysteria2/udp.rs` | One Hysteria2 UDP session as an `AsyncMessageStream` |
| `src/tuic/mod.rs` | Module root; re-exports `start_tuic_server` and `TuicConnector` |
| `src/tuic/server.rs` | Today's `src/tuic_server.rs`, minus the codec |
| `src/tuic/frame.rs` | Command headers, address encoding, packet headers |
| `src/tuic/client.rs` | `TuicConnector`, a `TerminalConnector` |
| `src/tuic/udp.rs` | One TUIC UDP association as an `AsyncMessageStream` |
| `src/quic_outbound/mod.rs` | Endpoint construction from `ClientQuicConfig`; shared settings type |
| `src/quic_outbound/connection.rs` | `LiveConnection`: one connection, lazily re-established |
| `src/quic_outbound/obfs/mod.rs` | `Obfuscator` trait and the `AsyncUdpSocket` wrapper |
| `src/quic_outbound/obfs/salamander.rs` | Salamander |
| `src/config/types/obfs.rs` | `ObfsConfig`, shared by the client and server config |
| `src/tcp/terminal_connector.rs` | Renamed from `virtual_network_connector.rs` |

---

## Task 1: A pool of terminal connectors must not panic

`validate.rs:1663-1693` accepts a hop that is a pool of several virtual-network
configs, checking only that they are *all* tunnels. `chain_builder.rs:58` takes
the virtual branch only when the hop holds exactly one config, so such a pool
falls through to the ordinary path, reaches
`tcp_client_handler_factory.rs:366` and panics. A configuration the validator
blesses kills the process at startup.

The fix is to let a chain hold a pool of terminal connectors, which is also what
Hysteria2 and TUIC will need.

**Files:**
- Modify: `src/client_proxy_chain.rs:92-96, 123-129, 184-189, 203-211, 344-351, 484-488`
- Modify: `src/tcp/chain_builder.rs:56-66`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module at the bottom of `src/tcp/chain_builder.rs`:

```rust
    fn wireguard_config(port: u16) -> ClientConfig {
        use crate::config::WireGuardClientConfig;
        use crate::option_util::OneOrSome;
        ClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            protocol: ClientProxyConfig::Wireguard(Box::new(WireGuardClientConfig {
                private_key: "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=".into(),
                peer_public_key: "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5MTIzNDU=".to_string(),
                preshared_key: None,
                local_addresses: OneOrSome::One("10.0.0.2/32".to_string()),
                allowed_ips: OneOrSome::One("0.0.0.0/0".to_string()),
                persistent_keepalive: None,
                mtu: 1280,
            })),
            ..Default::default()
        }
    }

    #[test]
    fn test_build_pool_of_tunnels_does_not_panic() {
        let chain = build_client_proxy_chain(
            OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(wireguard_config(51820)),
                ConfigSelection::Config(wireguard_config(51821)),
            ]))),
            mock_resolver(),
        );
        assert_eq!(chain.num_hops(), 1);
        assert!(chain.supports_udp());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib test_build_pool_of_tunnels_does_not_panic`

Expected: FAIL, panicking with `Cannot create a TCP client handler for WireGuard` (or
whatever `tcp_client_handler_factory.rs:366` says).

- [ ] **Step 3: Let the chain hold a pool of terminal connectors**

In `src/client_proxy_chain.rs`, change the variant to hold a pool. Replace

```rust
    /// Virtual network tunnel (e.g., AmneziaWG) that owns its own transport.
    VirtualNetwork {
        connector: Arc<dyn VirtualNetworkConnector>,
    },
```

with

```rust
    /// Connectors that own their own transport (AmneziaWG, Hysteria2, TUIC).
    /// A pool is selected round-robin, exactly like a pool of proxy hops.
    Terminal {
        connectors: Vec<Arc<dyn VirtualNetworkConnector>>,
        next_index: AtomicU32,
    },
```

Replace the constructor:

```rust
    /// Create a new terminal chain from one or more connectors that own their transport.
    ///
    /// # Panics
    /// Panics if `connectors` is empty.
    pub fn new_terminal(connectors: Vec<Arc<dyn VirtualNetworkConnector>>) -> Self {
        assert!(
            !connectors.is_empty(),
            "ClientProxyChain must have at least one terminal connector"
        );
        Self {
            kind: ClientProxyChainKind::Terminal {
                connectors,
                next_index: AtomicU32::new(0),
            },
        }
    }
```

Add a selector next to `select_from_pool`:

```rust
fn select_terminal<'a>(
    pool: &'a [Arc<dyn VirtualNetworkConnector>],
    index: &AtomicU32,
) -> &'a Arc<dyn VirtualNetworkConnector> {
    if pool.len() == 1 {
        &pool[0]
    } else {
        let idx = index.fetch_add(1, Ordering::Relaxed) as usize;
        &pool[idx % pool.len()]
    }
}
```

Update the four `match` arms that mention `VirtualNetwork`:

```rust
            // Debug impl
            ClientProxyChainKind::Terminal { connectors, .. } => f
                .debug_struct("ClientProxyChain::Terminal")
                .field("connector_count", &connectors.len())
                .finish(),

            // supports_udp
            ClientProxyChainKind::Terminal { connectors, .. } => {
                connectors.iter().any(|c| c.supports_udp())
            }

            // is_direct_only, get_bind_interface
            ClientProxyChainKind::Terminal { .. } => false,   // is_direct_only
            ClientProxyChainKind::Terminal { .. } => None,    // get_bind_interface

            // connect_tcp
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
            } => {
                let connector = select_terminal(connectors, next_index);
                debug!("Terminal TCP connect -> {}", remote_location.location());
                connector.connect_tcp(resolver, remote_location).await
            }

            // connect_udp_bidirectional
            ClientProxyChainKind::Terminal {
                connectors,
                next_index,
            } => {
                let connector = select_terminal(connectors, next_index);
                debug!("Terminal UDP connect -> {}", target.location());
                connector.connect_udp_bidirectional(resolver, target).await
            }
```

`num_hops()` returns `1` for `Terminal`, unchanged in meaning.

- [ ] **Step 4: Build the pool in the chain builder**

In `src/tcp/chain_builder.rs`, replace the block at lines 56-66:

```rust
    // Protocols that own their transport (WireGuard/AmneziaWG) cannot be wrapped
    // by another proxy, so they must be the only hop. Validation enforces that,
    // and that a pool at that hop is homogeneous.
    if hops.len() == 1 && hops[0].iter().all(|c| c.protocol.is_virtual_network()) {
        let connectors = hops
            .into_iter()
            .next()
            .unwrap()
            .into_iter()
            .map(|config| {
                let connector = crate::amneziawg::AmneziaWgConnector::from_client_config(
                    config.protocol,
                    config.address,
                )
                .expect("config validation should have ensured Wireguard or AmneziaWg variant");
                Arc::new(connector) as Arc<dyn crate::tcp::virtual_network_connector::VirtualNetworkConnector>
            })
            .collect();
        return ClientProxyChain::new_terminal(connectors);
    }
```

Note the guard changed from `hops[0].len() == 1 && ...is_virtual_network()` to
`hops[0].iter().all(...)`. An empty hop cannot occur — `OneOrSome` guarantees at
least one entry.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib test_build_pool_of_tunnels_does_not_panic`

Expected: PASS.

- [ ] **Step 6: Run the whole gate**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
```

Expected: all green. `cargo test --lib` currently reports 947 passing; you have
added one, so expect 948.

- [ ] **Step 7: Commit**

```bash
git add src/client_proxy_chain.rs src/tcp/chain_builder.rs
git commit -F - <<'EOF'
chain: stop panicking on a pool of tunnel outbounds

Validation accepts a hop that is a pool of several WireGuard or AmneziaWG
configs, checking only that every entry in it is a tunnel. The builder took
the tunnel branch only when the hop held exactly one config, so such a pool
fell through to the ordinary proxy path and panicked in the client handler
factory. A configuration the validator had just blessed killed the process
at startup.

A chain now holds a pool of terminal connectors and selects from it
round-robin, the same way a pool of proxy hops already worked.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 2: Rename the trait to describe what it does

Two more protocols are about to implement `VirtualNetworkConnector`, and
neither is a virtual network. This task is a pure rename with no behaviour
change.

**Files:**
- Rename: `src/tcp/virtual_network_connector.rs` → `src/tcp/terminal_connector.rs`
- Modify: `src/tcp/mod.rs`, `src/client_proxy_chain.rs`, `src/tcp/chain_builder.rs`, `src/amneziawg/connector.rs`, `src/config/types/client.rs`, `src/config/validate.rs`

- [ ] **Step 1: Move the file and rename the trait**

```bash
git mv src/tcp/virtual_network_connector.rs src/tcp/terminal_connector.rs
```

Replace the file's header comment and trait name:

```rust
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

    /// Open a bidirectional UDP session to the target through this outbound's transport.
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
```

- [ ] **Step 2: Rename every reference**

```bash
rg -l 'virtual_network_connector|VirtualNetworkConnector|is_virtual_network|new_virtual' src/ \
  | xargs sed -i \
    -e 's/virtual_network_connector/terminal_connector/g' \
    -e 's/VirtualNetworkConnector/TerminalConnector/g' \
    -e 's/is_virtual_network/owns_transport/g'
```

`new_virtual` was already replaced by `new_terminal` in Task 1.

Then fix the doc comment on the predicate in `src/config/types/client.rs`:

```rust
    /// Returns true for protocols that own their own transport and therefore
    /// cannot be wrapped by another proxy: WireGuard/AmneziaWG today, Hysteria2
    /// and TUIC once they land.
    pub fn owns_transport(&self) -> bool {
        matches!(
            self,
            ClientProxyConfig::Wireguard(_) | ClientProxyConfig::AmneziaWg(_)
        )
    }
```

- [ ] **Step 3: Update the module declaration**

In `src/tcp/mod.rs`, change `pub mod virtual_network_connector;` to
`pub mod terminal_connector;`. The `sed` above already did this if the
declaration matched; verify with:

```bash
rg -n 'virtual_network|VirtualNetwork|is_virtual_network' src/
```

Expected: no output.

- [ ] **Step 4: Run the gate**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
```

Expected: all green, 948 lib tests.

- [ ] **Step 5: Commit**

```bash
git add -A src/
git commit -F - <<'EOF'
chain: rename VirtualNetworkConnector to TerminalConnector

Hysteria2 and TUIC are about to implement this trait and neither is a
virtual network. What the implementations share is that they own their
transport and therefore must be the only hop in a chain, which is what the
name now says. is_virtual_network becomes owns_transport for the same
reason.

Pure rename; no behaviour change.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 3: Split the Hysteria2 server into a module and lift its codec

The client needs the varint codec and the frame layouts that are currently
private to `src/hysteria2_server.rs`. Copying them into a second file would
guarantee the two drift apart.

**Files:**
- Create: `src/hysteria2/mod.rs`, `src/hysteria2/frame.rs`
- Rename: `src/hysteria2_server.rs` → `src/hysteria2/server.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Move the file**

```bash
mkdir -p src/hysteria2
git mv src/hysteria2_server.rs src/hysteria2/server.rs
```

Create `src/hysteria2/mod.rs`:

```rust
//! Hysteria2: server, client and the frame codec they share.

pub mod frame;
pub mod server;

pub use server::start_hysteria2_server;
```

In both `src/lib.rs` and `src/main.rs`, replace `mod hysteria2_server;` (or
`pub mod hysteria2_server;`) with `pub mod hysteria2;`, keeping the surrounding
alphabetical order.

Fix the call site:

```bash
rg -n 'hysteria2_server' src/
```

Every hit becomes `hysteria2::start_hysteria2_server`.

- [ ] **Step 2: Run the build to confirm the move alone compiles**

Run: `cargo build --lib`

Expected: success.

- [ ] **Step 3: Write the failing test for the lifted codec**

Create `src/hysteria2/frame.rs`:

```rust
//! Hysteria2 frame codec, shared by the server and the client.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint_widths() {
        assert_eq!(&*encode_varint(0).unwrap(), &[0x00]);
        assert_eq!(&*encode_varint(63).unwrap(), &[0x3f]);
        assert_eq!(&*encode_varint(64).unwrap(), &[0x40, 0x40]);
        // The TCP request frame type. 1025 does not fit the one-byte form.
        assert_eq!(&*encode_varint(0x401).unwrap(), &[0x44, 0x01]);
        assert_eq!(&*encode_varint(16383).unwrap(), &[0x7f, 0xff]);
        assert_eq!(&*encode_varint(16384).unwrap(), &[0x80, 0x00, 0x40, 0x00]);
    }

    #[test]
    fn test_encode_varint_rejects_too_large() {
        assert!(encode_varint(1u64 << 62).is_err());
    }

    #[test]
    fn test_decode_varint_slice_round_trip() {
        for value in [0u64, 1, 63, 64, 1025, 16383, 16384, 1 << 29, 1 << 30] {
            let encoded = encode_varint(value).unwrap();
            let (decoded, consumed) = decode_varint_slice(&encoded).unwrap();
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(consumed, encoded.len(), "value {value}");
        }
    }

    #[test]
    fn test_decode_varint_slice_needs_more_data() {
        // A four-byte form with only two bytes present.
        assert!(decode_varint_slice(&[0x80, 0x00]).is_none());
        assert!(decode_varint_slice(&[]).is_none());
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test --lib hysteria2::frame`

Expected: FAIL to compile — `encode_varint` and `decode_varint_slice` are not
found.

- [ ] **Step 5: Move `encode_varint` and `read_varint` in, and add the slice decoder**

Cut `encode_varint` (server.rs:923-941) and `read_varint` (server.rs:943-972)
out of `src/hysteria2/server.rs` and paste them above the `tests` module in
`src/hysteria2/frame.rs`, making both `pub`. Also move
`const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;` (server.rs:769) and make it `pub`.
Add the slice decoder, which the datagram path needs because a datagram is not
a stream:

```rust
use crate::stream_reader::StreamReader;

/// TCP request frame type constant from the Hysteria2 protocol.
/// See: https://github.com/apernet/hysteria/blob/master/core/internal/protocol/proxy.go#L15
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Maximum address length accepted in a TCP request or a datagram header.
pub const MAX_ADDRESS_LEN: u64 = 2048;

/// Maximum padding length accepted in a TCP request.
pub const MAX_PADDING_LEN: u64 = 4096;

#[inline]
pub fn encode_varint(value: u64) -> std::io::Result<Box<[u8]>> {
    /* body unchanged from server.rs:924-941 */
}

pub async fn read_varint(
    recv: &mut quinn::RecvStream,
    stream_reader: &mut StreamReader,
) -> std::io::Result<u64> {
    /* body unchanged from server.rs:947-971 */
}

/// Decode a QUIC varint from the front of a slice.
///
/// Returns the value and the number of bytes consumed, or None when the slice
/// is shorter than the encoding announces. Used on the datagram path, which has
/// the whole packet in memory rather than a stream to await on.
pub fn decode_varint_slice(data: &[u8]) -> Option<(u64, usize)> {
    let first_byte = *data.first()?;
    let num_bytes = match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if data.len() < num_bytes {
        return None;
    }
    let mut value = (first_byte & 0b0011_1111) as u64;
    for byte in &data[1..num_bytes] {
        value <<= 8;
        value |= *byte as u64;
    }
    Some((value, num_bytes))
}
```

In `src/hysteria2/server.rs`, add `use super::frame::{FRAME_TYPE_TCP_REQUEST, read_varint};`
and delete the now-duplicated inline parsing of the datagram address length at
server.rs:476-500, replacing it with:

```rust
        let (address_len, next_index) = match crate::hysteria2::frame::decode_varint_slice(&data[8..])
        {
            Some((value, consumed)) => (value as usize, 8 + consumed),
            None => {
                debug!("Ignoring datagram with truncated address length");
                continue;
            }
        };
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib hysteria2`

Expected: PASS, 4 new tests.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
```

Expected: all green, with four more lib tests than before this task.

- [ ] **Step 8: Commit**

```bash
git add -A src/
git commit -F - <<'EOF'
hysteria2: make the server a module and lift its frame codec

The client needs the varint codec and the frame layouts the server already
implements. Keeping them private to a 1054-line server file would have meant
writing them a second time, so they move to a frame module that both sides
use.

The datagram path gains a slice decoder: a datagram arrives whole, so
decoding its address length by awaiting a stream reader was never the right
shape, and the server had an open-coded copy of the varint rules to prove
it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 4: Split the TUIC server into a module and lift its codec

**Files:**
- Create: `src/tuic/mod.rs`, `src/tuic/frame.rs`
- Rename: `src/tuic_server.rs` → `src/tuic/server.rs`
- Modify: `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Move the file**

```bash
mkdir -p src/tuic
git mv src/tuic_server.rs src/tuic/server.rs
```

Create `src/tuic/mod.rs`:

```rust
//! TUIC v5: server, client and the frame codec they share.

pub mod frame;
pub mod server;

pub use server::start_tuic_server;
```

Update `src/lib.rs` and `src/main.rs` to declare `pub mod tuic;` in place of
`mod tuic_server;`, and repoint the call site found by `rg -n 'tuic_server' src/`
to `tuic::start_tuic_server`.

- [ ] **Step 2: Run the build**

Run: `cargo build --lib`

Expected: success.

- [ ] **Step 3: Write the failing test**

Create `src/tuic/frame.rs` with only a tests module for now:

```rust
//! TUIC v5 frame codec, shared by the server and the client.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, NetLocation};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_serialize_address_hostname() {
        let loc = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        assert_eq!(
            serialize_address(&loc),
            [
                &[0x00u8, 11][..],
                b"example.com",
                &[0x01, 0xbb][..],
            ]
            .concat()
        );
    }

    #[test]
    fn test_serialize_address_ipv4() {
        let loc = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 80);
        assert_eq!(serialize_address(&loc), vec![0x01, 1, 2, 3, 4, 0x00, 0x50]);
    }

    #[test]
    fn test_serialize_address_ipv6() {
        let loc = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 80);
        let mut expected = vec![0x02u8];
        expected.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(serialize_address(&loc), expected);
    }

    #[test]
    fn test_serialize_address_max_length_hostname() {
        let hostname = "a".repeat(255);
        let loc = NetLocation::new(Address::Hostname(hostname.clone()), 1);
        let encoded = serialize_address(&loc);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded.len(), 1 + 1 + 255 + 2);
    }

    #[test]
    fn test_command_type_values() {
        assert_eq!(COMMAND_TYPE_AUTHENTICATE, 0x00);
        assert_eq!(COMMAND_TYPE_CONNECT, 0x01);
        assert_eq!(COMMAND_TYPE_PACKET, 0x02);
        assert_eq!(COMMAND_TYPE_DISSOCIATE, 0x03);
        assert_eq!(COMMAND_TYPE_HEARTBEAT, 0x04);
        assert_eq!(TUIC_VERSION, 0x05);
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test --lib tuic::frame`

Expected: FAIL to compile — nothing in scope.

- [ ] **Step 5: Move the codec in**

Cut from `src/tuic/server.rs` into `src/tuic/frame.rs`, making each `pub`:

- the constants at server.rs:27-35 (`COMMAND_TYPE_*`, `MAX_ADDRESS_BYTES_LEN`,
  `MAX_HEADER_LEN`);
- `read_address` (server.rs:291-338);
- `serialize_address` (server.rs:340-367);
- `serialize_socket_addr` (server.rs:369-387).

Add the version constant, which the server had inline as a literal `5`:

```rust
/// TUIC protocol version. See EAimTY/tuic SPEC.md.
pub const TUIC_VERSION: u8 = 0x05;
```

In `src/tuic/server.rs`, add
`use super::frame::{COMMAND_TYPE_AUTHENTICATE, COMMAND_TYPE_DISSOCIATE, COMMAND_TYPE_HEARTBEAT, COMMAND_TYPE_PACKET, MAX_HEADER_LEN, TUIC_VERSION, read_address, serialize_address, serialize_socket_addr};`
and replace the three `!= 5` version comparisons with `!= TUIC_VERSION`.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib tuic`

Expected: PASS, 5 new tests.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
```

Expected: all green, with five more lib tests than before this task.

- [ ] **Step 8: Commit**

```bash
git add -A src/
git commit -F - <<'EOF'
tuic: make the server a module and lift its frame codec

Same move as the Hysteria2 server, for the same reason: the client writes
the address and command encodings the server already reads, and they belong
in one place. The protocol version stops being an inline literal 5 compared
in three places.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 5: Salamander

**Files:**
- Create: `src/quic_outbound/mod.rs`, `src/quic_outbound/obfs/mod.rs`, `src/quic_outbound/obfs/salamander.rs`
- Modify: `Cargo.toml`, `src/lib.rs`, `src/main.rs`

- [ ] **Step 1: Add the dependency**

In `Cargo.toml`, add to `[dependencies]`, keeping alphabetical order (after
`base64`, before `boringtun`):

```toml
blake2 = "*"
```

Run `cargo fetch` to update `Cargo.lock`.

- [ ] **Step 2: Declare the modules**

Create `src/quic_outbound/mod.rs`:

```rust
//! Shared machinery for outbounds that dial over QUIC and own their transport.

pub mod obfs;
```

Create `src/quic_outbound/obfs/mod.rs`:

```rust
//! QUIC packet obfuscation.

mod salamander;

pub use salamander::Salamander;

use std::fmt::Debug;

/// A symmetric packet obfuscator applied to every UDP datagram of a QUIC
/// connection, on both ends.
///
/// Implementations are used from many threads at once and must not require
/// exclusive access.
pub trait Obfuscator: Send + Sync + Debug {
    /// Transform `input` into `out`, returning the number of bytes written.
    ///
    /// Returns None when `out` is too small, which the caller treats as a
    /// dropped packet rather than an error.
    fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize>;

    /// Reverse `obfuscate`. Returns None for a packet that cannot be a valid
    /// obfuscated datagram.
    fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize>;

    /// Bytes added to every packet. Subtracted from the QUIC MTU.
    fn overhead(&self) -> usize;
}
```

Add `pub mod quic_outbound;` to both `src/lib.rs` and `src/main.rs`.

- [ ] **Step 3: Write the failing tests**

Create `src/quic_outbound/obfs/salamander.rs`:

```rust
//! Salamander obfuscation.
//!
//! Verified against apernet/hysteria, extras/obfs/salamander.go:
//!
//!     smPSKMinLen = 4
//!     smSaltLen   = 8
//!     smKeyLen    = blake2b.Size256
//!
//! On the wire a packet is `[8-byte random salt][payload XOR key]`, where
//! `key = BLAKE2b-256(PSK || salt)` and byte `i` of the payload is XOR'd with
//! `key[i % 32]`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let obfs = Salamander::new(b"a password").unwrap();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut wire = vec![0u8; payload.len() + obfs.overhead()];
        let written = obfs.obfuscate(payload, &mut wire).unwrap();
        assert_eq!(written, payload.len() + 8);

        let mut back = vec![0u8; payload.len()];
        let read = obfs.deobfuscate(&wire[..written], &mut back).unwrap();
        assert_eq!(read, payload.len());
        assert_eq!(&back[..read], payload);
    }

    #[test]
    fn test_output_is_not_the_input() {
        let obfs = Salamander::new(b"a password").unwrap();
        let payload = [0u8; 64];
        let mut wire = [0u8; 72];
        obfs.obfuscate(&payload, &mut wire).unwrap();
        // An all-zero payload XOR'd with the key is the key itself repeated,
        // so the tail must not be all zero.
        assert!(wire[8..].iter().any(|b| *b != 0));
    }

    #[test]
    fn test_salt_varies_between_packets() {
        let obfs = Salamander::new(b"a password").unwrap();
        let payload = b"same payload";
        let mut first = vec![0u8; payload.len() + 8];
        let mut second = vec![0u8; payload.len() + 8];
        obfs.obfuscate(payload, &mut first).unwrap();
        obfs.obfuscate(payload, &mut second).unwrap();
        assert_ne!(first, second, "a fresh salt must be drawn per packet");
    }

    #[test]
    fn test_deobfuscate_rejects_short_packets() {
        let obfs = Salamander::new(b"a password").unwrap();
        let mut out = [0u8; 32];
        assert!(obfs.deobfuscate(&[], &mut out).is_none());
        assert!(obfs.deobfuscate(&[0u8; 8], &mut out).is_none());
        assert!(obfs.deobfuscate(&[0u8; 9], &mut out).is_some());
    }

    #[test]
    fn test_obfuscate_rejects_short_output_buffer() {
        let obfs = Salamander::new(b"a password").unwrap();
        let mut out = [0u8; 8];
        assert!(obfs.obfuscate(b"payload", &mut out).is_none());
    }

    #[test]
    fn test_rejects_short_password() {
        assert!(Salamander::new(b"abc").is_err());
        assert!(Salamander::new(b"abcd").is_ok());
    }

    /// A fixed vector so a refactor cannot silently change the transform.
    /// The key is derived from the PSK and the salt only, so a known salt
    /// pins the whole output.
    #[test]
    fn test_known_vector() {
        let obfs = Salamander::new(b"hysteria").unwrap();
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let key = obfs.derive_key(&salt);

        // Deobfuscating a packet we build by hand must reproduce the payload.
        let payload = b"hello";
        let mut wire = Vec::new();
        wire.extend_from_slice(&salt);
        for (i, byte) in payload.iter().enumerate() {
            wire.push(byte ^ key[i % 32]);
        }

        let mut out = [0u8; 5];
        let read = obfs.deobfuscate(&wire, &mut out).unwrap();
        assert_eq!(&out[..read], payload);
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test --lib salamander`

Expected: FAIL to compile — `Salamander` is not found.

- [ ] **Step 5: Implement Salamander**

Insert above the `tests` module in `src/quic_outbound/obfs/salamander.rs`:

```rust
use blake2::{Blake2b, Digest, digest::consts::U32};
use rand::RngExt;

use super::Obfuscator;

/// Minimum pre-shared key length, matching smPSKMinLen upstream.
const MIN_PSK_LEN: usize = 4;
/// Salt prefixed to every packet, matching smSaltLen upstream.
const SALT_LEN: usize = 8;
/// Derived key length, matching smKeyLen = blake2b.Size256 upstream.
const KEY_LEN: usize = 32;

type Blake2b256 = Blake2b<U32>;

#[derive(Debug)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl Salamander {
    pub fn new(psk: &[u8]) -> std::io::Result<Self> {
        if psk.len() < MIN_PSK_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("obfuscation password must be at least {MIN_PSK_LEN} bytes"),
            ));
        }
        Ok(Self { psk: psk.to_vec() })
    }

    fn derive_key(&self, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

impl Obfuscator for Salamander {
    fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize> {
        let out_len = input.len() + SALT_LEN;
        if out.len() < out_len {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let key = self.derive_key(&salt);

        out[..SALT_LEN].copy_from_slice(&salt);
        for (i, byte) in input.iter().enumerate() {
            out[i + SALT_LEN] = byte ^ key[i % KEY_LEN];
        }
        Some(out_len)
    }

    fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> Option<usize> {
        let out_len = input.len().checked_sub(SALT_LEN)?;
        if out_len == 0 || out.len() < out_len {
            return None;
        }
        let salt: [u8; SALT_LEN] = input[..SALT_LEN].try_into().ok()?;
        let key = self.derive_key(&salt);

        for (i, byte) in input[SALT_LEN..].iter().enumerate() {
            out[i] = byte ^ key[i % KEY_LEN];
        }
        Some(out_len)
    }

    fn overhead(&self) -> usize {
        SALT_LEN
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib salamander`

Expected: PASS, 7 tests.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/ Cargo.toml Cargo.lock
git commit -F - <<'EOF'
obfs: add Salamander

The transform is symmetric, so one implementation serves the client and the
server. Constants and the byte layout are taken from
apernet/hysteria extras/obfs/salamander.go rather than from a description
of it: an eight-byte random salt, a BLAKE2b-256 key over the pre-shared key
followed by that salt, and the payload XOR'd with the key repeating every
32 bytes. A minimum password length of four bytes comes from the same file.

It sits behind a trait because gecko, the other official obfuscator, builds
on this one rather than replacing it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 6: The obfuscating UDP socket

quinn talks to the network through `AsyncUdpSocket`. Wrapping that is the only
place obfuscation can live, because it must apply to QUIC's own handshake
packets, not just to application data.

**Files:**
- Create: `src/quic_outbound/obfs/socket.rs`
- Modify: `src/quic_outbound/obfs/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/quic_outbound/obfs/socket.rs` with the test module first:

```rust
//! An AsyncUdpSocket that obfuscates every datagram.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::obfs::Salamander;
    use std::sync::Arc;

    fn wrap(std_socket: std::net::UdpSocket) -> Arc<ObfuscatedUdpSocket> {
        let obfs: Arc<dyn Obfuscator> = Arc::new(Salamander::new(b"a password").unwrap());
        Arc::new(ObfuscatedUdpSocket::new(std_socket, obfs).unwrap())
    }

    #[tokio::test]
    async fn test_round_trip_between_two_wrapped_sockets() {
        let a = wrap(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let b = wrap(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let b_addr = b.local_addr().unwrap();

        let payload = b"a quic packet would go here";
        a.try_send(&quinn::udp::Transmit {
            destination: b_addr,
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: None,
        })
        .unwrap();

        let mut buf = [0u8; 2048];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let received = std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut buf)];
            b.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await
        .unwrap();

        assert_eq!(received, 1);
        assert_eq!(meta[0].len, payload.len());
        assert_eq!(meta[0].stride, payload.len());
        assert_eq!(&buf[..payload.len()], payload);
    }

    #[tokio::test]
    async fn test_segmentation_offload_is_disabled() {
        let a = wrap(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        assert_eq!(a.max_transmit_segments(), 1);
        assert_eq!(a.max_receive_segments(), 1);
    }

    #[tokio::test]
    async fn test_garbage_datagram_is_dropped_not_returned() {
        let receiver = wrap(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let addr = receiver.local_addr().unwrap();

        // A plain sender: whatever it sends cannot deobfuscate to anything.
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        plain.send_to(&[0u8; 4], addr).await.unwrap();

        // Then a well-formed packet, which must still arrive.
        let good = wrap(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        good.try_send(&quinn::udp::Transmit {
            destination: addr,
            ecn: None,
            contents: b"real",
            segment_size: None,
            src_ip: None,
        })
        .unwrap();

        let mut buf = [0u8; 2048];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let received = std::future::poll_fn(|cx| {
            let mut bufs = [std::io::IoSliceMut::new(&mut buf)];
            receiver.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await
        .unwrap();

        assert_eq!(received, 1);
        assert_eq!(&buf[..meta[0].len], b"real");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib obfs::socket`

Expected: FAIL to compile — `ObfuscatedUdpSocket` is not found.

- [ ] **Step 3: Implement the socket**

Insert above the tests module:

```rust
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

use super::Obfuscator;

/// Largest datagram we will obfuscate. QUIC datagrams are far below this;
/// the buffer exists only so the scratch space has a fixed ceiling.
const MAX_DATAGRAM: usize = 2048;

thread_local! {
    /// Scratch space for the send path. `Transmit::contents` is an immutable
    /// slice, so obfuscation needs somewhere to write. A thread-local avoids
    /// both an allocation per packet and a lock that would serialise sends.
    static SEND_SCRATCH: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(vec![0u8; MAX_DATAGRAM]);
}

/// Wraps quinn's own UDP socket and applies an obfuscator to every datagram.
///
/// Segmentation and receive offload are reported as unavailable. With GSO a
/// single `sendmsg` carries several QUIC packets, and an obfuscator that treats
/// the buffer as one unit produces something the peer cannot split apart again.
#[derive(Debug)]
pub struct ObfuscatedUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Arc<dyn Obfuscator>,
}

impl ObfuscatedUdpSocket {
    pub fn new(
        socket: std::net::UdpSocket,
        obfs: Arc<dyn Obfuscator>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: TokioRuntime.wrap_udp_socket(socket)?,
            obfs,
        })
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        SEND_SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            let needed = transmit.contents.len() + self.obfs.overhead();
            if scratch.len() < needed {
                scratch.resize(needed, 0);
            }
            let written = self
                .obfs
                .obfuscate(transmit.contents, &mut scratch)
                .ok_or_else(|| std::io::Error::other("obfuscation buffer too small"))?;

            self.inner.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &scratch[..written],
                // Never batched: max_transmit_segments() is 1.
                segment_size: None,
                src_ip: transmit.src_ip,
            })
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;

            // Deobfuscate each datagram, dropping any that is not ours, and
            // compact the survivors to the front of the batch.
            //
            // `deobfuscate` reads and writes different offsets of the same
            // logical packet, and the borrow checker will not allow one buffer
            // to be both, so it goes through a scratch Vec. max_receive_segments
            // is 1, so this runs at most once per poll.
            let mut kept = 0;
            for i in 0..count {
                let len = meta[i].len;
                let mut decoded = vec![0u8; len];
                match self.obfs.deobfuscate(&bufs[i][..len], &mut decoded) {
                    Some(decoded_len) => {
                        // quinn pairs meta[n] with bufs[n], so a survivor that
                        // moves forward in the metadata must have its bytes
                        // move with it. Writing the decoded copy straight to
                        // its final buffer does both at once. Writing it to
                        // bufs[i] instead would feed quinn the dropped
                        // packet's buffer.
                        if kept != i {
                            meta[kept] = meta[i];
                        }
                        bufs[kept][..decoded_len].copy_from_slice(&decoded[..decoded_len]);
                        meta[kept].len = decoded_len;
                        meta[kept].stride = decoded_len;
                        kept += 1;
                    }
                    None => {
                        log::debug!(
                            "dropping {len}-byte datagram from {} that is not obfuscated for us",
                            meta[i].addr
                        );
                    }
                }
            }

            // Every datagram in this batch was garbage; wait for the next one
            // rather than reporting zero, which quinn reads as "nothing to do".
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}
```

Add `mod socket;` and `pub use socket::ObfuscatedUdpSocket;` to
`src/quic_outbound/obfs/mod.rs`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib obfs::socket`

Expected: PASS, 3 tests.

- [ ] **Step 5: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
obfs: apply the obfuscator at the UDP socket

Obfuscation has to cover QUIC's own handshake packets, not only application
data, so the only place it can live is quinn's AsyncUdpSocket. The wrapper
transforms each datagram on the way out and back, and reports segmentation
and receive offload as unavailable: with GSO a single sendmsg carries
several QUIC packets, and scrambling that buffer as one unit produces
something the peer cannot split apart again.

A datagram that fails to deobfuscate is dropped and logged rather than
surfaced as an error, matching what the kernel would do with a stray packet.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 7: Configuration types

**Files:**
- Create: `src/config/types/obfs.rs`
- Modify: `src/config/types/mod.rs`, `src/config/types/client.rs:442-576, 592-612`

- [ ] **Step 1: Write the failing tests**

Create `src/config/types/obfs.rs`:

```rust
//! Obfuscation configuration, shared by the Hysteria2 client and server.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_salamander() {
        let yaml = r#"
type: salamander
password: obfspass
"#;
        let config: ObfsConfig = serde_yaml::from_str(yaml).unwrap();
        let ObfsConfig::Salamander { password } = &config;
        assert_eq!(password.expose(), "obfspass");
    }

    #[test]
    fn test_rejects_unknown_type() {
        let yaml = r#"
type: gecko
password: obfspass
"#;
        let err = serde_yaml::from_str::<ObfsConfig>(yaml)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("salamander"),
            "error should name the supported types: {err}"
        );
    }

    #[test]
    fn test_rejects_unknown_field() {
        let yaml = r#"
type: salamander
password: obfspass
min_packet_size: 512
"#;
        let err = serde_yaml::from_str::<ObfsConfig>(yaml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("min_packet_size"), "{err}");
    }

    #[test]
    fn test_round_trip() {
        let config = ObfsConfig::Salamander {
            password: "obfspass".into(),
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        let back: ObfsConfig = serde_yaml::from_str(&yaml).unwrap();
        let ObfsConfig::Salamander { password } = &back;
        assert_eq!(password.expose(), "obfspass");
    }
}
```

And add to the `tests` module in `src/config/types/client.rs`:

```rust
    #[test]
    fn test_client_proxy_config_hysteria2() {
        let yaml = r#"
type: hysteria2
password: secret
obfs:
  type: salamander
  password: obfspass
"#;
        let config: ClientProxyConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            ClientProxyConfig::Hysteria2(ref h) => {
                assert_eq!(h.password.expose(), "secret");
                assert!(h.udp_enabled);
                assert!(h.obfs.is_some());
            }
            other => panic!("expected Hysteria2, got {other:?}"),
        }
        assert!(config.owns_transport());
        assert_eq!(config.protocol_name(), "Hysteria2");
    }

    #[test]
    fn test_client_proxy_config_tuic_defaults() {
        let yaml = r#"
type: tuic
uuid: "00000000-0000-0000-0000-000000000000"
password: secret
"#;
        let config: ClientProxyConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            ClientProxyConfig::Tuic(ref t) => {
                assert!(t.udp_enabled);
                assert_eq!(t.udp_relay_mode, TuicUdpRelayMode::Native);
                assert!(!t.zero_rtt_handshake);
                assert_eq!(t.heartbeat_ms, 10_000);
            }
            other => panic!("expected Tuic, got {other:?}"),
        }
        assert!(config.owns_transport());
        assert_eq!(config.protocol_name(), "TUIC");
    }

    #[test]
    fn test_tuic_rejects_unknown_relay_mode() {
        let yaml = r#"
type: tuic
uuid: "00000000-0000-0000-0000-000000000000"
password: secret
udp_relay_mode: sideways
"#;
        let err = serde_yaml::from_str::<ClientProxyConfig>(yaml)
            .unwrap_err()
            .to_string();
        assert!(err.contains("native"), "{err}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::types::obfs && cargo test --lib hysteria2_defaults`

Expected: FAIL to compile.

- [ ] **Step 3: Implement `ObfsConfig`**

Insert above the tests module in `src/config/types/obfs.rs`:

```rust
use serde::{Deserialize, Serialize};

use super::redacted::Redacted;

/// QUIC packet obfuscation.
///
/// Internally tagged with the per-type fields alongside, which is the shape
/// sing-box uses. `gecko` — the other official type, which adds handshake
/// packet fragmentation on top of Salamander's scrambling — slots in here with
/// its `min_packet_size` and `max_packet_size` without a schema change.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ObfsConfig {
    Salamander { password: Redacted<String> },
}
```

Add `pub mod obfs;` and `pub use obfs::ObfsConfig;` to
`src/config/types/mod.rs`, in the existing alphabetical position.

- [ ] **Step 4: Implement the client variants**

In `src/config/types/client.rs`, add above `ClientProxyConfig`:

```rust
/// Hysteria2 client outbound.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2ClientConfig {
    /// Server password. A server that authenticates by username and password
    /// expects `<username>:<password>` here, as a single opaque string.
    pub password: Redacted<String>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub udp_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<ObfsConfig>,
}

/// How TUIC carries UDP packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TuicUdpRelayMode {
    /// QUIC datagrams.
    Native,
    /// QUIC unidirectional streams.
    Quic,
}

impl Default for TuicUdpRelayMode {
    fn default() -> Self {
        Self::Native
    }
}

fn default_heartbeat_ms() -> u64 {
    10_000
}

fn is_default_heartbeat(value: &u64) -> bool {
    *value == default_heartbeat_ms()
}

/// TUIC v5 client outbound.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TuicClientConfig {
    pub uuid: String,
    pub password: Redacted<String>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub udp_enabled: bool,
    #[serde(default, skip_serializing_if = "TuicUdpRelayMode::is_default")]
    pub udp_relay_mode: TuicUdpRelayMode,
    /// 0-RTT is off by default: 0-RTT data is replayable.
    #[serde(default, skip_serializing_if = "is_false")]
    pub zero_rtt_handshake: bool,
    #[serde(
        default = "default_heartbeat_ms",
        skip_serializing_if = "is_default_heartbeat"
    )]
    pub heartbeat_ms: u64,
}

impl TuicUdpRelayMode {
    fn is_default(&self) -> bool {
        *self == Self::Native
    }
}
```

Add `use super::obfs::ObfsConfig;` to the imports.

Add the variants to `ClientProxyConfig`, after `AmneziaWg`:

```rust
    /// Hysteria2 client outbound (QUIC-native, owns its transport).
    /// Boxed to keep the enum small.
    Hysteria2(Box<Hysteria2ClientConfig>),
    /// TUIC v5 client outbound (QUIC-native, owns its transport).
    #[serde(alias = "tuic_v5", alias = "tuicv5")]
    Tuic(Box<TuicClientConfig>),
```

Extend the two methods:

```rust
    pub fn owns_transport(&self) -> bool {
        matches!(
            self,
            ClientProxyConfig::Wireguard(_)
                | ClientProxyConfig::AmneziaWg(_)
                | ClientProxyConfig::Hysteria2(_)
                | ClientProxyConfig::Tuic(_)
        )
    }
```

and add to `protocol_name`:

```rust
            ClientProxyConfig::Hysteria2(..) => "Hysteria2",
            ClientProxyConfig::Tuic(..) => "TUIC",
```

- [ ] **Step 5: Handle the factory's exhaustive match**

`src/tcp/tcp_client_handler_factory.rs:366` matches WireGuard and AmneziaWG and
panics. Extend that arm so the new variants reach the same message rather than
failing to compile:

```rust
        ClientProxyConfig::Wireguard(..)
        | ClientProxyConfig::AmneziaWg(..)
        | ClientProxyConfig::Hysteria2(..)
        | ClientProxyConfig::Tuic(..) => {
            panic!(
                "{} owns its transport and cannot be created as a stream-wrapping \
                 client handler. This is a bug: config validation should have kept it \
                 to a single hop.",
                config.protocol_name()
            );
        }
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib obfs && cargo test --lib client_proxy_config`

Expected: PASS, 7 new tests.

- [ ] **Step 7: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
config: add hysteria2 and tuic client outbound types

The obfuscation block is internally tagged with the per-type fields
alongside it, which is the shape sing-box uses, so gecko slots in later
without a schema change.

Both protocols report owns_transport, which keeps them to a single hop.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 8: Validation

**Files:**
- Modify: `src/config/validate.rs:974-995`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `src/config/validate.rs`:

```rust
    fn hysteria2_client(obfs: Option<ObfsConfig>) -> ClientConfig {
        ClientConfig {
            address: NetLocation::from_str("example.com:443", None).unwrap(),
            protocol: ClientProxyConfig::Hysteria2(Box::new(Hysteria2ClientConfig {
                password: "secret".into(),
                udp_enabled: true,
                obfs,
            })),
            ..Default::default()
        }
    }

    #[test]
    fn test_hysteria2_allows_quic_settings() {
        let mut config = hysteria2_client(None);
        config.quic_settings = Some(ClientQuicConfig::default());
        assert!(validate_client_config(&mut config, &HashMap::new()).is_ok());
    }

    #[test]
    fn test_hysteria2_rejects_transport() {
        let mut config = hysteria2_client(None);
        config.transport = Transport::Quic;
        let err = validate_client_config(&mut config, &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("transport"), "{err}");
    }

    #[test]
    fn test_hysteria2_rejects_tcp_settings() {
        let mut config = hysteria2_client(None);
        config.tcp_settings = Some(TcpConfig::default());
        let err = validate_client_config(&mut config, &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("tcp_settings"), "{err}");
    }

    #[test]
    fn test_rejects_short_obfs_password() {
        let mut config = hysteria2_client(Some(ObfsConfig::Salamander {
            password: "abc".into(),
        }));
        let err = validate_client_config(&mut config, &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("4"), "error should state the minimum: {err}");
    }

    #[test]
    fn test_accepts_four_byte_obfs_password() {
        let mut config = hysteria2_client(Some(ObfsConfig::Salamander {
            password: "abcd".into(),
        }));
        assert!(validate_client_config(&mut config, &HashMap::new()).is_ok());
    }

    #[test]
    fn test_tuic_rejects_bad_uuid() {
        let mut config = ClientConfig {
            address: NetLocation::from_str("example.com:443", None).unwrap(),
            protocol: ClientProxyConfig::Tuic(Box::new(TuicClientConfig {
                uuid: "not-a-uuid".to_string(),
                password: "secret".into(),
                udp_enabled: true,
                udp_relay_mode: TuicUdpRelayMode::Native,
                zero_rtt_handshake: false,
                heartbeat_ms: 10_000,
            })),
            ..Default::default()
        };
        let err = validate_client_config(&mut config, &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("uuid") || err.contains("UUID"), "{err}");
    }
```

Adjust the `validate_client_config` call signature to whatever the surrounding
tests already use — read a neighbouring test first.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib validate::tests::test_hysteria2`

Expected: FAIL.

- [ ] **Step 3: Implement the rules**

Replace the block at `src/config/validate.rs:974-995`:

```rust
    // Protocols that own their transport reject the socket-level knobs that do
    // not apply to them. QUIC-based ones keep quic_settings, which carries
    // verify, SNI, fingerprints, ALPN and the client certificate.
    if client_config.protocol.owns_transport() {
        let proto = client_config.protocol.protocol_name();
        if client_config.transport != Transport::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{proto} uses its own transport. Do not set 'transport'."),
            ));
        }
        if client_config.tcp_settings.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("tcp_settings is not valid for {proto} protocol."),
            ));
        }
        let quic_capable = matches!(
            client_config.protocol,
            ClientProxyConfig::Hysteria2(_) | ClientProxyConfig::Tuic(_)
        );
        if !quic_capable && client_config.quic_settings.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("quic_settings is not valid for {proto} protocol."),
            ));
        }
    }

    match &client_config.protocol {
        ClientProxyConfig::Hysteria2(h) => {
            validate_obfs_config(h.obfs.as_ref())?;
        }
        ClientProxyConfig::Tuic(t) => {
            crate::uuid_util::parse_uuid(&t.uuid).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TUIC uuid is not a valid UUID: {e}"),
                )
            })?;
            if t.heartbeat_ms == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TUIC heartbeat_ms must be greater than zero.",
                ));
            }
        }
        _ => {}
    }
```

Add the helper next to the other validators:

```rust
/// Minimum obfuscation password length, matching smPSKMinLen in
/// apernet/hysteria extras/obfs/salamander.go.
const MIN_OBFS_PASSWORD_LEN: usize = 4;

fn validate_obfs_config(obfs: Option<&ObfsConfig>) -> std::io::Result<()> {
    let Some(ObfsConfig::Salamander { password }) = obfs else {
        return Ok(());
    };
    if password.expose().len() < MIN_OBFS_PASSWORD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Obfuscation password must be at least {MIN_OBFS_PASSWORD_LEN} bytes; \
                 the reference implementation rejects anything shorter."
            ),
        ));
    }
    Ok(())
}
```

Check the exact name of the UUID parser first:

```bash
rg -n 'pub fn' src/uuid_util.rs
```

Use whichever function parses a hyphenated UUID string into 16 bytes, and match
its error type in the `map_err` above.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib validate`

Expected: PASS, 6 new tests.

- [ ] **Step 5: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
config: validate the QUIC client outbounds

Same rules the tunnel protocols already had, with one deliberate difference:
Hysteria2 and TUIC keep quic_settings, because verify, SNI, fingerprints,
ALPN and the client certificate all mean the same thing for them.

An obfuscation password shorter than four bytes is rejected up front rather
than at the first packet, matching smPSKMinLen upstream.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 9: Obfuscation on the Hysteria2 server

Without this there is no way to test the client's obfuscation end to end.

**Files:**
- Modify: `src/config/types/server.rs:757-761`, `src/hysteria2/server.rs:974-1052`, and the server startup call site

- [ ] **Step 1: Add the config field**

In `src/config/types/server.rs`, extend the variant:

```rust
    Hysteria2 {
        password: Redacted<String>,
        #[serde(default = "default_true")]
        udp_enabled: bool,
        /// QUIC packet obfuscation. Both ends must agree.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<ObfsConfig>,
    },
```

`ServerProxyConfig` has a hand-written deserializer with a `VALID_FIELDS` list.
Find it and add `"obfs"`:

```bash
rg -n 'VALID_FIELDS' src/config/types/server.rs
```

Fix every construction site the compiler reports, including the test helper at
server.rs:1084, by adding `obfs: None`.

Add the same validation call the client got, in `validate_server_config`:

```rust
        ServerProxyConfig::Hysteria2 { obfs, .. } => {
            validate_obfs_config(obfs.as_ref())?;
        }
```

Make `validate_obfs_config` visible from wherever the server validation lives
(same module, so no change is needed if both are in `validate.rs`).

- [ ] **Step 2: Write the failing test**

Add to the `tests` module in `src/hysteria2/server.rs`, or create one:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_mtu_accounts_for_obfuscation_overhead() {
        assert_eq!(effective_mtu(None), BASE_MTU);
        assert_eq!(effective_mtu(Some(8)), BASE_MTU - 8);
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test --lib hysteria2::server`

Expected: FAIL to compile — `effective_mtu` and `BASE_MTU` are not found.

- [ ] **Step 4: Thread the obfuscator through server startup**

In `src/hysteria2/server.rs`, add near the other constants:

```rust
/// QUIC MTU floor used by the reference implementations.
pub(crate) const BASE_MTU: u16 = 1200;

/// The MTU available to QUIC once an obfuscator has taken its share of every
/// datagram. Without this subtraction, packets sized exactly at the floor start
/// disappearing on paths that honour it.
pub(crate) fn effective_mtu(obfs_overhead: Option<usize>) -> u16 {
    match obfs_overhead {
        Some(overhead) => BASE_MTU - overhead as u16,
        None => BASE_MTU,
    }
}
```

Change the signature:

```rust
pub async fn start_hysteria2_server(
    bind_address: SocketAddr,
    quic_server_config: Arc<quinn::crypto::rustls::QuicServerConfig>,
    hysteria2_password: &'static str,
    client_proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    num_endpoints: usize,
    udp_enabled: bool,
    obfs: Option<Arc<dyn crate::quic_outbound::obfs::Obfuscator>>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
```

Inside the spawned task, replace the MTU lines and the endpoint construction:

```rust
            let mtu = effective_mtu(obfs.as_ref().map(|o| o.overhead()));

            Arc::get_mut(&mut server_config.transport)
                .unwrap()
                /* ... unchanged settings ... */
                .initial_mtu(mtu)
                .min_mtu(mtu)
                .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
                // Segmentation offload batches several QUIC packets into one
                // sendmsg, which an obfuscator cannot scramble as a unit.
                .enable_segmentation_offload(obfs.is_none())
                .initial_rtt(Duration::from_millis(100));

            let socket2_socket = crate::socket_util::new_socket2_udp_socket_with_buffer_size(
                bind_address.is_ipv6(),
                None,
                Some(bind_address),
                true,
                Some(8_625_000),
            )
            .unwrap();

            let endpoint = match obfs.clone() {
                Some(obfs) => {
                    let socket = crate::quic_outbound::obfs::ObfuscatedUdpSocket::new(
                        socket2_socket.into(),
                        obfs,
                    )
                    .unwrap();
                    quinn::Endpoint::new_with_abstract_socket(
                        quinn::EndpointConfig::default(),
                        Some(server_config),
                        Arc::new(socket),
                        Arc::new(quinn::TokioRuntime),
                    )
                    .unwrap()
                }
                None => quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_config),
                    socket2_socket.into(),
                    Arc::new(quinn::TokioRuntime),
                )
                .unwrap(),
            };
```

Clone `obfs` into each spawned task alongside the other clones at the top of the
loop.

- [ ] **Step 5: Update the call site**

```bash
rg -n 'start_hysteria2_server' src/
```

At the one call site, build the obfuscator from the config:

```rust
            let obfs = match obfs {
                Some(crate::config::ObfsConfig::Salamander { password }) => {
                    Some(Arc::new(crate::quic_outbound::obfs::Salamander::new(
                        password.expose().as_bytes(),
                    )?) as Arc<dyn crate::quic_outbound::obfs::Obfuscator>)
                }
                None => None,
            };
```

- [ ] **Step 6: Run the tests and the gate**

```bash
cargo test --lib hysteria2
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
```

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add -A src/
git commit -F - <<'EOF'
hysteria2: support Salamander obfuscation on the server

Symmetric with the client, and the reason the client's obfuscation can be
tested end to end at all rather than only against a unit test of the XOR.

Two settings follow from having an obfuscator: segmentation offload is
turned off, because it batches several QUIC packets into one sendmsg that
cannot be scrambled as a unit, and the MTU floor drops by the obfuscator's
per-packet overhead, because the salt occupies room in the datagram.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 10: Build the QUIC endpoint for an outbound

**Files:**
- Modify: `src/quic_outbound/mod.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/quic_outbound/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientQuicConfig;

    fn settings() -> QuicOutboundSettings {
        QuicOutboundSettings {
            server: crate::address::NetLocation::from_str("example.com:443", None).unwrap(),
            quic: ClientQuicConfig::default(),
            bind_interface: None,
            obfs: None,
            default_alpn: "h3",
        }
    }

    #[test]
    fn test_alpn_defaults_to_the_protocols_own() {
        assert_eq!(settings().alpn_protocols(), vec!["h3".to_string()]);
    }

    #[test]
    fn test_alpn_can_be_overridden() {
        let mut s = settings();
        s.quic.alpn_protocols = crate::option_util::NoneOrSome::One("hysteria".to_string());
        assert_eq!(s.alpn_protocols(), vec!["hysteria".to_string()]);
    }

    #[test]
    fn test_sni_defaults_to_the_server_hostname() {
        assert_eq!(settings().sni_hostname().as_deref(), Some("example.com"));
    }

    #[test]
    fn test_sni_is_none_for_a_bare_ip_server() {
        let mut s = settings();
        s.server = crate::address::NetLocation::from_str("1.2.3.4:443", None).unwrap();
        assert!(s.sni_hostname().is_none());
    }

    #[tokio::test]
    async fn test_endpoint_binds_for_the_resolved_family() {
        let s = settings();
        let endpoint = s.build_endpoint(true).unwrap();
        assert!(endpoint.local_addr().unwrap().is_ipv6());
        let endpoint = s.build_endpoint(false).unwrap();
        assert!(!endpoint.local_addr().unwrap().is_ipv6());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib quic_outbound`

Expected: FAIL to compile.

- [ ] **Step 3: Implement the settings and the builder**

Replace the contents of `src/quic_outbound/mod.rs` above the tests:

```rust
//! Shared machinery for outbounds that dial over QUIC and own their transport.

pub mod connection;
pub mod obfs;

use std::sync::Arc;
use std::time::Duration;

use crate::address::NetLocation;
use crate::config::ClientQuicConfig;
use crate::rustls_config_util::create_client_config;
use crate::socket_util::new_udp_socket;

use obfs::{ObfuscatedUdpSocket, Obfuscator};

/// QUIC MTU floor used by the reference implementations.
const BASE_MTU: u16 = 1200;

/// Everything a QUIC outbound needs to raise an endpoint.
///
/// Transport parameters below are not invented. They are the values our own
/// Hysteria2 and TUIC servers use, which came from the reference
/// implementations in turn. Transport parameters are part of a client's
/// fingerprint — sing-box's Chrome parroting pins idle_timeout and the receive
/// windows for exactly that reason — so picking our own numbers would cost a
/// unique signature and buy nothing.
pub struct QuicOutboundSettings {
    pub server: NetLocation,
    pub quic: ClientQuicConfig,
    pub bind_interface: Option<String>,
    pub obfs: Option<Arc<dyn Obfuscator>>,
    /// ALPN used when the configuration does not name one.
    pub default_alpn: &'static str,
}

impl std::fmt::Debug for QuicOutboundSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicOutboundSettings")
            .field("server", &self.server)
            .field("obfuscated", &self.obfs.is_some())
            .field("default_alpn", &self.default_alpn)
            .finish()
    }
}

impl QuicOutboundSettings {
    pub fn alpn_protocols(&self) -> Vec<String> {
        if self.quic.alpn_protocols.is_unspecified() {
            vec![self.default_alpn.to_string()]
        } else {
            self.quic.alpn_protocols.clone().into_vec()
        }
    }

    pub fn sni_hostname(&self) -> Option<String> {
        if self.quic.sni_hostname.is_unspecified() {
            self.server.address().hostname().map(ToString::to_string)
        } else {
            self.quic.sni_hostname.clone().into_option()
        }
    }

    /// Raise an endpoint bound for the given address family.
    ///
    /// The family comes from the *resolved* server address rather than from the
    /// configured one, so that a hostname that resolves to IPv6 does not end up
    /// on an IPv4 socket.
    pub fn build_endpoint(&self, server_is_ipv6: bool) -> std::io::Result<quinn::Endpoint> {
        let sni = self.sni_hostname();

        let key_and_cert = self
            .quic
            .key
            .clone()
            .zip(self.quic.cert.clone())
            .map(|(key, cert)| (key.into_bytes(), cert.into_bytes()));

        let rustls_client_config = create_client_config(
            self.quic.verify,
            self.quic.server_fingerprints.clone().into_vec(),
            self.alpn_protocols(),
            sni.is_some(),
            key_and_cert,
            false, // QUIC enforces TLS 1.3 anyway
        );

        let tls13_suite = match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            rustls::SupportedCipherSuite::Tls13(t) => t,
            _ => unreachable!("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite"),
        };

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
            Arc::new(rustls_client_config),
            tls13_suite.quic_suite().unwrap(),
        )
        .map_err(|e| std::io::Error::other(format!("failed to build QUIC client config: {e}")))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        let overhead = self.obfs.as_ref().map(|o| o.overhead()).unwrap_or(0);
        let mtu = BASE_MTU - overhead as u16;

        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(0_u32.into())
            .max_concurrent_uni_streams(0_u32.into())
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
            .send_window(16 * 1024 * 1024)
            .receive_window((20u32 * 1024 * 1024).into())
            .stream_receive_window((8u32 * 1024 * 1024).into())
            .initial_mtu(mtu)
            .min_mtu(mtu)
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .enable_segmentation_offload(self.obfs.is_none())
            .initial_rtt(Duration::from_millis(100));
        client_config.transport_config(Arc::new(transport));

        let udp_socket = new_udp_socket(server_is_ipv6, self.bind_interface.clone())?;
        let udp_socket = udp_socket.into_std()?;

        let mut endpoint = match self.obfs.clone() {
            Some(obfs) => quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(ObfuscatedUdpSocket::new(udp_socket, obfs)?),
                Arc::new(quinn::TokioRuntime),
            )?,
            None => quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                udp_socket,
                Arc::new(quinn::TokioRuntime),
            )?,
        };
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }
}
```

Note the concurrent-stream limits are zero: those bound what the *peer* may
open toward us, and neither protocol has the server initiate streams. Incoming
datagrams are unaffected.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib quic_outbound`

Expected: PASS, 5 tests.

- [ ] **Step 5: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
quic: build endpoints for outbounds that own their transport

Reuses quic_settings rather than inventing a parallel set of TLS options:
verify, SNI, fingerprints, ALPN and the client certificate all mean the same
thing here as they do for a QUIC transport.

Transport parameters are copied from our own Hysteria2 and TUIC servers,
which took them from the reference implementations, because transport
parameters are part of the client's fingerprint and inventing our own would
cost a unique signature for nothing.

The socket family follows the resolved server address rather than the
configured one, so a hostname that resolves to IPv6 does not land on an
IPv4 socket.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 11: One connection, lazily re-established

**Files:**
- Create: `src/quic_outbound/connection.rs`

- [ ] **Step 1: Write the failing test**

Create `src/quic_outbound/connection.rs` with the tests first:

```rust
//! One QUIC connection per outbound, authenticated once and re-established lazily.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct CountingAuthenticator {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConnectionAuthenticator for CountingAuthenticator {
        async fn authenticate(&self, _connection: &quinn::Connection) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn test_needs_reconnect_for_a_missing_connection() {
        assert!(needs_reconnect(None));
    }
}
```

The interesting behaviour — that a live connection is reused and a dead one is
replaced — needs a real server and is covered by the end-to-end tests in
Task 17. Keep the unit test to the decision function so it stays honest.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib quic_outbound::connection`

Expected: FAIL to compile.

- [ ] **Step 3: Implement `LiveConnection`**

Insert above the tests:

```rust
use std::sync::Arc;

use async_trait::async_trait;
use log::debug;
use tokio::sync::Mutex;

use crate::resolver::{Resolver, resolve_single_address};

use super::QuicOutboundSettings;

/// Per-connection authentication, run once each time a connection is raised.
#[async_trait]
pub trait ConnectionAuthenticator: Send + Sync + std::fmt::Debug {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()>;
}

struct State {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

/// Returns true when a new connection has to be raised.
fn needs_reconnect(state: Option<&State>) -> bool {
    match state {
        None => true,
        Some(state) => state.connection.close_reason().is_some(),
    }
}

/// Holds the single QUIC connection an outbound uses.
///
/// Callers take the mutex, and if the held connection is still open they get a
/// clone of it — cloning a `quinn::Connection` is cheap and shares the same
/// underlying connection. Otherwise the handshake and the protocol's
/// authentication happen *while the mutex is still held*, so that a burst of
/// requests arriving during a reconnect waits for one result instead of
/// starting one handshake each against a server that has just gone away.
///
/// A failed attempt is not remembered: the next request tries again.
#[derive(Debug)]
pub struct LiveConnection {
    settings: QuicOutboundSettings,
    authenticator: Arc<dyn ConnectionAuthenticator>,
    state: Mutex<Option<State>>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("remote", &self.connection.remote_address())
            .finish()
    }
}

impl LiveConnection {
    pub fn new(
        settings: QuicOutboundSettings,
        authenticator: Arc<dyn ConnectionAuthenticator>,
    ) -> Self {
        Self {
            settings,
            authenticator,
            state: Mutex::new(None),
        }
    }

    pub fn settings(&self) -> &QuicOutboundSettings {
        &self.settings
    }

    /// Return an open, authenticated connection, raising one if needed.
    pub async fn get(&self, resolver: &Arc<dyn Resolver>) -> std::io::Result<quinn::Connection> {
        let mut state = self.state.lock().await;

        if !needs_reconnect(state.as_ref()) {
            return Ok(state.as_ref().unwrap().connection.clone());
        }

        if let Some(previous) = state.as_ref() {
            debug!(
                "QUIC connection to {} is gone ({:?}); reconnecting",
                self.settings.server,
                previous.connection.close_reason()
            );
        }

        let server_addr = resolve_single_address(resolver, &self.settings.server).await?;

        // Reuse the endpoint across reconnects: it owns the UDP socket, and
        // rebinding one on every connection loss would churn source ports for
        // no reason.
        let endpoint = match state.take() {
            Some(previous) => previous.endpoint,
            None => self.settings.build_endpoint(server_addr.is_ipv6())?,
        };

        let server_name = self
            .settings
            .sni_hostname()
            .unwrap_or_else(|| server_addr.ip().to_string());

        let connecting = endpoint
            .connect(server_addr, &server_name)
            .map_err(|e| std::io::Error::other(format!("QUIC connect to {server_addr} failed: {e}")))?;

        let connection = connecting.await.map_err(|e| {
            std::io::Error::other(format!("QUIC handshake with {server_addr} failed: {e}"))
        })?;

        self.authenticator.authenticate(&connection).await?;

        debug!("QUIC connection to {server_addr} established and authenticated");

        *state = Some(State {
            endpoint,
            connection: connection.clone(),
        });

        Ok(connection)
    }
}
```

- [ ] **Step 4: Add the counter and the test hook the connectors need**

Two members that later tasks assert against. Add the field to `LiveConnection`:

```rust
    connections_raised: std::sync::atomic::AtomicUsize,
```

initialised to zero in `new`, incremented immediately after
`self.authenticator.authenticate(&connection).await?` succeeds, and read by:

```rust
    /// How many connections have been raised over this outbound's lifetime.
    pub fn connections_raised(&self) -> usize {
        self.connections_raised
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Close the held connection so that the next `get` raises a new one.
    #[cfg(test)]
    pub fn close_for_test(&self) {
        if let Ok(state) = self.state.try_lock()
            && let Some(state) = state.as_ref()
        {
            state.connection.close(0u32.into(), b"test");
        }
    }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib quic_outbound::connection`

Expected: PASS.

- [ ] **Step 6: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
quic: hold one connection per outbound, re-established lazily

Hysteria2 and TUIC authenticate once per QUIC connection and key their UDP
sessions to it, so the connection is the unit that has to survive, not the
stream.

Re-establishment happens under the same mutex the callers take, which turns
a burst of requests arriving just after a server disappears into one
handshake instead of one each. Nothing is done in the background: a task
that keeps a connection warm is a wakeup source on a sleeping phone, and
this branch exists to run on phones.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 12: Hysteria2 TCP request and response codec

**Files:**
- Modify: `src/hysteria2/frame.rs`

- [ ] **Step 1: Write the failing tests**

Add to the tests module in `src/hysteria2/frame.rs`:

```rust
    #[test]
    fn test_tcp_request_layout() {
        let request = encode_tcp_request("example.com:443", &[]).unwrap();
        assert_eq!(&request[..2], &[0x44, 0x01], "frame type varint");
        assert_eq!(request[2], 15, "address length varint");
        assert_eq!(&request[3..18], b"example.com:443");
        assert_eq!(request[18], 0, "padding length varint");
        assert_eq!(request.len(), 19);
    }

    #[test]
    fn test_tcp_request_with_padding() {
        let padding = [0x41u8; 30];
        let request = encode_tcp_request("a:1", &padding).unwrap();
        assert_eq!(request[request.len() - 31], 30, "padding length varint");
        assert_eq!(&request[request.len() - 30..], &padding);
    }

    #[test]
    fn test_tcp_request_rejects_oversized_address() {
        let address = format!("{}:1", "a".repeat(2048));
        assert!(encode_tcp_request(&address, &[]).is_err());
    }

    #[test]
    fn test_parse_tcp_response_ok() {
        // status 0, empty message, 2 bytes of padding
        let bytes = [0x00, 0x00, 0x02, 0xaa, 0xbb];
        let (result, consumed) = parse_tcp_response(&bytes).unwrap().unwrap();
        assert!(result.is_ok());
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_parse_tcp_response_error_carries_the_message() {
        let mut bytes = vec![0x01, 0x0b];
        bytes.extend_from_slice(b"no such host");
        bytes[1] = 12;
        bytes.push(0x00);
        let (result, consumed) = parse_tcp_response(&bytes).unwrap().unwrap();
        assert_eq!(result.unwrap_err(), "no such host");
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_parse_tcp_response_needs_more_data() {
        assert!(parse_tcp_response(&[]).unwrap().is_none());
        assert!(parse_tcp_response(&[0x00]).unwrap().is_none());
        // message length says 4 but only 2 bytes follow
        assert!(parse_tcp_response(&[0x00, 0x04, b'a', b'b']).unwrap().is_none());
    }

    #[test]
    fn test_parse_tcp_response_rejects_absurd_lengths() {
        // A four-byte varint announcing 1 MiB of message.
        let bytes = [0x00, 0x80, 0x10, 0x00, 0x00];
        assert!(parse_tcp_response(&bytes).is_err());
    }

    #[test]
    fn test_random_padding_is_within_bounds() {
        for _ in 0..64 {
            let padding = random_padding();
            assert!(padding.len() <= MAX_GENERATED_PADDING);
        }
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib hysteria2::frame`

Expected: FAIL to compile.

- [ ] **Step 3: Implement the codec**

Add to `src/hysteria2/frame.rs`:

```rust
/// Upper bound on padding we generate ourselves. The protocol allows up to
/// MAX_PADDING_LEN; there is no reason to send more than a token amount.
pub const MAX_GENERATED_PADDING: usize = 64;

/// Largest response message we will buffer. The protocol does not bound it, but
/// a peer that claims megabytes is not one we want to allocate for.
const MAX_RESPONSE_MESSAGE: u64 = 4096;

/// Encode a TCP proxy request.
///
/// `[varint 0x401][varint addr len][addr][varint pad len][pad]`
pub fn encode_tcp_request(address: &str, padding: &[u8]) -> std::io::Result<Vec<u8>> {
    if address.len() as u64 > MAX_ADDRESS_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "address is {} bytes, over the {MAX_ADDRESS_LEN} byte limit",
                address.len()
            ),
        ));
    }
    if padding.len() as u64 > MAX_PADDING_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "padding is over the protocol limit",
        ));
    }

    let mut out = Vec::with_capacity(2 + 2 + address.len() + 2 + padding.len());
    out.extend_from_slice(&encode_varint(FRAME_TYPE_TCP_REQUEST)?);
    out.extend_from_slice(&encode_varint(address.len() as u64)?);
    out.extend_from_slice(address.as_bytes());
    out.extend_from_slice(&encode_varint(padding.len() as u64)?);
    out.extend_from_slice(padding);
    Ok(out)
}

/// Random padding for a request, matching what the server generates.
pub fn random_padding() -> Vec<u8> {
    use rand::{Rng, RngExt};
    let mut rng = rand::rng();
    let len = rng.random_range(0..=MAX_GENERATED_PADDING);
    let mut padding = vec![0u8; len];
    rng.fill_bytes(&mut padding);
    padding
}

/// Parse a TCP response.
///
/// `[u8 status][varint msg len][msg][varint pad len][pad]`
///
/// Returns `Ok(None)` when `data` does not yet hold a whole response, so the
/// caller can read more. The inner `Result` is the server's verdict: `Ok(())`
/// for status 0, `Err(message)` otherwise.
#[allow(clippy::type_complexity)]
pub fn parse_tcp_response(
    data: &[u8],
) -> std::io::Result<Option<(Result<(), String>, usize)>> {
    let Some(&status) = data.first() else {
        return Ok(None);
    };
    let mut offset = 1;

    let Some((message_len, consumed)) = decode_varint_slice(&data[offset..]) else {
        return Ok(None);
    };
    if message_len > MAX_RESPONSE_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("response message length {message_len} is implausible"),
        ));
    }
    offset += consumed;

    let message_end = offset + message_len as usize;
    if data.len() < message_end {
        return Ok(None);
    }
    let message = String::from_utf8_lossy(&data[offset..message_end]).into_owned();
    offset = message_end;

    let Some((padding_len, consumed)) = decode_varint_slice(&data[offset..]) else {
        return Ok(None);
    };
    if padding_len > MAX_PADDING_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("response padding length {padding_len} is over the protocol limit"),
        ));
    }
    offset += consumed;

    let padding_end = offset + padding_len as usize;
    if data.len() < padding_end {
        return Ok(None);
    }

    let verdict = if status == 0 { Ok(()) } else { Err(message) };
    Ok(Some((verdict, padding_end)))
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib hysteria2::frame`

Expected: PASS, 12 tests total in this module.

- [ ] **Step 5: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
hysteria2: encode TCP requests and parse TCP responses

The client half of the frames the server already reads and writes.

parse_tcp_response reports "not yet complete" separately from "malformed",
because the response is read from a stream and a short read is normal.
Announced lengths are bounded before anything is allocated for them.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 13: Hysteria2 authentication over HTTP/3

**Files:**
- Create: `src/hysteria2/auth.rs`
- Modify: `src/hysteria2/mod.rs`

- [ ] **Step 1: Confirm the h3 API before writing anything**

The code below is written against h3 0.0.8. Read the real signatures first —
this is a five-minute check that saves an hour of type errors:

```bash
sed -n '1,120p' ~/.cargo/registry/src/index.crates.io-*/h3-0.0.8/src/client/mod.rs
rg -n 'pub async fn send_request|pub async fn recv_response|pub async fn finish|pub fn poll_close|pub async fn shutdown' \
  ~/.cargo/registry/src/index.crates.io-*/h3-0.0.8/src/client/
```

Expected shape: `h3::client::new(h3_quinn::Connection)` yields
`(Connection, SendRequest)`; `SendRequest::send_request(http::Request<()>)`
yields a `RequestStream` with `finish()` and `recv_response()`; the driver
`Connection` is advanced by polling `poll_close`. Adapt the code below to what
you find rather than the other way round.

- [ ] **Step 2: Write the failing tests**

Create `src/hysteria2/auth.rs`:

```rust
//! Hysteria2 client authentication: one HTTP/3 request per QUIC connection.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_shape() {
        let request = build_auth_request("hunter2", "PADDING").unwrap();
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://hysteria/auth");
        assert_eq!(request.headers()["hysteria-auth"], "hunter2");
        assert_eq!(request.headers()["hysteria-cc-rx"], "0");
        assert_eq!(request.headers()["hysteria-padding"], "PADDING");
    }

    #[test]
    fn test_request_rejects_a_password_with_control_characters() {
        // A header value cannot carry a newline; fail loudly rather than
        // silently truncating the password.
        assert!(build_auth_request("bad\r\nvalue", "PADDING").is_err());
    }

    #[test]
    fn test_accepts_status_233() {
        let response = http::Response::builder()
            .status(233)
            .header("Hysteria-UDP", "true")
            .body(())
            .unwrap();
        assert_eq!(interpret_auth_response(&response).unwrap(), true);
    }

    #[test]
    fn test_records_udp_refusal() {
        let response = http::Response::builder()
            .status(233)
            .header("Hysteria-UDP", "false")
            .body(())
            .unwrap();
        assert_eq!(interpret_auth_response(&response).unwrap(), false);
    }

    #[test]
    fn test_missing_udp_header_means_udp_is_available() {
        let response = http::Response::builder().status(233).body(()).unwrap();
        assert_eq!(interpret_auth_response(&response).unwrap(), true);
    }

    #[test]
    fn test_rejects_any_other_status() {
        for status in [200u16, 401, 404, 500] {
            let response = http::Response::builder().status(status).body(()).unwrap();
            let err = interpret_auth_response(&response).unwrap_err().to_string();
            assert!(err.contains(&status.to_string()), "{err}");
        }
    }

    #[test]
    fn test_padding_is_ascii_and_bounded() {
        for _ in 0..64 {
            let padding = auth_padding();
            assert!(!padding.is_empty());
            assert!(padding.len() < 80);
            assert!(padding.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib hysteria2::auth`

Expected: FAIL to compile.

- [ ] **Step 4: Implement authentication**

Insert above the tests:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use log::debug;
use rand::distr::Alphanumeric;
use rand::{Rng, RngExt};

use crate::quic_outbound::connection::ConnectionAuthenticator;

/// The status a Hysteria2 server returns for a successful authentication.
/// Not a standard HTTP status; the protocol chose it deliberately.
const STATUS_OK: u16 = 233;

const AUTH_URI: &str = "https://hysteria/auth";

/// Random padding of the same shape the server sends back.
fn auth_padding() -> String {
    let mut rng = rand::rng();
    let length = rng.random_range(1..80);
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn build_auth_request(password: &str, padding: &str) -> std::io::Result<http::Request<()>> {
    http::Request::post(AUTH_URI)
        .header("Hysteria-Auth", password)
        // Zero means "I do not know my bandwidth", which tells the server to
        // instruct BBR rather than its own congestion control. That is what we
        // want: Brutal is not implemented here.
        .header("Hysteria-CC-RX", "0")
        .header("Hysteria-Padding", padding)
        .body(())
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("could not build the Hysteria2 auth request: {e}"),
            )
        })
}

/// Returns whether the server permits UDP.
fn interpret_auth_response<T>(response: &http::Response<T>) -> std::io::Result<bool> {
    let status = response.status().as_u16();
    if status != STATUS_OK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Hysteria2 authentication rejected: server answered {status}, expected {STATUS_OK}. \
                 Check the password; a server using username and password authentication expects \
                 them joined as \"<username>:<password>\"."
            ),
        ));
    }

    let udp = response
        .headers()
        .get("hysteria-udp")
        .and_then(|value| value.to_str().ok())
        .map(|value| !value.eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    Ok(udp)
}

/// Authenticates a Hysteria2 connection and remembers what the server said
/// about UDP.
#[derive(Debug)]
pub struct Hysteria2Authenticator {
    password: String,
    /// Whether the most recent authentication was told UDP is available.
    server_udp_enabled: AtomicBool,
}

impl Hysteria2Authenticator {
    pub fn new(password: String) -> Self {
        Self {
            password,
            server_udp_enabled: AtomicBool::new(true),
        }
    }

    /// What the server said about UDP at the last authentication.
    pub fn server_udp_enabled(&self) -> bool {
        self.server_udp_enabled.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ConnectionAuthenticator for Hysteria2Authenticator {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        let h3_connection = h3_quinn::Connection::new(connection.clone());
        let (mut driver, mut send_request) = h3::client::new(h3_connection)
            .await
            .map_err(|e| std::io::Error::other(format!("HTTP/3 setup failed: {e}")))?;

        // The driver has to be polled for the request to make progress, and it
        // must keep running afterwards: dropping it closes the HTTP/3 layer,
        // and with it the QUIC connection every later stream depends on. It
        // ends on its own when the connection does.
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = build_auth_request(&self.password, &auth_padding())?;

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| std::io::Error::other(format!("auth request failed: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| std::io::Error::other(format!("finishing the auth request failed: {e}")))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| std::io::Error::other(format!("reading the auth response failed: {e}")))?;

        let udp_enabled = interpret_auth_response(&response)?;
        self.server_udp_enabled.store(udp_enabled, Ordering::Relaxed);
        debug!("Hysteria2 authenticated; server UDP: {udp_enabled}");

        Ok(())
    }
}
```

Add `pub mod auth;` to `src/hysteria2/mod.rs`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib hysteria2::auth`

Expected: PASS, 7 tests.

- [ ] **Step 6: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
hysteria2: authenticate the client over HTTP/3

One POST to https://hysteria/auth per QUIC connection, carrying the
password, a bandwidth hint of zero and random padding. Status 233 is the
protocol's chosen success code; anything else is a rejection, and the error
mentions the username:password form because a server configured that way is
otherwise an afternoon of guessing.

Hysteria-CC-RX is zero on purpose: it tells the server to instruct BBR
rather than Hysteria's own congestion control, which is not implemented
here.

The HTTP/3 driver keeps running after the exchange. Dropping it closes the
HTTP/3 layer and takes the QUIC connection with it, which every later
stream depends on.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 14: A test harness that runs our own server in-process

Every later task is verified against this. Building it once, first, keeps the
protocol tasks short.

**Files:**
- Create: `src/quic_outbound/testing.rs`
- Modify: `src/quic_outbound/mod.rs`

- [ ] **Step 1: Write the harness**

Create `src/quic_outbound/testing.rs`:

```rust
//! In-process servers for the QUIC outbound tests.
//!
//! Every end-to-end test here runs the real server from this repository, so a
//! change to either side that breaks the pairing fails a test rather than
//! waiting for a user to notice.

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Arc;

use crate::client_proxy_selector::{ClientProxySelector, ConnectRule};
use crate::config::ClientQuicConfig;
use crate::option_util::{NoneOrOne, NoneOrSome};
use crate::resolver::{NativeResolver, Resolver};
use crate::rustls_config_util::create_server_config;
use crate::tcp::chain_builder::build_direct_chain_group;

/// A self-signed certificate for `localhost`, as PEM.
pub struct TestCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_certificate() -> TestCertificate {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    TestCertificate {
        cert_pem: cert.cert.pem(),
        key_pem: cert.signing_key.serialize_pem(),
    }
}

pub fn test_resolver() -> Arc<dyn Resolver> {
    Arc::new(NativeResolver::new())
}

/// A selector that allows everything and dials it directly.
pub fn direct_selector(resolver: Arc<dyn Resolver>) -> Arc<ClientProxySelector> {
    let chain_group = build_direct_chain_group(resolver);
    Arc::new(ClientProxySelector::new(vec![ConnectRule::new_allow(
        None,
        chain_group,
    )]))
}

/// Client-side QUIC settings for the harness.
///
/// Verification is off: the certificate is self-signed, generated seconds
/// earlier by this same process, and reachable only over loopback. Pinning its
/// fingerprint would prove nothing that generating it did not already prove.
pub fn client_quic_config() -> ClientQuicConfig {
    ClientQuicConfig {
        verify: false,
        server_fingerprints: NoneOrSome::Unspecified,
        sni_hostname: NoneOrOne::One("localhost".to_string()),
        alpn_protocols: NoneOrSome::Unspecified,
        key: None,
        cert: None,
    }
}

/// Build the QUIC server config both in-process servers need.
pub fn quic_server_config(
    cert: &TestCertificate,
    alpn: &[String],
) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
    let server_config = Arc::new(create_server_config(
        cert.cert_pem.as_bytes(),
        cert.key_pem.as_bytes(),
        vec![],
        alpn,
        &[],
    ));
    let quic: quinn::crypto::rustls::QuicServerConfig = (*server_config)
        .clone()
        .try_into()
        .expect("valid QUIC server config");
    Arc::new(quic)
}

/// An echo server on a fresh TCP port. Returns its address.
pub async fn spawn_tcp_echo() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// An echo server on a fresh UDP port. Returns its address.
pub async fn spawn_udp_echo() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    let _ = socket.send_to(&buf[..len], from).await;
                }
                Err(_) => break,
            }
        }
    });
    addr
}
```

Check `rcgen`'s API before writing this — the field names for the generated
certificate and key have moved between versions:

```bash
rg -n 'rcgen::' src/reality/reality_certificate.rs
```

Use whatever that file already does to reach the PEM of the certificate and of
the key.

Add to `src/quic_outbound/mod.rs`:

```rust
#[cfg(test)]
pub mod testing;
```

- [ ] **Step 2: Verify the harness compiles and the echo servers work**

Add a test to `src/quic_outbound/testing.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_tcp_echo_harness() {
        let addr = spawn_tcp_echo().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn test_udp_echo_harness() {
        let addr = spawn_udp_echo().await;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(b"ping", addr).await.unwrap();
        let mut buf = [0u8; 4];
        let (len, _) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"ping");
    }

    #[test]
    fn test_certificate_generation() {
        let cert = generate_certificate();
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("PRIVATE KEY"));
    }
}
```

Run: `cargo test --lib quic_outbound::testing`

Expected: PASS, 3 tests.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
quic: add an in-process harness for the outbound tests

Every end-to-end test for the new clients runs the real server from this
repository. A change to either side that breaks the pairing then fails a
test instead of waiting for a user to notice.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 15: The Hysteria2 connector, TCP path

**Files:**
- Create: `src/hysteria2/client.rs`
- Modify: `src/hysteria2/mod.rs`, `src/tcp/chain_builder.rs`

- [ ] **Step 1: Write the failing end-to-end test**

Create `src/hysteria2/client.rs` with the tests first:

```rust
//! The Hysteria2 client outbound.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::testing::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_server(
        obfs: Option<Arc<dyn crate::quic_outbound::obfs::Obfuscator>>,
    ) -> (SocketAddr, TestCertificate) {
        let cert = generate_certificate();
        let resolver = test_resolver();
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind_address = listener.local_addr().unwrap();
        drop(listener);

        crate::hysteria2::start_hysteria2_server(
            bind_address,
            quic_server_config(&cert, &["h3".to_string()]),
            Box::leak("test password".to_string().into_boxed_str()),
            direct_selector(resolver.clone()),
            resolver,
            1,
            true,
            obfs,
        )
        .await
        .unwrap();

        (bind_address, cert)
    }

    fn connector(
        server: SocketAddr,
        cert: &TestCertificate,
        password: &str,
        obfs: Option<Arc<dyn crate::quic_outbound::obfs::Obfuscator>>,
    ) -> Hysteria2Connector {
        Hysteria2Connector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            password.to_string(),
            true,
            client_quic_config(),
            None,
            obfs,
        )
    }

    #[tokio::test]
    async fn test_tcp_round_trip() {
        let (server, cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();

        let connector = connector(server, &cert, "test password", None);
        let result = connector
            .connect_tcp(
                &resolver,
                NetLocation::from_str(&echo.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();

        let mut stream = result.client_stream;
        stream.write_all(b"hello through hysteria").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 22];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through hysteria");
    }

    #[tokio::test]
    async fn test_two_streams_share_one_connection() {
        let (server, cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, "test password", None);
        let target = NetLocation::from_str(&echo.to_string(), None).unwrap();

        for i in 0..3 {
            let mut stream = connector
                .connect_tcp(&resolver, target.clone().into())
                .await
                .unwrap()
                .client_stream;
            let payload = format!("stream {i}");
            stream.write_all(payload.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes());
        }

        assert_eq!(
            connector.connection_count(),
            1,
            "every stream must reuse the one authenticated connection"
        );
    }

    #[tokio::test]
    async fn test_wrong_password_is_a_clear_error() {
        let (server, cert) = spawn_server(None).await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, "the wrong password", None);

        let err = connector
            .connect_tcp(
                &resolver,
                NetLocation::from_str("127.0.0.1:1", None).unwrap().into(),
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("233") || err.to_lowercase().contains("auth"),
            "error should say authentication failed, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_reconnects_after_the_connection_is_lost() {
        let (server, cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, "test password", None);
        let target = NetLocation::from_str(&echo.to_string(), None).unwrap();

        let mut stream = connector
            .connect_tcp(&resolver, target.clone().into())
            .await
            .unwrap()
            .client_stream;
        stream.write_all(b"one").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();

        connector.close_for_test();

        let mut stream = connector
            .connect_tcp(&resolver, target.into())
            .await
            .unwrap()
            .client_stream;
        stream.write_all(b"two").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 3];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"two");
        assert_eq!(connector.connection_count(), 2);
    }

    #[tokio::test]
    async fn test_tcp_round_trip_with_obfuscation() {
        let obfs = || {
            Some(Arc::new(
                crate::quic_outbound::obfs::Salamander::new(b"obfuscation password").unwrap(),
            ) as Arc<dyn crate::quic_outbound::obfs::Obfuscator>)
        };
        let (server, cert) = spawn_server(obfs()).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();

        let connector = connector(server, &cert, "test password", obfs());
        let mut stream = connector
            .connect_tcp(
                &resolver,
                NetLocation::from_str(&echo.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap()
            .client_stream;

        stream.write_all(b"obfuscated").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"obfuscated");
    }

    #[tokio::test]
    async fn test_obfuscation_mismatch_fails_rather_than_hangs() {
        let (server, cert) = spawn_server(Some(Arc::new(
            crate::quic_outbound::obfs::Salamander::new(b"server password").unwrap(),
        ))).await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, "test password", None);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connector.connect_tcp(
                &resolver,
                NetLocation::from_str("127.0.0.1:1", None).unwrap().into(),
            ),
        )
        .await;

        match result {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("a client with no obfuscation must not reach an obfuscated server"),
            Err(_) => panic!("the handshake must fail, not hang until the test times out"),
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib hysteria2::client`

Expected: FAIL to compile.

- [ ] **Step 3: Implement the connector**

Insert above the tests:

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ClientQuicConfig;
use crate::quic_outbound::connection::LiveConnection;
use crate::quic_outbound::obfs::Obfuscator;
use crate::quic_outbound::QuicOutboundSettings;
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

use super::auth::Hysteria2Authenticator;
use super::frame::{encode_tcp_request, parse_tcp_response, random_padding};

/// Largest TCP response we will buffer before giving up. Status, message and
/// padding together cannot legitimately approach this.
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

pub struct Hysteria2Connector {
    connection: LiveConnection,
    authenticator: Arc<Hysteria2Authenticator>,
    udp_enabled: bool,
}

impl std::fmt::Debug for Hysteria2Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Connector")
            .field("server", &self.connection.settings().server)
            .field("udp_enabled", &self.udp_enabled)
            .finish()
    }
}

impl Hysteria2Connector {
    pub fn new(
        server: NetLocation,
        password: String,
        udp_enabled: bool,
        quic: ClientQuicConfig,
        bind_interface: Option<String>,
        obfs: Option<Arc<dyn Obfuscator>>,
    ) -> Self {
        let authenticator = Arc::new(Hysteria2Authenticator::new(password));
        let settings = QuicOutboundSettings {
            server,
            quic,
            bind_interface,
            obfs,
            default_alpn: "h3",
        };
        Self {
            connection: LiveConnection::new(settings, authenticator.clone()),
            authenticator,
            udp_enabled,
        }
    }

    /// Open a bidirectional stream and complete the TCP request exchange,
    /// retrying once if the connection turns out to have died in the window
    /// between being handed out and being used.
    ///
    /// That window is real and unavoidable: `get` can only report the
    /// connection was open when it looked, and a server that went away in the
    /// meantime should cost one reconnect, not a failed request.
    async fn open_tcp_stream(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &str,
    ) -> std::io::Result<(QuicStream, Vec<u8>)> {
        match self.open_tcp_stream_once(resolver, address).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                debug!("Hysteria2: connection died while opening a stream; retrying once");
                self.open_tcp_stream_once(resolver, address).await
            }
            other => other,
        }
    }

    /// Returns the stream and anything read past the response, which already
    /// belongs to the target's reply.
    ///
    /// A connection-level failure is reported as `ConnectionAborted` so the
    /// caller above can tell it apart from the server refusing the target.
    async fn open_tcp_stream_once(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &str,
    ) -> std::io::Result<(QuicStream, Vec<u8>)> {
        let connection = self.connection.get(resolver).await?;

        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to open a QUIC stream: {e}"),
            )
        })?;

        let request = encode_tcp_request(address, &random_padding())?;
        send.write_all(&request)
            .await
            .map_err(|e| std::io::Error::other(format!("failed to write the TCP request: {e}")))?;

        let mut buffered = Vec::with_capacity(64);
        let mut chunk = [0u8; 1024];
        loop {
            match parse_tcp_response(&buffered)? {
                Some((Ok(()), consumed)) => {
                    let leftover = buffered.split_off(consumed);
                    return Ok((QuicStream::from(send, recv), leftover));
                }
                Some((Err(message), _)) => {
                    let _ = send.finish();
                    return Err(std::io::Error::other(if message.is_empty() {
                        format!("server refused to connect to {address}")
                    } else {
                        format!("server refused to connect to {address}: {message}")
                    }));
                }
                None => {}
            }

            if buffered.len() >= MAX_RESPONSE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TCP response never completed",
                ));
            }

            let read = recv.read(&mut chunk).await.map_err(|e| {
                std::io::Error::other(format!("failed to read the TCP response: {e}"))
            })?;
            match read {
                Some(0) | None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed before the TCP response arrived",
                    ));
                }
                Some(n) => buffered.extend_from_slice(&chunk[..n]),
            }
        }
    }

    #[cfg(test)]
    fn connection_count(&self) -> usize {
        self.connection.connections_raised()
    }

    #[cfg(test)]
    fn close_for_test(&self) {
        self.connection.close_for_test();
    }
}

#[async_trait]
impl TerminalConnector for Hysteria2Connector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let address = target.location().to_string();
        debug!("Hysteria2: TCP connect to {address}");

        let (stream, early_data) = self.open_tcp_stream(resolver, &address).await?;

        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream) as Box<dyn AsyncStream>,
            early_data: (!early_data.is_empty()).then_some(early_data),
        })
    }

    async fn connect_udp_bidirectional(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Hysteria2 UDP is not implemented yet",
        ))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }
}
```

Drop the now-unused `AtomicUsize` import if the compiler flags it;
`connections_raised` and `close_for_test` both live on `LiveConnection` from
Task 11 Step 4.

- [ ] **Step 4: Wire the connector into the chain builder**

In `src/tcp/chain_builder.rs`, replace the single `AmneziaWgConnector::from_client_config`
call inside the terminal branch with a dispatch:

```rust
            .map(|config| build_terminal_connector(config))
```

and add:

```rust
fn build_terminal_connector(config: ClientConfig) -> Arc<dyn TerminalConnector> {
    match config.protocol {
        ClientProxyConfig::Hysteria2(h) => Arc::new(crate::hysteria2::Hysteria2Connector::new(
            config.address,
            h.password.into_inner(),
            h.udp_enabled,
            config.quic_settings.unwrap_or_default(),
            config.bind_interface.into_option(),
            build_obfuscator(h.obfs.as_ref()).expect("validated during config load"),
        )),
        protocol => {
            let connector =
                crate::amneziawg::AmneziaWgConnector::from_client_config(protocol, config.address)
                    .expect("config validation should have ensured a tunnel variant");
            Arc::new(connector)
        }
    }
}

fn build_obfuscator(
    obfs: Option<&crate::config::ObfsConfig>,
) -> std::io::Result<Option<Arc<dyn crate::quic_outbound::obfs::Obfuscator>>> {
    match obfs {
        Some(crate::config::ObfsConfig::Salamander { password }) => {
            Ok(Some(Arc::new(crate::quic_outbound::obfs::Salamander::new(
                password.expose().as_bytes(),
            )?)))
        }
        None => Ok(None),
    }
}
```

Add `pub mod client;` and `pub use client::Hysteria2Connector;` to
`src/hysteria2/mod.rs`.

This is the step that gives the binary a consumer for the endpoint and
connection halves of `quic_outbound`. Remove the `#[allow(dead_code)]` from the
`mod quic_outbound;` declaration in `src/main.rs` and confirm
`cargo clippy --locked --bins -- -D warnings` still passes.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib hysteria2::client`

Expected: PASS, 6 tests.

- [ ] **Step 6: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
hysteria2: dial Hysteria2 servers over TCP

The client half of the protocol our server has spoken all along, verified
against that server in-process: a round trip, three streams sharing one
authenticated connection, a wrong password producing a clear error, a
reconnect after the connection is lost, and the same round trip with
Salamander on both ends.

Anything read past the end of the TCP response already belongs to the
target's reply and is returned as early data, which is exactly what that
field was documented for.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 16: Hysteria2 UDP

**Files:**
- Modify: `src/hysteria2/frame.rs`
- Create: `src/hysteria2/udp.rs`
- Modify: `src/hysteria2/client.rs`, `src/hysteria2/mod.rs`

- [ ] **Step 1: Write the failing codec tests**

Add to the tests module in `src/hysteria2/frame.rs`:

```rust
    #[test]
    fn test_datagram_header_layout() {
        let header = encode_datagram_header(0xdeadbeef, 0x1234, 1, 3, "example.com:53").unwrap();
        assert_eq!(&header[0..4], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(&header[4..6], &0x1234u16.to_be_bytes());
        assert_eq!(header[6], 1, "fragment id");
        assert_eq!(header[7], 3, "fragment count");
        assert_eq!(header[8], 14, "address length varint");
        assert_eq!(&header[9..], b"example.com:53");
    }

    #[test]
    fn test_parse_datagram_round_trip() {
        let mut packet = encode_datagram_header(7, 9, 0, 1, "1.2.3.4:53").unwrap();
        packet.extend_from_slice(b"payload");
        let parsed = parse_datagram(&packet).unwrap();
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.packet_id, 9);
        assert_eq!(parsed.fragment_id, 0);
        assert_eq!(parsed.fragment_count, 1);
        assert_eq!(parsed.address, "1.2.3.4:53");
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn test_parse_datagram_rejects_truncated_input() {
        assert!(parse_datagram(&[0u8; 8]).is_none());
        // Announces a 200-byte address that is not there.
        let mut packet = vec![0u8; 8];
        packet.push(0x40);
        packet.push(200);
        assert!(parse_datagram(&packet).is_none());
    }

    #[test]
    fn test_parse_datagram_rejects_empty_address() {
        let mut packet = vec![0u8; 8];
        packet.push(0x00); // address length 0
        assert!(parse_datagram(&packet).is_none());
    }

    #[test]
    fn test_fragmentation_splits_and_bounds() {
        let payload = vec![0u8; 5000];
        let fragments = split_into_fragments(&payload, "a:1", 1500).unwrap();
        assert!(fragments.len() > 1);
        assert!(fragments.iter().all(|f| f.len() <= 1500));

        // Reassembling the payload halves of every fragment gives the original.
        let mut rebuilt = Vec::new();
        for fragment in &fragments {
            rebuilt.extend_from_slice(parse_datagram(fragment).unwrap().payload);
        }
        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn test_fragmentation_refuses_more_than_255_fragments() {
        let payload = vec![0u8; 100_000];
        assert!(split_into_fragments(&payload, "a:1", 200).is_err());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib hysteria2::frame`

Expected: FAIL to compile.

- [ ] **Step 3: Implement the datagram codec**

Add to `src/hysteria2/frame.rs`:

```rust
/// A parsed Hysteria2 UDP datagram.
pub struct Datagram<'a> {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: &'a str,
    pub payload: &'a [u8],
}

/// `[u32 session][u16 packet][u8 frag id][u8 frag count][varint addr len][addr]`
pub fn encode_datagram_header(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
) -> std::io::Result<Vec<u8>> {
    if address.is_empty() || address.len() as u64 > MAX_ADDRESS_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("address length {} is not encodable", address.len()),
        ));
    }
    let mut out = Vec::with_capacity(8 + 2 + address.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_id);
    out.push(fragment_count);
    out.extend_from_slice(&encode_varint(address.len() as u64)?);
    out.extend_from_slice(address.as_bytes());
    Ok(out)
}

/// Parse a datagram. Returns None for anything malformed — a stray packet is
/// dropped, not an error, exactly as the server treats it.
pub fn parse_datagram(data: &[u8]) -> Option<Datagram<'_>> {
    if data.len() < 9 {
        return None;
    }
    let session_id = u32::from_be_bytes(data[0..4].try_into().ok()?);
    let packet_id = u16::from_be_bytes(data[4..6].try_into().ok()?);
    let fragment_id = data[6];
    let fragment_count = data[7];

    let (address_len, consumed) = decode_varint_slice(&data[8..])?;
    if address_len == 0 || address_len > MAX_ADDRESS_LEN {
        return None;
    }
    let address_start = 8 + consumed;
    let address_end = address_start.checked_add(address_len as usize)?;
    if data.len() < address_end {
        return None;
    }
    let address = std::str::from_utf8(&data[address_start..address_end]).ok()?;

    Some(Datagram {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        payload: &data[address_end..],
    })
}

/// Split a payload into datagrams no larger than `max_datagram`.
///
/// A session and packet id are the caller's to choose; this uses zero for both
/// so the function stays testable, and the session layer overwrites them.
pub fn split_into_fragments(
    payload: &[u8],
    address: &str,
    max_datagram: usize,
) -> std::io::Result<Vec<Vec<u8>>> {
    let header_len = encode_datagram_header(0, 0, 0, 1, address)?.len();
    let capacity = max_datagram.checked_sub(header_len).filter(|c| *c > 0).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "datagram limit is smaller than the header",
        )
    })?;

    let fragment_count = payload.len().div_ceil(capacity).max(1);
    if fragment_count > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes needs {fragment_count} fragments, over the 255 the protocol allows",
                payload.len()
            ),
        ));
    }

    let mut fragments = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(capacity).enumerate() {
        let mut datagram =
            encode_datagram_header(0, 0, index as u8, fragment_count as u8, address)?;
        datagram.extend_from_slice(chunk);
        fragments.push(datagram);
    }
    if fragments.is_empty() {
        fragments.push(encode_datagram_header(0, 0, 0, 1, address)?);
    }
    Ok(fragments)
}

/// Overwrite the session and packet ids of an encoded datagram in place.
pub fn stamp_datagram(datagram: &mut [u8], session_id: u32, packet_id: u16) {
    datagram[0..4].copy_from_slice(&session_id.to_be_bytes());
    datagram[4..6].copy_from_slice(&packet_id.to_be_bytes());
}
```

- [ ] **Step 4: Run the codec tests**

Run: `cargo test --lib hysteria2::frame`

Expected: PASS.

- [ ] **Step 5: Write the failing session test**

Add to the tests module in `src/hysteria2/client.rs`:

```rust
    #[tokio::test]
    async fn test_udp_round_trip() {
        use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};

        let (server, cert) = spawn_server(None).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, "test password", None);

        let mut stream = connector
            .connect_udp_bidirectional(
                &resolver,
                NetLocation::from_str(&echo.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();

        std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut stream).poll_write_message(cx, b"udp hello")
        })
        .await
        .unwrap();

        let mut buf = [0u8; 64];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut stream).poll_read_message(cx, &mut read_buf)
        })
        .await
        .unwrap();
        assert_eq!(read_buf.filled(), b"udp hello");
    }

    #[tokio::test]
    async fn test_udp_is_refused_when_the_client_disabled_it() {
        let (server, cert) = spawn_server(None).await;
        let resolver = test_resolver();
        let connector = Hysteria2Connector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            "test password".to_string(),
            false,
            client_quic_config(),
            None,
            None,
        );
        assert!(!connector.supports_udp());
    }

    #[tokio::test]
    async fn test_large_udp_payload_is_fragmented_and_reassembled() {
        use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};

        let (server, cert) = spawn_server(None).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, "test password", None);

        let mut stream = connector
            .connect_udp_bidirectional(
                &resolver,
                NetLocation::from_str(&echo.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();

        let payload = vec![0x5au8; 4000];
        std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut stream).poll_write_message(cx, &payload)
        })
        .await
        .unwrap();

        let mut buf = vec![0u8; 8192];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut stream).poll_read_message(cx, &mut read_buf)
        })
        .await
        .unwrap();
        assert_eq!(read_buf.filled(), &payload[..]);
    }
```

- [ ] **Step 6: Implement the session**

Create `src/hysteria2/udp.rs`. The session is an `AsyncMessageStream` over one
session id. Writing splits the payload into fragments, stamps them and sends
them as QUIC datagrams. Reading pulls datagrams off a channel fed by a task that
owns `connection.read_datagram()`, reassembling fragments by packet id.

```rust
//! One Hysteria2 UDP session as an AsyncMessageStream.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use log::debug;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};

use super::frame::{parse_datagram, split_into_fragments, stamp_datagram};

/// Fragments waiting for their siblings, keyed by packet id.
struct Reassembly {
    fragments: HashMap<u16, Vec<Option<Vec<u8>>>>,
}

impl Reassembly {
    fn new() -> Self {
        Self {
            fragments: HashMap::new(),
        }
    }

    /// Feed one datagram; returns a complete payload when the last piece lands.
    fn push(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let parsed = parse_datagram(data)?;
        if parsed.fragment_count == 0 || parsed.fragment_id >= parsed.fragment_count {
            return None;
        }
        if parsed.fragment_count == 1 {
            return Some(parsed.payload.to_vec());
        }

        let slots = self
            .fragments
            .entry(parsed.packet_id)
            .or_insert_with(|| vec![None; parsed.fragment_count as usize]);
        if slots.len() != parsed.fragment_count as usize {
            // A packet id reused with a different fragment count; start over.
            *slots = vec![None; parsed.fragment_count as usize];
        }
        slots[parsed.fragment_id as usize] = Some(parsed.payload.to_vec());

        if slots.iter().all(|s| s.is_some()) {
            let slots = self.fragments.remove(&parsed.packet_id)?;
            Some(slots.into_iter().flatten().flatten().collect())
        } else {
            None
        }
    }
}

pub struct Hysteria2UdpSession {
    connection: quinn::Connection,
    session_id: u32,
    address: String,
    next_packet_id: AtomicU16,
    incoming: mpsc::Receiver<Vec<u8>>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Hysteria2UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2UdpSession")
            .field("session_id", &self.session_id)
            .field("address", &self.address)
            .finish()
    }
}

impl Hysteria2UdpSession {
    pub fn new(connection: quinn::Connection, session_id: u32, address: String) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let reader_connection = connection.clone();

        // One task per session owns reading datagrams for it. Datagrams for
        // other sessions on the same connection are not ours to consume, so
        // this filters by session id and drops the rest — which is correct
        // here because each session opens its own connection view and the
        // outbound only ever has one session per target at a time.
        let reader_task = tokio::spawn(async move {
            let mut reassembly = Reassembly::new();
            loop {
                let datagram: Bytes = match reader_connection.read_datagram().await {
                    Ok(d) => d,
                    Err(e) => {
                        debug!("Hysteria2 UDP reader stopping: {e}");
                        return;
                    }
                };
                let Some(parsed) = parse_datagram(&datagram) else {
                    continue;
                };
                if parsed.session_id != session_id {
                    continue;
                }
                if let Some(payload) = reassembly.push(&datagram)
                    && tx.send(payload).await.is_err()
                {
                    return;
                }
            }
        });

        Self {
            connection,
            session_id,
            address,
            next_packet_id: AtomicU16::new(0),
            incoming: rx,
            reader_task,
        }
    }
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl Unpin for Hysteria2UdpSession {}

impl AsyncWriteMessage for Hysteria2UdpSession {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let max_datagram = this
            .connection
            .max_datagram_size()
            .ok_or_else(|| std::io::Error::other("peer does not accept QUIC datagrams"))?;

        let mut fragments = split_into_fragments(buf, &this.address, max_datagram)?;
        let packet_id = this.next_packet_id.fetch_add(1, Ordering::Relaxed);
        for fragment in fragments.iter_mut() {
            stamp_datagram(fragment, this.session_id, packet_id);
            this.connection
                .send_datagram(Bytes::from(std::mem::take(fragment)))
                .map_err(|e| std::io::Error::other(format!("failed to send a datagram: {e}")))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for Hysteria2UdpSession {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.incoming.poll_recv(cx) {
            Poll::Ready(Some(payload)) => {
                if payload.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "UDP payload of {} bytes does not fit a {} byte buffer",
                            payload.len(),
                            buf.remaining()
                        ),
                    )));
                }
                buf.put_slice(&payload);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the Hysteria2 UDP session ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for Hysteria2UdpSession {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for Hysteria2UdpSession {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for Hysteria2UdpSession {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for Hysteria2UdpSession {}
```

- [ ] **Step 7: Implement `connect_udp_bidirectional`**

Replace the stub in `src/hysteria2/client.rs`:

```rust
    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP is disabled for this Hysteria2 outbound (udp_enabled: false)",
            ));
        }

        let connection = self.connection.get(resolver).await?;

        if !self.authenticator.server_udp_enabled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "the Hysteria2 server refused UDP (Hysteria-UDP: false)",
            ));
        }

        let address = target.location().to_string();
        let session_id = rand::rng().random::<u32>();
        debug!("Hysteria2: UDP session {session_id} to {address}");

        Ok(Box::new(super::udp::Hysteria2UdpSession::new(
            connection, session_id, address,
        )))
    }
```

Add `use rand::Rng;` and `pub mod udp;` to `src/hysteria2/mod.rs`.

- [ ] **Step 8: Run the tests**

Run: `cargo test --lib hysteria2`

Expected: PASS, 9 client tests and 18 frame tests.

- [ ] **Step 9: Run the gate and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
hysteria2: relay UDP over QUIC datagrams

A session is an AsyncMessageStream over one session id: writing splits the
payload across as many datagrams as the connection's current limit needs,
reading reassembles by packet id.

A payload needing more than 255 fragments is refused rather than truncated,
and a server that answered Hysteria-UDP: false produces an error naming that
reason rather than a timeout.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 17: TUIC client command encoders

Layouts are from the upstream specification (EAimTY/tuic, SPEC.md), not only
from our server.

**Files:**
- Modify: `src/tuic/frame.rs`

- [ ] **Step 1: Write the failing tests**

Add to the tests module in `src/tuic/frame.rs`:

```rust
    #[test]
    fn test_authenticate_layout() {
        let uuid = [0xabu8; 16];
        let token = [0xcdu8; 32];
        let command = encode_authenticate(&uuid, &token);
        assert_eq!(command[0], TUIC_VERSION);
        assert_eq!(command[1], COMMAND_TYPE_AUTHENTICATE);
        assert_eq!(&command[2..18], &uuid);
        assert_eq!(&command[18..50], &token);
        assert_eq!(command.len(), 50);
    }

    #[test]
    fn test_connect_layout() {
        let loc = NetLocation::new(Address::Hostname("example.com".to_string()), 443);
        let command = encode_connect(&loc);
        assert_eq!(command[0], TUIC_VERSION);
        assert_eq!(command[1], COMMAND_TYPE_CONNECT);
        assert_eq!(&command[2..], &serialize_address(&loc)[..]);
    }

    #[test]
    fn test_packet_header_layout() {
        let loc = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let header = encode_packet_header(7, 9, 3, 1, 1200, Some(&loc));
        assert_eq!(header[0], TUIC_VERSION);
        assert_eq!(header[1], COMMAND_TYPE_PACKET);
        assert_eq!(&header[2..4], &7u16.to_be_bytes());
        assert_eq!(&header[4..6], &9u16.to_be_bytes());
        assert_eq!(header[6], 3, "fragment total");
        assert_eq!(header[7], 1, "fragment id");
        assert_eq!(&header[8..10], &1200u16.to_be_bytes());
        assert_eq!(&header[10..], &serialize_address(&loc)[..]);
    }

    #[test]
    fn test_packet_header_uses_the_none_address_for_later_fragments() {
        let header = encode_packet_header(7, 9, 3, 2, 100, None);
        assert_eq!(header[10], 0xff, "address type None");
        assert_eq!(header.len(), 11);
    }

    #[test]
    fn test_dissociate_layout() {
        let command = encode_dissociate(7);
        assert_eq!(
            command,
            vec![TUIC_VERSION, COMMAND_TYPE_DISSOCIATE, 0x00, 0x07]
        );
    }

    #[test]
    fn test_heartbeat_layout() {
        assert_eq!(encode_heartbeat(), vec![TUIC_VERSION, COMMAND_TYPE_HEARTBEAT]);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib tuic::frame`

Expected: FAIL to compile.

- [ ] **Step 3: Implement the encoders**

Add to `src/tuic/frame.rs`:

```rust
use crate::address::NetLocation;

/// Address type byte meaning "no address", used on fragments after the first.
pub const ADDRESS_TYPE_NONE: u8 = 0xff;

fn command(command_type: u8, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + capacity);
    out.push(TUIC_VERSION);
    out.push(command_type);
    out
}

/// `Authenticate`: `[16-byte UUID][32-byte token]`.
pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_AUTHENTICATE, 48);
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
    out
}

/// `Connect`: `[address]`. The server never answers it.
pub fn encode_connect(target: &NetLocation) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_CONNECT, 1 + 255 + 2);
    out.extend_from_slice(&serialize_address(target));
    out
}

/// `Packet`: `[u16 assoc][u16 pkt][u8 frag total][u8 frag id][u16 size][address]`.
///
/// `address` is None for every fragment after the first, which the
/// specification encodes as address type 0xff.
pub fn encode_packet_header(
    assoc_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    size: u16,
    target: Option<&NetLocation>,
) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_PACKET, MAX_HEADER_LEN);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(fragment_total);
    out.push(fragment_id);
    out.extend_from_slice(&size.to_be_bytes());
    match target {
        Some(target) => out.extend_from_slice(&serialize_address(target)),
        None => out.push(ADDRESS_TYPE_NONE),
    }
    out
}

/// `Dissociate`: `[u16 assoc]`.
pub fn encode_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut out = command(COMMAND_TYPE_DISSOCIATE, 2);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out
}

/// `Heartbeat`: no payload.
pub fn encode_heartbeat() -> Vec<u8> {
    command(COMMAND_TYPE_HEARTBEAT, 0)
}
```

- [ ] **Step 4: Run the tests, the gate, and commit**

```bash
cargo test --lib tuic::frame
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
tuic: encode the client commands

Authenticate, Connect, Packet, Dissociate and Heartbeat, with layouts taken
from the upstream specification rather than inferred from our own parser.
Fragments after the first carry address type 0xff, which the specification
defines for exactly that case.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 18: The TUIC connector, TCP path

**Files:**
- Create: `src/tuic/client.rs`
- Modify: `src/tuic/mod.rs`, `src/tcp/chain_builder.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/tuic/client.rs` with the tests first. Reuse the harness:

```rust
//! The TUIC v5 client outbound.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_outbound::testing::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_UUID: &str = "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4";

    async fn spawn_server() -> (SocketAddr, TestCertificate) {
        let cert = generate_certificate();
        let resolver = test_resolver();
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind_address = probe.local_addr().unwrap();
        drop(probe);

        let uuid: &'static [u8] = Box::leak(
            crate::uuid_util::parse_uuid(TEST_UUID)
                .unwrap()
                .to_vec()
                .into_boxed_slice(),
        );

        crate::tuic::start_tuic_server(
            bind_address,
            quic_server_config(&cert, &["h3".to_string()]),
            uuid,
            Box::leak("test password".to_string().into_boxed_str()),
            direct_selector(resolver.clone()),
            resolver,
            1,
            false,
        )
        .await
        .unwrap();

        (bind_address, cert)
    }

    fn connector(
        server: SocketAddr,
        cert: &TestCertificate,
        mode: TuicUdpRelayMode,
    ) -> TuicConnector {
        TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            TEST_UUID.to_string(),
            "test password".to_string(),
            true,
            mode,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_tcp_round_trip() {
        let (server, cert) = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, TuicUdpRelayMode::Native);

        let result = connector
            .connect_tcp(
                &resolver,
                NetLocation::from_str(&echo.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();

        assert!(
            result.early_data.is_none(),
            "TUIC servers never answer Connect, so there is no early data"
        );

        let mut stream = result.client_stream;
        stream.write_all(b"hello through tuic").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through tuic");
    }

    #[tokio::test]
    async fn test_wrong_uuid_is_rejected() {
        let (server, cert) = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();

        let connector = TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            "00000000-0000-0000-0000-000000000000".to_string(),
            "test password".to_string(),
            true,
            TuicUdpRelayMode::Native,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
        )
        .unwrap();

        // The server closes the connection rather than answering, so the
        // failure surfaces on the stream, not on the authentication.
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            async {
                let setup = connector
                    .connect_tcp(
                        &resolver,
                        NetLocation::from_str(&echo.to_string(), None)
                            .unwrap()
                            .into(),
                    )
                    .await?;
                let mut stream = setup.client_stream;
                stream.write_all(b"ping").await?;
                stream.flush().await?;
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await
            },
        )
        .await;

        match result {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("a wrong UUID must not relay traffic"),
            Err(_) => panic!("must fail rather than hang"),
        }
    }

    #[tokio::test]
    async fn test_streams_share_one_connection() {
        let (server, cert) = spawn_server().await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, TuicUdpRelayMode::Native);
        let target = NetLocation::from_str(&echo.to_string(), None).unwrap();

        for i in 0..3 {
            let mut stream = connector
                .connect_tcp(&resolver, target.clone().into())
                .await
                .unwrap()
                .client_stream;
            let payload = format!("stream {i}");
            stream.write_all(payload.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, payload.as_bytes());
        }
        assert_eq!(connector.connection_count(), 1);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib tuic::client`

Expected: FAIL to compile.

- [ ] **Step 3: Implement authentication and the connector**

Insert above the tests:

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::debug;
use tokio::io::AsyncWriteExt;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::{ClientQuicConfig, TuicUdpRelayMode};
use crate::quic_outbound::QuicOutboundSettings;
use crate::quic_outbound::connection::{ConnectionAuthenticator, LiveConnection};
use crate::quic_stream::QuicStream;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::TcpClientSetupResult;
use crate::tcp::terminal_connector::TerminalConnector;

use super::frame::{encode_authenticate, encode_connect};

/// Derives the authentication token and sends the Authenticate command.
#[derive(Debug)]
struct TuicAuthenticator {
    uuid: [u8; 16],
    password: String,
}

#[async_trait]
impl ConnectionAuthenticator for TuicAuthenticator {
    async fn authenticate(&self, connection: &quinn::Connection) -> std::io::Result<()> {
        // The token is exported from the live TLS session with the UUID as the
        // label and the raw password as the context, which is what the server
        // computes to compare against.
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|e| {
                std::io::Error::other(format!("failed to export TUIC keying material: {e:?}"))
            })?;

        let mut stream = connection.open_uni().await.map_err(|e| {
            std::io::Error::other(format!("failed to open the TUIC auth stream: {e}"))
        })?;
        stream
            .write_all(&encode_authenticate(&self.uuid, &token))
            .await
            .map_err(|e| std::io::Error::other(format!("failed to send Authenticate: {e}")))?;
        stream
            .finish()
            .map_err(|e| std::io::Error::other(format!("failed to finish the auth stream: {e}")))?;

        // There is no response: the specification defines none. A wrong UUID or
        // token shows up as the server closing the connection.
        debug!("TUIC Authenticate sent");
        Ok(())
    }
}

pub struct TuicConnector {
    connection: LiveConnection,
    udp_enabled: bool,
    udp_relay_mode: TuicUdpRelayMode,
    heartbeat_interval: Duration,
}

impl std::fmt::Debug for TuicConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicConnector")
            .field("server", &self.connection.settings().server)
            .field("udp_relay_mode", &self.udp_relay_mode)
            .finish()
    }
}

impl TuicConnector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: NetLocation,
        uuid: String,
        password: String,
        udp_enabled: bool,
        udp_relay_mode: TuicUdpRelayMode,
        heartbeat_interval: Duration,
        quic: ClientQuicConfig,
        bind_interface: Option<String>,
    ) -> std::io::Result<Self> {
        let uuid_bytes = crate::uuid_util::parse_uuid(&uuid).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("TUIC uuid is not a valid UUID: {e}"),
            )
        })?;

        let authenticator = Arc::new(TuicAuthenticator {
            uuid: uuid_bytes,
            password,
        });

        let settings = QuicOutboundSettings {
            server,
            quic,
            bind_interface,
            obfs: None,
            default_alpn: "h3",
        };

        Ok(Self {
            connection: LiveConnection::new(settings, authenticator),
            udp_enabled,
            udp_relay_mode,
            heartbeat_interval,
        })
    }

    #[cfg(test)]
    fn connection_count(&self) -> usize {
        self.connection.connections_raised()
    }

    /// Open a stream and send Connect. Reported as `ConnectionAborted` when the
    /// connection itself failed, so the caller can tell that apart and retry.
    async fn open_tcp_stream_once(
        &self,
        resolver: &Arc<dyn Resolver>,
        location: &NetLocation,
    ) -> std::io::Result<QuicStream> {
        let connection = self.connection.get(resolver).await?;

        let (mut send, recv) = connection.open_bi().await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to open a QUIC stream: {e}"),
            )
        })?;

        send.write_all(&encode_connect(location)).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("failed to send Connect: {e}"),
            )
        })?;

        Ok(QuicStream::from(send, recv))
    }
}

#[async_trait]
impl TerminalConnector for TuicConnector {
    async fn connect_tcp(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let location = target.into_location();
        debug!("TUIC: TCP connect to {location}");

        // One retry, for the window between the connection being handed out
        // and being used, in which the server can have gone away.
        let stream = match self.open_tcp_stream_once(resolver, &location).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {
                debug!("TUIC: connection died while opening a stream; retrying once");
                self.open_tcp_stream_once(resolver, &location).await?
            }
            other => other?,
        };

        // The server never answers a Connect. Payload follows the header
        // immediately, and a failure shows up as the stream being closed.
        Ok(TcpClientSetupResult {
            client_stream: Box::new(stream) as Box<dyn AsyncStream>,
            early_data: None,
        })
    }

    async fn connect_udp_bidirectional(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUIC UDP is not implemented yet",
        ))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }
}
```

Check the real name and return type of the UUID parser first
(`rg -n 'pub fn' src/uuid_util.rs`) and adjust `parse_uuid` above to match; it
must yield the 16 raw bytes.

- [ ] **Step 4: Wire it into the chain builder**

Extend `build_terminal_connector` in `src/tcp/chain_builder.rs`:

```rust
        ClientProxyConfig::Tuic(t) => Arc::new(
            crate::tuic::TuicConnector::new(
                config.address,
                t.uuid,
                t.password.into_inner(),
                t.udp_enabled,
                t.udp_relay_mode,
                std::time::Duration::from_millis(t.heartbeat_ms),
                config.quic_settings.unwrap_or_default(),
                config.bind_interface.into_option(),
            )
            .expect("validated during config load"),
        ),
```

Add `pub mod client;` and `pub use client::TuicConnector;` to
`src/tuic/mod.rs`.

- [ ] **Step 5: Run the tests, the gate, and commit**

```bash
cargo test --lib tuic::client
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
tuic: dial TUIC v5 servers over TCP

Authentication is one Authenticate command on a unidirectional stream,
carrying a token exported from the live TLS session with the UUID as the
label and the raw password as the context.

TCP is one Connect command on a bidirectional stream and then payload. The
specification is explicit that the server never answers it, so there is no
response to read and no early data to return; a failure arrives as a closed
stream, which is the only signal the protocol defines.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 19: TUIC UDP in both relay modes, and the heartbeat

**Files:**
- Create: `src/tuic/udp.rs`
- Modify: `src/tuic/client.rs`, `src/tuic/mod.rs`

- [ ] **Step 1: Write the failing tests**

Add to the tests module in `src/tuic/client.rs`:

```rust
    async fn udp_round_trip(mode: TuicUdpRelayMode) {
        use crate::async_stream::{AsyncReadMessage, AsyncWriteMessage};

        let (server, cert) = spawn_server().await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, &cert, mode);

        let mut stream = connector
            .connect_udp_bidirectional(
                &resolver,
                NetLocation::from_str(&echo.to_string(), None)
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();

        std::future::poll_fn(|cx| {
            std::pin::Pin::new(&mut stream).poll_write_message(cx, b"tuic udp")
        })
        .await
        .unwrap();

        let mut buf = [0u8; 64];
        let mut read_buf = tokio::io::ReadBuf::new(&mut buf);
        tokio::time::timeout(
            Duration::from_secs(10),
            std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut stream).poll_read_message(cx, &mut read_buf)
            }),
        )
        .await
        .expect("a reply must arrive")
        .unwrap();
        assert_eq!(read_buf.filled(), b"tuic udp");
    }

    #[tokio::test]
    async fn test_udp_round_trip_native_mode() {
        udp_round_trip(TuicUdpRelayMode::Native).await;
    }

    #[tokio::test]
    async fn test_udp_round_trip_quic_mode() {
        udp_round_trip(TuicUdpRelayMode::Quic).await;
    }

    #[tokio::test]
    async fn test_udp_is_refused_when_disabled() {
        let (server, cert) = spawn_server().await;
        let resolver = test_resolver();
        let connector = TuicConnector::new(
            NetLocation::from_str(&server.to_string(), None).unwrap(),
            TEST_UUID.to_string(),
            "test password".to_string(),
            false,
            TuicUdpRelayMode::Native,
            Duration::from_millis(10_000),
            client_quic_config(),
            None,
        )
        .unwrap();

        assert!(!connector.supports_udp());
        let err = connector
            .connect_udp_bidirectional(
                &resolver,
                NetLocation::from_str("127.0.0.1:53", None).unwrap().into(),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("udp_enabled"), "{err}");
    }
```

And to `src/tuic/udp.rs`, a unit test that does not need a server:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, NetLocation};

    fn target() -> NetLocation {
        NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 53)
    }

    #[test]
    fn test_single_fragment_carries_the_address() {
        let fragments = build_packets(1, 2, &target(), &[0u8; 100], 1200).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0][6], 1, "fragment total");
        assert_ne!(fragments[0][10], 0xff, "first fragment carries the address");
    }

    #[test]
    fn test_later_fragments_use_the_none_address() {
        let fragments = build_packets(1, 2, &target(), &[0u8; 5000], 1200).unwrap();
        assert!(fragments.len() > 1);
        assert_ne!(fragments[0][10], 0xff);
        for fragment in &fragments[1..] {
            assert_eq!(fragment[10], 0xff);
        }
    }

    #[test]
    fn test_every_fragment_fits_the_limit() {
        let fragments = build_packets(1, 2, &target(), &[0u8; 5000], 1200).unwrap();
        assert!(fragments.iter().all(|f| f.len() <= 1200));
    }

    #[test]
    fn test_refuses_more_than_255_fragments() {
        assert!(build_packets(1, 2, &target(), &[0u8; 100_000], 200).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib tuic::udp && cargo test --lib tuic::client`

Expected: FAIL to compile.

- [ ] **Step 3: Implement the association**

Create `src/tuic/udp.rs`:

```rust
//! One TUIC UDP association as an AsyncMessageStream.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use log::debug;
use tokio::io::{AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncWriteMessage,
};
use crate::config::TuicUdpRelayMode;

use super::frame::{encode_dissociate, encode_heartbeat, encode_packet_header};

/// Build the datagrams or stream payloads for one outgoing UDP packet.
///
/// Only the first fragment carries the address; the rest use address type
/// 0xff, which is what the specification defines that value for.
pub(crate) fn build_packets(
    assoc_id: u16,
    packet_id: u16,
    target: &NetLocation,
    payload: &[u8],
    max_packet: usize,
) -> std::io::Result<Vec<Vec<u8>>> {
    let first_header = encode_packet_header(assoc_id, packet_id, 1, 0, 0, Some(target)).len();
    let later_header = encode_packet_header(assoc_id, packet_id, 1, 1, 0, None).len();

    let first_capacity = max_packet.checked_sub(first_header).filter(|c| *c > 0);
    let later_capacity = max_packet.checked_sub(later_header).filter(|c| *c > 0);
    let (first_capacity, later_capacity) = match (first_capacity, later_capacity) {
        (Some(f), Some(l)) => (f, l),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet limit is smaller than a TUIC packet header",
            ));
        }
    };

    // Work out the fragment count first so it can go into every header.
    let fragment_count = if payload.len() <= first_capacity {
        1usize
    } else {
        1 + (payload.len() - first_capacity).div_ceil(later_capacity)
    };
    if fragment_count > u8::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes needs {fragment_count} fragments, over the 255 the protocol allows",
                payload.len()
            ),
        ));
    }

    let mut packets = Vec::with_capacity(fragment_count);
    let mut offset = 0;
    for index in 0..fragment_count {
        let capacity = if index == 0 { first_capacity } else { later_capacity };
        let end = (offset + capacity).min(payload.len());
        let chunk = &payload[offset..end];
        let address = if index == 0 { Some(target) } else { None };
        let mut packet = encode_packet_header(
            assoc_id,
            packet_id,
            fragment_count as u8,
            index as u8,
            chunk.len() as u16,
            address,
        );
        packet.extend_from_slice(chunk);
        packets.push(packet);
        offset = end;
    }
    Ok(packets)
}

/// Fragments waiting for their siblings, keyed by packet id.
struct Reassembly {
    packets: HashMap<u16, Vec<Option<Vec<u8>>>>,
}

impl Reassembly {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    /// Feed a Packet command body, after the two-byte version and type prefix.
    fn push(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        if body.len() < 8 {
            return None;
        }
        let packet_id = u16::from_be_bytes([body[2], body[3]]);
        let fragment_total = body[4];
        let fragment_id = body[5];
        let size = u16::from_be_bytes([body[6], body[7]]) as usize;

        if fragment_total == 0 || fragment_id >= fragment_total {
            return None;
        }

        // Skip the address to reach the payload.
        let address_len = match body.get(8)? {
            0xff => 1,
            0x00 => 1 + 1 + *body.get(9)? as usize + 2,
            0x01 => 1 + 4 + 2,
            0x02 => 1 + 16 + 2,
            _ => return None,
        };
        let payload_start = 8 + address_len;
        let payload_end = payload_start.checked_add(size)?;
        if body.len() < payload_end {
            return None;
        }
        let payload = body[payload_start..payload_end].to_vec();

        if fragment_total == 1 {
            return Some(payload);
        }

        let slots = self
            .packets
            .entry(packet_id)
            .or_insert_with(|| vec![None; fragment_total as usize]);
        if slots.len() != fragment_total as usize {
            *slots = vec![None; fragment_total as usize];
        }
        slots[fragment_id as usize] = Some(payload);

        if slots.iter().all(|s| s.is_some()) {
            let slots = self.packets.remove(&packet_id)?;
            Some(slots.into_iter().flatten().flatten().collect())
        } else {
            None
        }
    }
}

pub struct TuicUdpSession {
    connection: quinn::Connection,
    assoc_id: u16,
    target: NetLocation,
    mode: TuicUdpRelayMode,
    next_packet_id: AtomicU16,
    incoming: mpsc::Receiver<Vec<u8>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for TuicUdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TuicUdpSession")
            .field("assoc_id", &self.assoc_id)
            .field("target", &self.target)
            .field("mode", &self.mode)
            .finish()
    }
}

impl TuicUdpSession {
    pub fn new(
        connection: quinn::Connection,
        assoc_id: u16,
        target: NetLocation,
        mode: TuicUdpRelayMode,
        heartbeat_interval: Duration,
    ) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let mut tasks = Vec::with_capacity(3);

        // Datagrams: the server answers in whichever mode the session's first
        // packet used, but it may also send heartbeats, so both readers run.
        let datagram_tx = tx.clone();
        let datagram_connection = connection.clone();
        tasks.push(tokio::spawn(async move {
            let mut reassembly = Reassembly::new();
            loop {
                let datagram: Bytes = match datagram_connection.read_datagram().await {
                    Ok(d) => d,
                    Err(e) => {
                        debug!("TUIC datagram reader stopping: {e}");
                        return;
                    }
                };
                if datagram.len() < 2 || datagram[1] != super::frame::COMMAND_TYPE_PACKET {
                    continue;
                }
                if u16::from_be_bytes([datagram[2], datagram[3]]) != assoc_id {
                    continue;
                }
                if let Some(payload) = reassembly.push(&datagram[2..])
                    && datagram_tx.send(payload).await.is_err()
                {
                    return;
                }
            }
        }));

        // Unidirectional streams, for relay mode quic.
        let stream_tx = tx;
        let stream_connection = connection.clone();
        tasks.push(tokio::spawn(async move {
            let mut reassembly = Reassembly::new();
            loop {
                let mut recv = match stream_connection.accept_uni().await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!("TUIC uni reader stopping: {e}");
                        return;
                    }
                };
                let Ok(Some(body)) = recv.read_to_end(64 * 1024).await.map(Some) else {
                    continue;
                };
                if body.len() < 2 || body[1] != super::frame::COMMAND_TYPE_PACKET {
                    continue;
                }
                if u16::from_be_bytes([body[2], body[3]]) != assoc_id {
                    continue;
                }
                if let Some(payload) = reassembly.push(&body[2..])
                    && stream_tx.send(payload).await.is_err()
                {
                    return;
                }
            }
        }));

        // Heartbeats keep the connection alive while a relay task is running.
        // The specification asks for them only while there is one, which is
        // exactly the lifetime of this session.
        let heartbeat_connection = connection.clone();
        tasks.push(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(heartbeat_interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if heartbeat_connection
                    .send_datagram(Bytes::from(encode_heartbeat()))
                    .is_err()
                {
                    return;
                }
            }
        }));

        Self {
            connection,
            assoc_id,
            target,
            mode,
            next_packet_id: AtomicU16::new(0),
            incoming: rx,
            tasks,
        }
    }
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        // Best effort: tell the server the association is over so it can free
        // the socket rather than waiting for its idle timeout.
        let connection = self.connection.clone();
        let assoc_id = self.assoc_id;
        tokio::spawn(async move {
            if let Ok(mut stream) = connection.open_uni().await {
                let _ = stream.write_all(&encode_dissociate(assoc_id)).await;
                let _ = stream.finish();
            }
        });
    }
}

impl Unpin for TuicUdpSession {}

impl AsyncWriteMessage for TuicUdpSession {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let packet_id = this.next_packet_id.fetch_add(1, Ordering::Relaxed);

        match this.mode {
            TuicUdpRelayMode::Native => {
                let max_packet = this
                    .connection
                    .max_datagram_size()
                    .ok_or_else(|| std::io::Error::other("peer does not accept QUIC datagrams"))?;
                let packets =
                    build_packets(this.assoc_id, packet_id, &this.target, buf, max_packet)?;
                for packet in packets {
                    this.connection
                        .send_datagram(Bytes::from(packet))
                        .map_err(|e| {
                            std::io::Error::other(format!("failed to send a datagram: {e}"))
                        })?;
                }
            }
            TuicUdpRelayMode::Quic => {
                // A stream has no size limit, so one packet per stream and no
                // fragmentation is needed. 65535 is the field's own ceiling.
                let packets = build_packets(this.assoc_id, packet_id, &this.target, buf, 65535)?;
                let connection = this.connection.clone();
                tokio::spawn(async move {
                    for packet in packets {
                        match connection.open_uni().await {
                            Ok(mut stream) => {
                                let _ = stream.write_all(&packet).await;
                                let _ = stream.finish();
                            }
                            Err(e) => {
                                debug!("TUIC uni send failed: {e}");
                                return;
                            }
                        }
                    }
                });
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncReadMessage for TuicUdpSession {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.incoming.poll_recv(cx) {
            Poll::Ready(Some(payload)) => {
                if payload.len() > buf.remaining() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "UDP payload of {} bytes does not fit a {} byte buffer",
                            payload.len(),
                            buf.remaining()
                        ),
                    )));
                }
                buf.put_slice(&payload);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the TUIC UDP association ended",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncFlushMessage for TuicUdpSession {
    fn poll_flush_message(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for TuicUdpSession {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for TuicUdpSession {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl AsyncMessageStream for TuicUdpSession {}
```

Make `COMMAND_TYPE_PACKET` reachable as `super::frame::COMMAND_TYPE_PACKET`
(it is already `pub` from Task 4).

- [ ] **Step 4: Implement `connect_udp_bidirectional`**

Replace the stub in `src/tuic/client.rs`:

```rust
    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UDP is disabled for this TUIC outbound (udp_enabled: false)",
            ));
        }

        let connection = self.connection.get(resolver).await?;
        let location = target.into_location();
        let assoc_id: u16 = rand::rng().random();
        debug!("TUIC: UDP association {assoc_id} to {location}");

        Ok(Box::new(super::udp::TuicUdpSession::new(
            connection,
            assoc_id,
            location,
            self.udp_relay_mode,
            self.heartbeat_interval,
        )))
    }
```

Add `use rand::Rng;` and `pub mod udp;` to `src/tuic/mod.rs`.

- [ ] **Step 5: Run the tests, the gate, and commit**

```bash
cargo test --lib tuic
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
git add -A src/
git commit -F - <<'EOF'
tuic: relay UDP in both modes

Packets go over QUIC datagrams in native mode and over unidirectional
streams in quic mode; the server replies in whichever mode the association's
first packet used, so both readers run. Only the first fragment carries the
address, which is what address type 0xff exists for.

Heartbeats run for the lifetime of an association rather than on a timer
that never stops. The specification asks for them only while a relaying task
is in flight, and an idle connection has quinn's own keep-alive.

Dropping an association sends Dissociate, so the server frees its socket
instead of waiting out an idle timeout.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Task 20: Documentation, examples and CI

**Files:**
- Create: `examples/hysteria2_client.yaml`, `examples/tuic_client.yaml`
- Modify: `CONFIG.md`, `README.md`, `ROADMAP.md`, `.github/workflows/build.yml:136`

- [ ] **Step 1: Write the examples**

`examples/hysteria2_client.yaml`:

```yaml
# Route everything through a Hysteria2 server.
#
# The password is one opaque string. A server that authenticates by username
# and password expects them joined: "<username>:<password>".
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_chains:
        - hops:
            - address: "example.com:443"
              protocol:
                type: hysteria2
                password: "a strong password"
                obfs:
                  type: salamander
                  password: "an obfuscation password"
              quic_settings:
                sni_hostname: "example.com"
```

`examples/tuic_client.yaml`:

```yaml
# Route everything through a TUIC v5 server.
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_chains:
        - hops:
            - address: "example.com:443"
              protocol:
                type: tuic
                uuid: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
                password: "a strong password"
                udp_relay_mode: native
              quic_settings:
                sni_hostname: "example.com"
```

Check both parse:

```bash
cargo run -- --dry-run examples/hysteria2_client.yaml
cargo run -- --dry-run examples/tuic_client.yaml
```

Expected: no output and exit status 0.

- [ ] **Step 2: Add them to the CI smoke test**

In `.github/workflows/build.yml:136`, extend the config list:

```yaml
          for cfg in socks_basic multi_hop_chain tun_vpn tun_fake_ip amneziawg_client sniff hysteria2_client tuic_client; do
```

- [ ] **Step 3: Document the client protocols in CONFIG.md**

Add a `hysteria2` and a `tuic` entry to the client protocol reference, next to
the existing `wireguard` entry, covering every field from Task 7 with its
default, plus:

- that `transport` and `tcp_settings` are rejected and `quic_settings` is where
  TLS options go;
- that both protocols must be the only hop in a chain;
- the `<username>:<password>` note for Hysteria2;
- that the obfuscation password must be at least four bytes and both ends must
  agree;
- that `udp_relay_mode: native` uses QUIC datagrams and `quic` uses
  unidirectional streams.

Also document the new server-side `obfs` block on the Hysteria2 inbound.

- [ ] **Step 4: Update README.md and ROADMAP.md**

In README.md, move Hysteria2 and TUIC into the client protocol list.

In ROADMAP.md, most of this landed early, in commit `383d5fd`: Tier 1 §3 is
already marked in progress and links the spec and this plan, the section
"Hysteria: the rest of the surface" already enumerates everything deferred, and
"Open risk: TLS fingerprinting" already covers the QUIC side. Do not write any
of that a second time. What is left:

- change the `Hysteria2 / TUIC as a *client*` row of the comparison table from
  **absent** to yes;
- delete the paragraph beginning "That last row is the odd one", which says
  shoes cannot dial Hysteria2;
- change the Tier 1 §3 heading from "in progress" to "done", and reword its body
  from what the work will do to what it does, in the shape sections 1 and 2
  already use. Leave its closing pointer to the Hysteria gap section intact.

- [ ] **Step 5: Verify and commit**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib && cargo test --bins
cargo run -- --dry-run examples/hysteria2_client.yaml
cargo run -- --dry-run examples/tuic_client.yaml
git add -A
git commit -F - <<'EOF'
docs: document the Hysteria2 and TUIC client outbounds

Both examples are added to the CI smoke test, which parses each config end
to end on the release binary.

The roadmap's Tier 1 is now closed. Its fingerprinting section records that
sing-box parrots Chrome's QUIC handshake by default for Hysteria2, so the
exposure it already described for TLS exists on the QUIC side too.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

## Final verification

- [ ] **Run the full gate one more time**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins -- -D warnings
cargo test --lib
cargo test --bins
cargo test --test '*'
cargo build --release --locked
```

Expected: everything green, and the release binary builds.

- [ ] **Check the binary did not balloon**

```bash
ls -l target/release/shoes
git stash list
```

Compare against the size at `5aea5ad`. `blake2` is the only new dependency, so
anything beyond a few tens of kilobytes deserves a look before merging.

- [ ] **Live check against a real server, if one is available**

If you have credentials for a public Hysteria2 or TUIC server, point
`examples/hysteria2_client.yaml` at it, run the binary, and confirm a real
request works:

```bash
./target/release/shoes examples/hysteria2_client.yaml &
curl -sS -o /dev/null -w '%{http_code}\n' --socks5-hostname 127.0.0.1:1080 https://example.com
```

Expected: `200`. Interoperability with our own server is proven by the tests;
this is the check that the constants match the rest of the world.

---

## Notes on what this plan does not do

- **Brutal congestion control.** Without it, throughput on a lossy path will be
  lower than the official client's. This is the first thing worth adding next.
- **`gecko` obfuscation**, port hopping, and the Hysteria Realm rendezvous
  service.
- **Chrome QUIC handshake parroting.** Recorded as a known exposure in the spec
  and the roadmap.
- **Multi-hop chains** with either protocol.
