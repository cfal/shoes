# Hysteria2 Client Port Hopping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Hysteria2 client outbound rotate its UDP port on a timer, so it can reach a server published as a port range and so the connection's 4-tuple does not stay constant.

**Architecture:** A `HoppingUdpSocket` implements `quinn::AsyncUdpSocket`, sitting at the same layer as the existing `ObfuscatedUdpSocket`. It owns a current and a previous inner socket, binds a fresh one on every hop through a factory that goes via `socket_util::new_udp_socket` (and therefore the VPN protector), and lies to quinn about addresses so the QUIC layer never sees a path change.

**Tech Stack:** Rust, quinn 0.11.11 (`AsyncUdpSocket`, `UdpPoller`, `Transmit`, `RecvMeta`), tokio, parking_lot, `futures::task::AtomicWaker`.

**Spec:** [docs/superpowers/specs/2026-08-23-hysteria2-port-hopping-design.md](../specs/2026-08-23-hysteria2-port-hopping-design.md)

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/address.rs` | Gains `parse_port_union`, extracted from `NetLocationPortRange::from_str` so the hop config and listen addresses share one notation |
| `src/quic_transport/hop.rs` (new) | `PortSet`, `HopSchedule`, `HopSettings`, `HoppingUdpSocket`, `HoppingPoller`, `spawn_hop_task` |
| `src/quic_transport/mod.rs` | Declares the `hop` module |
| `src/config/types/client.rs` | `PortHoppingConfig`, and the field on `Hysteria2ClientConfig` |
| `src/config/validate.rs` | Rejects the four bad shapes at config load |
| `src/quic_outbound/mod.rs` | `QuicOutboundSettings.port_hopping`, and the factory in `build_endpoint` |
| `src/hysteria2/client.rs` | `Hysteria2Connector::new` takes the settings through |
| `src/tcp/tcp_client_handler_factory.rs` | Passes the config into the connector |
| `CONFIG.md`, `examples/`, `ROADMAP.md` | Documentation |

Everything hop-related lives in one new file. It is a single responsibility — "the socket that moves" — and keeping the poller next to the socket it polls is what makes the generation dance readable.

---

### Task 1: Extract the port-union parser

`NetLocationPortRange::from_str` already parses `80,443,1000-2000`. Hysteria2's
port-hopping syntax is the same notation. Extract it so there is one parser
rather than two that drift.

**Files:**
- Modify: `src/address.rs:283-360` (the `NetLocationPortRange::from_str` body)
- Test: `src/address.rs` (the existing `mod tests`)

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `src/address.rs`:

```rust
    /// One notation, two callers: the listen-address parser and Hysteria2
    /// port hopping. Extracted so they cannot drift apart.
    #[test]
    fn test_port_union_accepts_the_documented_forms() {
        assert_eq!(parse_port_union("443").unwrap(), vec![443]);
        assert_eq!(parse_port_union("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_port_union("1000-1003").unwrap(), vec![1000, 1001, 1002, 1003]);
        assert_eq!(
            parse_port_union("7044,5000-5002,80").unwrap(),
            vec![80, 5000, 5001, 5002, 7044],
            "the result is sorted and deduplicated"
        );
        assert_eq!(
            parse_port_union("80,80,80").unwrap(),
            vec![80],
            "a repeated port is one port, not three chances of picking it"
        );
    }

    #[test]
    fn test_port_union_rejects_nonsense() {
        for input in ["", "  ", "0-", "-100", "80-70", "70000", "80,", "a-b", "1-2-3"] {
            assert!(
                parse_port_union(input).is_err(),
                "{input:?} must not parse as a port union"
            );
        }
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib address::tests::test_port_union -- --nocapture`
Expected: FAIL to compile — `cannot find function 'parse_port_union' in this scope`.

- [ ] **Step 3: Write the parser and route the existing caller through it**

Add to `src/address.rs`, above `pub struct NetLocationPortRange`:

```rust
/// Parse a comma-separated union of ports and inclusive ranges: `443`,
/// `80,443`, `20000-50000`, or `1234,5000-6000,7044`.
///
/// The result is sorted and deduplicated, so a port listed twice is one
/// candidate rather than two.
///
/// This is the notation used both for a listener's port range and for
/// Hysteria2's port hopping (<https://v2.hysteria.network/docs/advanced/Port-Hopping/>).
/// They are the same syntax and must stay the same syntax, which is why there
/// is one parser.
pub fn parse_port_union(s: &str) -> std::io::Result<Vec<u16>> {
    let invalid = |detail: String| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, detail)
    };

    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(invalid(format!("Empty port in port union: {s:?}")));
        }
        match part.split_once('-') {
            Some((start, end)) => {
                let start: u16 = start.trim().parse().map_err(|e| {
                    invalid(format!("Invalid port number in {part:?}: {e}"))
                })?;
                let end: u16 = end.trim().parse().map_err(|e| {
                    invalid(format!("Invalid port number in {part:?}: {e}"))
                })?;
                if start > end {
                    return Err(invalid(format!(
                        "Port range {part:?} ends before it starts"
                    )));
                }
                ports.extend(start..=end);
            }
            None => {
                ports.push(part.parse::<u16>().map_err(|e| {
                    invalid(format!("Invalid port number in {part:?}: {e}"))
                })?);
            }
        }
    }

    if ports.is_empty() {
        return Err(invalid(format!("No ports in port union: {s:?}")));
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}
```

Then replace the port-parsing loop inside `NetLocationPortRange::from_str` —
everything from `// Parse the port ranges` down to the construction of `ports`
— with:

```rust
        let ports = parse_port_union(port_str)?;
```

Note `1-2-3` is rejected by `split_once('-')` giving `("1", "2-3")` and
`"2-3".parse::<u16>()` failing, so no extra check is needed.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib address::`
Expected: PASS, including the pre-existing `NetLocationPortRange` tests, which
now exercise the extracted function.

- [ ] **Step 5: Commit**

```bash
git add src/address.rs
git commit -m "address: extract the port-union parser

Hysteria2 port hopping uses the same notation as a listener's port range.
One parser rather than two that drift."
```

---

### Task 2: `PortSet` and `HopSchedule`

**Files:**
- Create: `src/quic_transport/hop.rs`
- Modify: `src/quic_transport/mod.rs`

- [ ] **Step 1: Write the failing tests**

Create `src/quic_transport/hop.rs` containing only:

```rust
//! A UDP socket that moves: Hysteria2 client port hopping.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_set_only_yields_configured_ports() {
        let set = PortSet::parse("5000-5002,7044").unwrap();
        for _ in 0..200 {
            let port = set.pick();
            assert!(
                [5000, 5001, 5002, 7044].contains(&port),
                "picked {port}, which is not in the set"
            );
        }
    }

    /// A set of one is legal and must not loop forever or panic.
    #[test]
    fn test_a_single_port_set_is_constant() {
        let set = PortSet::parse("443").unwrap();
        assert_eq!(set.pick(), 443);
    }

    /// Every port has to be reachable, or a range is a lie: a picker that only
    /// ever returned the first port would pass a weaker test.
    #[test]
    fn test_every_port_is_reachable() {
        let set = PortSet::parse("100-103").unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            seen.insert(set.pick());
        }
        assert_eq!(seen.len(), 4, "only saw {seen:?}");
    }

    #[test]
    fn test_a_fixed_schedule_returns_its_interval() {
        let schedule = HopSchedule::Fixed(Duration::from_millis(250));
        for _ in 0..10 {
            assert_eq!(schedule.next(), Duration::from_millis(250));
        }
    }

    #[test]
    fn test_a_ranged_schedule_stays_within_its_bounds() {
        let schedule = HopSchedule::Range {
            min: Duration::from_millis(100),
            max: Duration::from_millis(200),
        };
        for _ in 0..200 {
            let interval = schedule.next();
            assert!(
                interval >= Duration::from_millis(100)
                    && interval <= Duration::from_millis(200),
                "{interval:?} is outside the configured range"
            );
        }
    }
}
```

Add to `src/quic_transport/mod.rs`, beside the existing module declarations:

```rust
pub mod hop;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib quic_transport::hop`
Expected: FAIL to compile — `cannot find type 'PortSet' in this scope`.

- [ ] **Step 3: Implement `PortSet` and `HopSchedule`**

Put this above the test module in `src/quic_transport/hop.rs`:

```rust
use std::time::Duration;

use rand::RngExt;

use crate::address::parse_port_union;

/// The candidate ports a hopping socket draws from.
///
/// Upstream picks uniformly at random rather than cycling
/// (`extras/transport/udphop/conn.go`); a predictable cycle would be a
/// pattern, and hiding the pattern is the entire point of the feature.
#[derive(Debug, Clone)]
pub struct PortSet {
    ports: Vec<u16>,
}

impl PortSet {
    pub fn parse(s: &str) -> std::io::Result<Self> {
        Ok(Self {
            ports: parse_port_union(s)?,
        })
    }

    pub fn pick(&self) -> u16 {
        // parse_port_union rejects an empty union, so this cannot be empty.
        self.ports[rand::rng().random_range(0..self.ports.len())]
    }
}

/// How long to wait before the next hop.
#[derive(Debug, Clone, Copy)]
pub enum HopSchedule {
    Fixed(Duration),
    Range { min: Duration, max: Duration },
}

impl HopSchedule {
    pub fn next(&self) -> Duration {
        match *self {
            HopSchedule::Fixed(interval) => interval,
            HopSchedule::Range { min, max } => {
                if min >= max {
                    return min;
                }
                let span = (max - min).as_millis() as u64;
                min + Duration::from_millis(rand::rng().random_range(0..=span))
            }
        }
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib quic_transport::hop`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/quic_transport/hop.rs src/quic_transport/mod.rs
git commit -m "quic: add the port set and hop schedule"
```

---

### Task 3: Configuration and validation

**Files:**
- Modify: `src/config/types/client.rs:215-223` (`Hysteria2ClientConfig`)
- Modify: `src/config/validate.rs` (the Hysteria2 arm of the client-config match)
- Test: `src/config/validate.rs` (the existing `mod tests`)

- [ ] **Step 1: Write the failing tests**

Add to the client-outbound test module in `src/config/validate.rs`, beside the
existing mieru tests:

```rust
        fn hysteria2_client_with_hopping(
            hopping: Option<PortHoppingConfig>,
        ) -> ClientConfig {
            ClientConfig {
                address: NetLocation::from_str("example.com:443", None).unwrap(),
                protocol: ClientProxyConfig::Hysteria2(Box::new(Hysteria2ClientConfig {
                    password: "hunter2".into(),
                    udp_enabled: true,
                    obfs: None,
                    port_hopping: hopping,
                })),
                ..Default::default()
            }
        }

        fn hopping(ports: &str) -> PortHoppingConfig {
            PortHoppingConfig {
                ports: ports.to_string(),
                interval_ms: None,
                min_interval_ms: None,
                max_interval_ms: None,
            }
        }

        #[test]
        fn test_port_hopping_accepts_a_range() {
            let mut config = hysteria2_client_with_hopping(Some(hopping("20000-20010")));
            assert!(validate(&mut config).is_ok());
        }

        /// Nothing to hop between is not a configuration, it is a typo.
        #[test]
        fn test_port_hopping_rejects_an_unparsable_range() {
            let mut config = hysteria2_client_with_hopping(Some(hopping("not-ports")));
            assert!(validate(&mut config).is_err());
        }

        /// Upstream's floor. Below it the hop rate is itself a signature, and a
        /// silently clamped value would be a setting that does not do what it
        /// says.
        #[test]
        fn test_port_hopping_rejects_an_interval_under_the_floor() {
            let mut c = hopping("20000-20010");
            c.interval_ms = Some(4_999);
            let mut config = hysteria2_client_with_hopping(Some(c));
            let err = validate(&mut config).unwrap_err();
            assert!(err.to_string().contains("5000"), "{err}");
        }

        #[test]
        fn test_port_hopping_rejects_an_inverted_range() {
            let mut c = hopping("20000-20010");
            c.min_interval_ms = Some(30_000);
            c.max_interval_ms = Some(10_000);
            let mut config = hysteria2_client_with_hopping(Some(c));
            assert!(validate(&mut config).is_err());
        }

        /// Two answers to one question. Picking one silently would be a guess
        /// the user never sees.
        #[test]
        fn test_port_hopping_rejects_a_fixed_interval_beside_a_range() {
            let mut c = hopping("20000-20010");
            c.interval_ms = Some(30_000);
            c.min_interval_ms = Some(10_000);
            c.max_interval_ms = Some(20_000);
            let mut config = hysteria2_client_with_hopping(Some(c));
            assert!(validate(&mut config).is_err());
        }

        #[test]
        fn test_port_hopping_rejects_half_a_range() {
            let mut c = hopping("20000-20010");
            c.min_interval_ms = Some(10_000);
            let mut config = hysteria2_client_with_hopping(Some(c));
            assert!(validate(&mut config).is_err());
        }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::validate::tests 2>&1 | head -30`
Expected: FAIL to compile — `struct 'Hysteria2ClientConfig' has no field named 'port_hopping'`.

- [ ] **Step 3: Add the config type**

In `src/config/types/client.rs`, add above `Hysteria2ClientConfig`:

```rust
/// Rotate the client's UDP port on a timer, for a server published as a port
/// range.
///
/// <https://v2.hysteria.network/docs/advanced/Port-Hopping/>
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortHoppingConfig {
    /// Ports to hop between: `20000-50000`, `1234,5000-6000,7044`.
    ///
    /// This *replaces* the port in the outbound's `address`, which is then
    /// never dialled. That is upstream's behaviour and what a
    /// `hysteria2://` sharing link means by its multi-port parameter.
    pub ports: String,

    /// A fixed interval between hops. Defaults to 30000. Mutually exclusive
    /// with the min/max pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ms: Option<u64>,

    /// A random interval drawn from `[min, max]` on every hop. Both bounds
    /// must be given together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_interval_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interval_ms: Option<u64>,
}
```

Add the field to `Hysteria2ClientConfig`:

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_hopping: Option<PortHoppingConfig>,
```

- [ ] **Step 4: Add the validation**

In `src/config/validate.rs`, add a constant beside `MIERU_MAX_CREDENTIAL_LEN`:

```rust
/// Upstream's floor for the hop interval
/// (`extras/transport/udphop/conn.go`). Hopping faster is a pattern of its
/// own, and it costs a fresh socket every time.
const MIN_HOP_INTERVAL_MS: u64 = 5_000;
```

Then, in the `ClientProxyConfig::Hysteria2` arm of the client-config match (add
the arm if the protocol currently falls through to a catch-all):

```rust
        ClientProxyConfig::Hysteria2(hysteria2) => {
            if let Some(ref hopping) = hysteria2.port_hopping {
                let invalid = |detail: String| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, detail)
                };

                crate::address::parse_port_union(&hopping.ports).map_err(|e| {
                    invalid(format!("Hysteria2 port_hopping.ports is unusable: {e}"))
                })?;

                let has_range =
                    hopping.min_interval_ms.is_some() || hopping.max_interval_ms.is_some();
                if hopping.interval_ms.is_some() && has_range {
                    return Err(invalid(
                        "Hysteria2 port_hopping takes either interval_ms or the \
                         min_interval_ms/max_interval_ms pair, not both."
                            .to_string(),
                    ));
                }

                match (hopping.min_interval_ms, hopping.max_interval_ms) {
                    (Some(min), Some(max)) => {
                        if min > max {
                            return Err(invalid(format!(
                                "Hysteria2 port_hopping.min_interval_ms ({min}) is \
                                 greater than max_interval_ms ({max})."
                            )));
                        }
                        if min < MIN_HOP_INTERVAL_MS {
                            return Err(invalid(format!(
                                "Hysteria2 port_hopping.min_interval_ms must be at \
                                 least {MIN_HOP_INTERVAL_MS}."
                            )));
                        }
                    }
                    (None, None) => {}
                    _ => {
                        return Err(invalid(
                            "Hysteria2 port_hopping needs both min_interval_ms and \
                             max_interval_ms, or neither."
                                .to_string(),
                        ));
                    }
                }

                if let Some(interval) = hopping.interval_ms
                    && interval < MIN_HOP_INTERVAL_MS
                {
                    return Err(invalid(format!(
                        "Hysteria2 port_hopping.interval_ms must be at least \
                         {MIN_HOP_INTERVAL_MS}."
                    )));
                }
            }
        }
```

Import `PortHoppingConfig` in the validate test module alongside the other
config types it already imports.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib config::validate::tests`
Expected: PASS, including the six new tests.

- [ ] **Step 6: Commit**

```bash
git add src/config/types/client.rs src/config/validate.rs
git commit -m "config: accept Hysteria2 port hopping

Four bad shapes are refused at load rather than ignored: an unparsable
port union, an interval under upstream's 5s floor, an inverted range, and
a fixed interval given beside a range."
```

---

### Task 4: The socket, without hopping yet

Address rewriting first, with a single fixed inner socket. This isolates the
lying-to-quinn half from the moving half, so a failure in the next task cannot
be confused with a failure in this one.

**Files:**
- Modify: `src/quic_transport/hop.rs`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `src/quic_transport/hop.rs`:

```rust
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;

    /// Build a hopping socket whose set contains exactly `peer`'s port, so it
    /// cannot hop anywhere, and whose factory binds loopback sockets.
    fn fixed_socket(peer: SocketAddr) -> Arc<HoppingUdpSocket> {
        let factory: SocketFactory = Arc::new(|| {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            Ok(quinn::TokioRuntime.wrap_udp_socket(socket)?)
        });
        HoppingUdpSocket::new(factory, peer, PortSet::parse(&peer.port().to_string()).unwrap())
            .unwrap()
    }

    async fn send_one(socket: &HoppingUdpSocket, payload: &[u8]) {
        // The destination quinn asks for is deliberately wrong: the socket
        // must ignore it and use its own chosen address.
        let bogus: SocketAddr = "127.0.0.1:1".parse().unwrap();
        std::future::poll_fn(|_cx| {
            std::task::Poll::Ready(socket.try_send(&quinn::udp::Transmit {
                destination: bogus,
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            }))
        })
        .await
        .unwrap();
    }

    /// quinn is told where to send; the hopping socket overrules it. Honouring
    /// the requested destination would send every packet to the original port
    /// and the feature would do nothing.
    #[tokio::test]
    async fn test_a_send_goes_to_the_chosen_destination_not_the_requested_one() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        peer.set_nonblocking(false).unwrap();

        let socket = fixed_socket(peer_addr);
        send_one(&socket, b"overruled").await;

        let mut buf = [0u8; 64];
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"overruled");
    }

    /// Every datagram must be reported as coming from one constant address.
    /// Reporting the real source would show quinn a new peer on every hop,
    /// which it reads as a path change.
    #[tokio::test]
    async fn test_every_datagram_is_reported_from_the_canonical_address() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = fixed_socket(peer_addr);

        // Learn the socket's current local address by sending first.
        send_one(&socket, b"ping").await;
        let mut buf = [0u8; 64];
        let (_, from) = peer.recv_from(&mut buf).unwrap();
        peer.send_to(b"pong", from).unwrap();

        let mut recv_buf = [0u8; 64];
        let mut bufs = [std::io::IoSliceMut::new(&mut recv_buf)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();

        assert_eq!(count, 1);
        assert_eq!(
            meta[0].addr, peer_addr,
            "the source must be canonicalised, not reported as it arrived"
        );
    }

    /// We report max_transmit_segments() == 1, so quinn must never hand us a
    /// batch. Sending one anyway would put several packets on the wire as one.
    #[test]
    fn test_a_segmented_transmit_is_refused() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let socket = fixed_socket(peer);
        let err = socket
            .try_send(&quinn::udp::Transmit {
                destination: peer,
                ecn: None,
                contents: b"batched",
                segment_size: Some(4),
                src_ip: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("segmented"), "{err}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib quic_transport::hop`
Expected: FAIL to compile — `cannot find type 'HoppingUdpSocket' in this scope`.

- [ ] **Step 3: Implement the socket**

Add to `src/quic_transport/hop.rs`, above the test module:

```rust
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use parking_lot::RwLock;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};

/// Builds a fresh inner socket, already wrapped in whatever the outbound needs
/// (obfuscation) and already protected from the VPN route.
///
/// Every socket in this module comes from here. There are no direct binds: a
/// socket is created on a timer for the life of a connection, and one that
/// skipped the protector would be routed back into the tunnel it carries.
pub type SocketFactory =
    Arc<dyn Fn() -> std::io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;

struct HopState {
    current: Arc<dyn AsyncUdpSocket>,
    /// The socket from the last hop. It is kept because the server may already
    /// have sent to the old port; without it those datagrams vanish silently.
    previous: Option<Arc<dyn AsyncUdpSocket>>,
    destination: SocketAddr,
    generation: u64,
}

pub struct HoppingUdpSocket {
    factory: SocketFactory,
    /// The address quinn is told about, in both directions, for the whole
    /// connection. The real destination moves underneath it.
    canonical: SocketAddr,
    ports: PortSet,
    state: RwLock<HopState>,
    /// Woken on a hop, so a quinn task parked on the old socket learns about
    /// the new one instead of waiting for a datagram that may never come.
    waker: AtomicWaker,
}

impl std::fmt::Debug for HoppingUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read();
        f.debug_struct("HoppingUdpSocket")
            .field("canonical", &self.canonical)
            .field("destination", &state.destination)
            .field("generation", &state.generation)
            .finish_non_exhaustive()
    }
}

impl HoppingUdpSocket {
    pub fn new(
        factory: SocketFactory,
        canonical: SocketAddr,
        ports: PortSet,
    ) -> std::io::Result<Arc<Self>> {
        let current = factory()?;
        let destination = SocketAddr::new(canonical.ip(), ports.pick());
        Ok(Arc::new(Self {
            factory,
            canonical,
            ports,
            state: RwLock::new(HopState {
                current,
                previous: None,
                destination,
                generation: 0,
            }),
            waker: AtomicWaker::new(),
        }))
    }
}

/// Report every datagram in the batch as having come from `canonical`.
///
/// Upstream rewrites unconditionally rather than filtering by source, and so
/// do we. A stranger's datagram fails QUIC's own authentication and is
/// discarded a layer up, whereas filtering by address would break a
/// multi-homed server for no security gain.
fn canonicalise(meta: &mut [RecvMeta], count: usize, canonical: SocketAddr) {
    for entry in meta.iter_mut().take(count) {
        entry.addr = canonical;
    }
}

impl AsyncUdpSocket for HoppingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let (generation, current) = {
            let state = self.state.read();
            (state.generation, state.current.clone())
        };
        Box::pin(HoppingPoller {
            socket: self,
            generation,
            inner: current.create_io_poller(),
        })
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        // max_transmit_segments() is 1, so quinn must never batch. If that
        // promise breaks, sending the batch as one datagram would put several
        // packets on the wire glued together.
        if transmit.segment_size.is_some() {
            return Err(std::io::Error::other(
                "hopping sockets cannot send segmented transmits",
            ));
        }

        let state = self.state.read();
        state.current.try_send(&Transmit {
            destination: state.destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: None,
            // The socket quinn believes it is using is not the one carrying
            // this datagram, so its source hint is stale.
            src_ip: None,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        self.waker.register(cx.waker());

        let state = self.state.read();
        match state.current.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                canonicalise(meta, count, self.canonical);
                return Poll::Ready(Ok(count));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }

        if let Some(previous) = state.previous.as_ref() {
            match previous.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    canonicalise(meta, count, self.canonical);
                    return Poll::Ready(Ok(count));
                }
                // The previous socket is scheduled to die; its errors are
                // expected and must not take the connection with them.
                Poll::Ready(Err(_)) | Poll::Pending => {}
            }
        }

        Poll::Pending
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.state.read().current.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.read().current.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// quinn asks for a poller once and holds it for the connection's life, while
/// the socket underneath is replaced on every hop. This one notices.
struct HoppingPoller {
    socket: Arc<HoppingUdpSocket>,
    generation: u64,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl std::fmt::Debug for HoppingPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoppingPoller")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl UdpPoller for HoppingPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let (generation, current) = {
            let state = this.socket.state.read();
            (state.generation, state.current.clone())
        };
        if generation != this.generation {
            this.inner = current.create_io_poller();
            this.generation = generation;
        }
        this.inner.as_mut().poll_writable(cx)
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib quic_transport::hop`
Expected: PASS, 8 tests.

If `UdpPoller`'s method signature differs from the one written above, the
compiler names the required method and its exact shape; adjust to what it says
rather than guessing.

- [ ] **Step 5: Commit**

```bash
git add src/quic_transport/hop.rs
git commit -m "quic: a socket that overrules quinn's addresses

Sends go to the chosen destination rather than the requested one, and
every datagram is reported from one constant address so QUIC never sees
a path change."
```

---

### Task 5: The hop

**Files:**
- Modify: `src/quic_transport/hop.rs`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
    /// A helper whose factory counts its calls and can be made to fail.
    fn counting_factory(
        fail_after: usize,
    ) -> (SocketFactory, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let factory: SocketFactory = Arc::new(move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n >= fail_after {
                return Err(std::io::Error::other("factory exhausted"));
            }
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            Ok(TokioRuntime.wrap_udp_socket(socket)?)
        });
        (factory, calls)
    }

    /// The point of the feature: the local port must change too. Rotating only
    /// the destination leaves the flow linkable by its unchanged source.
    #[tokio::test]
    async fn test_a_hop_binds_a_new_local_port() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let socket = fixed_socket(peer);

        let before = socket.local_addr().unwrap();
        socket.hop().unwrap();
        let after = socket.local_addr().unwrap();

        assert_ne!(before, after, "the local port did not move");
    }

    /// The server may already have sent to the old port. Without the overlap
    /// those datagrams are lost, and on a busy connection that is a stall.
    #[tokio::test]
    async fn test_the_previous_socket_still_receives_after_a_hop() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = fixed_socket(peer_addr);

        // Make the peer learn the pre-hop local address.
        send_one(&socket, b"before").await;
        let mut buf = [0u8; 64];
        let (_, old_local) = peer.recv_from(&mut buf).unwrap();

        socket.hop().unwrap();

        // The server answers the address it knew about.
        peer.send_to(b"late reply", old_local).unwrap();

        let mut recv_buf = [0u8; 64];
        let mut bufs = [std::io::IoSliceMut::new(&mut recv_buf)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("a datagram sent to the previous socket must still arrive")
        .unwrap();

        assert_eq!(count, 1);
        assert_eq!(&recv_buf[..meta[0].len], b"late reply");
    }

    /// Two hops later the oldest socket is gone. Keeping every socket forever
    /// would leak a file descriptor per hop for the life of the connection.
    #[tokio::test]
    async fn test_the_socket_from_two_hops_ago_is_closed() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = fixed_socket(peer_addr);

        send_one(&socket, b"first").await;
        let mut buf = [0u8; 64];
        let (_, oldest_local) = peer.recv_from(&mut buf).unwrap();

        socket.hop().unwrap();
        socket.hop().unwrap();

        peer.send_to(b"too late", oldest_local).unwrap();

        let mut recv_buf = [0u8; 64];
        let mut bufs = [std::io::IoSliceMut::new(&mut recv_buf)];
        let mut meta = [quinn::udp::RecvMeta::default()];
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await;
        assert!(
            outcome.is_err(),
            "a datagram to the socket from two hops ago must not arrive"
        );
    }

    /// A hop that cannot bind must not take the connection down. Turning an
    /// anti-blocking feature into an outage is worse than not having it.
    #[tokio::test]
    async fn test_a_failed_hop_leaves_the_current_socket_working() {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let (factory, _calls) = counting_factory(1);
        let socket = HoppingUdpSocket::new(
            factory,
            peer_addr,
            PortSet::parse(&peer_addr.port().to_string()).unwrap(),
        )
        .unwrap();

        let before = socket.local_addr().unwrap();
        assert!(socket.hop().is_err(), "the factory was set to fail");
        assert_eq!(
            socket.local_addr().unwrap(),
            before,
            "a failed hop must leave the working socket in place"
        );

        send_one(&socket, b"still alive").await;
        let mut buf = [0u8; 64];
        peer.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"still alive");
    }

    /// Without this wake, a task parked on the old socket waits for a datagram
    /// that may never come.
    #[tokio::test]
    async fn test_a_hop_wakes_a_parked_receiver() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let socket = fixed_socket(peer);
        let parked = socket.clone();

        let receiver = tokio::spawn(async move {
            let mut recv_buf = [0u8; 64];
            let mut bufs = [std::io::IoSliceMut::new(&mut recv_buf)];
            let mut meta = [quinn::udp::RecvMeta::default()];
            let mut polls = 0;
            std::future::poll_fn(|cx| {
                polls += 1;
                if polls > 1 {
                    return std::task::Poll::Ready(());
                }
                let _ = parked.poll_recv(cx, &mut bufs, &mut meta);
                std::task::Poll::Pending
            })
            .await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        socket.hop().unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
            .await
            .expect("the hop must wake a parked receiver")
            .unwrap();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib quic_transport::hop`
Expected: FAIL to compile — `no method named 'hop' found`.

- [ ] **Step 3: Implement the hop and the timer**

Add to `impl HoppingUdpSocket`:

```rust
    /// Bind a fresh socket, pick a fresh destination, and retire the oldest.
    ///
    /// The ordering matters and mirrors upstream: the socket that was previous
    /// is dropped — which closes it — the current becomes previous, and the
    /// new one becomes current. Two sockets are therefore live between hops,
    /// which is what covers the datagrams already in flight to the old port.
    pub fn hop(&self) -> std::io::Result<()> {
        let socket = (self.factory)()?;
        let destination = SocketAddr::new(self.canonical.ip(), self.ports.pick());

        {
            let mut state = self.state.write();
            state.previous = Some(std::mem::replace(&mut state.current, socket));
            state.destination = destination;
            state.generation += 1;
        }

        self.waker.wake();
        Ok(())
    }
```

And, at module level:

```rust
/// Drive `socket` on `schedule` until it is dropped.
///
/// The task holds a `Weak`, so it ends when the endpoint does rather than
/// keeping a connection's sockets alive forever.
pub fn spawn_hop_task(socket: &Arc<HoppingUdpSocket>, schedule: HopSchedule) {
    let weak = Arc::downgrade(socket);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(schedule.next()).await;
            let Some(socket) = weak.upgrade() else {
                return;
            };
            if let Err(e) = socket.hop() {
                // Staying put beats dropping a working connection.
                log::warn!("port hop failed, keeping the current socket: {e}");
            }
        }
    });
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib quic_transport::hop`
Expected: PASS, 13 tests.

- [ ] **Step 5: Mutation-check the overlap test**

Temporarily change `hop` so it does not keep the previous socket:

```rust
            state.previous = None;
            state.current = socket;
```

Run: `cargo test --lib quic_transport::hop`
Expected: `test_the_previous_socket_still_receives_after_a_hop` FAILS. Restore
the real implementation and re-run to confirm everything passes again. If the
test passed with the overlap removed, it is not testing the overlap.

- [ ] **Step 6: Commit**

```bash
git add src/quic_transport/hop.rs
git commit -m "quic: bind a new socket on every hop

Two sockets stay live across a hop so datagrams already sent to the old
port still land. A hop that cannot bind keeps the working socket."
```

---

### Task 6: Wire it into the QUIC outbound

**Files:**
- Modify: `src/quic_outbound/mod.rs:28` (`QuicOutboundSettings`) and `:119-137` (`build_endpoint`)
- Modify: `src/hysteria2/client.rs:43-64` (`Hysteria2Connector::new`)
- Modify: `src/tcp/tcp_client_handler_factory.rs` (the Hysteria2 arm)

- [ ] **Step 1: Add the settings type**

In `src/quic_transport/hop.rs`:

```rust
/// Everything the outbound needs to hop, resolved from config.
#[derive(Debug, Clone)]
pub struct HopSettings {
    pub ports: PortSet,
    pub schedule: HopSchedule,
}

impl HopSettings {
    /// Build from the config's raw fields. Validation has already rejected the
    /// impossible combinations; this is the translation, not a second check.
    pub fn new(
        ports: &str,
        interval_ms: Option<u64>,
        min_interval_ms: Option<u64>,
        max_interval_ms: Option<u64>,
    ) -> std::io::Result<Self> {
        let schedule = match (interval_ms, min_interval_ms, max_interval_ms) {
            (_, Some(min), Some(max)) => HopSchedule::Range {
                min: Duration::from_millis(min),
                max: Duration::from_millis(max),
            },
            (Some(interval), _, _) => HopSchedule::Fixed(Duration::from_millis(interval)),
            _ => HopSchedule::Fixed(DEFAULT_HOP_INTERVAL),
        };
        Ok(Self {
            ports: PortSet::parse(ports)?,
            schedule,
        })
    }
}

/// Upstream's default (`extras/transport/udphop/conn.go`).
pub const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
```

- [ ] **Step 2: Add the field to `QuicOutboundSettings`**

In `src/quic_outbound/mod.rs`, add to the struct:

```rust
    /// When set, the outbound rotates its UDP port on a timer instead of
    /// dialling `server`'s port. Hysteria2 only.
    pub port_hopping: Option<crate::quic_transport::hop::HopSettings>,
```

Update the test fixture `fn settings()` in that file's test module to include
`port_hopping: None`.

- [ ] **Step 3: Use it in `build_endpoint`**

Replace the socket-and-endpoint block at the end of `build_endpoint` with:

```rust
        let Some(hop) = self.port_hopping.clone() else {
            // Unchanged path: no hopping, so nothing about how the socket is
            // built or handed to quinn changes.
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
            return Ok(endpoint);
        };

        // Hopping binds sockets for the life of the connection, so the factory
        // is the only way one is made: new_udp_socket consults the VPN
        // protector, and a socket that skipped it would route back into the
        // tunnel it carries.
        let bind_interface = self.bind_interface.clone();
        let obfs = self.obfs.clone();
        let factory: SocketFactory = Arc::new(move || {
            let socket = new_udp_socket(server_is_ipv6, bind_interface.clone())?.into_std()?;
            match obfs.clone() {
                Some(obfs) => Ok(Arc::new(ObfuscatedUdpSocket::new(socket, obfs)?)),
                None => Ok(quinn::TokioRuntime.wrap_udp_socket(socket)?),
            }
        });

        let canonical = self
            .server
            .to_socket_addr_nonblocking()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "port hopping needs a resolved server address",
                )
            })?;

        let socket = HoppingUdpSocket::new(factory, canonical, hop.ports)?;
        spawn_hop_task(&socket, hop.schedule);

        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
```

Also set `enable_segmentation_offload: self.obfs.is_none() && self.port_hopping.is_none()`
in the `QuicTransportParams`, mirroring what obfuscation already does: the
hopping socket reports one segment per transmit, so asking quinn to coalesce
would only produce transmits it has to refuse.

`to_socket_addr_nonblocking()` returns `None` when the configured server is a
hostname, and a hostname cannot work here: the canonical peer address is fixed
for the connection's life, so there is nowhere for a re-resolution to go. That
has to be a config error rather than a runtime one, so add this to the
`ClientProxyConfig::Hysteria2` arm written in Task 3, inside the
`if let Some(ref hopping)` block:

```rust
                if client_config.address.address().hostname().is_some() {
                    return Err(invalid(
                        "Hysteria2 port_hopping requires a literal IP address. \
                         The peer address is fixed for the connection's life, so \
                         a hostname has nowhere to re-resolve to."
                            .to_string(),
                    ));
                }
```

and this test beside the other port-hopping tests:

```rust
        /// A hostname has nowhere to re-resolve to once the connection is up,
        /// so it is refused at load rather than failing when the endpoint is
        /// built.
        #[test]
        fn test_port_hopping_rejects_a_hostname_address() {
            let mut config = hysteria2_client_with_hopping(Some(hopping("20000-20010")));
            config.address = NetLocation::from_str("example.com:443", None).unwrap();
            let err = validate(&mut config).unwrap_err();
            assert!(err.to_string().contains("literal IP"), "{err}");
        }
```

`hysteria2_client_with_hopping` already builds a hostname address, so change
its default to `NetLocation::from_str("203.0.113.10:443", None)` and let this
test set the hostname explicitly. Otherwise every other port-hopping test
fails on the new rule.

- [ ] **Step 4: Thread the settings through the connector**

`Hysteria2Connector::new` gains a parameter after `obfs`:

```rust
        port_hopping: Option<crate::quic_transport::hop::HopSettings>,
```

and passes it into `QuicOutboundSettings`. Update every caller: the four
`connector(...)` helpers in `src/hysteria2/client.rs`'s test module pass
`None`, and `src/tcp/tcp_client_handler_factory.rs` builds it:

```rust
            let port_hopping = match hysteria2.port_hopping {
                Some(ref hopping) => Some(crate::quic_transport::hop::HopSettings::new(
                    &hopping.ports,
                    hopping.interval_ms,
                    hopping.min_interval_ms,
                    hopping.max_interval_ms,
                )?),
                None => None,
            };
```

- [ ] **Step 5: Build and run the whole suite**

Run: `cargo build --lib && cargo test --lib`
Expected: compiles; every existing test still passes.

- [ ] **Step 6: Commit**

```bash
git add src/quic_transport/hop.rs src/quic_outbound/mod.rs src/hysteria2/client.rs src/tcp/tcp_client_handler_factory.rs src/config/validate.rs
git commit -m "hysteria2: dial through a hopping socket when configured

The non-hopping path is untouched, so the default cannot regress."
```

---

### Task 7: The integration test — an iptables REDIRECT in userspace

**Files:**
- Modify: `src/hysteria2/client.rs` (its test module)

- [ ] **Step 1: Write the relay bank**

Add to the test module in `src/hysteria2/client.rs`:

```rust
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Stand in for an `iptables REDIRECT`: bind `count` UDP ports and forward
    /// everything that arrives to `server`, relaying the replies back.
    ///
    /// Not a perfect stand-in. Real DNAT rewrites only the destination, so the
    /// server keeps seeing one client address; this relays through its own
    /// socket, so the server sees a new source on every hop and handles it as
    /// QUIC connection migration. That makes the test stricter than the real
    /// deployment, not weaker, and it is the closest thing achievable without
    /// root.
    ///
    /// What the bank observed, which is the only window the test has into
    /// whether hopping actually happened.
    #[derive(Default)]
    struct RelayObservations {
        /// Bank-side ports that carried at least one datagram.
        server_ports: HashSet<u16>,
        /// Client source ports seen. This is what proves the local rebind,
        /// which is the half of the feature that makes the flow unlinkable.
        client_ports: HashSet<u16>,
    }

    /// Returns the bound ports and what the bank saw.
    async fn spawn_relay_bank(
        server: SocketAddr,
        count: usize,
    ) -> (Vec<u16>, Arc<Mutex<RelayObservations>>) {
        let seen: Arc<Mutex<RelayObservations>> =
            Arc::new(Mutex::new(RelayObservations::default()));
        let mut ports = Vec::with_capacity(count);

        for _ in 0..count {
            let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = front.local_addr().unwrap().port();
            ports.push(port);

            let seen = seen.clone();
            tokio::spawn(async move {
                let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                back.connect(server).await.unwrap();

                let mut from_client = [0u8; 2048];
                let mut from_server = [0u8; 2048];
                let mut client: Option<SocketAddr> = None;

                loop {
                    tokio::select! {
                        Ok((n, peer)) = front.recv_from(&mut from_client) => {
                            client = Some(peer);
                            {
                                let mut seen = seen.lock().unwrap();
                                seen.server_ports.insert(port);
                                seen.client_ports.insert(peer.port());
                            }
                            let _ = back.send(&from_client[..n]).await;
                        }
                        Ok(n) = back.recv(&mut from_server) => {
                            if let Some(peer) = client {
                                let _ = front.send_to(&from_server[..n], peer).await;
                            }
                        }
                    }
                }
            });
        }

        (ports, seen)
    }
```

- [ ] **Step 2: Write the failing test**

```rust
    /// The whole feature, end to end: a server published as a port range, a
    /// client that rotates across it, and a transfer that outlives several
    /// hops.
    ///
    /// The last two assertions are the test. Without them it passes with
    /// hopping switched off entirely, which is exactly the kind of green test
    /// that lets a feature ship doing nothing.
    #[tokio::test]
    async fn test_a_transfer_survives_several_hops() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_tcp_echo().await;
        let resolver = test_resolver();

        let (ports, seen) = spawn_relay_bank(server, 6).await;
        let range = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // 200ms, far below the 5000ms config floor. That floor is a
        // validation rule, not a property of the mechanism, and raising this
        // would turn the test into a minute of waiting.
        let hop = crate::quic_transport::hop::HopSettings::new(
            &range,
            Some(200),
            None,
            None,
        )
        .unwrap();

        let connector = Hysteria2Connector::new(
            NetLocation::from_str(&format!("127.0.0.1:{}", ports[0]), None).unwrap(),
            SERVER_PASSWORD.to_string(),
            true,
            client_quic_config(),
            None,
            None,
            Some(hop),
        );

        let result = connector
            .connect_tcp(&resolver, target(echo))
            .await
            .unwrap();
        let mut stream = result.client_stream;

        // Nine exchanges a quarter-second apart outlive several hops.
        for i in 0..9u8 {
            let payload = [i; 32];
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();

            let mut buf = [0u8; 32];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
                .await
                .expect("the transfer stalled across a hop")
                .unwrap();
            assert_eq!(buf, payload, "exchange {i} came back corrupted");

            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let seen = seen.lock().unwrap();
        assert!(
            seen.server_ports.len() >= 2,
            "every datagram went to one server port, so nothing hopped: {:?}",
            seen.server_ports
        );
        assert!(
            seen.client_ports.len() >= 2,
            "the client kept one local port, so the 4-tuple never changed: {:?}",
            seen.client_ports
        );
    }
```

- [ ] **Step 3: Run it**

Run: `cargo test --lib hysteria2::client::tests::test_a_transfer_survives_several_hops -- --nocapture`
Expected: PASS.

- [ ] **Step 4: Mutation-check it**

Temporarily make `spawn_hop_task` return immediately without spawning:

```rust
pub fn spawn_hop_task(_socket: &Arc<HoppingUdpSocket>, _schedule: HopSchedule) {}
```

Run the test again.
Expected: FAIL on both port-diversity assertions. Restore
`spawn_hop_task` and confirm it passes again. If it still passed, the
assertion is measuring nothing and must be fixed before moving on.

- [ ] **Step 5: Commit**

```bash
git add src/hysteria2/client.rs
git commit -m "hysteria2: test a transfer across several port hops

A bank of UDP relays stands in for an iptables REDIRECT, so the whole
path runs in process with no root. The test asserts that more than one
port carried traffic, without which it passes with hopping disabled."
```

---

### Task 8: Documentation

**Files:**
- Modify: `CONFIG.md`
- Create: `examples/hysteria2_port_hopping.yaml`
- Modify: `ROADMAP.md`
- Modify: `docs/superpowers/specs/2026-08-23-hysteria2-port-hopping-design.md`

- [ ] **Step 1: Document the config**

Add to `CONFIG.md`, in the Hysteria2 client section:

````markdown
#### Port hopping

A Hysteria2 server is often published as a port range. `port_hopping` rotates
the client's UDP port across that range on a timer, which is also how the
connection avoids keeping one 4-tuple for its whole life.

```yaml
- address: 203.0.113.10:443
  protocol:
    type: hysteria2
    password: ...
    port_hopping:
      ports: "20000-50000"       # or "1234,5000-6000,7044"
      interval_ms: 30000         # default 30000, minimum 5000
      # or, instead of interval_ms:
      # min_interval_ms: 15000
      # max_interval_ms: 45000
```

**`ports` replaces the port in `address`.** In the example above, 443 is never
dialled. This matches the reference client and the meaning of a
`hysteria2://` link's multi-port parameter.

`address` must be a literal IP when port hopping is on: the peer address is
fixed for the connection's life, so a hostname that could re-resolve has
nowhere to go.
````

- [ ] **Step 2: Add the example**

Create `examples/hysteria2_port_hopping.yaml`:

```yaml
# A Hysteria2 server published as a port range, dialled with port hopping.
#
# The server side is not shoes: point this at a Hysteria2 deployment whose
# range is reachable, whether by the reference server's native range support
# or by a DNAT rule.
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - mask: 0.0.0.0/0
      action: allow
      client_proxies:
        - address: 203.0.113.10:443
          protocol:
            type: hysteria2
            password: replace-me
            port_hopping:
              ports: "20000-50000"
              interval_ms: 30000
```

- [ ] **Step 3: Update the roadmap**

In `ROADMAP.md`, under "Hysteria: the rest of the surface" →
"Interoperability", delete the **Port hopping** row from the gap table and add
this paragraph directly beneath that table:

```markdown
**Port hopping — done, client side.** A server published as a port range is
reachable now: `src/quic_transport/hop.rs` binds a fresh UDP socket on a timer
and rotates the destination across the configured union, reporting one constant
address to QUIC so the connection never sees a path change. The local port
moves with it, which is the half that makes the 4-tuple stop being a handle for
a middlebox. Our own Hysteria2 server still listens on a single port; upstream's
supports a range natively on Linux and programs the firewall rules itself, and
that is not implemented here.
```

- [ ] **Step 4: Correct the spec**

The spec calls the relay bank "what an iptables REDIRECT does". That is not
exactly true, and the difference is worth recording. In the "Integration — the
iptables mimicry" section, replace:

> This is what an iptables REDIRECT does, in userspace and without root, and it
> runs in CI on every commit.

with:

> This is close to what an iptables REDIRECT does, in userspace and without
> root, and it runs in CI on every commit. It is not identical: real DNAT
> rewrites only the destination, so the server keeps seeing one client address,
> whereas the relay forwards through its own socket and the server sees a new
> source on every hop. It therefore handles the test's traffic as QUIC
> connection migration, which a real deployment would not have to. That makes
> the test stricter than the deployment rather than weaker, and it is the
> closest thing reachable without root.

- [ ] **Step 5: Run the full gate**

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
cargo test --bins
cargo test --test '*'
cargo clippy --locked --features ffi --lib --tests -- -D warnings
cargo clippy --locked --features ffi --bins -- -D warnings
```

Expected: all clean. This is the gate AGENTS.md requires before any push.

- [ ] **Step 6: Commit**

```bash
git add CONFIG.md examples/hysteria2_port_hopping.yaml ROADMAP.md docs/superpowers/specs/2026-08-23-hysteria2-port-hopping-design.md
git commit -m "docs: Hysteria2 port hopping"
```

---

## Live verification

Not a task in the plan, because it needs a server that does not exist yet.
Once a Hysteria2 server is published on a port range — the reference server's
`listen: :20000-50000` handles the firewall rules itself on Linux — run a
transfer through it for several minutes and confirm the connection survives.
Record it in ROADMAP.md the way the mieru run is recorded.

Test configs carrying real server credentials go in a temp directory outside
the working tree and are deleted afterwards. `git status` and the outgoing
diff get scanned before any push.
