# Named outbounds, and bytes counted against them

Written 2026-08-26 against `mobile` at `81d08e6`.

## Why

A client UI wants one number per configured server: how much has gone through
Frankfurt, how much through Amsterdam. Today there is nothing to hang that on.
`ClientConfig` (`src/config/types/client.rs:543`) has six fields —
`bind_interface`, `address`, `protocol`, `transport`, `tcp_settings`,
`quic_settings` — and none of them is a label. The only candidate key is the
address, which is neither stable across config edits nor meaningful to show a
person.

`src/control/stats.rs` says so in its own header comment, and stops there. This
spec is the thing that comment defers to.

Naming is not only about statistics. Three other roadmap items are waiting on
the same missing string: `urltest` produces per-node latency with nowhere to
display it, the Tauri GUI needs a server list with human labels, and every
`ss://` / `vmess://` share link carries a name in its fragment that currently
has nowhere to go. This spec does not build any of those. It builds the
identifier they all need, and it proves the identifier arrives intact by
wiring exactly one consumer: per-outbound byte counters.

Scope: **the `name` field, its identity rules, and per-outbound upload/download
and active-connection counts in `control::stats::snapshot()`.** Nothing else.

## Sources

| What | Where |
| --- | --- |
| The type gaining a field | `src/config/types/client.rs:543` |
| Group resolution (clones configs) | `src/config/validate.rs:239` |
| Selection points to instrument | `src/client_proxy_chain.rs:279`, `:385` |
| Terminal (AmneziaWG) selection | `src/client_proxy_chain.rs`, `ClientProxyChainKind::Terminal` |
| Existing counters and their convention | `src/tun/traffic.rs` |
| Where counting happens today | `src/tun/mod.rs:326`, `src/tun/udp_manager.rs:497`, `:530` |
| The stats surface being extended | `src/control/stats.rs` |
| Unspecified address for `direct` | `src/config/types/common.rs:36`, `src/address.rs:115` |
| Where a service actually starts | `src/control/mod.rs:318`, `src/main.rs:404` |
| Validation-only callers of the same function | `src/main.rs:394` (`--dry-run`), the config editor |
| The RSS policy and its gate | `Cargo.toml:27-37`, `src/tun/traffic.rs:22-28` |

## What is actually true today

Read from the source, because two of these are the opposite of what the shape
suggests.

**Byte counting does not happen at the outbound.** `TrafficCountingStream`
wraps the *device-side* stream at `src/tun/mod.rs:326`, with two more call
sites in `udp_manager.rs`. It counts at the TUN edge, under `cfg(unix)`, in TUN
mode only. Those counters structurally cannot know which outbound carried the
bytes, and in server mode they are never incremented at all. Per-outbound
figures need a new counting point.

**Its direction convention inverts at the outbound.** On the device side, a
read is upload — bytes travelling device to proxy. At the outbound, a read is
download. Reusing that type unchanged would silently swap the two numbers, and
no test that only checks totals would notice.

**A hop is a pool, selected per connection.** `client_chains` round-robins over
chains, and each hop within a chain round-robins over its members. The exit
outbound is therefore not a static property of a chain; it is whichever member
`connect_tcp` picked for this connection. Attribution has to be read after
selection.

**Group expansion clones.** `resolve_client_groups_topologically`
(`src/config/validate.rs:239`) `.clone()`s a `ClientConfig` into every group
that references it, and groups may reference other groups. One authored server
therefore appears as several distinct values, and they must share one counter.

**`direct` has no address.** `ClientConfig::default()` sets
`NetLocation::UNSPECIFIED` (`0.0.0.0:0`), and the default rule action is a
direct chain, so nearly every config contains one.

## Decisions

| Question | Decision |
| --- | --- |
| What does a name identify? | One `ClientConfig` — a single server endpoint |
| What identifies an unnamed one? | Its address, rendered as a string |
| Which hop do a chain's bytes count against? | The exit hop |
| Where is the counting done? | Inside the chain, against a global name-keyed registry |
| When is the registry populated? | At service start, from a set validation computed |
| Is any of it feature-gated? | The runtime state, behind `control-stats`; the config rules are not |

The unit is the individual `ClientConfig` because that is what the waiting
consumers are shaped like: one share link is one endpoint, `urltest` probes one
endpoint, and endpoint figures aggregate up to a chain or a group whereas the
reverse cannot be recovered.

The exit hop is credited because that is the server a person means by "which
one am I using". Bytes are still physically measured on the socket to hop 1;
they are credited to the exit. Each connection is credited once and to exactly
one outbound, so the per-outbound column sums to the total traffic rather than
double-counting a chain.

## The config surface

One optional field:

```yaml
client_group: eu
client_proxies:
  - name: "Frankfurt #1"
    address: fra1.example:443
    protocol: {type: trojan, password: hunter2}
  - address: ams1.example:443           # unnamed, keyed by address
    protocol: {type: vless, user_id: ...}
```

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub name: Option<String>,
```

Optional, so every config that exists today keeps loading — including ones
shipped inside released mobile apps. `skip_serializing_if` keeps a config that
does not use it round-tripping byte-identically, which matters because the
desktop config editor re-serializes what it loads.

`ClientConfig` is a plain derive with `deny_unknown_fields`, so no custom
deserializer is involved. A `name` on an outbound that already rejects unknown
fields simply becomes a known one.

## Identity

Validation resolves every outbound to a non-empty **key**:

1. `name`, if set and non-empty after trimming
2. otherwise `"direct"`, if the protocol is `Direct` and the address is
   unspecified
3. otherwise the address rendered through `Display for NetLocation`
   (`src/address.rs:198`), giving `host:port`

Rule 2 exists because of the unspecified address above: without it every
direct outbound in every config collides on `0.0.0.0:0`. Sharing one `direct`
counter is not a workaround — it is the number a person wants, being the
traffic that bypassed the proxy entirely.

An empty or whitespace-only `name` is a config error rather than a silent fall
through to the address, because it is always a mistake and the silent form is
undebuggable.

**Conflicts.** Two outbounds resolving to the same key must describe the same
server. Same key with the same address is expected — that is a group reference,
and the clones share a counter, which is the whole point. Same key with a
different address is rejected:

```
two outbounds are named "Frankfurt" but have different addresses
(fra1.example:443 and fra2.example:443); a name must identify one server
```

Comparing addresses rather than whole configs is deliberate. Full structural
equality would demand `PartialEq` across `ClientProxyConfig`, `Redacted<String>`
and the transport types, and it would reject the legitimate case of one server
reachable by two credentials. The address is the discriminator that catches the
actual mistake.

## The registry

A process-global map from key to `Arc<OutboundCounters>`:

```rust
struct OutboundCounters {
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    active_connections: AtomicUsize,
}
```

**Computed during validation, installed at start.** Validation builds an
`OutboundSet` — every key with its address, conflict-checked — from every
outbound the config mentions: group members and hops written inline in a
`client_chains` entry alike, since inline is the more common form and a server
missing from the list is exactly the bug this is meant to fix. The set travels
out in `ValidatedConfigs`.

Validation must not touch the global registry, because `create_server_configs`
is not only the start path. `--dry-run` (`src/main.rs:394`) calls it and exits,
and the config editor will call it on a draft; if it reset the registry, then
validating a draft would wipe the live list of the service running in the same
process. So validation is pure, and `outbound_stats::install(&set)` replaces
the registry contents at the two places a service actually starts:
`prepare_from_config` (`src/control/mod.rs:318`) and the binary's start path
(`src/main.rs:404`). A reload goes through the same call, so it replaces the
list rather than accumulating servers from the config it just discarded —
stale entries would also produce false address conflicts.

A GUI therefore lists every configured server at zero before any of them has
carried a byte — an empty list on a fresh connection would read as "no
servers", which is wrong.

Process-global rather than owned by the service, for the reason `traffic.rs`
already states: "process-global rather than per-service, which is an invariant
`crate::control::start` documents: one service per process". `stats::snapshot()`
is a free function with no service handle to thread a registry through, and
inventing one here would be a larger change than the feature.

Registration is idempotent — a repeated key returns the existing handle, which
is what makes cloned group members share a counter.

## Feature gate

`Cargo.toml` states a policy and `src/tun/traffic.rs` applies it: code costs
download size and almost no RSS, while "a log ring and a counter table cost
RSS", so runtime state lives behind `control-stats`. `ACTIVE_CONNECTIONS` is
gated that way, measured at 720 bytes, and `crate::control::stats` itself is
compiled only with the feature.

This is a counter table. It follows the policy:

- **Unconditional:** the `name` field, `stats_key`, the `OutboundSet` that
  validation builds, and the conflict check. These are config rules; a config
  that is wrong is wrong on every build.
- **Behind `control-stats`:** `OutboundCounters`, the registry, both counting
  adapters, the counter handles the chain carries, and the wrapping in
  `connect_tcp` / `connect_udp_bidirectional`. With the feature off, the chain
  returns the stream untouched and nothing about a connection changes.

`desktop = ["control-logs", "control-stats"]`, so every consumer this is being
built for gets it. Tests of the gated half run with `--features control-stats`.

## Counting

`connect_tcp` (`src/client_proxy_chain.rs:279`) and
`connect_udp_bidirectional` (`:385`) already choose the pool member. After the
stream is built, each wraps it in `OutboundCountingStream` holding the exit
hop's `Arc<OutboundCounters>`. `ClientProxyChainKind::Terminal` gets the same
treatment at its own selection point.

**What is counted is the application payload stream** — the value
`connect_tcp` returns, after every proxy handshake has completed. That is the
same quantity the device-side counter measures, so the two are comparable
rather than being unrelated numbers at different layers. They will not agree to
the byte: the device-side counter also sees the sniffed prefix and anything a
blocked or failed connection wrote before it died. The point is that the
difference is explainable, not that it is zero.

`TcpClientSetupResult::early_data` bypasses the stream, so it is added to the
download counter explicitly at the wrap point. Forgetting it would lose the
first bytes of every connection whose final hop reads ahead — a small number,
but a systematically biased one.

`OutboundCountingStream` is a new type rather than a reuse of
`TrafficCountingStream`, because of the direction inversion: here a read is
download and a write is upload. It delegates `AsyncPing` through the existing
`impl<T: ?Sized + AsyncPing + Unpin> AsyncPing for Box<T>`
(`src/async_stream.rs:264`), and increments `active_connections` on
construction and decrements on drop, so the count falls again when a connection
ends.

The UDP path wraps at the message level rather than the byte level, counting
payload lengths as `run_udp_routing` already sees them. It does **not** touch
`active_connections`: that figure counts TCP connections today, and folding
datagram sessions into it would silently change what an existing consumer is
reading.

## The stats surface

```rust
pub struct OutboundStats {
    pub name: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub active_connections: usize,
}
```

added to `StatsSnapshot` as `pub outbounds: Vec<OutboundStats>`, sorted by name
so a GUI redrawing on a timer does not reorder its own rows. The three existing
fields keep their present meaning exactly, so no current consumer changes
behaviour.

The header comment in `src/control/stats.rs` that defers to this spec is
replaced by a description of what the module now does.

## Testing

Tests of the registry, the adapters and the chain run with
`--features control-stats`; the config-level tests need no feature.

**Config level.** A `name` round-trips through load and serialize. An absent
name falls back to the address. A direct outbound keys to `direct` rather than
to `0.0.0.0:0`, and two direct outbounds in one config do not conflict. An
empty name is rejected. Two different addresses under one name are rejected,
and the message names both addresses. A config whose group is referenced from
three places yields one entry in the set, not three. Validating a config does
not change what the registry reports — the dry-run and editor property — and
installing a second set replaces the first.

**Counting level.** A two-hop chain credits the exit hop and leaves the relay
at zero. A pool credits the member actually selected, verified by driving
selection rather than by inspecting structure. `early_data` is counted.
`active_connections` returns to zero after the streams are dropped. Upload and
download are not transposed — asserted with deliberately asymmetric byte counts
in the two directions, since equal counts would pass either way round.

## What this does not do

- **`urltest`, the connection list, share-link import, the Clash API.** Each
  wants this identifier and each is its own design problem.
- **Fix the global counters in server mode.** Nothing outside the TUN path
  increments `upload_bytes` / `download_bytes` today, so in server mode the
  per-outbound figures will be populated while the two globals stay at zero.
  That asymmetry is pre-existing and is named here rather than quietly widened
  into this change.
- **Rename anything.** `client_group` keeps its current meaning as a named pool
  of alternatives. An outbound name and a group name live in separate
  namespaces and may coincide without ambiguity, because nothing resolves a
  reference against outbound names.
- **Persist counters.** They are process lifetime, like the existing ones. A
  cache file is a Tier 3 roadmap item covering several such needs at once.
