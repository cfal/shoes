# Protocol sniffing

Recover the destination hostname from the first bytes a client sends, so that
domain rules and rule-sets keep working when the destination is a bare IP
address.

Written 2026-08-10 against `mobile` at `c633523`. Roadmap item: Tier 1 #2.

## Table of Contents

- [Problem](#problem)
- [Scope](#scope)
- [What sing-box and Xray do](#what-sing-box-and-xray-do)
- [Sniffer contract](#sniffer-contract)
- [The peek loop](#the-peek-loop)
- [Connections that are never sniffed](#connections-that-are-never-sniffed)
- [Carrying the sniffed name into routing](#carrying-the-sniffed-name-into-routing)
- [Integration points](#integration-points)
- [Configuration](#configuration)
- [Error handling](#error-handling)
- [Reading application payload](#reading-application-payload)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Order of work](#order-of-work)
- [Deliberately out of scope](#deliberately-out-of-scope)

## Problem

A routing rule can match a domain — through `masks` or, since the rule-set
work, through a compiled `.srs` list. Both need a hostname to match against.

Today a hostname is available only when the client hands us one:

- a SOCKS5 or HTTP client that sends a name rather than an address;
- a TUN connection whose destination address was handed out by the Fake IP
  pool, so `fake_ip::destination_to_net_location` can map it back.

Anything else arrives as a bare IP. An application with a hardcoded DoH
resolver never asks our DNS, so Fake IP never sees the query and never
allocates a mapping. An application that dials a literal address does the same.
A client configured for `socks5` rather than `socks5h` resolves locally and
sends us the result.

In all three cases every domain rule silently degrades to IP matching. The
rule-sets we just shipped are the ones that suffer most: `geosite-*` lists are
domains only, so they stop matching entirely.

The first bytes of the connection usually carry the name anyway. A TLS
ClientHello carries it in the `server_name` extension; an HTTP request carries
it in the request line or the `Host` header. Reading those bytes before routing
recovers the name on the connection itself, with no dependency on DNS.

## Scope

In:

- TLS ClientHello (SNI) and HTTP/1.x (`Host` and absolute-URI) over TCP.
- The TUN TCP path and every TCP inbound that ends in
  `TcpServerSetupResult::TcpForward`.
- Opt-in per server and per TUN. Off by default.

Out, and why:

- **A QUIC sniffer.** Worth doing, but it is a different shape of work: HKDF
  from the
  version-specific initial salt, header-protection removal, an AES-128-GCM
  open, CRYPTO frame reassembly across datagrams that may arrive out of order,
  and only then the same ClientHello. It also lives on the UDP path, which has
  its own session lifecycle. It gets its own spec once this framing is proven.

  This is about sniffing the QUIC protocol, not about our QUIC *transport*. A
  server configured with `transport: quic` forwards streams through the same
  `TcpForward` arm (`src/quic_server.rs:136`) and is sniffed like any other TCP
  inbound.
- **DNS.** We already have a DNS module and a Fake IP pool. A DNS sniffer would
  duplicate them.
- **Protocol-only sniffers** (`bittorrent`, `ssh`, `rdp`, `stun`, `dtls`,
  `ntp`). These do not yield a hostname. They exist to support a `protocol`
  rule matcher, which we do not have. That matcher is a separate feature.
- **Destination override.** See below.

## What sing-box and Xray do

Both were read before designing this, because both have already walked into the
mistakes available here.

**sing-box.** Sniffing is no longer an inbound flag; it is a route rule action,
`{"action": "sniff"}` (`route/rule/rule_action.go`). The old inbound options
`sniff`, `sniff_override_destination` and `sniff_timeout` are marked
`// Deprecated: Use rule action instead` in `option/inbound.go`.

The mechanics live in `common/sniff/sniff.go`:

- read from the connection in a loop until a deadline; each sniffer returns
  either a result or `ErrNeedMoreData`, in which case more is read and every
  sniffer is re-run over the accumulated buffer;
- the default deadline is `ReadPayloadTimeout = 300 * time.Millisecond`
  (`constant/timeout.go`);
- a hardcoded set of ports is never sniffed, because the server speaks first
  there and waiting would stall the connection for the whole timeout: 25, 465,
  587 (SMTP), 143, 993 (IMAP), 110, 995 (POP3);
- the result is written into connection metadata as `protocol` and `domain`,
  and rule matching then continues, so later rules can match `domain`,
  `domain_suffix`, `rule_set` and `protocol`.

`RuleActionSniff.OverrideDestination` is marked `// Deprecated`.

**Xray.** Sniffing is an inbound setting: `enabled`, `destOverride`,
`metadataOnly`, `domainsExcluded`, `routeOnly`. `destOverride` replaces the
destination address with the sniffed name — the original behaviour. `routeOnly`
uses the name for routing only and dials the original address. `domainsExcluded`
exists specifically because destination override breaks services pinned to an
address, iOS push notifications and smart-home devices being the documented
examples.

**The conclusion we take from both.** Overriding the destination for a direct
connection is a dead end: Xray had to bolt an exclusion list onto it, and
sing-box deprecated it outright. This design does not re-resolve the sniffed
name for direct connections.

## Sniffer contract

A sniffer is a pure function over a byte slice. No I/O, no state, no side
effects. This is what makes them testable and fuzzable in isolation.

```rust
// src/sniff/mod.rs
pub enum SniffedProtocol { Tls, Http }

pub struct Sniffed {
    pub protocol: SniffedProtocol,
    /// `None` when the protocol was recognised but carries no name:
    /// a ClientHello without SNI, an HTTP/1.0 request without `Host`.
    pub domain: Option<String>,
}

pub enum SniffOutcome {
    Found(Sniffed),
    /// The prefix is consistent with this protocol; read more and ask again.
    NeedMore,
    /// Definitively not this protocol; stop asking.
    NotThisOne,
}

type SnifferFn = fn(&[u8]) -> SniffOutcome;
```

The three-way outcome is the point. sing-box distinguishes "need more data"
from "not this protocol" by inspecting a returned error value; here the
distinction is in the type, so the peek loop cannot get it wrong.

`src/sniff/tls.rs` parses a ClientHello out of a slice. The extension walk and
the `server_name` decoding are ported from `read_client_hello`
(`src/shadow_tls/shadow_tls_server_handler.rs:360`), but the surrounding
framing is new: that function is a streaming parser bound to `StreamReader`
that reads exact lengths, errors on anything short, and extracts a shadow-TLS
digest on the way through. None of that suits a sniffer.

`src/sniff/http.rs` parses the request line and the `Host` header. The method is
checked against a fixed list so that arbitrary text is not mistaken for HTTP.
An absolute-URI request line (`GET http://host/path HTTP/1.1`) takes precedence
over `Host`, matching what an origin server would do.

## The peek loop

```rust
// src/sniff/peek.rs
pub struct PeekResult {
    pub sniffed: Option<Sniffed>,
    /// Everything that was read, including `prefix`. Must reach the remote
    /// unchanged.
    pub buffered: Vec<u8>,
}

pub async fn peek_stream<S: AsyncRead + Unpin>(
    stream: &mut S,
    prefix: &[u8],
    protocols: &[SniffedProtocol],
    timeout: Duration,
    max_bytes: usize,
) -> PeekResult
```

`prefix` is what the inbound handler already read — `initial_remote_data`. For
the plain HTTP inbound that prefix already holds the whole request
(`src/http_handler.rs:294`), so the name is found without a single read.

The function does not return an error. A failed sniff is not a failed
connection: if a read fails, `buffered` is simply shorter, and the connect and
copy that follow hit the same failure on their own. The cost is one pointless
upstream connect on an already-dead connection, which buys the guarantee that
this function cannot lose bytes.

One `tokio::time::timeout` covers the whole loop rather than each read.

Each iteration: read a chunk, append it, run every enabled sniffer over the
**whole** buffer, first `Found` wins. If every sniffer answered `NotThisOne`,
stop immediately rather than waiting out the deadline. If any answered
`NeedMore`, read again.

The loop stops at `max_bytes`, at EOF, or at the deadline. `max_bytes` is 16
KiB. The format allows a TLS record of 65540 bytes
(`src/shadow_tls/shadow_tls_stream.rs`), but a real ClientHello does not exceed
a few kilobytes even with post-quantum key shares. Above the cap we stop
sniffing and route by IP.

The buffer starts at 1 KiB and grows only as far as reading actually goes, so
the 16 KiB ceiling is a worst case per in-flight sniff, not a per-connection
allocation.

## Connections that are never sniffed

- The destination is already a hostname. Fake IP resolved it, or the client
  sent a name. There is nothing to recover.
- The destination port is one of 25, 465, 587, 143, 993, 110, 995. The server
  speaks first on those, so the client sends nothing and we would stall for the
  full timeout. The list is taken from sing-box unchanged.

## Carrying the sniffed name into routing

`ResolvedLocation` (`src/address.rs:179`) already models exactly what is
needed:

```rust
pub struct ResolvedLocation {
    location: NetLocation,
    resolved_addr: Option<SocketAddr>,
}
```

A sniffed connection is judged as
`ResolvedLocation::with_resolved(NetLocation::new(Address::Hostname(name), port), original_addr)`.

Everything then follows from code that already exists:

- `judge` derives `resolved_ip` from `resolved_addr`
  (`src/client_proxy_selector.rs:304`), so CIDR masks match the real address;
- `match_mask` resolves lazily only when `resolved_ip` is `None`
  (`src/client_proxy_selector.rs:598`), so sniffing adds no DNS lookup;
- domain masks and rule-sets match `location`, which is the sniffed name;
- `SocketConnectorImpl::connect` uses `resolved_addr` when present
  (`src/tcp/socket_connector_impl.rs:218`), so a direct connection dials the
  original address and never re-resolves.

There is one deliberate consequence. Proxy client handlers encode
`remote_location.location()` into their protocol — `src/socks_handler.rs:546`
is the clearest example. A connection routed through a proxy therefore carries
the **name** upstream, and the exit node resolves it. This is not the
destination override that Xray and sing-box retreated from: no direct
connection is re-resolved, and it matches what already happens today whenever
Fake IP supplies the name. It is what a user running `socks5h` is asking for.

The decision cache keys on `location`, which after sniffing is the hostname.
Two addresses behind one name share a cached rule index, which is correct: the
cached value is a rule index, not a route.

## Integration points

**`src/tcp/tcp_server.rs`.** The `TcpServerSetupResult::TcpForward` arm
(`src/tcp/tcp_server.rs:150`) is duplicated almost verbatim in
`src/quic_server.rs:136`. It is extracted into one shared function first; two
hooks maintained in two copies would diverge.

With sniffing enabled the order inside that function becomes:

```
write connection_success_response to the client   (moved earlier)
peek_stream(server_stream, initial_remote_data, …)
judge(with_resolved(name, original_addr))
connect upstream
write PeekResult::buffered to the client stream   (replaces the old
                                                   initial_remote_data write)
```

The move is required: a SOCKS5 client sends nothing until it has the success
reply, so sniffing before that reply would always time out with an empty
buffer. The cost is that the client is told the connection succeeded before we
know that it can. That is the same trade sing-box and Xray make, and it applies
only to servers that opted in — with sniffing disabled the order is byte for
byte what it is today.

**`src/tun/mod.rs`.** `handle_tcp_connection` (`src/tun/mod.rs:213`) gets the
same treatment without the reordering: the TCP handshake completed locally in
smoltcp, so the application has already sent its first bytes and there is
nothing to write first.

Configuration reaches these points as `ServerConfig.sniff` →
`start_tcp_servers` → `run_tcp_server` → `process_stream` → the shared forward
function; the same value follows `start_quic_servers` down the QUIC transport
path; and `TunConfig.sniff` → `run_tun_from_config` → `run_tun_server` →
`handle_tcp_connection`.

**Adjacent defect fixed first.** `src/tun/mod.rs:241` takes
`setup_result.client_stream` and drops `setup_result.early_data` on the floor.
The inbound path writes it to the client (`src/tcp/tcp_server.rs:307`); the TUN
path does not. This is a pre-existing data-loss bug in the function this work
rewrites, so it is fixed in its own commit, with its own test, before anything
else.

## Configuration

```yaml
sniff:
  enabled: true
  protocols: [tls, http]   # default: both
  timeout_ms: 300          # default: 300
```

A shorthand is accepted, because it is the form that will actually be typed:

```yaml
sniff: true    # equivalent to { enabled: true } with all defaults
```

That is a hand-written `Deserialize` accepting either a boolean or a map.

`timeout_ms` is a plain integer of milliseconds. The tree's existing idiom is
`timeout_secs: u32` with a `default_timeout_secs` function
(`src/config/types/dns.rs:11`); this follows it with a different unit, because
300 ms is not expressible in whole seconds.

The field is added to `ServerConfig` (`src/config/types/server.rs:162`) and
`TunConfig` (`src/config/types/tun.rs:52`), both `Option<SniffConfig>`,
defaulting to `None`. `SniffConfig` uses `deny_unknown_fields`, as
`RuleSetConfig` does.

Config errors are reported at load time, following the precedent set by
rule-sets:

- an unknown protocol name is an error, and the message lists the valid ones;
- `enabled: true` with an explicitly empty `protocols` list is an error; it is
  almost certainly a typo, and silently sniffing nothing would be worse. With
  `enabled: false` the list is not examined;
- `timeout_ms: 0` is **not** an error. It means "sniff whatever is already
  buffered and wait for nothing", which is a useful setting and the equivalent
  of Xray's `metadataOnly`. It is documented as such.

## Error handling

| Situation | Behaviour |
| --- | --- |
| Destination is already a hostname | Not sniffed |
| Destination port speaks server-first | Not sniffed |
| Deadline expired, nothing recognised | Route by IP, `debug!` |
| Protocol recognised, no name in it | Route by IP |
| Buffer hit the 16 KiB cap | Route by IP |
| Read failed | `buffered` is shorter; proceed as usual |
| Name recovered | Judge `with_resolved(name, original_addr)` |
| Decision is `Block` | Connection is dropped; buffered bytes are discarded |

The invariant: **sniffing can never itself cause a connection to fail.** Every
failure inside it degrades to today's behaviour, which is routing by IP.

Successful sniffs are logged at `debug` — one line per connection is too much
for `info`.

## Reading application payload

With `sniff` enabled the proxy reads the first bytes of application payload
before deciding where to route. Those bytes are not stored, are not logged
above `debug`, live only in the per-connection buffer, and reach the remote
unchanged. The feature is off by default for this reason, and the
documentation says so plainly: a user turning it on is entitled to know what it
does.

## Testing

Sniffer unit tests run on slices, with no I/O:

- **TLS**: SNI present; no SNI; a ClientHello split across two reads
  (`NeedMore`); non-TLS bytes (`NotThisOne`); a truncated record header; a
  trailing dot on the name; a punycode name; more than one entry in
  `server_name_list`.
- **HTTP**: `GET / HTTP/1.1` with `Host`; `CONNECT host:443`; an absolute-URI
  request line; `Host` carrying a port; mixed-case header name; HTTP/1.0 with
  no `Host`; non-HTTP bytes; headers split in the middle of `Host`.
- **Peek loop**: satisfied by `prefix` alone with no read at all; deadline
  expiry leaves everything read intact; the `max_bytes` cap; EOF mid-stream;
  every sniffer answering `NotThisOne` returns before the deadline.

One test matters more than the rest: **byte-for-byte integrity**. For an
arbitrary input stream, what the remote receives must equal what the client
sent, on every sniff outcome. A lost or duplicated byte here does not surface
as an error; it silently corrupts someone else's traffic and gets debugged in
someone else's application.

An integration test drives a live SOCKS listener: the client issues CONNECT to
a bare IP, then sends a ClientHello with SNI; the assertion is that the domain
rule matched and that the connection landed on the original address.

## Dependencies

None added.

## Order of work

1. Fix the dropped `early_data` in the TUN path, with a test.
2. Extract the shared `TcpForward` handling out of `src/tcp/tcp_server.rs` and
   `src/quic_server.rs`. Pure refactor, no behaviour change.
3. `src/sniff/` — the sniffers and the peek loop, complete under unit tests,
   wired to nothing.
4. Configuration and validation.
5. Wire both integration points.
6. Documentation, an example config, and a CI dry-run.

## Deliberately out of scope

QUIC sniffing, DNS sniffing, protocol-only sniffers and a `protocol` rule
matcher, destination override for direct connections, and a per-rule sniff
action. Each is listed with its reasoning in [Scope](#scope) or
[What sing-box and Xray do](#what-sing-box-and-xray-do).
