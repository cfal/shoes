# shoes

shoes is a high-performance multi-protocol proxy server written in Rust.

## Supported Protocols

### Proxy Protocols
- **HTTP/HTTPS**
- **SOCKS5** (with UDP ASSOCIATE)
- **Mixed** (auto-detect HTTP/SOCKS5)
- **VMess AEAD**
- **VLESS** (with fallback support)
- **Shadowsocks**
- **Trojan**
- **Snell v3**
- **Hysteria2**
- **TUIC v5**
- **AnyTLS**
- **NaiveProxy**
- **H2MUX** (supported with VMess, VLESS, Trojan, Shadowsocks, Snell)

### Transport Protocols
All server protocols plus:
- **SagerNet UDP over TCP** (for Shadowsocks, SOCKS5, AnyTLS, NaiveProxy)
- **ShadowTLS v3**
- **TLS**
- **WebSocket** (Shadowsocks SIP003)
- **XHTTP / SplitHTTP** (packet-up, stream-up, stream-one over HTTP/1.1, HTTP/2, HTTP/3)
- **XTLS Reality**
  - Hybrid-first X25519MLKEM768 key exchange and optional ML-DSA-65 server authentication
- **XTLS Vision** (for VLESS)

### TUN/VPN Mode
- **TUN device support** - Layer 3 VPN for transparent proxying
- Supported platforms: Linux, Android, iOS

### Supported Ciphers
- **VMess**: `aes-128-gcm`, `chacha20-poly1305`, `none`
- **Shadowsocks**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-ietf-poly1305`
- **Snell v3**: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`

For Clash.Meta/Mihomo legacy Snell clients, use `chacha20-ietf-poly1305` with v1
or `aes-128-gcm` with v3. Run Shoes v0.3.3 or newer for the corrected 16-byte
Snell salts. These clients do not offer an AES-256 option. Do not use v2:
Shoes does not implement Snell v2 connection reuse or its half-close markers.
Older Clash.Meta clients fail requests on reused v2 connections.
Shoes-to-Shoes connections can also use `aes-256-gcm`; both ends must use the
same cipher and run v0.3.3 or newer for AES-256 or ChaCha20.

## Features

- **Multi-transport**: TCP or QUIC for all protocols
- **TLS with SNI routing**: Route by Server Name Indication
- **Upstream proxy chaining**: Multi-hop chains with load balancing
- **Rule-based routing**: Route by IP/CIDR or hostname masks
- **Named PEM certificates**: Define once, reference everywhere
- **TLS fingerprint authentication**: Certificate pinning for TLS/QUIC
- **Hot reloading**: Apply config changes without restart
- **Unix socket support**: Bind to Unix domain sockets

For advanced access control (IP allowlist/blocklists), see [tobaru](https://github.com/cfal/tobaru).

## Installation

Precompiled binaries for x86_64 and Apple aarch64 are available on [Github Releases](https://github.com/cfal/shoes/releases).

For the previously published release:

```bash
cargo install shoes
```

GitHub release builds pin `h3` and `h3-quinn` to the
[`cfal/h3` fork](https://github.com/cfal/h3/tree/a0a7a53a143798d71884df36cfac4dd36cd087e6),
including the [empty-DATA fix](https://github.com/hyperium/h3/pull/373).
Empty HTTP/3 DATA frames must not be treated as body EOF; XHTTP uses them for
idle cancellation probes. The workspace patches cover direct and transitive
dependencies, including DNS over HTTP/3. The experimental zero-copy change in
[h3 #368](https://github.com/hyperium/h3/pull/368) is not included.

GitHub releases and checkout builds retain these patches. Crates.io publishing
remains disabled because Cargo removes workspace patches from published packages.
Remove the patches and publishing guard only after adopting fixed registry
versions that pass the H3 empty-DATA and idle-stream regressions. To install this
revision from its checkout:

```bash
cargo install --path . --locked
```

After updating the H3 pins, run the empty-DATA and idle-stream regressions:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --lib --features ffi h3_ -- --test-threads=1
```

## Usage

```
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
    -t, --threads NUM    Set the number of worker threads (default: CPU count)
    -d, --dry-run        Validate the config and certificates, then exit
    --no-reload          Disable automatic config reloading on file changes

COMMANDS:
    check <config.yaml>                       Alias for --dry-run
    version                                  Alias for --version
    generate-reality-keypair                  Generate a new Reality X25519 keypair
    generate-reality-mldsa65-keypair           Generate optional Reality ML-DSA-65 keys
    generate-shadowsocks-2022-password <cipher>    Generate a Shadowsocks password
```

### Examples
```bash
# Run with a single config file
shoes config.yaml

# Run with multiple config files
shoes server1.yaml server2.yaml rules.yaml

# Run with custom thread count
shoes --threads 8 config.yaml

# Validate configuration without starting
shoes --dry-run config.yaml

# Run without hot-reloading
shoes --no-reload config.yaml

# Generate Reality keypair
shoes generate-reality-keypair

# Generate Shadowsocks 2022 cipher password
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

## Configuration

See [CONFIG.md](./CONFIG.md) for the complete YAML configuration reference.

## Examples

See the [examples](./examples) directory for all examples.

### Basic VMess Server
```yaml
- address: 0.0.0.0:16823
  protocol:
    type: vmess
    cipher: chacha20-poly1305
    user_id: b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4
    udp_enabled: true
```

### VLESS with Vision over TLS
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    tls_targets:
      "vless.example.com":
        cert: cert.pem
        key: key.pem
        vision: true
        alpn_protocols: ["http/1.1"]
        protocol:
          type: vless
          user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
          udp_enabled: true
```

### Reality Server
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    reality_targets:
      "www.example.com":
        private_key: "YOUR_BASE64URL_PRIVATE_KEY"
        short_ids: ["0123456789abcdef", ""]
        dest: "www.example.com:443"
        protocol:
          type: vless
          user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
          udp_enabled: true
```

### Reality Client
```yaml
- address: 127.0.0.1:1080
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "server.example.com:443"
        protocol:
          type: reality
          public_key: "SERVER_PUBLIC_KEY"
          short_id: "0123456789abcdef"
          sni_hostname: "www.example.com"
          protocol:
            type: vless
            user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
```

### Hysteria2 Server
```yaml
- address: 0.0.0.0:443
  transport: quic
  quic_settings:
    cert: cert.pem
    key: key.pem
    alpn_protocols: ["h3"]
  protocol:
    type: hysteria2
    password: supersecret
    udp_enabled: true
```

### TUIC v5 Server
```yaml
- address: 0.0.0.0:443
  transport: quic
  quic_settings:
    cert: cert.pem
    key: key.pem
  protocol:
    type: tuic
    uuid: d685aef3-b3c4-4932-9a9d-d0c2f6727dfa
    password: supersecret
```

### Mixed HTTP/SOCKS5 Server
```yaml
- address: 0.0.0.0:7890
  protocol:
    type: mixed
    username: myuser
    password: mypassword
```

### AnyTLS Server
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    tls_targets:
      "anytls.example.com":
        cert: cert.pem
        key: key.pem
        protocol:
          type: anytls
          users:
            - name: user1
              password: secret123
          udp_enabled: true
```

### NaiveProxy Server
```yaml
- address: 0.0.0.0:443
  protocol:
    type: tls
    tls_targets:
      "naive.example.com":
        cert: cert.pem
        key: key.pem
        alpn_protocols: ["h2"]
        protocol:
          type: naiveproxy
          users:
            - username: user1
              password: secret123
          padding: true
```

### TUN VPN
```yaml
- device_name: tun0
  address: 10.0.0.1
  netmask: 255.255.255.0
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: tls
          protocol:
            type: vless
            user_id: b85798ef-e9dc-46a4-9a87-8da4499d36d0
```

On created Linux devices, TCPv4 transmit segmentation offload is selected
automatically when available. IPv6 continues using ordinary MTU-sized packets;
the configured MTU and TCP buffer sizes are unchanged. Set
`segmentation_offload: false` to disable it, or `true` to require it at startup.
Explicit enablement is not supported with `device_fd`, packet-information
headers, or non-Linux devices. Automatic setup falls back to ordinary packets
if offload initialization fails.

### XHTTP / SplitHTTP

See [examples/xhttp.yaml](examples/xhttp.yaml) for client/server configurations
covering all three modes and HTTP versions. `type: splithttp` is an alias for
`type: xhttp`; the inner `protocol` still handles authentication and destinations.

- `http_version: auto`: H1 for plaintext TCP, H2 for TLS/REALITY, H3 for QUIC.
  An explicit TLS ALPN of `http/1.1` selects H1. Explicit plaintext H2 uses h2c
  prior knowledge, not HTTP Upgrade.
- Client `mode: auto`: packet-up normally, stream-one under REALITY. Servers
  default to accepting all modes. Stream-one uses one request; stream-up uses
  separate streaming upload/download requests; packet-up uses bounded POSTs.
- Packet-up cannot transmit upload EOF. Use a streaming mode when the target
  must receive EOF before responding. After upload shutdown and packet acknowledgements,
  client `download_idle_timeout_secs` bounds the download-only tail (900 seconds,
  or 15 minutes, by default; must be positive). Download forwarding and successful
  local reads reset this timer. Expiry reports a timeout, not a successful EOF.
  Peer EOF or dropping the stream closes it immediately. An idle timeout cannot
  prove delivery of queued uploads; allow for the destination's expected stalls.
  Streaming bodies require unbuffered proxies. H1 stream-one closes the whole HTTP
  connection when its response ends; use H2/H3 or stream-up for remote-first half-close.
  In stream-up/auto server mode, normal download EOF allows an unclaimed streaming
  upload 30 seconds to attach; an absent upload is then reaped. Packet uploads do
  not receive this grace period.
- H1/H2 preserve selected upstream proxy chains. H3 must be the first proxy hop;
  it reuses the existing QUIC/H3 dependencies, not Hysteria2 framing.
- Server `matching_headers` requires every configured header on every request,
  including OPTIONS. Names are case-insensitive; values must match exactly and
  occur only once. Missing, wrong, or repeated values close the entire carrier
  without an HTTP response, before session admission or body processing. On
  H2/H3 this also terminates other requests sharing the connection. Configure
  the client's `headers` with the same values, for example
  `matching_headers: { X-Tunnel-Key: "replace-me" }` on the server and
  `headers: { X-Tunnel-Key: "replace-me" }` on the client. An empty map (default)
  adds no requirements; an empty value requires a present, empty header.
  Use `host`, not `matching_headers`, to match Host/`:authority` across versions.
  Transport-managed headers and values with leading/trailing spaces or tabs
  are rejected at startup. With multiplexing reverse proxies or CDNs, closing
  a shared upstream connection can also interrupt other clients.
  Browser preflights without the required headers are also rejected.
  On H3, exhausting request admission closes the connection when header
  requirements are configured: the server cannot validate more headers within
  its request budget. This also affects valid clients, regardless of `close_on_error`.
- Server `close_on_error: true` closes the carrier instead of sending any
  XHTTP-generated 4xx/5xx response, including invalid requests, unmatched paths
  or hosts, conflicts, timeouts, oversized bodies, and resource exhaustion.
  Admission failures also close instead of refusing an individual stream.
  On H2/H3, other requests sharing that connection are terminated too.
  With a CDN or reverse proxy, this can interrupt other clients sharing its
  upstream connection. Late packets, routine session teardown, or request slots
  awaiting cancellation cleanup can also trigger strict closure; this option
  trades shared-connection resilience for silent rejection.
  The default is `false`, preserving HTTP errors and stream refusals; 400 and
  404 responses omit XHTTP-specific and CORS headers. Required-header mismatches
  always close once checked, regardless of this option. Observed peer stream
  resets stay stream-local, as do H2 library resets for malformed request bodies
  (for example, Content-Length or flow-control violations). H3 may not observe
  cancellation while a request is awaiting admission or the peer only stops
  reading; a later timeout or other rejection still closes the carrier.
  HTTP-library parsing/protocol errors before
  XHTTP receives a request, and body failures after a successful response has
  started, retain their existing handling.
- `host` overrides HTTP authority independently of TLS SNI. Default Referer
  padding, path/query handling, packet sizing/pacing, and stream-up keepalives
  follow modern Xray. `limits` bounds sessions, buffered bytes, requests and
  setup/header deadlines and packet inactivity; `pool` bounds connections and
  idle retention.
  Split legs may use different carriers on the same selected route. H2/H3 admission
  respects peer stream capacity; draining carriers retain their connection slots.
  A full pool refuses new sessions rather than exceeding its configured cap.
  Split modes require at least two effective request lanes: two H1 connections,
  or `pool.max_connections * effective_requests_per_connection >= 2` for H2/H3.
  The effective per-connection limit is the smaller of
  `limits.max_requests_per_connection` and `global_limits.max_streams_per_connection`
  when the latter is configured. Peer stream limits can reduce runtime capacity further.
  Stream-one needs only one lane, including REALITY's automatic mode.
- Server `x_padding_bytes` is an acceptance range, independent of
  `server_max_header_bytes` (8192 by default). A wide range can accept clients
  using smaller padding without raising the header cap. To use larger Referer
  padding, raise the cap to fit the padding plus the URL, other headers, and
  HTTP-version framing overhead. Padding within the range is still rejected
  when the request exceeds that cap.
- `packet_timeout_secs` defaults to 300 seconds and measures inactivity, not a
  POST's total lifetime. On the server, each POST's body must keep receiving
  nonempty bytes. Admission waits stay alive while the inner
  stream consumes upload bytes or the original receiver of the missing next
  packet receives bytes. Duplicate bodies, empty packets, download traffic and
  resource wakeups do not count as progress.
  On the client, the timer covers only body transmission: H2/H3 transport
  acceptance, or handoff into Hyper's bounded H1 write buffer. After the body is
  sent, the ACK has no packet or response-header deadline. HTTP 200 acknowledges
  acceptance into the server's bounded packet queue, as in Xray, not delivery to
  the destination. Queued bytes retain their budget permits until consumed.
  Carrier readiness and request headers retain `response_header_timeout_secs`;
  other request types also retain it for response headers. `setup_timeout_secs`
  is unchanged. A live peer that never ACKs can retain bounded client resources
  until the stream is dropped or the transport fails.
- H2/H3 packet-up follows Xray's paced, write-gated pipeline: the next POST may start
  after the preceding body is transmitted, without waiting for its ACK. Client
  `packet_pipeline_depth` defaults to 30 (minimum 1), matching the reference peers'
  default reorder depth. The window advances only through consecutive ACKs, so
  later ACKs cannot accumulate an unbounded sequence gap at a stalled peer.
  Larger depths require a correspondingly larger peer reorder queue. Client
  and Shoes server request limits must also agree: allow at least the effective
  client POST depth plus one reserved head slot in server
  `limits.max_requests_per_session` (31 for the default H2/H3 client depth).
  Lower the client depth when using a smaller server cap; Shoes does not replay
  refused POSTs. Pool, byte and client request limits may reduce the effective depth.
  Each H2/H3 packet-up session can hold up to the effective POST depth plus one
  download slot in the shared pool (31 slots at the default depth). Delayed ACKs
  retain those slots; several stalled or high-latency sessions can fill the pool
  and refuse new sessions, including sessions to healthy destinations.
  Client `limits.max_requests_per_session` is an additional ceiling (128, minimum 2): one
  slot is for the download leg. `limits.max_requests`
  bounds outstanding POSTs across a client instance (4096 by default). Reaching
  either client bound backpressures the local writer. Pool limits may constrain
  concurrency further. H1 keeps one ACK-gated POST on a reusable upload connection,
  plus the download connection; it does not open opportunistic upload connections
  or use raw HTTP/1 pipelining. Use H2/H3 for high-latency packet-up throughput.
  Unsent bytes remain subject to the byte budgets;
  successfully transmitted bodies are not retained while awaiting ACKs.
  Outstanding POST payload sizes also count against a separate logical credit
  limit equal to `max_session_buffered_bytes`, bounding peer-side backlog without
  keeping sent allocations or consuming the download's memory allowance.
  Tiny writes are coalesced into allocations of at most 16 KiB while transferring
  their existing byte permits, avoiding per-write metadata and small-DATA-frame
  amplification without throttling datagram-sized writes.
  On the server, `limits.max_requests_per_session` bounds live packet requests
  across carriers, including empty bodies, duplicates and admission waiters.
  One slot is reserved for a missing head packet. `limits.max_requests` additionally
  bounds all active HTTP request handlers across the service, including waiters
  and streaming requests, and must be at least 2 for split server modes.
  Body pumps start only after packet byte/reorder admission;
  waiting packets do not each absorb an extra four-slot application pipe.
  H2 rejects never-admitted excess POSTs with `REFUSED_STREAM`, preserving the
  existing session. The pinned Xray transport can replay these requests with bounded
  backoff; HTTP 503 cannot provide that recovery. Refusal is not an unlimited-stall
  guarantee or a universal retry mechanism: Shoes does not replay submitted POSTs,
  and Mihomo does not provide Xray's replayable body. H1/H3 per-session overflow
  still terminates the session. Hard limits and inactivity expiry remain backstops,
  not promises of lossless operation under arbitrary overload.
  Attached sessions wait for late predecessors beyond the default 30-packet reorder
  window, subject to this request cap and packet inactivity timeout. Unattached
  sessions still reject out-of-window packets.
  Budget `max_session_buffered_bytes` for the desired bandwidth-delay product
  and packet queue, not a fixed POST concurrency multiplier. Server download
  pipes have an independent allowance of the same size, so a full packet queue
  cannot block a write-before-read handshake locally. All pipes still share the
  global byte budget. Smaller budgets remain valid,
  but concurrent bodies can exhaust shared transport credit before their
  predecessors finish. Byte caps do not provide per-session transport isolation:
  stalled consumers or global byte-budget exhaustion can also block other sessions
  on the same carrier. Server packet inactivity timeouts still bound stalled waits.
  Slowly progressing sessions can hold global byte-budget capacity and shared
  carrier flow-control credit indefinitely, so other sessions may time out.
- H2 receive windows default to 4 MiB per stream and 8 MiB per connection through
  `limits.h2_stream_window_bytes` and `limits.h2_connection_window_bytes`. The
  stream window is capped by session/global byte limits; the connection window
  is capped by the global limit, with HTTP/2's mandatory 65535-byte minimum.
  Increase both the window and byte limits for higher bandwidth-delay products.
  Transport buffers are additional to application-accounted bytes: window limits
  apply per carrier, not to total RSS. Exposed servers also need connection limits.
- The server bounds the initial TCP HTTP header/preface to four seconds after
  transport setup (or the shorter configured setup timeout). H1 keep-alive idle
  periods and subsequent partial headers have no deadline. For exposed listeners,
  set `global_limits.max_connections` and `global_limits.max_connections_per_ip`.
- Xray 26.10.10's H1 packet-up uploader can lose pipelined requests when Go GC
  discards pooled connections with unread responses. Sustained uploads to slow
  destinations can therefore fail despite bounded server backpressure. Prefer
  H2/H3 or a streaming mode for these clients; disabling GC is not a production fix.
- Advanced placement/padding obfuscation, custom session IDs, separate downloads,
  full XMUX policy, and Vision over XHTTP are not supported. Unsupported options
  are rejected rather than silently ignored. Public CDN compatibility is not implied.
- REALITY XHTTP interoperates with Xray 26.10.10 in both directions over H2,
  including all three modes and `auto`. REALITY prefers X25519MLKEM768 with
  X25519 fallback according to the cover target. Optional `mldsa65_seed` and
  `mldsa65_verify` apply to the outer REALITY configuration, independently of
  XHTTP; see [CONFIG.md](CONFIG.md#reality-client).

## Similar Projects

- [apernet/hysteria](https://github.com/apernet/hysteria)
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [EAimTY/tuic](https://github.com/EAimTY/tuic)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
