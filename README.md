# shoes

shoes is a high-performance multi-protocol proxy server written in Rust.

## Supported Protocols

### Proxy Protocols
- **HTTP/HTTPS**
- **SOCKS5** (with UDP ASSOCIATE)
- **Mixed** (auto-detect HTTP/SOCKS5)
- **VMess AEAD**
- **VLESS** (native encryption, resumption, and fallback for unencrypted VLESS)
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
- **WireGuard** - Userspace TCP/UDP server and client protocols using GotaTun, without root, an OS TUN, or host route changes (Unix only). See [WireGuard configuration](CONFIG.md#wireguard).
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
- **TLS with SNI routing**: Select the outer TLS handler by Server Name Indication
- **Opt-in TCP hostname sniffing**: Match inner TLS SNI or cleartext HTTP/1 Host without changing the connection destination ([TLS example](examples/sni_sniffing.yaml), [HTTP example](examples/http_host_sniffing.yaml), [semantics](CONFIG.md#tcp-hostname-sniffing))
- **Upstream proxy chaining**: Multi-hop chains with load balancing
- **Rule-based routing**: Route by IP/CIDR or hostname masks
- **Named PEM certificates**: Define once, reference everywhere
- **Live certificate sources**: Shared TLS/QUIC file rotation and built-in ACME HTTP-01/TLS-ALPN-01 ([configuration](CONFIG.md#certificate-sources))
- **TLS fingerprint authentication**: Certificate pinning for TLS/QUIC
- **Hot reloading**: Apply config changes without restart
- **Unix socket support**: Bind to Unix domain sockets
- **Optional Clash controller**: Named selectors, connection monitoring/cancellation, outbound delay tests, and optional selector persistence ([configuration](CONFIG.md#clash-controller), [example](examples/clash_api.yaml))

For advanced access control (IP allowlist/blocklists), see [tobaru](https://github.com/cfal/tobaru).

## Installation

Building Shoes requires Rust 1.95 or newer. Unix WireGuard builds include
MPL-2.0-covered GotaTun code; binary and library distributors must retain
[the dependency notices and corresponding source information](THIRD_PARTY_NOTICES.md).

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

The `blake3` patch pins our [binary-context fork](https://github.com/cfal/BLAKE3/tree/cd98c1c4112ed3b2cf2140e1844f266b3d665b53),
rebased onto upstream buffer-alignment and AVX-512 soundness fixes. VLESS Encryption
requires `derive_key_bytes` for contexts that are not valid UTF-8. Retain the patch
until a registry release provides equivalent binary-context derivation; validate
updates against the fork's tests and Shoes' Go-derived VLESS vectors.

The `nix` patch pins an [upstream commit](https://github.com/nix-rust/nix/commit/3eae6d68ec6382fef7b38cd58f97458e59a71af9)
containing [nix #2821](https://github.com/nix-rust/nix/pull/2821) for iOS socket
compatibility. Retain it until adopting a registry release containing that fix.

The `smoltcp` patch pins a commit from our [fork's main branch](https://github.com/cfal/smoltcp/tree/a80fa50dce926117669ef061f55f4d6bdad0904a)
to preserve TCP ACK sequencing during partial retransmission in TUN and WireGuard.
Retain it until adopting a registry release with equivalent loss-recovery fixes.
When updating the pin, run the fork's `socket::tcp::test::` regressions with Reno
and CUBIC enabled, plus Shoes' rootless TUN and WireGuard suites.

GitHub releases and checkout builds retain these patches. Crates.io publishing
remains disabled because Cargo removes workspace patches from published packages.
Remove the H3 patches only after adopting fixed registry versions that pass the
H3 empty-DATA and idle-stream regressions. Remove the publishing guard only when
all workspace patches have been replaced with registry dependencies. To install
this revision from its checkout:

```bash
cargo install --path . --locked
```

After updating the H3 pins, run the empty-DATA and idle-stream regressions:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --lib --features ffi h3_ -- --test-threads=1
```

### Mobile Embedding

Android and iOS embedding remains supported through the Rust JNI/C interfaces.
This repository does not ship Kotlin wrappers, AARs, or XCFrameworks. Applications
own their platform glue and packaging, including Android `VpnService` or iOS
Network Extension setup.

For Android, install `cargo-ndk`, set `ANDROID_NDK_HOME` to an installed Android
NDK, and build the native libraries:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi
CARGO_BUILD_JOBS=1 cargo ndk -t arm64-v8a -t armeabi-v7a -P 21 -- build --release --lib --locked
```

The resulting `target/<target>/release/libshoes.so` files expose the JNI methods
in `src/ffi/android.rs`. The app supplies the matching
`com.shoesproxy.ShoesNative` declarations and socket-protection callback.
The callback object must expose `protect(fd: Int): Boolean`, delegating to
`VpnService.protect`; a plain Kotlin lambda does not satisfy this JNI contract.

For iOS, build on macOS with Xcode installed. These commands match CI's deployment
target; set it to match the consuming app when integrating:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
export IPHONEOS_DEPLOYMENT_TARGET=16.0
CARGO_BUILD_JOBS=1 cargo build --release --lib --locked --target aarch64-apple-ios
CARGO_BUILD_JOBS=1 cargo build --release --lib --locked --target aarch64-apple-ios-sim
```

Link `target/<target>/release/libshoes.a` using `include/shoes.h` through the app's
bridging header or module map. After changing the C interface, use cbindgen 0.29.4
to regenerate the header with
`cbindgen --config cbindgen.toml --output include/shoes.h`. CI verifies the header
matches the Rust interface.

On both platforms, the app supplies `device_fd` in the TUN configuration and
retains ownership of that descriptor until the native service has stopped.
Distribute [the dependency notices and source information](THIRD_PARTY_NOTICES.md)
with the app. CI cross-compiles the native libraries without packaging or
publishing a mobile SDK.

### Docker

GHCR images are published at `ghcr.io/cfal/shoes` for `linux/amd64` and
`linux/arm64`:

- `master` follows the current branch head after both architectures pass the
  container smoke test.
- `sha-<full commit SHA>` is published before smoke verification and pins a
  commit image; retries and releases reuse it.
- A published GitHub release adds its exact tag, such as `v0.3.4`.
- `latest` is set only by a `published` release event when that stable release
  is GitHub's latest at promotion time.

Only `master`, release tags, and `latest` wait for successful smoke tests.
Converting a prerelease to stable or changing GitHub's latest release later
does not update the image tags.

Draft releases and tag pushes alone do not publish release image tags. Release
tag names must be valid Docker tags; `master`, `latest`, `buildcache*`, and `sha-*`
are reserved. Publishing uses the repository's `GITHUB_TOKEN` with package
write permission. After the first publication, make the GHCR package public
in its package settings to allow anonymous pulls. Forks publish under their
own repository name.

```sh
docker pull ghcr.io/cfal/shoes:master
```

Build the release binary and its runtime image from the checkout:

```sh
docker build -t shoes:local .
```

Verify the image on Linux with Python 3.11 or newer:

```sh
python3 scripts/smoke-docker.py shoes:local
```

The image runs as UID/GID `65532:65532` and reads `/etc/shoes/config.yaml` by
default. Create a `config` directory containing `config.yaml`, for example:

```yaml
- address: "0.0.0.0:1080"
  protocol:
    type: socks
```

Mount the whole directory so configuration reloads also see files replaced by
an editor. Configuration, certificates, and keys must be readable by the
container user; relative paths resolve from `/etc/shoes`.

```sh
docker run --rm --name shoes \
  --publish 127.0.0.1:1080:1080 \
  --mount type=bind,src="$(pwd)/config",dst=/etc/shoes,readonly \
  ghcr.io/cfal/shoes:master
```

Use `shoes:local` instead to run the checkout build.

Files Shoes writes cannot live in the read-only `/etc/shoes` mount. Give
`cache_file_path`, fake DNS `state_file`, Unix socket listeners, and `--log-file`
targets absolute paths on a separate writable mount owned by the container
user. For example, create a private state directory:

```sh
mkdir -p state
sudo chown 65532:65532 state
sudo chmod 700 state
```

Set `cache_file_path: /var/lib/shoes/cache.db` in the configuration and add this
option to `docker run`:

```sh
--mount type=bind,src="$(pwd)/state",dst=/var/lib/shoes
```

Publish UDP ports separately for UDP listeners. Bind listeners to `0.0.0.0`
inside the container; host port bindings control which clients can reach them.
Configure authentication before exposing a proxy beyond the host.

Arguments after the image name replace the default configuration argument:

```sh
docker run --rm shoes:local --version
docker run --rm \
  --mount type=bind,src="$(pwd)/config",dst=/etc/shoes,readonly \
  shoes:local check /etc/shoes/config.yaml
```

The runtime includes CA certificates and the license/source notices under
`/usr/share/doc/shoes`. No configuration or credentials are baked into it.
Ordinary proxy and userspace WireGuard listeners need no extra capabilities.
Linux TUN configurations require `--user 0:0`, `--cap-add NET_ADMIN`, and
`--device /dev/net/tun`; their network changes remain in the container's network
namespace unless host networking is explicitly selected.

### WireGuard Kernel Interoperability

Linux kernel peer tests require kernel WireGuard support, network/PID namespaces,
passwordless sudo, `ip`, `wg`, `unshare`, and `timeout`. They run both Shoes roles
inside isolated namespaces without changing host routes. Coverage includes
inner IPv4/IPv6 TCP and UDP, TCP half-close, PSK/no-PSK, MTUs 1280/1408, and VLESS
chaining in both directions. Kernel handshake and byte counters verify that
payloads actually cross WireGuard. Outer-chain cases require SOCKS -> VLESS before
WireGuard, optionally with VLESS after it, and use an unreachable destination that
only the outer proxy can translate, including IPv6 outer destinations. The 64-case
matrix is supplemented by carrier outage/recovery, a real two-minute rekey with
the same TCP flow, concurrent kernel peers, cross-peer source spoofing rejection,
and wrong-PSK rejection/recovery. Missing prerequisites fail rather than skip.
Set `SHOES_TEST_WG_BIN` to an absolute path to override `wg`.

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --features privileged-tests --test privileged wireguard_kernel:: -- --test-threads=1
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

### Native VLESS Encryption

Generate matching client `encryption` and server `decryption` strings:

```sh
shoes generate-vless-encryption
shoes generate-vless-encryption --auth x25519 --auth mlkem768 --mode random
shoes generate-vless-encryption --auth x25519 --rtt 1rtt --lifetime 0s
```

The default uses ML-KEM-768 authentication, `native` appearance, and resumable
sessions with a maximum 600-second ticket lifetime. Repeated `--auth` options
form an ordered key chain; preserve that order on both ends. Private credentials
are printed only by the generator and should be treated as passwords.

Put the generated settings on the VLESS protocol itself. Native Vision uses
`vision: true` at that same level. When wrapping native VLESS in TLS or REALITY,
leave the **outer** `vision` flag false. Native DIRECT removes only the native
record encryption; it never bypasses an outer TLS, REALITY, WebSocket, XHTTP, or
QUIC transport. Existing encryption-disabled Vision configurations keep their
outer TLS/REALITY flag unchanged. See [the native example](examples/vless_encryption.yaml).

The appearances `native`, `xorpub`, and `random` share the same encrypted protocol.
`xorpub` masks the key-exchange relay; `random` additionally masks record headers,
including application TLS headers after Vision DIRECT. Random mode cannot use
TCP splice. Fresh exchanges combine ephemeral ML-KEM-768 and X25519; Vision
DIRECT subsequently relies on the application's own TLS, which is not necessarily
post-quantum. Native encryption works with pinned Xray and Mihomo peers, not
sing-box. Empty settings and `none` preserve unencrypted VLESS.
Server `encryption` and client `decryption` are rejected; use the setting for the
correct side rather than swapping the generated strings.

Native decryption rejects VLESS fallback. Native Vision rejects H2MUX; encrypted
VLESS without Vision supports H2MUX. Command-2 UDP uses an empty flow, while
XUDP may use Vision. No failed encrypted connection is silently retried as
plaintext or automatically replayed to a destination.

Server `encryption_limits` defaults are `max_sessions: 4096`,
`max_replays: 262144`, and `max_replays_per_session: 65536`. All must be positive.
Size replay limits for the expected resumption rate times the maximum ticket
lifetime plus the 120-second retention grace.
At 75% session/replay occupancy, new connections receive zero-lifetime tickets
and remain usable through fresh handshakes. At the hard replay limit, the whole
requesting ticket is invalidated; that resumption fails, and the next independent
connection performs a fresh handshake. New resumable tickets are issued only
once both session and replay occupancy fall below 75%. Duplicate resumes never
repeat destination I/O.
Ticket state is shared across addresses of one logical listener, not across
different protocol targets. Reloads reset ticket state; existing streams retain
their cryptographic state. TLS/REALITY/QUIC resumption is independent.

Rollback requires rolling back configuration as well as the binary: older Shoes
versions silently ignore native encryption fields. Conversely, a previously
ignored VLESS-level `vision: true` without native encryption now produces a
migration error instead of silently disabling Vision.

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
  including OPTIONS, so browser preflights without them are rejected. Names are
  case-insensitive; values must match exactly and occur only once, and an empty
  value requires a present, empty header. Requests that fail the check get a
  plain 404 on every HTTP version, without session admission or body reads;
  other requests sharing an H2/H3 connection are unaffected. Configure the
  client's `headers` with the same values, for example
  `matching_headers: { X-Tunnel-Key: "replace-me" }` on the server and
  `headers: { X-Tunnel-Key: "replace-me" }` on the client. Xray clients that
  set `extra` must put `headers` inside `extra`; Xray ignores top-level
  `headers` when `extra` is present. A value may also be a list, such as
  `X-Tunnel-Key: [old, new]`, to accept any one of them while rotating
  secrets. Use `host`, not `matching_headers`, to match Host/`:authority`.
- XHTTP error responses are plain: a status code and an empty body, without
  padding, caching, or CORS headers.
- `host` overrides HTTP authority independently of TLS SNI. Default Referer
  padding, path/query handling, packet sizing/pacing, and stream-up keepalives
  follow modern Xray. `limits` can bound sessions, buffered bytes and requests;
  setup/header deadlines and packet inactivity remain bounded by default.
  `pool` bounds connections and idle retention.
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
- XHTTP client and server admission caps are opt-in:
  `limits.max_sessions`, `max_pending_sessions`, `max_requests`,
  `max_requests_per_session`, `max_buffered_bytes` and `max_session_buffered_bytes`
  default to unlimited. Omitted or `null` caps are unlimited, except that setting
  an aggregate byte or request cap also supplies a per-session safeguard when
  its corresponding session cap is omitted or `null`: `min(max_buffered_bytes,
  4194304)` bytes or 128 requests. The aggregate cap still applies when lower.
  This preserves ordered-packet headroom and bounds one session's admission waiters. Explicit
  session caps override these fallbacks. Values must be positive
  (`max_requests_per_session` must be at least 2).
  `limits.max_requests_per_connection` defaults to 250. Explicit global limits
  still apply. Packet sizes, reorder windows, timeouts and transport flow-control
  windows remain bounded. Without admission or byte caps, overload can consume
  more memory; configure explicit caps when resource isolation is required.
- H2/H3 packet-up follows Xray's paced, write-gated pipeline: the next POST may start
  after the preceding body is transmitted, without waiting for its ACK. Client
  `packet_pipeline_depth` defaults to 30 (minimum 1), matching the reference peers'
  default reorder depth. The window advances only through consecutive ACKs, so
  later ACKs cannot accumulate an unbounded sequence gap at a stalled peer.
  Larger depths require a correspondingly larger peer reorder queue. Explicit
  server request limits must accommodate the effective client POST depth plus
  one reserved head slot in server
  `limits.max_requests_per_session` (31 for the default H2/H3 client depth).
  Lower the client depth when using a smaller server cap; Shoes does not replay
  refused POSTs. Pool, byte and client request limits may reduce the effective depth.
  Each H2/H3 packet-up session can hold up to the effective POST depth plus one
  download slot in the shared pool (31 slots at the default depth). Delayed ACKs
  retain those slots; several stalled or high-latency sessions can fill the pool
  and refuse new sessions, including sessions to healthy destinations.
  The effective client `limits.max_requests_per_session` is an additional
  ceiling: one slot is for the download leg. `limits.max_requests`, when configured,
  bounds outstanding POSTs across a client instance. Reaching
  either client bound backpressures the local writer. Pool limits may constrain
  concurrency further. H1 keeps one ACK-gated POST on a reusable upload connection,
  plus the download connection; it does not open opportunistic upload connections
  or use raw HTTP/1 pipelining. Use H2/H3 for high-latency packet-up throughput.
  Unsent bytes remain subject to any configured byte budgets;
  successfully transmitted bodies are not retained while awaiting ACKs.
  Outstanding POST payload sizes also count against a separate logical credit
  limit when a session byte cap is configured or derived, bounding peer-side
  backlog without keeping sent allocations or consuming the download's memory allowance.
  Tiny writes are coalesced into allocations of at most 16 KiB while transferring
  their existing byte permits, avoiding per-write metadata and small-DATA-frame
  amplification without throttling datagram-sized writes.
  On the server, the effective `limits.max_requests_per_session` bounds live packet
  requests across carriers, including empty bodies, duplicates and admission waiters.
  One slot is reserved for a missing head packet. An explicit `limits.max_requests`
  additionally bounds all active HTTP request handlers across the service,
  including waiters and streaming requests, and must be at least 2 for split server modes.
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
  window, subject to packet inactivity and any configured or derived request cap.
  Unattached sessions still reject out-of-window packets.
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
  stream window is capped by the effective (configured or derived) session byte
  limit and any configured global byte limit. The connection window is capped
  by an explicit global byte limit, with HTTP/2's mandatory 65535-byte minimum.
  Increase windows and effective byte limits for higher bandwidth-delay products.
  When a global byte cap is set, stream windows above 4 MiB also require an
  explicit `limits.max_session_buffered_bytes` above 4 MiB.
  Transport buffers are additional to application-accounted bytes: window limits
  apply per carrier, not to total RSS. Exposed servers also need connection limits.
- The server bounds the initial TCP HTTP header/preface to four seconds after
  transport setup (or the shorter configured setup timeout). H1 keep-alive idle
  periods and subsequent partial headers have no deadline. For exposed listeners,
  set `global_limits.max_connections` and `global_limits.max_connections_per_ip`.
- Xray's H1 packet-up uploader (observed on 26.10.10) can lose pipelined requests
  when Go GC discards pooled connections with unread responses. Sustained uploads
  to slow destinations can therefore fail despite bounded server backpressure.
  Prefer H2/H3 or a streaming mode for these clients; disabling GC is not a production fix.
- Advanced placement/padding obfuscation, custom session IDs, separate downloads,
  full XMUX policy, and legacy Vision over XHTTP are not supported. Unsupported
  options are rejected rather than silently ignored. Public CDN compatibility is not implied.
- REALITY XHTTP interoperates with Xray 26.10.21 in both directions over H2,
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
