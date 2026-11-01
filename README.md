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
- **Sudoku TCP mask** (Xray FinalMask-compatible, composable client/server wrapper; [configuration](https://shoes-rs.github.io/protocols/sudoku/))

### TUN/VPN Mode
- **WireGuard** - Userspace TCP/UDP server and client protocols using GotaTun, without root, an OS TUN, or host route changes (Unix only). See [WireGuard configuration](https://shoes-rs.github.io/protocols/wireguard/).
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
- **Opt-in TCP hostname sniffing**: Match inner TLS SNI or cleartext HTTP/1 Host without changing the connection destination ([TLS example](examples/sni_sniffing.yaml), [HTTP example](examples/http_host_sniffing.yaml), [semantics](https://shoes-rs.github.io/routing/rules/#tcp-hostname-sniffing))
- **Upstream proxy chaining**: Multi-hop chains with load balancing
- **Rule-based routing**: Route by IP/CIDR or hostname masks
- **Named PEM certificates**: Define once, reference everywhere
- **Live certificate sources**: Shared TLS/QUIC file rotation and built-in ACME HTTP-01/TLS-ALPN-01 ([configuration](https://shoes-rs.github.io/security/certificates/))
- **TLS fingerprint authentication**: Certificate pinning for TLS/QUIC
- **Hot reloading**: Apply config changes without restart
- **Unix socket support**: Bind to Unix domain sockets
- **Upstream groups and optional Clash controller**: Round-robin, manual selectors, and automatic URL tests (without an API listener); connection monitoring/cancellation and optional selector persistence ([configuration](https://shoes-rs.github.io/routing/clash-controller/), [example](examples/clash_api.yaml), [URL-test example](examples/url_test.yaml))

For advanced access control (IP allowlist/blocklists), see [tobaru](https://github.com/cfal/tobaru).

## Installation

Building Shoes requires Rust 1.99.1 or newer. Unix WireGuard builds include
MPL-2.0-covered GotaTun code; binary and library distributors must retain
[the dependency notices and corresponding source information](THIRD_PARTY_NOTICES.md).
See [dependency maintenance](DEPENDENCIES.md) for protected forks, update
constraints and required integration checks.

Precompiled binaries are available on [GitHub Releases](https://github.com/cfal/shoes/releases)
for Linux x86_64/aarch64 and macOS Intel/Apple Silicon. The next release also adds
Linux ARMv7 hard-float (`armv7-unknown-linux-gnueabihf` and
`armv7-unknown-linux-musleabihf`), for CPUs that support 32-bit ARMv7 hard-float
execution, not ARMv6 devices. GNU builds require a matching glibc userspace;
musl builds are statically linked. ARMv7 release smoke checks run under QEMU,
not on physical boards.

Starting with the next release, releases provide a separate `SHA256SUMS` asset
and GitHub build-provenance attestations. From the directory containing the
downloaded archives and checksum file:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify shoes-armv7-unknown-linux-musleabihf.tar.gz --repo cfal/shoes
```

On macOS, use `shasum -a 256 --check SHA256SUMS` (download all listed archives or
check the selected archive's entry). Attestations verify build provenance, not
Apple Developer ID signing or notarization; macOS signing is not yet provided.

For the previously published release:

```bash
cargo install shoes
```

GitHub release builds pin `h3` and `h3-quinn` to the
[`cfal/h3` fork](https://github.com/cfal/h3/tree/90e3013710e35143d1969dc3421f5951fbe49966),
including the [empty-DATA fix](https://github.com/hyperium/h3/pull/373).
Empty HTTP/3 DATA frames must not be treated as body EOF; XHTTP uses them for
idle cancellation probes. The fork also backports
[bounded frame buffering](https://github.com/hyperium/h3/pull/366): oversized
buffered frames are rejected from their declared lengths, and unknown-frame
payloads are skipped incrementally. The fork defaults the local decoded-header
limit to 64 KiB; callers can set their own limit. DATA payloads remain streamed.
The workspace patches cover direct and transitive
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

The `smoltcp` patch pins our [rebased TCP recovery fork](https://github.com/cfal/smoltcp/tree/042e568bfa39d0f111a23a4718ec257e474fd1e7)
to preserve TCP ACK sequencing during partial retransmission in TUN and WireGuard.
It tracks unreleased upstream main after 0.14.0, including the receive-window arithmetic fix;
see [fork maintenance notes](DEPENDENCIES.md#smoltcp) for provenance and invariants.
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

For Android, install `cargo-ndk` 4.1.2, set `ANDROID_NDK_HOME` to an installed Android
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

See the [configuration documentation](https://shoes-rs.github.io/) for guides, protocol-specific reference pages, and copyable examples. [CONFIG.md](./CONFIG.md) is a short source index.

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

See the [VLESS Encryption reference](https://shoes-rs.github.io/protocols/vless-encryption/)
for credential generation, native Vision composition, resumption limits, and
rollback considerations.

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
Hysteria2 and TUIC also support native QUIC clients with TCP and UDP. See
[Hysteria2 client configuration](https://shoes-rs.github.io/protocols/hysteria2/) and
[runnable client examples](examples/quic_clients.yaml). Hysteria2 clients support
Salamander and port hopping; TUIC clients support both UDP relay modes.

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

See the [XHTTP configuration reference](https://shoes-rs.github.io/protocols/xhttp/) for modes, limits, placement, and complete examples.

## Similar Projects

- [apernet/hysteria](https://github.com/apernet/hysteria)
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [EAimTY/tuic](https://github.com/EAimTY/tuic)
- [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core)
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
