# Dependency Maintenance

Refresh registry dependencies and maintained build tools without changing peer
fixtures. Change supported Rust/platform floors only when explicitly requested.
Use targeted Cargo updates and inspect source changes as well as versions.
Existing wildcard requirements are intentional; narrower requirements must be
reconsidered when upstream advances.
Regenerate [dependency notices](THIRD_PARTY_NOTICES.md) after lockfile changes.

## Protected Sources

The workspace patches in `Cargo.toml` are required by checkout/release builds:

- `cfal/rustls`: REALITY/TLS integration; retain the matching exact rustls
  requirements in both workspace manifests.
- `cfal/BLAKE3`: binary-context derivation for VLESS Encryption.
- `cfal/h3`: empty-DATA handling and idle-stream cancellation, plus the
  [bounded-frame backport](https://github.com/hyperium/h3/pull/366) that rejects
  oversized buffered frames from their declared lengths and skips unknown-frame
  payloads incrementally. The fork also defaults the local decoded-header limit
  to 64 KiB. Used by both Shoes and Hickory through h3/h3-quinn.
- `cfal/hickory-dns`: connection-close recovery and healthy-upstream failover.
- `cfal/smoltcp`: TUN/WireGuard TCP retransmission ACK sequencing.

Preserve each repository and full revision unless explicitly updating that fork.
Check every resolved consumer, especially Quinn, tokio-rustls, hyper-rustls,
rustls-platform-verifier, Hickory and Shoes; absence of unused-patch warnings is
not sufficient. Keep `publish = false` while workspace patches remain.

### smoltcp

The October 2026 refresh rebases the two TCP recovery commits from published
`cfal/smoltcp` main (`a80fa50dce926117669ef061f55f4d6bdad0904a`) onto upstream
[`24bda3b4f982625d8453d4360172557d24921c76`](https://github.com/smoltcp-rs/smoltcp/commit/24bda3b4f982625d8453d4360172557d24921c76).
Their previous upstream base was `72a0d7892d696620541b1147c7cac471d421e554`,
not the older release-based `fix/tcp-ack-sequence` branch. The new series lives
on `shoes/tcp-recovery-20261028-GsfiI8`, pinned at
[`042e568bfa39d0f111a23a4718ec257e474fd1e7`](https://github.com/cfal/smoltcp/commit/042e568bfa39d0f111a23a4718ec257e474fd1e7);
existing branches and old pins remain intact.

The package version and latest registry release are still **0.14.0**. The new
upstream change is unreleased [smoltcp #1223](https://github.com/smoltcp-rs/smoltcp/pull/1223):
defensively clamp the remaining advertised receive window after FIN consumes
sequence space at a full window. Earlier post-release RTO bounds, zero-window
timer recovery, failed-fast-retransmission retry and no-std CUBIC fixes were
already in our pin and remain included. This refresh changes no public API, features, dependencies,
Rust minimum or platform support.

Preserve the complete recovery patch, not only its persistent send frontier:

- Pure ACKs use the non-rewound frontier; a zero peer window with queued stream
  data uses SND.UNA, while FIN-only flight retains the frontier.
- RSTs retain the baseline retransmission cursor. Fast retransmit cannot extend
  the frontier with unsent data. Keepalive probes use SND.UNA minus one.
- Probes and empty emissions do not advance the retransmission cursor; failed
  emission does not advance the send frontier. Socket reuse resets it.
- Relaxed receive acceptance applies only to empty None/PSH segments, bounded
  by scaling slack, physical receive capacity and the one-byte lost-FIN allowance.

The exact lost-FIN allowance, FIN-only ACK frontier and RST cursor are retained
fork policies, not universal RFC or OS behavior. Keepalive sequence placement
does not establish timer reachability with outstanding data.

Shoes retains explicit CUBIC, IPv4/IPv6, medium-IP and 32-segment assembly.
Linux TUN transmit offload remains IPv4-only: the interface still does not
forward IPv6 segmentation metadata. TUN supplies partial TCP checksums when
offload is enabled; WireGuard's queue device uses software checksums and MTU-sized
packets without segmentation capabilities. Do not enable new offload paths
without checking `Device`, tokens, `PacketMeta`, ownership and poll wakeups.

For future refreshes, discover and compare published fork branches before
rebasing, inspect the complete upstream delta and `range-diff`, and pin the
tested full SHA in both manifest and lockfile. Run the fork's `ci.sh` matrix,
`socket::tcp::test::` with Reno/CUBIC, and library tests with the exact Shoes
feature set. Use separate target directories for baseline comparisons.
The oversized-frame offload fixture selects no congestion control; a separate
CUBIC regression checks its real flight limit. This avoids mistaking the old
fixture's 65 KB expectation under a 2,048-byte CUBIC window for a runtime bug.
Require deterministic loss/window/FIN/reset regressions as well as Shoes'
rootless TUN, shared IP-stack, WireGuard, kernel and macOS rootless-TUN checks.
Neither those tests nor the original [Shoes #197](https://github.com/cfal/shoes/pull/197)
establish the historical macOS stall's cause or comprehensive Linux/BSD/XNU interoperability.

### nix

The `nix-rust/nix` patch is upstream, not a maintained fork. Published 0.31.3
still lacks [#2821](https://github.com/nix-rust/nix/pull/2821), despite sharing
the pinned commit's package version. With libc 0.2.191 and Shoes' iOS features
(`fs,ioctl,net,socket,time,uio,user`), registry 0.31.3 fails to compile on
`aarch64-apple-ios`; the pinned commit succeeds. Retain it until a published
release passes that regression and the complete mobile builds.

## October 2026 Refresh

Registry updates include notify 8.2.1, Web PKI roots/root-certs 1.0.11, ICU 2.4,
ctutils 0.4.6, der 0.8.3, cc 1.10.0, openssl-probe 0.2.2, smallvec 1.16.4,
tinystr 0.8.5, uuid 1.29.0, yoke 0.8.4, zerovec 0.11.9/derive 0.11.7 and
rustix 1.1.6 through the test-only tempfile dependency.
ctutils fixes RUSTSEC-2026-0385; the root set removes two more eMudhra anchors.
ICU updates Unicode/IDNA data, and der tightens malformed DER handling.
Notify changes the macOS FSEvents bindings; stream-wide restart errors must not
be swallowed as optional per-path failures. See the changelog for user effects.

`parking_lot` stays on 0.12.5 (core 0.9.12). Version 0.13/core 0.10 probes
`futex_time64` before the legacy syscall for 32-bit waits and wakes, falling back
only on `ENOSYS`. Android API 26-29 app seccomp instead traps syscall 422 with
`SIGSYS`; API 30 and later explicitly allow it. There is no published fixed
successor. A global 0.12 constraint preserves the API 21 floor without adding
platform-specific lock types or rewriting synchronization. Reconsider when an
Android-safe stable release exists, including 0.13's removed eventual fairness
and the public `DynamicFileLogWriter::new` mutex-type compatibility.
See the [upstream probe](https://github.com/Amanieu/parking_lot/blob/85827ffa2ffb0b60d416e2e2a091f36b0e8e5a91/core/src/thread_parker/linux.rs#L42)
and [Android 8 ARM policy](https://android.googlesource.com/platform/bionic/+/f711b078b9656f7dbb52a046a7f992a450e8fa13/libc/seccomp/arm_policy.cpp#121).

The other non-excluded direct dependencies were already at their latest
non-yanked stable releases, including AWS-LC, Quinn, GotaTun, tun, rcgen,
instant-acme, Tokio and ML-KEM. Prereleases (including notify 9) and unreleased
git commits are not stable upgrades.

Newer incompatible transitive families remain constrained by their parents:
GotaTun retains its older RustCrypto/rand/x25519/thiserror families; Hickory
retains prefix-trie 0.8 and system-configuration 0.7; Quinn retains quinn-udp 0.5;
DashMap retains hashbrown 0.14; prost-derive caps itertools at 0.14; ASN.1
parsers retain nom 7 and num-bigint 0.4. Platform parents likewise constrain
older Windows/JNI/WASI families. Do not force these through patches, extra direct
dependencies, or fork-manifest edits. The deprecated serde_yaml dependency still
pulls unmaintained unsafe-libyaml; replacing the configuration parser is a
separate compatibility change, not an available version bump.

Build tools use cargo-about 0.9.3, cargo-ndk 4.1.2, cross 0.2.5, Node 26 and
the Rust 1.99.1 Docker builder. The Rust minimum is now 1.99.1, checked separately
in CI, and the Docker runtime remains Bookworm. Go 1.27.3, cbindgen 0.29.4 and
cargo-llvm-cov 0.9.1 were already current. Keep peer hashes, frozen Shoes
baselines, fixture-generation provenance and historical benchmark evidence
unchanged when refreshing tooling.

## November 2026 Refresh

The November 6 inventory checks direct, development and transitive dependencies
against non-yanked stable releases. The refresh advances Shoes' BLAKE2 requirement
to 0.11 and rtnetlink to 0.24, and takes ML-KEM 0.3.4, log 0.4.35, mime 0.3.18, cc 1.11.0,
crc32fast 1.5.4, ctutils 0.4.8, module-lattice 0.2.4, notify-types 2.2.0,
netlink-packet-route 0.34, netlink-proto 0.14.1, utf8_iter 1.1/utf_types 1.0,
and wasm-bindgen 0.2.130/js-sys 0.3.107. All protected cfal repositories and
full revisions remain unchanged, including Hickory; the publishing guard remains.

[ML-KEM 0.3.4](https://github.com/RustCrypto/KEMs/releases/tag/ml-kem%2Fv0.3.4)
hardens secret-key formatting, comparisons, reduction and zeroization. Its XOF
sampling optimization must preserve the committed cross-language vectors.
[BLAKE2 0.11](https://github.com/RustCrypto/hashes/blob/blake2-v0.11.0/blake2/CHANGELOG.md)
uses digest 0.11, defaults to `alloc` instead of `std`, and removes its old SIMD
implementation. Salamander still hashes password followed by salt with unkeyed
BLAKE2b-256; full digest vectors cover compression-block boundaries.
GotaTun still requires BLAKE2 0.10 and the older RustCrypto families, so both
BLAKE2 versions are intentional. Its crypto-common 0.1.7 requires exactly
generic-array 0.14.7, blocking even the newer 0.14.9 patch release.

[rtnetlink 0.24](https://github.com/rust-netlink/rtnetlink/releases/tag/v0.24.0)
updates route/link parsing and netlink error handling. Strict kernel checking
remains opt-in; Shoes retains its existing connection construction, request
timeouts and reconciliation. Its nix 0.31 requirement removes the older 0.30
registry copy: Linux rtnetlink now selects the existing upstream git pin too,
enabling its `mount,process,sched,signal` features in the Linux cross-build matrix.
Published nix 0.31.3 still fails the actual iOS feature set with
libc 0.2.191; the unchanged upstream git pin passes that isolated compile check.
Parking_lot 0.13 remains blocked by the Android seccomp issue described above.
The rtnetlink and netlink-proto licenses now use standard MIT text with contributor
attribution instead of their previous modified-MIT bug-reporting condition;
the checksummed clarifications and generated notices retain the new originals.

AWS-LC, Quinn, Tokio, rcgen, instant-acme, GotaTun, tun, tendns and the remaining
eligible direct Rust dependencies were already current. Newer incompatible
transitive families remain constrained by their parents, not forced through
patches or fork edits. Prereleases are not stable upgrade candidates.

Documentation uses Astro 7.4.7, Starlight 0.42.9 and linkedom 0.18.15, with
compatible transitive updates and Node 26 LTS, matching the other Node jobs.
Vite retains rolldown 1.2 while Astro also accepts 1.3; Starlight retains satteri
0.10 while Astro requires 0.11. These parent constraints explain the duplicate
families and their platform-specific native/WASM packages.
Sitemap retains `@types/node` 24 despite the Node 26 build runtime; the shared
type package also satisfies Vite and `@types/sax` without another major copy.
Stable rolldown 1.3.0 requires optional WASM emnapi 2.0.0-beta.2 exactly; that
upstream transitive pin is not a direct prerelease upgrade or a forced override.
Pinned Actions advance Docker login to 4.8.0, release creation to 3.0.4 and build
provenance to 4.2.2. File-subject attestation keeps the existing permissions;
registry storage-record permissions are unnecessary. Artifact names, inputs,
architectures, credentials policy and peer baselines are unchanged.
Rust 1.99.1, Go 1.27.3, cargo-about 0.9.3, cargo-ndk 4.1.2, cbindgen 0.29.4,
cargo-llvm-cov 0.9.1 and cross 0.2.5 remain current.

## Validation

Use [the test guide](tests/README.md) and current workflows for exact commands.
In addition to formatting, strict clippy, unit/process and license checks, run
the pinned REALITY/Vision, VLESS Encryption, XHTTP/H3, Shadowsocks, DNS and
WireGuard suites. Preserve binary-context vectors, H3 empty-DATA/idle-stream
cancellation, TLS authentication and TUN/WireGuard loss-recovery regressions.
Require nonzero test counts and verify that requested peers actually execute.

Hosted macOS watcher/rootless-TUN tests, desktop builds, Android arm64/armv7 and
iOS device/simulator builds remain required. Cross-compilation is not device
runtime coverage; Windows and mobile-device execution are not covered by these
workflows. Do not claim those platforms passed runtime tests.
