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
- `cfal/hickory-dns`: connection-close recovery, healthy-upstream failover and
  bounded TCP/DoT receive progress.
- `cfal/smoltcp`: TUN/WireGuard TCP retransmission ACK sequencing.
- `mullvad/gotatun`: upstream's portable 64-bit atomics for targets without
  native support, including MIPS32.

Preserve each repository and full revision unless explicitly updating that fork.
Check every resolved consumer, especially Quinn, tokio-rustls, hyper-rustls,
rustls-platform-verifier, Hickory and Shoes; absence of unused-patch warnings is
not sufficient. Keep `publish = false` while workspace patches remain.

### GotaTun

Pinned to upstream main at `c06582e41022bcecbf33751631fd5a63d5794dc5`, including
[#221](https://github.com/mullvad/gotatun/pull/221). Published 0.10.2 lacks that
fix despite sharing the package version. The git workspace also splits out
`gotatun-crypto` and `gotatun-packet`; retain their matching source revision and
the corresponding source links in `THIRD_PARTY_NOTICES.md`. Shoes keeps AWS-LC
and uses its own conditional atomic imports on targets without 64-bit atomics.

### Hickory

The stable base remains [v0.26.3](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3),
[`bd37cafbdd86112a6da32878f8c9bab22e14377e`](https://github.com/hickory-dns/hickory-dns/commit/bd37cafbdd86112a6da32878f8c9bab22e14377e).
As of November 7, 2026, this is the latest non-yanked stable release of
`hickory-net`, `hickory-proto` and `hickory-resolver`; all three published crate
archives identify that exact source commit. The release branch has newer,
unreleased commits despite still declaring 0.26.3; main is 0.27.0-alpha.1.
Neither is a published stable upgrade.

The maintained series is pinned at
[`14df4ec4d6c501e23d7815cecd7f556b1cece4a1`](https://github.com/cfal/hickory-dns/commit/14df4ec4d6c501e23d7815cecd7f556b1cece4a1)
on `shoes/0.26.3-multiplexer-wakeup-20261107-1794067200053000`.
It retains both original commits from `fix/0.26-closed-transport-failover`,
including the previous Shoes pin
[`3fa0a0e3ebd9df778256f18e9264f70d284d31c0`](https://github.com/cfal/hickory-dns/commit/3fa0a0e3ebd9df778256f18e9264f70d284d31c0)
as an ancestor. Existing published branches and tags remain intact. The fork's
default branch does not carry the complete series; discover published refs
before choosing a maintenance source.

The additional patch backports upstream
[`a14d6027eca8a1cdcc3ef1d5d2deeafed21175b0`](https://github.com/hickory-dns/hickory-dns/commit/a14d6027eca8a1cdcc3ef1d5d2deeafed21175b0):
count received messages rather than their zero-based index, so consuming the
100-message receive budget schedules another poll. The budget itself is
unchanged. Shoes retains the 32-request per-connection limit, so this is not a
normal high-concurrency lookup failure. A buffered burst of unsolicited or stale
responses can nevertheless hide a valid answer behind that limit. Local,
certificate-verified DoT regressions reproduce timeouts in both hostname lookup
and raw exchange with 100 unsolicited responses, while 0 and 99 are controls.
The backport lets both paths finish without another query, reconnect or retry.

The original series backports upstream #3861's typed `ConnectionClosed` design
and adds narrowly scoped H3 recovery. Disconnected exchange channels are not
`Busy`; genuine queue pressure still is. H3 body errors retain their type,
remote whole-connection `ApplicationClose` is recognized alongside existing
clean-close handling, and stream-level `H3_REQUEST_CANCELLED` remains distinct.
The pool preserves healthy pending siblings and meaningful exhausted-pool
errors. The existing reused/fresh/repeated-close reconnect budgets remain
unchanged. Upstream merging #3861 does not supersede the complete H3 additions.
Neither this work nor external DNS successes establish the cause of Cloudflare's
original application close.

The multiplexer backport leaves package versions, public APIs, features,
Rust 1.88 minimum, platform support, server scoring and negative-response policy
unchanged. In particular, the
unreleased SERVFAIL retry change and connection-setup SRTT changes are not
included. Keep the resolver/net/proto pins together and verify tendns also uses
the fork proto, with no split registry/git types. Preserve the shared rustls and
h3/h3-quinn fork graph and the publishing guard.

Future refreshes must retain the closed-exchange, H3 body/classification,
pool-failover, error-precedence and exact reconnect-count regressions. Run the
standalone production check `cargo check -p hickory-net --locked --features
h3-aws-lc-rs` as well as tests: H3's test-only backend feature can hide production
compilation errors. Test Shoes' high-level hostname resolver and separate raw
exchange path, including buffered-response progress, deadlines, configured
routing and H3 socket-memory teardown.

### smoltcp

The maintained TCP recovery series originates on published `cfal/smoltcp` main
(`a80fa50dce926117669ef061f55f4d6bdad0904a`), based on upstream
`72a0d7892d696620541b1147c7cac471d421e554`, not the older release-based
`fix/tcp-ack-sequence` branch. The October refresh added regression coverage and
rebased it onto `24bda3b4f982625d8453d4360172557d24921c76`, producing the previous
pin [`042e568bfa39d0f111a23a4718ec257e474fd1e7`](https://github.com/cfal/smoltcp/commit/042e568bfa39d0f111a23a4718ec257e474fd1e7).

The November 2026 refresh retains all three October commits on upstream
[`8b0e5c8598647fe92e2a1b87932d1932354fee0b`](https://github.com/smoltcp-rs/smoltcp/commit/8b0e5c8598647fe92e2a1b87932d1932354fee0b).
The series lives on `shoes/tcp-recovery-20261107-000034`, pinned at
[`7ef43e497f575cb0340a43e4f414f0f0b8760bf6`](https://github.com/cfal/smoltcp/commit/7ef43e497f575cb0340a43e4f414f0f0b8760bf6);
existing branches, tags and old pins remain intact.

The package version and latest stable registry release remain **0.14.0**.
The new upstream changes are unreleased: [#1242](https://github.com/smoltcp-rs/smoltcp/pull/1242)
cancels an armed idle keepalive deadline when `set_keep_alive(None)` is called,
without cancelling retransmission, persist or closing timers. Shoes uses this
when draining orphaned connections. [#1238](https://github.com/smoltcp-rs/smoltcp/pull/1238)
ends SLAAC polling after router solicitations are exhausted, and
[#1240](https://github.com/smoltcp-rs/smoltcp/pull/1240) adds `Interface::reset_slaac()`.
SLAAC remains disabled in Shoes. Features, dependencies, Rust minimum and
platform requirements are unchanged; no Shoes adapter changes are required.
Earlier RTO bounds, zero-window timer recovery, failed-fast-retransmission retry,
no-std CUBIC and full-window FIN clamping fixes remain included.

The refresh also fixes upstream's optional-deadline combination: an exhausted
SLAAC timer must not erase a pending socket deadline, and an idle socket set must
not erase a pending solicitation. An interface regression exercises exhaustion,
a pending TCP SYN, restarted solicitation scheduling and competing deadlines.
The keepalive sequence regression adds an open-window case that distinguishes
SND.UNA from the frontier, alongside the existing closed-window case. Both check
that probes leave the retransmission cursor and send frontier unchanged.

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
