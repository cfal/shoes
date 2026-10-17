# VLESS Encryption Fixtures

All credentials and secrets here are public test data. Never deploy them.

`vectors.json` was generated using Xray-core
`0f3d884786f9ec73d3be8899cb6b9e1e6dd3c41e` and Go 1.27.1. It records:

- Binary BLAKE3 contexts, including invalid UTF-8.
- Go ML-KEM-768 seed expansion, public keys and encapsulations.
- Both AEADs with the six protocol contexts, increment-before-use nonces and the explicit all-ones nonce.
- Three records spanning wrapped-zero rekey, including the following key's nonce sequence.
- AES-CTR carry boundaries and permissive header masking under byte-at-a-time writes.

Hex fields preserve the exact bytes. `material` is the last-hop 32-byte NFS secret
for the handshake context and the 96-byte united secret for data contexts. `one`
and `two` use sequential implicit nonces; `max` is explicit and does not advance
the sequence. `rekey.wire` contains three complete records, beginning with the
wrapped-zero record whose unmasked header and ciphertext derive the next key.

To regenerate from a checkout at the pinned Xray revision:

```sh
GOMAXPROCS=1 go run -p 1 /path/to/shoes/tests/fixtures/vless_encryption/generate.go \
  /path/to/shoes/tests/fixtures/vless_encryption/vectors.json
```

ML-KEM encapsulation is randomized on regeneration. Other fields are deterministic.
Rust consumes the committed bytes in ordinary library tests; no Go toolchain is
needed for those tests. To verify the opposite encapsulation direction:

```sh
# In Shoes:
VLESS_RUST_VECTORS="$HOME/vless-rust-vectors.json" CARGO_BUILD_JOBS=1 \
  cargo test --locked --lib export_rust_encapsulations -- --ignored
# In the pinned Xray checkout:
GOMAXPROCS=1 go run -p 1 /path/to/shoes/tests/fixtures/vless_encryption/generate.go \
  --verify-rust "$HOME/vless-rust-vectors.json"
```

The peer suite uses `XRAY_BINARY`, `MIHOMO_BINARY`, `SHOES_TEST_SING_BOX_BIN`, and
optionally `SHOES_TEST_SHOES_BIN`. CI pins Xray 26.10.17
(`92ccc939aaf4f8965f369cf0b142e005aeaa11d5`), including its Vision TLS-buffer
compatibility fix. The committed vectors retain their original provenance above.
Missing requested peers fail rather than skip. The wire tap distinguishes fresh
from resumed handshakes and checks raw DIRECT lengths. Successful transfers plus
secret-free debug diagnostics verify resumption inside opaque carriers.
Xray's command-2 replies are limited to 8190 bytes; its XUDP writer limits
payloads to 7526 bytes. Peer UDP tests use that intersection. Separate Shoes
tests cover larger XUDP frames and preservation of the existing empty-DATA
and control-frame semantics. Sing-box has no native encryption support and is
used only by the legacy TLS/REALITY regression suites.

The enabled matrix covers:

- Native TCP and UDP over TLS, WebSocket, WSS, REALITY, and Shoes raw QUIC.
- Encrypted XHTTP with and without Vision: packet-up, stream-up, and stream-one
  over H1, H2C, H2, H3, and REALITY; auto mode over H2 and REALITY. Xray cannot
  initiate H2C, and Mihomo cannot serve H3; those directions are excluded.
- Legacy plain VLESS over WS/WSS and Mihomo raw/TLS/REALITY. Legacy Vision uses
  Xray, Mihomo, and sing-box in both roles, asserting DIRECT for inner TLS 1.3,
  END for plain/TLS 1.2 traffic, exact payloads under slow reads, and remote EOF.
  Clients half-close before receiving the full reply except in the sing-box cases
  below.
  The pinned sing-box Vision client closes both directions on upload EOF, so its
  enabled cases finish receiving before closing. The ignored
  `singbox_vision_client_half_close_preserves_pending_reply` retains that failing
  peer reproducer. The sing-box Vision server can also reset inner TLS 1.2 replies
  when the target closes before upload EOF arrives. Only those server cases, over
  TLS and REALITY, receive the full payload before sending inner `close_notify`
  and requiring clean EOF. The ignored
  `singbox_vision_server_half_close_preserves_tls12_reply` retains the intermittent
  server reproducer. Remove this server workaround when the pinned peer includes
  the Vision half-close fix in
  [SagerNet/sing-vmess#16](https://github.com/SagerNet/sing-vmess/pull/16).
  Plain and TLS 1.3 server cases still assert early half-close.
  All native-Vision peer cases close inner TLS gracefully without
  requiring transport-level half-close support: WebSocket and Mihomo's masked
  native wrapper can close both transport halves. Native TCP half-close and a
  delayed reverse reply are asserted separately in the library/splice tests.
- Live server reload, zero ticket lifetime, key rotation, expiry, peer restart,
  and recovery on a new request without replaying failed application data.
- Live ChaCha20-Poly1305 from peer clients with Go AES acceleration disabled.
- Actual TLS/SOCKS and TLS/AnyTLS consumers chained over native encryption,
  including slow full-duplex reads and cancellation of another stream.

The library suite complements the process matrix with native fresh/resumed
Vision decisions, fragmented and malformed records, the maximum native record
across Vision's 8 KiB buffer, real Linux splice transfers and masked/wrapped
negative controls, concurrent duplicate flights across bind IPs, SNI/WS ticket
isolation, IPv4/IPv6/domain destinations, empty UDP replies, and native-Vision
H2MUX rejection. IPv6 address cases run when IPv6 loopback is available;
IPv4 and domain cases always run without relying on dual-stack sockets.
These tests also run without optional peer binaries.

The ignored `legacy_baseline_matches_backpressure_and_half_close` test compares
both Shoes roles against Xray over TLS, including slow reads and half-close
after DIRECT. It verifies payload integrity, observes remote EOF within five
seconds, and checks both read and write DIRECT transitions in the Shoes logs.
Both Shoes binaries must be debug builds; release builds omit the DIRECT logs.
Set `SHOES_BASELINE_BINARY` to a debug binary built from
`001495285ac16e2121a539682d1a1f6a7c07c5ed` and run that named test with `--ignored`.
The pinned-peer CI job builds that baseline and runs the comparison explicitly.

Run the self-contained pressure test with
`cargo test --features stress-tests --test stress vless_encryption -- --nocapture`.
It exercises tiny replay budgets, recovery, cancelled handshakes and transfers,
and slow full-duplex traffic. Linux also checks process memory high-water growth;
exact cache accounting is covered by the session unit tests.

Local performance samples are available as an explicitly ignored peer test:

```sh
SHOES_BASELINE_BINARY=/path/to/baseline/shoes XRAY_BINARY=/path/to/xray \
  CARGO_BUILD_JOBS=1 cargo test --locked --features optional-peer-tests \
  --test vless_encryption_interop native_and_legacy_latency_throughput \
  -- --ignored --nocapture --test-threads=1
```

Use identically built binaries on an otherwise idle host. The test reports
end-to-end TTFB, bulk round-trip rate, cumulative process CPU ticks and peak RSS;
it is not a cryptographic microbenchmark or a substitute for production sizing.
Those small exchanges are not sustained throughput. For that, run the ignored
`native_sustained_download_without_injected_latency` test with release Shoes and
Xray binaries. It streams 2 GiB to curl's discard sink without per-chunk echoes,
compares plain/native VLESS and native Vision, and calibrates the HTTP/HTTPS
source directly. The existing `stress` target's `benchmarks::test_reality_`
cases provide the corresponding 2 GiB legacy VLESS/Vision comparisons.
