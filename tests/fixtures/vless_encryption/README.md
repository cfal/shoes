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

The native peer suite uses `XRAY_BINARY`, `MIHOMO_BINARY` and optionally
`SHOES_TEST_SHOES_BIN`. Missing requested peers fail rather than skip. Its wire
tap distinguishes fresh from resumed handshakes and checks raw DIRECT lengths.
Xray's command-2 replies are limited to 8190 bytes; its XUDP writer limits
payloads to 7526 bytes. Peer UDP tests use that intersection. Separate Shoes
tests cover larger XUDP frames and preservation of the existing empty-DATA
and control-frame semantics. Sing-box has no native encryption support and is
used only by the legacy TLS/REALITY regression suites.

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
