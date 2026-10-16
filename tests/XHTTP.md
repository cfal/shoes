# XHTTP Interoperability Tests

The `xhttp_interop` integration target runs real Shoes processes against Shoes,
Xray-core, and Mihomo Alpha. CI builds and caches these peers from pinned source:

- Xray-core: `701af60772cda123492f86e383e1fdba066614a9` (26.10.10).
- Mihomo Alpha: `94b13aed49b8dc41973e4bb3f721c5fa2c5c5c1f`.

Use Go 1.27.1, `GOMAXPROCS=1`, and `go build -p 1`. Build Xray's `./main` package.
Build Mihomo's root package with `CGO_ENABLED=0` and
`-ldflags '-X github.com/metacubex/mihomo/constant.Version=alpha-94b13aed'`.
The full peer setup is in `.github/workflows/test.yml`; the stable Mihomo peer
used by `optional_peer` is deliberately unchanged.

```sh
export SHOES_TEST_XRAY_BIN=/absolute/path/to/xray
export SHOES_TEST_MIHOMO_BIN=/absolute/path/to/mihomo
CARGO_BUILD_JOBS=1 cargo test --locked --features integration-tests \
  --test xhttp_interop -- --test-threads=1
```

Missing or incorrectly versioned peers fail the tests rather than skipping them.
Use the `shoes_to_shoes`, `shoes_backpressure`, or `wire::` test filters to run
local-only coverage without external peers.

## Coverage

- VLESS in both external-peer directions: cleartext H1/H2C, TLS H1/H2/H3,
  and REALITY/H2 where supported; all three explicit modes plus representative
  `auto` cases. Xray also covers Trojan. Shoes covers default HTTP selection.
- Fixed 32 KiB packet limits and offset/session-dependent binary payloads force
  fragmentation. Concurrent sessions, sequential reuse, and two UDP destinations
  check integrity and routing, not just successful handshakes. Dedicated UDP
  cases use 1 KiB POST limits and concurrent associations so 4 KiB datagrams cross
  POST boundaries without exceeding the external peers' UDP buffer limits.
- H2/H3 packet-up transfers pause upload/download consumers with 16 MiB in flight,
  for at least twice the measured unpaused transfer duration (minimum one second),
  then resume and verify exact bytes and continued session progress. Shoes uses
  256 KiB per-session and 1 MiB global byte budgets, with the default 30-packet
  reorder window and 128 live requests per session. Test-owned sending and
  receiving sockets use 64 KiB buffers
  to keep kernel autotuning from absorbing the entire paused transfer.
  Cancellation and connection churn use the same processes.
- Separate Xray cases use the default 64 MiB global and 4 MiB session byte
  budgets with 32 KiB POSTs and 30 ms pacing. H2's non-ACK-waiting uploader
  reaches the live-request cap during a stalled upload; the test requires bounded
  teardown and successful use of a subsequent session. H3 recovers after a
  ten-second destination pause in the pinned-peer fixture. Small-budget pressure
  recovery does not imply recovery from live-request-cap exhaustion.
- Raw H1 requests exercise reordering, matching/conflicting duplicates, exclusive
  download ownership, wrong host/path, missing padding, oversized packets,
  reorder-window rejection, and recovery after rejected requests.
- A single POST trickles at about 5 KiB/s for four seconds with a two-second
  inactivity timeout. Stalled bodies must time out and release admission.
- Wrong UUIDs must fail without dialing the destination; matching controls pass.
  Existing TLS/QUIC allowlist and REALITY ML-DSA verification cases remain enabled.
- SOCKS -> XHTTP and QUIC XHTTP -> VLESS chains carry TCP/UDP and fail closed when
  a hop disappears.

## Boundaries

Mihomo has no XHTTP H3 listener or Trojan/XHTTP adapter. Its client supports H3;
its REALITY fixture permits classical X25519 as well as hybrid key exchange.
Mihomo uses a simple path because its normalization treats query syntax as path
text. Shoes/Xray retain the escaped-path/query interoperability fixture.

Xray client H2C is not included. Packet-up does not signal upload FIN. A completely
stalled session can retain shared-carrier flow-control credit, so the pressure
tests require recovery after consumption resumes, not independent progress while
the shared window is exhausted. Attached out-of-window POSTs wait for their
predecessors subject to inactivity and per-session request limits; the pressure
fixtures do not widen either request-count limit. Deterministic GOAWAY, credit starvation,
timeout races, and memory-release ordering remain covered by the XHTTP library tests.
