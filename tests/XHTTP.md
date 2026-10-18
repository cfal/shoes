# XHTTP Interoperability Tests

The `xhttp_interop` integration target runs real Shoes processes against Shoes,
Xray-core, and Mihomo Alpha. CI builds and caches these peers from pinned source:

- Xray-core: `92ccc939aaf4f8965f369cf0b142e005aeaa11d5` (26.10.17).
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
- H2/H3 packet-up transfers pause consumers with 16 MiB uploads and 64 MiB downloads,
  for at least twice the measured unpaused transfer duration (minimum one second),
  then resume and verify exact bytes and continued session progress. Shoes uses
  256 KiB per-session and 1 MiB global byte budgets, with the default 30-packet
  reorder window and 128 live requests per session. Test-owned sending and
  receiving sockets use 64 KiB buffers
  to keep kernel autotuning from absorbing the entire paused transfer.
  Downloads exceed the combined peer transport windows and intermediate TCP buffers;
  a 16 MiB download can fit in those buffers without backpressuring the source.
  Cancellation and connection churn use the same processes.
- Separate Xray cases use the default 64 MiB global and 4 MiB session byte
  budgets with 32 KiB POSTs and 30 ms pacing. H2's non-ACK-waiting uploader
  reaches the live-request cap during a stalled upload; never-admitted requests
  are refused for transport retry without closing the logical session. H2 and H3
  recover after a ten-second destination pause while download heartbeats continue
  on that same session. A separate H2 case uses a two-second packet inactivity
  timeout to check permanent-stall containment and subsequent session availability.
- Mihomo server recovery is also checked with the default Shoes client byte limits.
  The client sequence window prevents ACKs for later packets from advancing past
  a stalled earlier packet and overflowing the peer's reorder queue.
  H1's single-POST client path undergoes the same stall/resume checks against both peers.
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

## Throughput And Stall Qualification

The ignored `packet_up_throughput_and_stall_qualification` test compares
Xray-to-Xray, Xray-to-Shoes and Shoes-to-Xray using 16 MiB in each direction per
session. A bounded TCP relay delays each byte batch by half the requested RTT
without serializing a whole RTT per batch. It models latency, not loss or congestion.
Linux `/proc` sampling records aggregate peer RSS; debug resource logs record
application byte and request-budget peaks. Neither measurement includes relay RSS
in the peer figure or equates application byte accounting with total RSS.

```sh
XHTTP_BENCH_RTT_MS=0,50,150,300 \
XHTTP_BENCH_PAUSE_SECS=0,5,10,30,60 \
XHTTP_BENCH_POST_BYTES=32768,1000000 \
XHTTP_BENCH_REQUEST_CAP=128,1024 \
XHTTP_BENCH_SESSIONS=1,4 \
CARGO_BUILD_JOBS=1 cargo test --locked --features integration-tests \
  --test xhttp_interop packet_up_throughput_and_stall_qualification \
  -- --ignored --nocapture --test-threads=1
```

Each variable accepts a comma-separated list. Defaults run RTT 0/150 ms, no stall,
32 KiB/1 MB packets, cap 128 and one session. `XHTTP_QUALIFICATION` JSON records
integrity success, elapsed time, aggregate duplex throughput and sampled peak RSS.
The server-request-cap override applies only to the Shoes server, not Xray.
Set `XHTTP_BENCH_H2_WINDOW_BYTES=262144` to compare the previous fixed H2 receive
windows with the new defaults without changing the binary.
`XHTTP_BENCH_DIRECTIONS` selects comma-separated `xray-xray`, `xray-shoes`, or
`shoes-xray` cases. Set `SHOES_TEST_SHOES_BIN` to a release binary for throughput
comparisons; debug builds are useful for correctness, not production rate claims.
This extended sweep is opt-in; normal CI runs the focused recovery/containment cases.

### Local Stall Qualification

On 2026-10-16, the then-pinned Xray 26.10.10 (`701af607`) client completed all six
16 MiB duplex cases against Shoes with 32 KiB POSTs, 30 ms pacing, no added RTT,
and destination pauses of 10/30/60 seconds. These correctness runs used a debug
Shoes binary; their rates are not production throughput measurements.

| Server request cap | Total duration, 10/30/60 s pause | Peak service handlers | Peak application bytes | Combined peer RSS range |
| --- | --- | --- | --- | --- |
| 128 | 16.2 / 47.8 / 83.1 s | 133 | 1.03 MiB | 89.4-103.8 MiB |
| 1024 | 16.3 / 31.0 / 61.1 s | 397 | 1.03 MiB | 93.4-117.0 MiB |

Service handlers include the GET and briefly rejected requests, not just admitted
packet requests. RSS includes both Shoes and Xray and excludes the test harness.
The default cap survived every tested pause, but Xray's retry backoff delayed
completion after longer pauses. A larger cap reduced that delay while retaining
more requests. These samples qualify this workload, not arbitrary stalls, packet
sizes, transport-credit contention, or overload.

A release-build run with four concurrent sessions, 150 ms added RTT, 32 KiB POSTs
and a ten-second destination pause also passed all three directions. Total times
were 19.2 seconds for Xray-to-Xray, 19.2 seconds for Xray-to-Shoes and 25.0 seconds
for Shoes-to-Xray. Each session resumed with exact upload and download bytes.

### Local Throughput Qualification

Using the then-pinned Xray 26.10.10 (`701af607`), the release Shoes binary passed
all 24 combinations of 0/50/150/300 ms added RTT, 32 KiB/1,000,000-byte POST limits,
and the three peer directions. All used 30 ms
pacing and exact 16 MiB transfers each way; Shoes used its default client pipeline
depth of 30. Representative aggregate duplex rates for 1,000,000-byte POSTs:

| Direction | 150 ms RTT | 300 ms RTT |
| --- | --- | --- |
| Xray to Xray | 8.22 MiB/s | 4.84 MiB/s |
| Xray to Shoes | 14.31 MiB/s | 10.14 MiB/s |
| Shoes to Xray | 7.62 MiB/s | 4.62 MiB/s |

With 32 KiB POSTs, pacing dominated: all directions were within about 3% of the
reference across these RTTs. At 150 ms RTT, overriding only the Shoes H2 windows
to the former 256 KiB values reduced the 1,000,000-byte cases to 2.31 MiB/s inbound
and 2.28 MiB/s outbound. This supports larger bounded windows rather than an
unbounded request pipeline. These are single local samples, including session
setup and harness overhead, not link-capacity guarantees or statistical benchmarks.
