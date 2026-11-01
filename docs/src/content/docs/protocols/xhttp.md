---
title: XHTTP / SplitHTTP
description: XHTTP client and server configuration, modes, limits, and interoperability.
---

**Complete example:** [xhttp.yaml](/examples/xhttp/). Generate certificates and replace demo credentials before deployment.

`type: splithttp` is an alias for `type: xhttp`. XHTTP wraps an inner proxy
protocol, which still handles authentication and destinations. The complete
example covers all three modes and H1, H2, and H3.

## Server

Place `type: xhttp` in the listener's `protocol`: directly on TCP for cleartext
H1/h2c or on QUIC for H3, or inside a TLS/REALITY target for H1/H2. `protocol` is the required inner server
protocol. `path`, `host`, and `matching_headers` select which requests are
accepted; `mode: auto` accepts all supported modes by default. Add `limits`
to constrain sessions, requests, and buffered bytes on an exposed listener.

## Client

Place `type: xhttp` in a client hop's `protocol`. `protocol` is the required
inner client protocol. Match the server's `path`, `host`, and any required
`matching_headers` values using client `headers`. The defaults are
`mode: auto`, `http_version: auto`, `download_idle_timeout_secs: 900`, and
`packet_pipeline_depth: 30`. The client `pool` defaults to three H2/H3
connections, at most 64 H1 connections, and a 60-second idle timeout.

## Modes and transport

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
  An inner TLS client with no explicit `sni_hostname` does not send wire SNI,
  but still verifies the certificate against the proxy hop address.
  `pool` bounds connections and idle retention.
  Split legs may use different carriers on the same selected route. H2/H3 admission
  respects peer stream capacity; draining carriers retain their connection slots.
  A full pool refuses new sessions rather than exceeding its configured cap.
  Split modes require at least two effective request lanes: two H1 connections,
  or `pool.max_connections * effective_requests_per_connection >= 2` for H2/H3.
  The effective per-connection limit is the smaller of
  `limits.max_requests_per_connection` and `global_settings.max_streams_per_connection`
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
  set `global_settings.max_connections` and `global_settings.max_connections_per_ip`.
- Xray's H1 packet-up uploader (observed on 26.10.10) can lose pipelined requests
  when Go GC discards pooled connections with unread responses. Sustained uploads
  to slow destinations can therefore fail despite bounded server backpressure.
  Prefer H2/H3 or a streaming mode for these clients; disabling GC is not a production fix.
- Advanced placement/padding obfuscation, custom session IDs, separate downloads,
  full XMUX policy, and legacy Vision over XHTTP are not supported. Unsupported
  options are rejected rather than silently ignored. Public CDN compatibility is not implied.
- REALITY XHTTP interoperates with Xray 26.10.29 in both directions over H2,
  including all three modes and `auto`. REALITY prefers X25519MLKEM768 with
  X25519 fallback according to the cover target. Optional `mldsa65_seed` and
  `mldsa65_verify` apply to the outer REALITY configuration, independently of
  XHTTP; see [REALITY client configuration](/protocols/reality/).

