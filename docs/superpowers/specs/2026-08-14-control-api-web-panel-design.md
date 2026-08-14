# Control API for a web panel — design

Date: 2026-08-14
Status: approved for planning

## Goal

Let a separate web panel (config management, monitoring, logs, live connections —
the sing-box-dashboard shape, not the 3x-ui multi-tenant shape) drive shoes as its
engine, with **minimal additions to shoes and zero footprint impact on the
iOS/Android artifacts.**

shoes exposes a small, authenticated **control API** over HTTP; the panel is a
separate application (any language) that consumes it and owns everything the API
deliberately leaves out.

## Scope

**In scope (v1):**
- Read/replace the running config (whole-config, validated).
- Snapshot of live connections with per-connection up/down byte counts.
- Aggregate metrics (Prometheus text format).
- Streamed connection open/close events, metric ticks, and log lines.
- Single bearer-token auth; localhost bind by default.
- Feature-gated so mobile/FFI builds are unaffected.

**Out of scope (v1), by decision:**
- Persistence of any kind (no DB, no traffic history, no stored events).
- User accounts, per-user credentials, per-user accounting, quotas, expiry,
  subscription links.
- Granular config mutation endpoints (`POST /inbounds`, etc.).
- Serving the panel UI or its static assets (the panel is a separate app).
- Per-target byte breakdown; TUN per-flow accounting (see Known limits).

These belong in the panel backend or a later engine phase. shoes stays
**stateless**: it reports live state and streams events; it remembers nothing.

## Confirmed decisions

1. **Coupling: model B** — shoes = engine + control API; panel is separate.
2. **Transport: HTTP/JSON request-response + SSE for streams**, reusing the
   existing `hyper` server stack. No gRPC (tonic/prost + codegen would grow the
   crate, which is the opposite of the goal).
3. **shoes is stateless** — live state + event stream only; history lives in the
   panel backend.
4. **Whole-config apply** — `GET`/`PUT` the entire config; the panel edits
   client-side and submits the whole thing.
5. **Byte accounting via a counting stream wrapper at each accept point**
   (option b), not counters threaded through every copy call site.
6. **Auth: a single static bearer token.** The API is not meant to face the
   internet; localhost bind is the default.

## Feature gate — the mobile-off guarantee

A **non-default** Cargo feature `control-api`. Cargo features are additive, so a
build gets it only if it explicitly asks:

- Server binary (`build.yml`): built with `--features control-api`.
- iOS (`build-ios.sh`), Android (`build-android.sh`), and the `ffi` library:
  never pass it → the control plane is not compiled in at all. Mobile artifacts
  are byte-for-byte unchanged.

CI assertion: a step in `mobile.yml` greps the built library's symbols and fails
if any `api::` symbol is present, so the guarantee cannot regress silently.

New dependency footprint (server builds only):
- `serde_json` promoted from dev-dependency to a `control-api`-gated dependency.
- Everything else reused: `hyper`/`hyper-util` (already deps), `tokio` (sync/net),
  `serde`, `dashmap`, `subtle`, `parking_lot`, `rustls` (optional TLS).

## Module layout

New module `src/api/`, entirely `#[cfg(feature = "control-api")]`:

- `mod.rs` — server bootstrap (bind, TLS, auth middleware), route dispatch.
- `handlers.rs` — endpoint handlers.
- `logsink.rs` — the broadcast `LogWriter` and its ring buffer.

The **connection registry** is referenced from core accept paths that exist
regardless of the feature, so it lives at `src/connection_registry.rs` with two
shapes:

- Feature on: a real registry (`DashMap<u64, Arc<ConnectionInfo>>` + a broadcast
  sender for events).
- Feature off: a zero-sized shim whose `register`/`counting_stream` calls inline
  to nothing, so the hot path and binary are unaffected on mobile.

The accept sites call the registry through this shim interface only, so there are
no `#[cfg]` blocks scattered through `tcp_server.rs` / `quic_server.rs`.

## API surface

All endpoints require `Authorization: Bearer <token>` (constant-time compare via
`subtle`). Base path `/api`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/status` | version, uptime, active listener count |
| GET | `/api/config` | current config as JSON |
| PUT | `/api/config` | validate + apply a full config (see below) |
| GET | `/api/connections` | snapshot array of live connections |
| GET | `/api/metrics` | aggregate counters, **Prometheus text format** |
| GET | `/api/events` | SSE: connection `open`/`close` + periodic metric ticks |
| GET | `/api/logs` | SSE: live log lines (ring buffer replay, then tail) |

**Connection JSON** (snapshot and `open` events):
`{ id, inbound, protocol, client_addr, target, started_at, up_bytes, down_bytes }`.
`close` events add `ended_at` and final byte totals.

**Config bootstrap:** the API is configured from the same config file, under a new
optional top-level `control_api` section: `{ bind (default 127.0.0.1:port),
token, tls: optional { cert, key } }`. Absent section ⇒ API not started even when
the feature is compiled in.

## Connection registry + counting wrapper (the invasive part)

**Registration.** Each stream-based accept site — `run_tcp_server` after
`accept()` and before the handler spawn, and the equivalent in `quic_server.rs` —
allocates a connection id, wraps the accepted client stream in `CountingStream`,
and inserts a `ConnectionInfo` into the registry. On task completion (drop guard),
it deregisters and emits a `close` event. Target/protocol fields are filled in
once the handler resolves them (the registry entry is updated in place via the
shared `Arc`).

**Counting.** `CountingStream<S: AsyncStream>` wraps the client stream and bumps
per-connection `up`/`down` `AtomicU64`s on each `poll_read`/`poll_write` — once
per poll (not per byte), and the atomics are owned by that connection alone, so
they are uncontended. Applied once at the edge, it is protocol-agnostic and
covers every downstream copy path (`copy_bidirectional`, the UDP message copy)
without touching them. It also forwards `poll_write_vectored`/`is_write_vectored`
so it never silently disables a vectored-write fast path.

**Metrics/events.** `/connections` snapshots the map (O(active connections);
scraped rarely). `/metrics` is served from a handful of **global `AtomicU64`
counters** so a Prometheus scrape is O(1), not a full map scan:
- `active_connections` (gauge): +1 in `register`, -1 in `Drop`.
- `total_connections` (counter): +1 in `register`.
- `total_up_bytes` / `total_down_bytes` (counters): a connection's final byte
  totals are folded into these **once, in `Drop`** — never per poll, so the hot
  path never touches a shared counter and there is no cross-connection
  contention. Standard monotonic-counter semantics: in-flight bytes of a still-open
  connection are attributed when it closes.

The per-poll hot path touches only the connection's own (uncontended) atomics.
`open`/`close` push onto the events broadcast channel; a timer pushes metric
ticks. Both the event send and the log send (below) are **guarded by
`receiver_count() > 0`**, so when no panel is watching — the common case — a
connection open/close or a log line costs only an atomic load and a skip, not a
channel write.

**Known limits (documented, not fixed in v1):**
- Byte counts are **client-edge, client-perspective**: `up` = bytes read from the
  client, `down` = bytes written to the client.
- A UDP-associate or mux inbound that fans out to many targets is **one** registry
  entry, not one per target.
- **TUN is packet-based**, not stream-based; TUN inbounds are out of scope for the
  counting wrapper in v1 (they may register with approximate/no byte counts). This
  is a follow-up.

## Performance cost

- **Data path:** one relaxed, uncontended `fetch_add` per `poll_read`/`poll_write`
  — i.e. per ~16 KB copy-buffer fill, not per byte — plus the wrapper's own
  branch. Well under 1% of throughput; the atomic is a rounding error next to the
  memcpy beside it. No new dynamic dispatch (the accepted stream is already
  `Box<dyn AsyncStream>`), and the wrapper sits below TLS/protocol layers.
- **Per connection:** one `Arc` alloc + a `DashMap` insert/remove + count-atomic
  updates + (only if watched) two event sends. Microseconds against a
  handshake-dominated connection lifecycle. Memory ~100 B/connection.
- **Per scrape:** `/metrics` is O(1) (global atomics). `/connections` is O(active
  connections) but scraped rarely.
- **Feature off:** compiles to nothing (ZST handle, identity `counted`, inlined
  no-ops); mobile artifacts byte-for-byte unchanged.

## Logs

Add `BroadcastLogWriter` (in `api/logsink.rs`, feature-gated) implementing the
existing `logging::LogWriter` trait: each record is formatted, always pushed into
a bounded ring buffer (recent-N) for replay, and — **only when
`receiver_count() > 0`** — sent on a `tokio::sync::broadcast` channel, so with no
panel streaming logs a record costs the ring push plus an atomic load, not a
channel write. `logging.rs` stays untouched — because `init_multi_logger` already
takes `Vec<Box<dyn LogWriter>>`, `main.rs` (itself feature-gated at this point)
constructs the `BroadcastLogWriter` and includes it in the writers vec alongside
the existing stderr/file writers when the feature and a `control_api` section are
both present. `/api/logs` replays the ring buffer to
a new subscriber, then streams live records; slow SSE clients that lag the
broadcast channel are dropped with a "logs skipped" marker rather than applying
backpressure to logging.

## Config get/apply

- `GET`: serialize the in-memory config to JSON.
- `PUT`: deserialize → run the existing `config::validate` → on success, write the
  validated config atomically (temp file + rename) to the configured config path;
  the existing `notify` watcher in `main.rs` reloads it. On validation failure,
  return `400` with the validation error and change nothing.

The only new logic is validate-then-atomic-write; reload reuses `main.rs`'s
existing path (extracted into a callable function if it is currently inline).

## Security

- Bearer token, constant-time compare; missing/wrong token ⇒ `401`.
- Default bind `127.0.0.1`; a non-loopback bind SHOULD be paired with TLS (reuse
  the existing rustls setup). Document that the token is the only gate, so a
  non-loopback bind without TLS exposes it in cleartext.
- `PUT /config` can reconfigure the proxy arbitrarily (it is effectively remote
  control of the process); this is why the endpoint is auth-gated and localhost by
  default, and why the feature is off for the shipped mobile clients.

## Build / CI integration

- `build.yml`: add `--features control-api` to the server binary build.
- `mobile.yml`: unchanged build commands (feature stays off) + a new assertion
  step that the built `.so`/`.a` exports no `api::` / control-plane symbols.
- Feature-gated integration tests run in the `Test` job with
  `--features control-api`.

## Testing

Feature-gated integration tests (`#[cfg(feature = "control-api")]`), each spinning
up shoes with the API on an ephemeral loopback port:

- auth: missing/wrong token ⇒ 401; correct token ⇒ 200.
- config round-trip: `GET` then `PUT` the same config succeeds; a deliberately
  invalid config ⇒ 400 and the running config is unchanged.
- live connection: open a proxied connection, assert it appears in
  `/connections` with growing byte counts and that `open`/`close` arrive on
  `/events`.
- logs: assert a known log line arrives over `/logs` SSE.
- registry no-op: a normal (feature-off) build compiles and the hot path contains
  no registry calls (covered by the CI symbol check).

## Open questions / follow-ups (post-v1)

- Per-target / per-stream byte breakdown for mux and UDP-associate.
- TUN per-flow accounting.
- Granular config endpoints if whole-config apply proves clumsy for the panel.
- Multi-node: one panel backend fanning out to several shoes instances (already
  supported by the transport; purely a panel concern).
