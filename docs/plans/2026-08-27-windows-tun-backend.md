# Windows TUN backend — implementation plan

Spec: [docs/specs/2026-08-27-windows-tun-backend.md](../specs/2026-08-27-windows-tun-backend.md).
Kept in sync with reality; a step is marked done when its verification has run.

## Steps

1. **Extract the shared stack loop.** New `src/tun/stack_common.rs` holding
   `PooledBuffer` and its pool, `TcpStackOptions`, `SharedState`,
   `NewTcpConnection`, `SocketInfo`, packet classification
   (`get_ip_protocol`, `extract_tcp_info`, `should_filter_packet`),
   `create_tcp_connection`, the `StackDevice` trait, and
   `run_stack_loop<D>`. `tcp_stack_direct.rs` keeps `FdDevice` (the renamed
   `DirectDevice`), the wake pipe, `poll()`, `TcpStackDirect`, and every
   existing test. Verification: the full gate on Windows (compiles, tun
   module still `cfg`'d correctly), and CI's Linux/macOS jobs run the Unix
   stack tests unchanged.

2. **Scripted-device tests for the shared loop.** A channel-backed
   `StackDevice` double; tests for shutdown on device error, prompt exit,
   SYN accept, and the `control-stats` counter reset — running on all
   platforms. Prove each new test can fail.

3. **Wintun device.** `src/tun/wintun_device.rs`: `load()` with
   `verify_binary_signature`, deterministic GUID from `device_name`,
   adapter create/configure (`set_mtu`, `set_network_addresses_tuple`),
   session start at `0x800000`. `src/tun/tcp_stack_wintun.rs`:
   `WintunDevice` implementing `StackDevice` (try_receive copy-in,
   allocate/send out, `WaitForMultipleObjects` wait), `TcpStackWintun`
   with the same accessor surface as `TcpStackDirect`, shutdown via
   `Session::shutdown()`.

4. **Wire it up.** Platform arms in `src/tun/mod.rs` (device creation) and
   `src/tun/tun_server.rs` (`create_sync_device` stays unix-only). Move
   `tun` to `[target.'cfg(unix)'.dependencies]`; add `wintun-bindings` and
   `windows-sys` under `cfg(windows)`.

5. **Validation and gates.** Windows arm in `src/config/validate.rs`
   (require `device_name`/`address`/`netmask`, refuse `device_fd`); widen
   `cfg(unix)` to `cfg(any(unix, windows))` in `src/lib.rs`, `src/main.rs`,
   `src/tcp/tcp_server.rs`, `src/control/mod.rs`, `src/control/stats.rs`.

6. **Docs.** CONFIG.md TUN platform notes (wintun.dll, Administrator,
   manual route/DNS commands), README platform list, ROADMAP desktop
   section, CHANGELOG, `examples/tun_windows.yaml`.

7. **Verification.** The full gate on Windows including the `ffi` and
   `desktop` feature configurations; the `#[ignore]`d adapter round-trip
   test elevated; a live run on Windows 11 — TUN up, route added by hand,
   TCP + UDP/DNS + Fake IP through a real rule chain.

## Status

- [x] 1. Shared loop extracted (plus a shared `StackHandle` manager, so the
  two backends duplicate nothing platform-neutral); full gate green on
  Windows, Unix suite pending this branch's first CI run
- [x] 2. Scripted-device tests, each proven able to fail by reintroducing
  its defect
- [x] 3. Wintun device + stack; the `#[ignore]`d adapter round-trip passed
  elevated (0.88 s, teardown under 2 s)
- [x] 4. Wiring and dependencies (`tun` moved to unix-only,
  `wintun-bindings` + `windows-sys` added under `cfg(windows)`)
- [x] 5. Validation and cfg gates — including refusing `destination` (it
  would become a default route) and non-IPv4 addresses (wintun-bindings
  cannot express IPv6) on Windows
- [x] 6. Docs
- [x] 7. Verification gate + live run on Windows 11: fake-IP DNS answered in
  6–12 ms measured raw-socket (baseline 1–10 ms off-tunnel), TCP with domain
  restoration HTTP 200, TLS with restored SNI HTTP 200, 20 MB at ~35 MB/s
  through the tunnel, UDP relay returning real answers from a resolver
  outside the tunnel, ICMP echo 0% loss, clean teardown with the adapter
  gone afterwards. The first run also demonstrated the routing-loop hazard
  the docs warn about (routing an exit's own destination into the tunnel),
  which is what shaped the loop-free topology in the example's notes.
