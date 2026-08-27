# Working in this repository

Instructions for anyone — human or agent — adding to or maintaining this code.

Every rule below exists because something went wrong once. Where that is the
case the incident is named, because a rule whose reason is missing gets dropped
the first time it is inconvenient.

## Table of Contents

- [Orientation](#orientation)
- [The verification gate](#the-verification-gate)
- [Traps in this codebase](#traps-in-this-codebase)
- [Security rules](#security-rules)
- [Packet paths](#packet-paths)
- [Testing](#testing)
- [Implementing a protocol](#implementing-a-protocol)
- [Configuration surface](#configuration-surface)
- [Commits and documentation](#commits-and-documentation)
- [Where the known debt is written down](#where-the-known-debt-is-written-down)

## Orientation

Read before changing anything substantial:

| File | What it tells you |
| --- | --- |
| [ROADMAP.md](./ROADMAP.md) | What is deliberately missing and what each gap costs |
| [CONFIG.md](./CONFIG.md) | Every configuration option; the reference users read |
| [MOBILE.md](./MOBILE.md) | Mobile/FFI contracts and the defects recorded against them |
| `docs/specs/` | Design documents for shipped work, with sources cited |
| `docs/plans/` | Step-by-step implementation plans, kept in sync with reality |

For anything larger than a bug fix, write a spec in `docs/specs/` before code.
The two most recent ones show the expected shape: problem, scope, what the
reference implementations do with file-level citations, error handling, testing,
and an explicit list of what is deliberately out of scope.

## The verification gate

Run all of this before claiming anything works:

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo test --lib
cargo test --bins
cargo test --test '*'
```

There are no exclusions. Every clippy configuration is clean and is expected to
stay that way:

```bash
cargo clippy --locked --features ffi --lib --tests -- -D warnings
cargo clippy --locked --features ffi --bins -- -D warnings
```

`--tests` is in the gate on purpose. It catches a class the other passes cannot
see — `err().expect()` instead of `expect_err`, a lock held across an await, an
assertion whose value is a constant, a test double nothing constructs. It was
excluded until the backlog behind it was cleared; putting anything back on that
list means fixing it instead.

**Run the FFI configurations whenever you touch `src/tun/`,
`src/socket_protector.rs`, `src/config/mod.rs` or `src/ffi/`.** Those are partly
gated behind `cfg(any(target_os = "android", target_os = "ios", feature =
"ffi"))`, so the default build does not compile them at all. Moving the socket
protector out of `tun::platform` left duplicate definitions and a stale test
import behind, and the ordinary gate stayed green throughout.

Note what those two FFI lines do *not* include: `--features ffi --bins` compiles
FFI-gated code into the binary, which does not declare `mod ffi`, so anything
whose only caller is the FFI looks dead there. `config::load_config_str` carries
an allow saying exactly that. Prefer that shape — a narrow allow with the reason
— over dropping the configuration from the gate.

## Traps in this codebase

### `src/lib.rs` and `src/main.rs` declare the module tree separately

A new top-level module has to be added to both, or the binary fails to build
while the library succeeds.

The consequence that actually bites: **a module declared in `src/main.rs` that
nothing in the binary's code path uses is dead code**, and `-D warnings`
rejects it. The library never tells you this — `src/lib.rs` opens with a
crate-wide `#![allow(dead_code)]`, because server-side code looks unused there
and is reached through the binary and the FFI. So `--lib` stays green and
`--bins` is the half that catches it. This happens constantly when a module
lands before its consumer. The options, in order of preference:

1. Delay the declaration in `src/main.rs` until the consumer exists.
2. Use the item for its real purpose — a constant that duplicates a literal
   elsewhere should replace that literal.
3. `#[allow(dead_code)]` scoped as narrowly as possible, with a comment naming
   the change that removes it. Put that removal in the plan.

A permanent allow is correct in exactly one situation: `mod socket_protector`
in `src/main.rs`, because installing a protector is the FFI's job and the FFI
is compiled out of this binary. The comment above it explains that this is a
property of the build rather than something a later change will fix. Write that
kind of comment, not the word `dead_code` on its own.

### Config re-exports are part of the public surface

`src/config/types/mod.rs` re-exports config types. Four carry
`#[allow(unused_imports)]` because the binary names the module type directly.
Follow the neighbouring pattern rather than deleting the re-export.

### The socket constructors protect outbound sockets for you

`socket_util::new_tcp_socket` and `new_udp_socket` exclude the socket from the
VPN route. The `new_socket2_udp_socket*` functions are the listener-side
primitives and deliberately do not.

**If you build an outbound socket by other means, call
`socket_util::protect_outbound` yourself.** Three places do: the AmneziaWG
endpoint and both DNS paths. Getting this wrong on Android means the socket is
captured by the tunnel it is meant to feed.

This rule exists because for a long time exactly one socket in the program was
protected. The protector sat behind a mobile-only `cfg` inside the TUN module,
so calling it meant repeating that gate at every site, and five sites did not.

## Security rules

### Compare secrets in constant time

`subtle::ConstantTimeEq` is already a dependency. Use it for passwords, tokens,
hashes and any other value an attacker is trying to guess:

```rust
if presented.as_bytes().ct_eq(configured.as_bytes()).unwrap_u8() == 0 {
    return Err(/* ... */);
}
```

Read several values before judging any of them, so the rejection does not say
which one was wrong — `src/tuic/server.rs` does this for the UUID and token.

Three authentication paths had drifted to plain `!=` while four others did it
correctly a few files away. Ordinary equality stops at the first differing byte.

### Never put a presented credential in a log line or an error

An attempt worth logging may well be a valid credential for somewhere else, and
it ends up in the log either way. Say that authentication failed; do not say
what was sent.

`Redacted<T>` (`src/config/types/redacted.rs`) keeps configured secrets out of
`Debug` output. Use it for every new secret-bearing config field.

### Nothing from a live test enters the repository

Testing against a real server means handling someone's working credentials.
They do not go into a config in the tree, a test fixture, an example, a commit
message or a documentation snippet — not even a redacted-looking one. Put the
config in a temporary file outside the working tree and delete it. Check `git
status` before committing anything from a session that involved a live server.

### Do not hand back something the platform refused

If a security-relevant step fails — protecting a socket, verifying a
certificate — fail the operation. Returning the object anyway turns a loud
failure into a silent leak.

## Packet paths

Anything that runs once per packet is a different kind of code. In
`src/quic_outbound/obfs/`, `src/hysteria2/udp.rs`, `src/tuic/udp.rs`,
`src/routing/`, `src/tun/`:

- **No allocation per packet** where the work can be done in place or into a
  reusable buffer. The obfuscated socket transforms in place; its send path
  uses a thread-local scratch buffer rather than a lock or a fresh `Vec`.
- **No task spawn per packet.** Use one worker per session fed by a bounded
  channel. A task per packet grows without bound under a fast sender and lets
  packets overtake each other.
- **Bound every queue**, and decide what a full one does. For UDP, dropping is
  correct and matches what a full socket buffer does; say so in a comment.
- **Reject rather than truncate** when a limit is exceeded — a payload needing
  more than 255 fragments is an error, not something to silently cut.

## Testing

### Run the real thing, in-process

`src/quic_outbound/testing.rs` starts this repository's own server, generates a
certificate and spawns echo servers. Protocol work is tested against it, so a
change to either side that breaks the pairing fails a test rather than waiting
for a user.

Build the selector the way production builds it — the harness calls
`create_tcp_client_proxy_selector`, the same function server startup uses — so
the tests exercise the real routing path rather than a stand-in that can drift.

### Prove a new test can fail

Write the test first and watch it fail for the reason you expect. When a test
covers a specific defect, reintroduce the defect afterwards and confirm that
**exactly that test** goes red. Two real bugs were caught this way that reading
the code had missed, and one "fix" was shown to be tested by nothing.

### Global state in tests is process-wide

Tests run in parallel threads in one process. A test that installs something
global — the socket protector is the example — affects every other test running
at that moment.

Serialising your own tests with a mutex is not enough: the rest of the suite is
not holding it. Scope the effect instead. The protector doubles in
`src/socket_util.rs` act only for the thread that installed them, which is what
a test body runs on. Before that guard existed, a refusing protector failed
unrelated tests at random.

### Keep the suite fast

Over a thousand library tests run in about two seconds. A test that waits out a
network timeout
costs that on every run forever. Bound the wait to what proves the point: for
"this must not succeed", a short timeout and an assertion on the observable
state is enough.

### Test what a rejection does not contain

`assert!(!err.contains(secret))` is a real test. Error text gets rewritten
casually, and a credential creeps back in without anyone noticing.

## Implementing a protocol

### Read the upstream source, do not recall it

Constants, byte layouts and framing rules go into a spec with the file they came
from. Three examples of why:

- Salamander's constants were verified against
  `apernet/hysteria`, `extras/obfs/salamander.go`. They matched memory, but a
  wrong byte there is silent incompatibility with everything.
- TUIC's command layout and token derivation came from `EAimTY/tuic`, `SPEC.md`.
  It said two things memory would not have: the server never answers `Connect`,
  and heartbeats are sent only while a relay task is in flight.
- The `quic` UDP relay mode was fixed by reading `packet_quic` in
  `tuic-quinn/src/lib.rs`, which settled that it is one stream per fragment
  carrying a full command header.

Our own servers are authoritative for interoperating with us. The specification
is authoritative for interoperating with the world. When they disagree, the
specification wins and our server has a bug.

### An outbound that owns its transport is a `TerminalConnector`

Most outbounds are a `SocketConnector` plus a `ProxyConnector`, so they compose
into a chain. WireGuard, AmneziaWG, Hysteria2 and TUIC cannot be expressed that
way: they bring their own transport and are always the only hop. They implement
`TerminalConnector` (`src/tcp/terminal_connector.rs`) instead, and
`ClientProxyConfig::owns_transport()` is the predicate that routes a config down
that path.

If a new protocol carries its own transport, add it there rather than bending it
into the chaining traits. Configuration validation must then reject putting it
mid-chain, because the type system will not.

### The client and the server share one codec

`src/hysteria2/frame.rs` and `src/tuic/frame.rs` hold the encoders and parsers
both sides use. Do not write a second copy for the other direction; if the
server needs a different input shape, add a variant that shares the layout —
`encode_packet_header_with_address` exists because the server has the address
already serialized.

### QUIC transport parameters are part of the fingerprint

Copy the values our servers use rather than inventing plausible ones. Hysteria
pins its transport parameters as part of imitating Chrome, so novel values are a
signature that buys nothing.

One of them is not a preference: **`max_concurrent_uni_streams` must not be
zero on a client.** It bounds what the server may open toward us, and HTTP/3
needs its control and QPACK streams before Hysteria2's authentication can
finish. Zero produces a handshake that hangs rather than an error.

## Configuration surface

### Refuse loudly rather than ignoring

If a configuration option is accepted but not implemented, reject it in
`src/config/validate.rs` with a message that says so. A user who asks for
`zero_rtt_handshake` and silently gets an ordinary handshake believes something
false about their setup.

### Validate what the reference validates

Limits from an upstream implementation belong in validation, with the source
named — an obfuscation password shorter than four bytes is rejected because
`smPSKMinLen` upstream rejects it.

### Every option reaches the documentation and an example

`CONFIG.md` gets the field and its default. `examples/` gets a config that
parses, and `.github/workflows/build.yml` gets that example added to the
`Smoke test binary` loop, so a release binary parses it end to end every build.
Only cert-free examples can go in that loop — the rest reference PEM files the
repository does not carry.

Say the things a user would otherwise learn painfully. A Hysteria2 password is
one opaque string, so a `userpass` server wants `<username>:<password>`. A
mismatched obfuscation password produces no error at all and looks exactly like
an unreachable server.

## Commits and documentation

Subject: `area: imperative summary`, lowercase. Body: why, in prose. The diff
already says what changed; the message explains what the reader cannot see —
what was wrong, what was considered, what was deliberately not done.

End every message with:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

**Commit signing is flaky.** A commit failing with
`1Password: failed to fill whole buffer` needs the same command run again;
the files stay staged. Never work around it by disabling signing.

**A live check tests the binary, not the source.** Rebuild before running one.
A stale binary once reported a stub error for a feature that was already
implemented.

When a fix closes something recorded in `ROADMAP.md` or `MOBILE.md`, update that
record in the same commit. When it opens something new, write it down there with
enough detail to act on: what is broken, what fixing it touches, and what it
costs to leave.

## Where the known debt is written down

Open findings from the 2026-08-20 audit, none of them fixed yet:

- **No `catch_unwind` at the FFI boundary.** The 10 JNI and 11 C entry points
  are plain `extern` functions. On the mobile profile `panic = "abort"` makes
  a panic a defined abort, but a desktop `--features ffi` build unwinds, and a
  panic crossing an `extern "C"` frame is undefined behaviour. Either wrap the
  entry points in `catch_unwind` or build desktop FFI artifacts with
  `panic = "abort"` too.
- **Every crates.io dependency is `"*"`** (58 of them). `--locked` in CI and
  the committed lockfile mean builds are reproducible, but any plain
  `cargo update` may jump majors untested, and nothing pins what a fresh
  clone without the lockfile would get. Pinning majors (`"1"`, `"0.12"`) keeps
  the flexibility and removes the cliff.
- **No advisory coverage.** Dependabot alerts are disabled on the repository
  and `cargo audit` is not in CI. The h2 RUSTSEC fix in this branch's history
  was found by hand; the next one will not announce itself. Enable one of the
  two — a weekly `cargo audit` job is one workflow step.
- `MOBILE.md` says its line references were last checked against `037018e`;
  the branch has moved far since, so trust symbol names over line numbers
  until someone re-verifies them.

- `ROADMAP.md`, "Hysteria: the rest of the surface" — every unimplemented part
  of Hysteria2, grouped by whether it costs reachability, speed or visibility.
- `MOBILE.md` — mobile defects, numbered, with a suggested order at the end.
- `src/hysteria2/server.rs` and `src/tuic/server.rs` still reassemble fragments
  with their own `FragmentedPacket` and `LruCache` pair rather than
  `quic_transport::fragments::FragmentTable`. Both are already bounded, so
  there is no defect to fix — they carry extra per-packet state (a received
  counter, the accumulated length, and the address to reply to) that the shared
  table deliberately does not.
- One deliberate item not recorded elsewhere:
  - `src/vless/vision_stream.rs` and
    `src/shadow_tls/shadow_tls_server_handler.rs` have no tests at all. These
    are data paths, so covering them means designing the tests, not adding a
    few. `vmess_handler.rs`, `shadowsocks_stream.rs` and
    `routing/udp_router.rs` were on this list until each got tests; the first
    two surfaced real defects, which is the argument for doing the rest. The
    router's tests drive `run_udp_routing` end to end through a scripted
    server-side stream against real loopback echo sockets - reuse that double
    rather than inventing another.
- `src/quic_server.rs::start_quic_server`, the generic QUIC listener behind
  VLESS and the other TCP protocols, still builds its own endpoint and sets no
  transport parameters at all — there is a TODO in it proposing some. It was
  deliberately left out of the `quic_transport` consolidation: it binds with a
  different socket buffer size, and giving it the shared parameters would change
  behaviour for every QUIC inbound rather than remove a duplicate.
