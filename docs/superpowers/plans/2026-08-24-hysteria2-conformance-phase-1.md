# Hysteria2 Conformance, Phase 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the four Hysteria2 divergences that make a real peer fail against us, and stop the fifth from failing silently.

**Architecture:** Four independent repairs — a response that waits for the dial, a single datagram demultiplexer per connection, a wire-format address encoder, and one header value — plus a named error for the datagram limitation that cannot be fixed inside quinn.

**Tech Stack:** Rust, quinn 0.11, tokio. Reference: HyNetworks/hysteria at `619a6f8`, cloned at `/tmp/hysteria`.

**Spec:** [docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md](../specs/2026-08-24-hysteria2-conformance-design.md)

---

## File Structure

| File | Responsibility |
| --- | --- |
| `src/address.rs` | Gains `NetLocation::to_wire_string`, the RFC 3986 form used on any wire |
| `src/hysteria2/client.rs` | Uses it for the TCP request and the UDP session address |
| `src/hysteria2/server.rs` | Dials before answering; uses the wire form for reply addresses; sends `auto`; names the datagram failure |
| `src/quic_outbound/connection.rs` | Gains the per-connection datagram demultiplexer |
| `src/hysteria2/udp.rs` | Takes a channel from the demultiplexer instead of reading the shared connection |

Tasks 1 and 4 are independent of each other and of 2 and 3. Task 2 is the only
structural one.

---

### Task 1: Address the wire the way RFC 3986 does

Our encoder writes `2001:db8::1:443`; Go's `net.SplitHostPort` rejects it. Our
own parser accepts it, which is why no test has ever failed.

**Files:**
- Modify: `src/address.rs` (add a method to `impl NetLocation`)
- Modify: `src/hysteria2/client.rs:181`, `src/hysteria2/client.rs:214`
- Modify: `src/hysteria2/server.rs:363`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/address.rs`:

```rust
    /// The form that goes on a wire is not the form that goes in a log. Go's
    /// net.SplitHostPort - which is what a Hysteria2 server feeds the address
    /// to - rejects an unbracketed IPv6 literal with "too many colons".
    ///
    /// Our own parser accepts the unbracketed form because it splits at the
    /// last colon, so a round-trip test through our own code cannot catch
    /// this. The expected values below are what Go accepts, not what we parse.
    #[test]
    fn test_the_wire_form_brackets_an_ipv6_literal() {
        let v6 = NetLocation::from_str("[2001:db8::1]:443", None).unwrap();
        assert_eq!(v6.to_wire_string(), "[2001:db8::1]:443");

        let v4 = NetLocation::from_str("1.2.3.4:443", None).unwrap();
        assert_eq!(v4.to_wire_string(), "1.2.3.4:443");

        let host = NetLocation::from_str("example.com:443", None).unwrap();
        assert_eq!(host.to_wire_string(), "example.com:443");
    }

    /// Display is deliberately left alone: it is used in logs and errors all
    /// over the tree. This pins the difference so nobody "unifies" them.
    #[test]
    fn test_display_is_not_the_wire_form() {
        let v6 = NetLocation::from_str("[2001:db8::1]:443", None).unwrap();
        assert_eq!(v6.to_string(), "2001:db8::1:443");
        assert_ne!(v6.to_string(), v6.to_wire_string());
    }
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --lib address::tests::test_the_wire_form`
Expected: FAIL to compile — `no method named 'to_wire_string'`.

- [ ] **Step 3: Add the method**

In `src/address.rs`, inside `impl NetLocation`, after `pub fn port`:

```rust
    /// The address as a peer expects to receive it, per RFC 3986: an IPv6
    /// literal in brackets so its colons cannot be read as the port separator.
    ///
    /// `Display` does not do this and must not start: it is what logs and
    /// error messages use throughout the tree. This is the form for anything
    /// that leaves the process. Go's `net.SplitHostPort`, which is what the
    /// Hysteria2 reference feeds a received address to, rejects the
    /// unbracketed form outright.
    pub fn to_wire_string(&self) -> String {
        match self.address {
            Address::Ipv6(ref addr) => format!("[{addr}]:{}", self.port),
            _ => format!("{}:{}", self.address, self.port),
        }
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib address::`
Expected: PASS.

- [ ] **Step 5: Use it at the three sites**

`src/hysteria2/client.rs:181`, replace:

```rust
        let address = target.location().to_string();
```

with:

```rust
        let address = target.location().to_wire_string();
```

Then find the UDP session address near `src/hysteria2/client.rs:214` and the
server's reply-source override near `src/hysteria2/server.rs:363` and make the
same substitution. Read the surrounding lines first: both build an address
string for a datagram header, and both must use the wire form.

Run `grep -n "to_string()" src/hysteria2/` afterwards and check that no
remaining hit is an address destined for the wire.

- [ ] **Step 6: Run the whole suite**

Run: `cargo test --lib hysteria2 && cargo test --lib address`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/address.rs src/hysteria2/client.rs src/hysteria2/server.rs
git commit -m "hysteria2: bracket IPv6 literals on the wire

net.SplitHostPort rejects 2001:db8::1:443, which is what
NetLocation::to_string produces, so every IPv6 target failed against a
real server. Our parser splits at the last colon and accepted it, so
encoder and decoder agreed and no test failed."
```

---

### Task 2: One datagram demultiplexer per connection

Every UDP session reads the shared `quinn::Connection` and discards what is not
its own, so N concurrent sessions each lose about (N-1)/N of their traffic.

**Files:**
- Modify: `src/quic_outbound/connection.rs`
- Modify: `src/hysteria2/udp.rs:40-70`
- Modify: `src/hysteria2/client.rs:218` (where the session is built)

- [ ] **Step 1: Read what exists**

Read `src/hysteria2/udp.rs` in full and `src/quic_outbound/connection.rs`
lines 50-100. You need to know how `Hysteria2UdpSession` currently receives and
what `LiveConnection` holds. Note that `LiveConnection::get` returns a *clone*
of one `quinn::Connection`, which is the root of the defect.

- [ ] **Step 2: Write the failing test**

Add to `mod tests` in `src/hysteria2/client.rs`:

```rust
    /// Two UDP sessions over one outbound must not eat each other's
    /// datagrams. Before the demultiplexer each session ran its own
    /// read_datagram loop on the shared connection and dropped anything whose
    /// session id was not its own, so each lost about half.
    #[tokio::test]
    async fn test_two_udp_sessions_do_not_steal_from_each_other() {
        let (server, _cert) = spawn_server(None).await;
        let echo = spawn_udp_echo().await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        let mut first = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();
        let mut second = connector
            .connect_udp_bidirectional(&resolver, target(echo))
            .await
            .unwrap();

        // Interleave, so a stealing reader has every chance to win the race.
        for round in 0..8u8 {
            for (label, session) in [(1u8, &mut first), (2u8, &mut second)] {
                let payload = [label, round];
                std::future::poll_fn(|cx| {
                    Pin::new(&mut *session).poll_write_message(cx, &payload)
                })
                .await
                .unwrap();
            }
        }

        // Every session must get its own eight back.
        for (label, session) in [(1u8, &mut first), (2u8, &mut second)] {
            for round in 0..8u8 {
                let mut buf = [0u8; 64];
                let mut read = ReadBuf::new(&mut buf);
                tokio::time::timeout(
                    Duration::from_secs(5),
                    std::future::poll_fn(|cx| {
                        Pin::new(&mut *session).poll_read_message(cx, &mut read)
                    }),
                )
                .await
                .unwrap_or_else(|_| panic!("session {label} lost datagram {round}"))
                .unwrap();
                assert_eq!(read.filled()[0], label, "session {label} got another session's datagram");
            }
        }
    }
```

- [ ] **Step 3: Run it and watch it fail**

Run: `cargo test --lib hysteria2::client::tests::test_two_udp_sessions -- --nocapture`
Expected: FAIL — a timeout naming a lost datagram. If it passes, the race did
not trigger; raise the round count to 32 and re-run before concluding anything.

- [ ] **Step 4: Add the demultiplexer to `LiveConnection`**

In `src/quic_outbound/connection.rs`, add above `impl LiveConnection`:

```rust
/// Routes incoming QUIC datagrams to the session they belong to.
///
/// One `quinn::Connection` is shared by every session on an outbound, and
/// `read_datagram` pops from a single queue: a reader per session wins its
/// share of the datagrams and drops the rest. Upstream runs one demultiplexer
/// per connection and dispatches by session id
/// (`core/client/udp.go:126-142`); this is that.
#[derive(Default)]
pub struct DatagramRouter {
    sessions: parking_lot::Mutex<
        std::collections::HashMap<u32, tokio::sync::mpsc::UnboundedSender<bytes::Bytes>>,
    >,
}

impl DatagramRouter {
    /// Register a session and take the receiving end of its channel.
    pub fn register(&self, session_id: u32) -> tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.sessions.lock().insert(session_id, tx);
        rx
    }

    pub fn deregister(&self, session_id: u32) {
        self.sessions.lock().remove(&session_id);
    }

    /// Hand a datagram to its session. A datagram for a session that has gone
    /// away is dropped here, once, rather than by every reader in turn.
    fn dispatch(&self, session_id: u32, datagram: bytes::Bytes) {
        let sender = self.sessions.lock().get(&session_id).cloned();
        if let Some(sender) = sender {
            let _ = sender.send(datagram);
        }
    }
}
```

- [ ] **Step 5: Drive it from one task per connection**

Still in `connection.rs`, add to `LiveConnection` a field
`router: Arc<DatagramRouter>` initialised in `new`, a getter
`pub fn router(&self) -> Arc<DatagramRouter>`, and spawn the reader when a
connection is established — in `attempt`, immediately after
`self.authenticator.authenticate(&connection).await?`:

```rust
        // One reader for the whole connection. It ends when the connection
        // does, because read_datagram then returns an error.
        let router = self.router.clone();
        let reading = connection.clone();
        tokio::spawn(async move {
            while let Ok(datagram) = reading.read_datagram().await {
                // The session id is the first four bytes of every Hysteria2
                // datagram (`core/internal/protocol/proxy.go:151-223`).
                if datagram.len() >= 4 {
                    let session_id = u32::from_be_bytes([
                        datagram[0], datagram[1], datagram[2], datagram[3],
                    ]);
                    router.dispatch(session_id, datagram);
                }
            }
        });
```

- [ ] **Step 6: Take the channel in the session**

In `src/hysteria2/udp.rs`, replace the field that holds the receive side and the
task that reads the connection with an
`tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>` obtained from
`DatagramRouter::register`, polled in `poll_read_message` with
`Receiver::poll_recv`. Implement `Drop` for the session to call
`deregister(session_id)`, so a closed session stops holding a sender.

In `src/hysteria2/client.rs`, where the session is constructed, pass
`self.connection.router()` and the session id.

- [ ] **Step 7: Run the test**

Run: `cargo test --lib hysteria2 -- --nocapture`
Expected: PASS, including the new test and every existing UDP test.

- [ ] **Step 8: Mutation-check**

Temporarily make `dispatch` drop everything (`let _ = session_id; return;`).
Expected: the new test fails. Restore and confirm it passes. If it passed with
dispatch disabled, the test is not exercising the router.

- [ ] **Step 9: Commit**

```bash
git add src/quic_outbound/connection.rs src/hysteria2/udp.rs src/hysteria2/client.rs
git commit -m "hysteria2: demultiplex datagrams once per connection

Every session ran its own read_datagram loop on the shared connection
and discarded what was not its own, so N concurrent sessions each lost
(N-1)/N of their traffic. Two simultaneous DNS lookups lost about half
their replies."
```

---

### Task 3: Dial before answering

**Files:**
- Modify: `src/hysteria2/server.rs:841-861` and the dial site around `:902-923`

- [ ] **Step 1: Read both halves**

Read `src/hysteria2/server.rs:830-930`. `handle_tcp_header` builds the response
bytes; `process_tcp_stream` dials afterwards. The response must move to after
the dial, and must carry the outcome.

- [ ] **Step 2: Write the failing test**

Add to the server's test module (or the client's, whichever already spawns both
ends — reuse `spawn_server`):

```rust
    /// The protocol has a status byte and a message for exactly this case.
    /// Answering OK before dialling makes a failed dial look to the client
    /// like a connection that succeeded and then closed, and it makes our own
    /// client's error path unreachable against our own server.
    #[tokio::test]
    async fn test_a_failed_dial_is_reported_as_an_error() {
        let (server, _cert) = spawn_server(None).await;
        let resolver = test_resolver();
        let connector = connector(server, SERVER_PASSWORD, None);

        // Nothing listens here: the dial fails.
        let dead = NetLocation::from_str("127.0.0.1:1", None).unwrap();
        let err = connector
            .connect_tcp(&resolver, dead.into())
            .await
            .expect_err("a failed dial must be an error, not a silent EOF");
        assert!(
            !err.to_string().is_empty(),
            "the error must carry the server's message"
        );
    }
```

- [ ] **Step 3: Run it and watch it fail**

Run: `cargo test --lib test_a_failed_dial_is_reported`
Expected: FAIL — `connect_tcp` returns `Ok`, because the server said OK.

- [ ] **Step 4: Move the response after the dial**

Change `handle_tcp_header` to return the parsed request without writing a
response, and have `process_tcp_stream` write the response once the dial has
resolved. Build it with the existing encoder rather than a second copy:
`frame.rs` already writes a TCP response, and upstream sends `Connected` as the
success message (`core/server/server.go:322`) where we send an empty one.

On failure, write status 1 with the dial error's text, then shut down. On
success, write status 0 with `Connected`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib hysteria2`
Expected: PASS, including `frame.rs`'s
`test_parse_tcp_response_error_carries_the_message`, which is currently dead
against our own server.

- [ ] **Step 6: Commit**

```bash
git add src/hysteria2/server.rs
git commit -m "hysteria2: dial before answering the client

The server sent status OK before it had dialled anything, so a failed
dial reached the client as a connection that succeeded and then closed
with no diagnosis - and our own client's error path was unreachable
against our own server. Success now carries \"Connected\", as upstream
does."
```

---

### Task 4: `Hysteria-CC-RX: auto`

**Files:**
- Modify: `src/hysteria2/server.rs:239`

- [ ] **Step 1: Write the failing test**

```rust
    /// 0 means "no limit, send as fast as you like", which makes an official
    /// client switch to fixed-rate Brutal congestion control
    /// (`core/client/client.go:156-162`). We ignore the client's declared
    /// bandwidth and install no congestion control of our own, which is
    /// exactly the case upstream signals with "auto"
    /// (`core/server/server.go:172,206`).
    #[tokio::test]
    async fn test_the_server_reports_auto_congestion_control() {
        let (server, _cert) = spawn_server(None).await;
        let response = raw_auth_response(server).await;
        assert_eq!(
            response.headers().get("Hysteria-CC-RX").unwrap(),
            "auto",
            "0 tells the client to use Brutal at its configured rate"
        );
    }
```

If no helper performs a raw auth exchange, write one in the same test module
that opens a connection and sends the auth POST directly, returning the
response — the client's own auth code in `src/hysteria2/auth.rs` shows the
shape.

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --lib test_the_server_reports_auto`
Expected: FAIL — the header is `0`.

- [ ] **Step 3: Change the value**

At `src/hysteria2/server.rs:239`, replace the `"0"` with `"auto"`, and add:

```rust
        // "auto" is the server telling the client to run its own congestion
        // control. "0" means "no limit", which an official client reads as
        // permission to use Brutal at its configured rate against a server
        // that has installed no rate control at all.
```

- [ ] **Step 4: Run the tests, then commit**

Run: `cargo test --lib hysteria2`

```bash
git add src/hysteria2/server.rs
git commit -m "hysteria2: answer Hysteria-CC-RX with auto, not 0"
```

---

### Task 5: Name the datagram failure

Not a fix. `quinn::Datagrams::send` refuses when the peer omitted
`max_datagram_frame_size` (`quinn-proto-0.11.17/.../datagrams.rs:32-34`), which
every official client does, and quinn has no assume-peer knob. The spec records
the three options; the choice is the user's. What is implementable now is to
stop failing silently.

**Files:**
- Modify: `src/hysteria2/server.rs:341`, `:357-359`

- [ ] **Step 1: Raise the diagnosis**

At `server.rs:357`, where `max_datagram_size()` returns `None`, log at `warn`
with a message that names the cause and the consequence:

```rust
                log::warn!(
                    "UDP session {session_id} cannot reply: the client did not \
                     advertise max_datagram_frame_size, and quinn will not send \
                     datagrams to a peer that omitted it. Every official \
                     Hysteria2 client omits it. See \
                     docs/superpowers/specs/2026-08-24-hysteria2-conformance-design.md"
                );
```

At `server.rs:341`, where the spawned task ends, make sure the task's exit is
logged rather than silent.

- [ ] **Step 2: Run the suite and commit**

Run: `cargo fmt --all && cargo test --lib && cargo clippy --locked --lib --bins --tests -- -D warnings`

```bash
git add src/hysteria2/server.rs
git commit -m "hysteria2: say why UDP replies are impossible for some peers

Not a fix: quinn refuses to send datagrams to a peer that omitted
max_datagram_frame_size, which is every official client, and offers no
way to assume one. Until that is decided, the operator gets a named
warning instead of a task that dies at debug level."
```

---

### Task 6: The gate, and the record

- [ ] **Step 1: Full gate**

```bash
cargo fmt --all -- --check
cargo clippy --locked --lib --bins --tests -- -D warnings
cargo clippy --locked --features ffi --lib --tests -- -D warnings
cargo clippy --locked --features ffi --bins -- -D warnings
cargo test --lib
cargo test --bins
cargo test --test '*'
```

- [ ] **Step 2: Record it**

Add an `Unreleased` entry to `CHANGELOG.md` describing the four fixes in terms
of what a user sees — an IPv6 target that now works, UDP sessions that no
longer lose traffic, a failed dial that now says why, and a congestion-control
signal that no longer makes an official client misbehave. Mention the datagram
limitation and that it is unresolved.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: record the Hysteria2 conformance fixes"
```

---

## Live verification

Phase 1 is where a live run pays for itself: four of these are invisible to any
test where both ends are ours. Against a real Hysteria2 server, check an IPv6
target, two simultaneous UDP associations, and a connection to a dead port.

Test configs carrying real credentials go in a temp directory outside the
working tree and are deleted afterwards; `git status` and the outgoing diff get
scanned before any push.
