# HTTPUpgrade transport, server and client

Written 2026-08-25 against `mobile` at `44a1cd0`, and against
[SagerNet/sing-box](https://github.com/SagerNet/sing-box) at `0f17638`
(`transport/v2rayhttpupgrade`, last touched 2026-07-03; current release
v1.13.19).

## Why

HTTPUpgrade is WebSocket's HTTP handshake without WebSocket's framing. The
client sends an ordinary `GET` carrying `Connection: Upgrade` and
`Upgrade: websocket`, the server answers `101`, and from there both sides write
raw bytes. To a CDN, a reverse proxy or a DPI box it looks like a WebSocket
connection being established; on the wire afterwards there is no masking, no
frame headers and no ping machinery.

That absence is the point. WebSocket framing costs 2 to 14 bytes per write and
forces the client to XOR-mask every byte it sends, which buys nothing when both
ends are a proxy rather than a browser. sing-box and Xray both ship the
transport for that reason, and a fair number of CDN-fronted server
configurations use it in place of `ws`.

shoes cannot speak it at all today, which means those servers are unreachable
and our own server cannot be published behind a CDN in the shape their clients
expect.

Scope: **the transport only, both sides, matching sing-box.** Xray's `ed` early
data and its browser-shaped default headers are out — see "What this does not
do".

## Sources

| What | Where |
| --- | --- |
| Reference client | `transport/v2rayhttpupgrade/client.go` at `0f17638` |
| Reference server | `transport/v2rayhttpupgrade/server.go` at `0f17638` |
| Our WebSocket transport | `src/websocket/websocket_handler.rs` |
| Handler construction | `src/tcp/tcp_server_handler_factory.rs:225`, `:587`; `src/tcp/tcp_client_handler_factory.rs:325` |
| Config types to mirror | `src/config/types/server.rs:623` (`WebsocketServerConfig`), `src/config/types/client.rs:799` (`WebsocketClientConfig`) |

## What the reference actually does

Read from the Go source rather than from documentation, because the parts that
break interoperability are not documented anywhere.

**Client** (`client.go`):

- `Host` is `options.Host` if set, otherwise the TLS server name, otherwise the
  server address as `host:port`. Go's `request.Write` always emits the header.
- The request is `GET <path> HTTP/1.1` with the configured headers, and then
  `Connection: Upgrade` and `Upgrade: websocket` applied with `Set` — so they
  overwrite anything the user configured under those names.
- **No `Sec-WebSocket-Key` is sent.** There is no key, no `Sec-WebSocket-Version`
  and no accept-hash check.
- The response is accepted only when the status is `101` *and* `Connection`
  equals `upgrade` *and* `Upgrade` equals `websocket`, all compared without
  regard to case.
- Bytes the reader buffered past the header block are preserved and handed to
  the caller in front of the connection (`bufio.NewCachedConn`).

**Server** (`server.go`), in order, each failure logged with its cause:

| Condition | Response |
| --- | --- |
| `Host` differs from the configured one (when one is configured) | `400` |
| path differs from the configured one (exact comparison) | `404` |
| method is not `GET` | `404` |
| `Connection` is not `upgrade` | `404` |
| `Upgrade` is not `websocket` | `404` |
| `Sec-WebSocket-Key` is present | `404`, logged as "real websocket request received" |

On success it writes `Connection: upgrade`, `Upgrade: websocket` and
`101 Switching Protocols`, flushes, hijacks the connection and hands it over.

The last row is the interesting one: an HTTPUpgrade server **must refuse a real
WebSocket handshake** rather than accept it and get the framing wrong. Our
client must therefore never send the key, and our server must reject it.

## Architecture

A new module, `src/httpupgrade/`, with a server handler and a client handler,
each implementing the existing `TcpServerHandler` / `TcpClientHandler` traits.
No new plumbing: both slot into the same factories that build the WebSocket
handlers, and both wrap an inner protocol handler exactly as WebSocket does.

Two pieces move out of the modules that own them today, because HTTPUpgrade
needs them verbatim and a second copy of either is a second place for the same
defect:

- **`ParsedHttpData`** — currently private in `src/websocket/websocket_handler.rs:263`.
  Reads the start line and headers off a stream, lowercases header names,
  refuses a line over 4096 bytes or a block over 40 lines, and keeps the
  `StreamReader` so the caller can recover what was read past the block. Moves
  to a shared module; WebSocket keeps using it unchanged.
- **`PrependStream`** — currently private in `src/h2mux/prepend_stream.rs`.
  Puts a byte prefix in front of a stream. WebSocket does not need it because
  `WebsocketStream` already carries the leftover bytes; HTTPUpgrade has no
  wrapper at all, so without this the bytes that arrived in the same packet as
  the header block are silently dropped. Both reference implementations carry
  dedicated code for this case.

### Components

| Unit | Responsibility |
| --- | --- |
| `HttpUpgradeServerTarget` | One matchable target: path, headers, inner handler — the same shape as `WebsocketServerTarget` minus `ping_type` |
| `HttpUpgradeTcpServerHandler` | Parses the request, selects a target, answers `101` or a refusal, hands the raw stream to the inner handler |
| `HttpUpgradeTcpClientHandler` | Writes the request, validates the response, hands the raw stream to the inner handler |

There is no stream type in this module. That is the whole difference from
WebSocket, and it is why the module is small.

## Data flow

**Client.** `setup_client_tcp_stream` writes the request, reads the response,
wraps the connection in `PrependStream` when the parser buffered anything past
the header block, and calls the inner handler's `setup_client_tcp_stream` with
it. `setup_client_udp_bidirectional` does the same and calls the inner handler's
UDP entry point; `supports_udp_over_tcp` forwards to the inner handler. This
mirrors `WebsocketTcpClientHandler` line for line.

**Server.** `setup_server_stream` parses the request, walks the configured
targets in order and takes the first whose `matching_path` and
`matching_headers` are satisfied, writes the `101`, wraps in `PrependStream` if
needed, and calls the inner handler. As WebSocket does, it sets
`need_initial_flush` on the result unless the inner handler already handled the
connection.

## Configuration

Server, `type: httpupgrade` (aliases `http-upgrade`, `http_upgrade`):

```yaml
protocol:
  type: httpupgrade
  targets:
    - matching_path: /download
      matching_headers:
        Host: cdn.example.com
      protocol:
        type: vmess
        cipher: aes-128-gcm
        user_id: "..."
```

`matching_path`, `matching_headers`, `protocol` and `override_rules` carry the
same meaning as under `type: websocket`, and `targets` accepts one or several.
`ping_type` does not exist here: there are no frames, so there is nothing to
ping with.

Client:

```yaml
protocol:
  type: httpupgrade
  host: cdn.example.com
  matching_path: /download
  protocol:
    type: vmess
    cipher: aes-128-gcm
    user_id: "..."
```

`host` exists on the client and not on the server, which is deliberate rather
than an oversight. On the server, `Host` is one header among many and
`matching_headers` already matches it. On the client there is nowhere else to
get the value: `setup_client_tcp_stream` receives the user's *destination*, not
the proxy's address, and the TLS wrapper's SNI is not visible from this layer.
Left unset, the request goes out without a `Host` header — which a bare sing-box
server accepts as long as it has no `host` of its own configured, and which
anything behind a CDN will refuse. `CONFIG.md` says so.

## Error handling

**Server refusals** are HTTP responses rather than a dropped connection, because
this transport's whole purpose is to be indistinguishable from a web server to
whatever is looking:

| Condition | Response |
| --- | --- |
| Malformed start line, oversized line or header block | `400 Bad Request` |
| Method is not `GET` | `404 Not Found` |
| `Connection` is not `upgrade`, or `Upgrade` is not `websocket` | `404 Not Found` |
| `Sec-WebSocket-Key` present | `404 Not Found` |
| No target matched on path or headers | `404 Not Found` |

Each carries `Content-Length: 0`, a `Date`, and `Connection: close`, and the
connection closes after it. Each is logged with its cause, as the reference
logs it.

**One deliberate deviation.** sing-box answers `400` specifically for a Host
mismatch and `404` for everything else. We cannot: `Host` is an ordinary entry
in `matching_headers` here, indistinguishable from the rest at the point of
refusal. Every mismatch is therefore `404`. No client can tell — sing-box's own
client inspects nothing but the `101` and the two headers — and both codes are
equally ordinary from a web server. Introducing a `matching_host` field to
recover one status code is not worth the second name for the same thing.

**Client failures** are `std::io::Error` with the cause in the message: a
non-`101` status quotes the status line, a missing or wrong `Connection` /
`Upgrade` header names which one was wrong and what arrived. A truncated
response is whatever the parser returns.

## Testing

The failure this codebase keeps hitting is an encoder and a decoder that share
one misreading, so every round-trip test passes. mieru produced nine such
defects and then eight more; Hysteria2 produced fifteen. Tests here are written
against the bytes, not against ourselves.

- **Exact-byte tests.** The client's request and the server's `101` are asserted
  as literal byte strings, including header order and the `\r\n\r\n`
  terminator. A round-trip through our own parser proves nothing about sing-box.
- **The key is never sent, and is always refused.** One test asserts the client
  request contains no `sec-websocket-key`; another feeds the server a genuine
  WebSocket handshake and asserts `404`.
- **Leftover bytes survive, on both sides.** Feed the header block and the first
  payload bytes in a single write, and assert the inner handler receives every
  payload byte. This is the defect `PrependStream` exists to prevent, and it is
  invisible to any test that writes the two separately.
- **Refusals.** One test per row of the table above, asserting the status code
  and that the connection closes.
- **End to end through the factories.** A config with `type: httpupgrade`
  wrapping an inner protocol, server and client in-process, TCP and
  UDP-over-TCP.
- **Live interoperability with sing-box**, both directions: our client against
  their server, their client against our server, each carrying real traffic.
  Manual, recorded in the changelog with what it proved. This is the standard
  this repository already holds — it is what caught what the tests could not in
  mieru and in Hysteria2 — and it needs a Go toolchain and a sing-box binary.

## What this does not do

- **Xray's `ed` early data.** With `ed > 0` the client writes its payload
  without waiting for the `101` and reads the response lazily on first read.
  That is a 0-RTT optimisation, and it does not fit
  `setup_client_tcp_stream`'s contract, which returns a stream that is ready to
  use. Adding it means changing that contract for every transport. Out of scope,
  and a server that requires it is not a server sing-box could reach either.
- **Xray's default browser-shaped headers.** `TryDefaultHeadersWith` fills in a
  `User-Agent` and friends when the config names none. It belongs with the
  fingerprinting question in ROADMAP.md, not here.
- **A separate `host` matcher on the server.** See "Error handling".
- **HTTP/2.** The reference explicitly refuses to serve HTTPUpgrade over h2 —
  the connection cannot be hijacked. Ours never sees h2 on this path.
