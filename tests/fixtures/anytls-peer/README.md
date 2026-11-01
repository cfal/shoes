# AnyTLS Pooling Reference Peer

Plaintext, test-only service using SagerNet/sing-anytls at
`580984e4d8cb10f1c5e88d7ec14cfe4d955d66e6`. TCP echoes through the reference
session implementation. Connected UoT uses sing v0.8.14's request and packet
parser and forwards complete datagrams to the requested loopback UDP socket.
UoT success is deliberately delayed until its header arrives. A custom padding
scheme exercises negotiated state on later connections, including WASTE
payloads above 65535 bytes.

From this directory:

```sh
GOMAXPROCS=1 go build -mod=readonly -p 1 -o "$HOME/tmp/shoes-anytls-peer" .
```

From the repository root:

```sh
ANYTLS_REFERENCE_PEER="$HOME/tmp/shoes-anytls-peer" CARGO_BUILD_JOBS=1 \
  cargo test --locked --lib reference_peer_tcp_uot_and_concurrent_session_reuse -- --ignored
```

The Rust test launches and terminates the peer. It uses ephemeral TCP/UDP ports,
the test password `test`, and counts carrier dials. UDP payloads range from 1 to
65507 bytes, followed by a small packet to detect residual framing. The UDP
endpoint checks each complete payload and transforms the reply, so a byte-stream
echo cannot satisfy the assertions. Both sides are polled together without
detached fixture tasks; the entire exchange has a deadline. TLS handshake reuse
is tested separately by `chains_reuse_tls_once_per_selected_prefix_for_tcp_and_udp`.

The maximum UDP payload case is verified on Linux. Other platforms may impose
lower datagram limits; this test does not adjust system networking settings.
