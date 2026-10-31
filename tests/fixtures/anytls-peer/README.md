# AnyTLS Pooling Reference Peer

Plaintext, test-only echo service using SagerNet/sing-anytls at
`580984e4d8cb10f1c5e88d7ec14cfe4d955d66e6`. TCP and UoT stream handling use
the reference session implementation. UoT success is deliberately delayed until
its header arrives. A custom padding scheme exercises negotiated state on later
connections, including WASTE payloads above 65535 bytes.

From this directory:

```sh
GOMAXPROCS=1 go build -p 1 -o "$HOME/tmp/shoes-anytls-peer" .
```

From the repository root:

```sh
ANYTLS_REFERENCE_PEER="$HOME/tmp/shoes-anytls-peer" CARGO_BUILD_JOBS=1 \
  cargo test --locked --lib reference_peer_tcp_uot_and_concurrent_session_reuse -- --ignored
```

The Rust test launches and terminates the peer. It uses an ephemeral TCP port,
the test password `test`, and counts carrier dials. TLS handshake reuse is tested
separately by `chains_reuse_tls_once_per_selected_prefix_for_tcp_and_udp`.
