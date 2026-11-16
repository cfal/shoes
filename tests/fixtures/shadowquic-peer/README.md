# ShadowQuic reference peer

`main.rs` uses the reference repository's own `ShadowQuicClient`, TCP/UDP helpers,
and statistics decoder. Shoes does not compile this fixture as a normal test or
add a nonportable local dependency. The reference checkout is read only.

```sh
python3 tests/fixtures/shadowquic-peer/build.py /path/to/shadowquic /tmp/shadowquic-peer-target
SHOES_SHADOWQUIC_PEER=/tmp/shadowquic-peer-target/debug/shoes-shadowquic-reference-peer \
  cargo test --locked --lib shadowquic_server::tests::reference_client_interoperability -- --ignored --exact
```

Use reference version 0.4.10 with `quinn-jls` 0.4.0. The test runs loopback TCP
and UDP echo servers and validates both UDP transport modes and statistics using
the reference encoders and decoders, without Internet services or privileged ports.
