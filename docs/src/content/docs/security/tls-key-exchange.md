---
title: "TLS key exchange"
description: shoes tls key exchange configuration.
---

`key_exchange_groups` is an optional, ordered allowlist for ordinary TLS clients,
TLS server targets (including `default_tls_target`), and client/server
`quic_settings`. It applies to that TLS layer, regardless of the inner proxy
protocol. Supported names are case-sensitive:

- `X25519MLKEM768`: native rustls X25519 + ML-KEM-768 hybrid.
- `SecP256r1MLKEM768`: native rustls P-256 + ML-KEM-768 hybrid.
- `X25519`, `SecP256r1`, `SecP384r1`: classical groups.

Omitting the field preserves rustls defaults: currently X25519+ML-KEM-768 is
preferred, with classical fallback. An explicit list replaces those defaults;
the first client group normally supplies the initial key share. Empty lists, duplicates,
null, unknown names, standalone ML-KEM, and `SecP384r1MLKEM1024` are rejected.
No custom cryptographic implementations are used.

Client QUIC allowlists require a non-direct client at the first chain hop
(hop 0), where shoes creates the QUIC transport. Explicit allowlists on direct
clients or later hops are rejected, including entries resolved from groups or
pools. Use ordinary TLS in a later hop's `protocol` when that hop needs its own
hybrid-protected tunnel.

To require hybrid exchange without classical fallback:

```yaml
key_exchange_groups: [X25519MLKEM768, SecP256r1MLKEM768]
```

Hybrid-only lists force TLS 1.3 and disable early application data. TLS 1.3
resumption remains enabled and still performs a fresh exchange using an allowed
hybrid group. Peers offering only classical groups or TLS 1.2 cannot connect.
For opportunistic hybrid exchange with explicit classical fallback, use a mixed
list such as `[X25519MLKEM768, X25519, SecP256r1]`.

Hybrid-only lists cannot be combined with `vision: true` on the same TLS layer:
Vision direct copy bypasses that layer's encryption. They also cannot be
combined with TUIC `zero_rtt_handshake: true`. Ordinary outer TLS or QUIC can
still protect a separate inner Vision connection. The setting does not apply to
REALITY, VLESS encryption, or ShadowTLS camouflage handshakes; it is rejected on
ShadowTLS configurations and with deprecated `shadowtls_password`.

Hybrid key exchange protects session-key establishment, not certificate
signatures. Certificate verification, fingerprints, and mTLS work as before.
`verify: false` without a trusted fingerprint still permits active impersonation.
