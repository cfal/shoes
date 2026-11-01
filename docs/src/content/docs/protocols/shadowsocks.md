---
title: "Shadowsocks"
description: shoes shadowsocks configuration.
---

**Complete example:** [shadowsocks_basic.yaml](/examples/shadowsocks_basic/). Adapt addresses and secrets before deployment.

The field sketches below contain placeholders, not runnable values. Use a complete example when configuring a deployment.

## Server

```yaml
protocol:
  type: shadowsocks            # Aliases: ss
  cipher: string               # See supported ciphers below
  password: string

# Supported ciphers:
# - aes-128-gcm
# - aes-256-gcm
# - chacha20-ietf-poly1305
# - 2022-blake3-aes-128-gcm
# - 2022-blake3-aes-256-gcm
# - 2022-blake3-chacha20-ietf-poly1305
```


## Client

```yaml
protocol:
  type: shadowsocks
  cipher: string
  password: string
```

For `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`, a client can connect
to a multi-user server using `password: "server-key:user-key"`. Each component is
independently base64-encoded and must decode to 16 bytes for AES-128 or 32 bytes
for AES-256. For identity relays, use
`password: "relay-key:server-key:user-key"`, with identity keys in connection order
and the user key last. These are SS2022 extensible identity headers (EIH), not
separate entries in `client_chain`.

Single-key SS2022 configurations are unchanged. Identity chains are client-only
and are not supported by `2022-blake3-chacha20-poly1305`. Legacy Shadowsocks
passwords may still contain literal colons. shoes does not accept multi-user
identity chains in server configurations.

`udp_enabled: true` on the client uses the same identity handshake for SagerNet
UDP-over-TCP and requires a UoT-capable upstream. It does not enable native
SS2022 UDP. See [examples/shadowsocks-2022-client.yaml](/examples/shadowsocks-2022-client/).
