---
title: "客户端配置"
description: "shoes 客户端配置参考。"
---

客户端配置用于在规则中指定上游代理。

下面是字段示意，而不是完整配置。将 `address` 设为代理端点，选择[客户端协议](/zh-cn/protocols/socks5/)，再从[代理链或命名组](/zh-cn/routing/chains/)引用客户端。可选的 `name` 用于在控制器中标识内联组成员。`tcp_settings` 适用于 TCP，`quic_settings` 适用于 QUIC。受支持的组参见 [TLS 密钥交换](/zh-cn/security/tls-key-exchange/)；身份来源参见[证书](/zh-cn/security/certificates/)。

```yaml
address: string                # Proxy server address (e.g., "proxy.example.com:1080")
protocol: ClientProxyConfig
name: string?                 # Optional named group member
transport: tcp | quic          # Default: tcp; WireGuard only: udp (default, required)
bind_interface: string         # Optional, Linux/Android/Fuchsia only

tcp_settings:
  no_delay: true

quic_settings:
  verify: true                 # Default: true
  server_fingerprints: [string]
  sni_hostname: string
  alpn_protocols: [string]
  cert: string                 # Client certificate for mTLS
  key: string                  # Client key for mTLS
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS key exchange
```

WireGuard 客户端使用 `address` 作为其对等端点，并拒绝 TCP/QUIC 套接字设置。有关其协议字段，请参阅 [WireGuard](/zh-cn/protocols/wireguard/)。

对于 QUIC，如果省略 `sni_hostname`，当 `address` 为主机名时会发送该主机名作为 SNI；显式设置为 `null` 则不发送 SNI。即使不发送 SNI，证书验证仍使用代理地址，包括 IPv4 和 IPv6 字面地址。显式设置的主机名覆盖值同时用于 SNI 和证书验证。
