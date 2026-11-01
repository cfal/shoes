---
title: "服务器配置"
description: "shoes 服务器配置参考。"
---

WireGuard 服务器需要一个带有非零端口的文字 UDP 地址，或者在配置 `peer_client_chain` 时省略绑定位置。它们不支持端口范围、多个绑定地址或 Unix 套接字路径。请参阅[WireGuard](/zh-cn/protocols/wireguard/)。

这是一个字段示意，而不是一个可运行的监听器：选择一种绑定形式和具体的[服务器协议](/zh-cn/protocols/socks5/)。 `name` 可以选择为监听器提供稳定的仪表板身份。省略`rules`允许直接转发；使用[路由规则](/zh-cn/routing/rules/)来限制目的地或选择上游。可选的`dns`选择监听器的解析器（参见[DNS](/zh-cn/dns/configuration/)和[Fake DNS](/zh-cn/dns/fake/))； `sniff: true` 启用 [TCP 主机名嗅探](/zh-cn/routing/rules/#tcp-hostname-sniffing)。

```yaml
# Bind to IP address and port
address: "0.0.0.0:8080"        # IPv4
address: "[::]:8080"           # IPv6
address: "0.0.0.0:443-445"     # Port range

# OR bind to multiple addresses and port ranges (`address` is also accepted)
addresses:
  - "127.0.0.1:22223"
  - "172.17.0.1:22223-22225"

# OR bind to Unix socket (TCP only)
path: "/tmp/shoes.sock"

# Protocol configuration (required)
protocol: ServerProxyConfig
name: string?                 # Optional dashboard identity
sniff: false                  # TCP hostname sniffing, default false
dns: {servers: system}        # Optional resolver configuration

# Transport layer (default: tcp)
transport: tcp | quic          # WireGuard only: udp (default, required)

# TCP settings (only when transport: tcp)
tcp_settings:
  no_delay: true               # Default: true

# QUIC settings (required when transport: quic)
quic_settings:
  cert: string                 # TLS certificate (path or named PEM)
  key: string                  # TLS private key (path or named PEM)
  certificate_source: string   # Alternative managed certificate source
  alpn_protocols: [string]     # Optional ALPN protocols
  client_ca_certs: [string]    # Optional client CA certificates
  client_fingerprints: [string] # Optional client certificate fingerprints
  num_endpoints: int           # Optional, 0 = auto (based on thread count)
  key_exchange_groups: [X25519MLKEM768] # Optional; see TLS key exchange

# Routing rules (default: allow-all-direct; WireGuard requires explicit nonempty rules)
rules: string | [RuleConfig]
```

使用 `certificate_source` 或 `cert`/`key`，而不是同时使用；参见[证书来源](/zh-cn/security/certificates/)。有关支持的混合组和经典组，请参阅[TLS 密钥交换](/zh-cn/security/tls-key-exchange/)。
