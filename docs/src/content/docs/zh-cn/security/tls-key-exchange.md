---
title: "TLS 密钥交换"
description: "shoes tls 密钥交换配置。"
---

`key_exchange_groups` 是普通 TLS 客户端、TLS 服务器目标（包括 `default_tls_target`）和客户端/服务器 `quic_settings` 的可选有序白名单。它适用于 TLS 层，无论内部代理协议如何。支持的名称区分大小写：

- `X25519MLKEM768`：原生 rustls X25519 + ML-KEM-768 混合体。
- `SecP256r1MLKEM768`：天然 rustls P-256 + ML-KEM-768 混合体。
- `X25519`、`SecP256r1`、`SecP384r1`：经典组。

省略该字段会保留 rustls 默认值：目前首选 X25519+ML-KEM-768，具有经典的后备功能。明确的列表取代了这些默认值；第一客户组通常提供初始密钥共享。空列表、重复项、空列表、未知名称、独立 ML-KEM 和 `SecP384r1MLKEM1024` 将被拒绝。不使用自定义加密实现。

客户端 QUIC 允许列表需要位于第一个链跃点（跃点 0）的非直接客户端，其中 shoes 创建 QUIC 传输。直接客户端或后续跃点上的显式白名单将被拒绝，包括从组或池解析的条目。当后面一跳需要自己的混合保护隧道时，在该跳的 `protocol` 中使用普通 TLS。

需要混合交换而无需经典回退：

```yaml
key_exchange_groups: [X25519MLKEM768, SecP256r1MLKEM768]
```

仅混合列表强制 TLS 1.3 并禁用早期应用程序数据。 TLS 1.3 恢复保持启用状态，并且仍然使用允许的混合组执行新的交换。仅提供经典组或 TLS 1.2 的对等点无法连接。对于具有显式经典回退的机会混合交换，请使用混合列表，例如 `[X25519MLKEM768, X25519, SecP256r1]`。

仅混合列表不能与同一 TLS 层上的 `vision: true` 组合：Vision 直接复制会绕过该层的加密。它们也不能与 TUIC `zero_rtt_handshake: true` 组合。普通外部TLS或QUIC仍然可以保护单独的内部Vision连接。该设置不适用于REALITY、VLESS加密或ShadowTLS伪装握手；它在 ShadowTLS 配置和已弃用的 `shadowtls_password` 上被拒绝。

混合密钥交换保护会话密钥的建立，而不是证书签名。证书验证、指纹和 mTLS 的工作方式与以前一样。没有可信指纹的 `verify: false` 仍然允许主动模仿。
