---
title: "使用技巧"
description: "shoes提示配置。"
---

### 生成密钥

**Reality 密钥对：**
```bash
shoes generate-reality-keypair
```

**可选的 Reality 后量子身份验证密钥：**
```bash
shoes generate-reality-mldsa65-keypair
```
在服务器上保留`mldsa65_seed`；仅向客户端分发 `mldsa65_verify`。

**Shadowsocks 2022 密码：**
```bash
shoes generate-shadowsocks-2022-password 2022-blake3-aes-256-gcm
```

**UUID：**
```bash
uuidgen
```

**TLS 证书指纹：**
```bash
openssl x509 -in cert.pem -noout -fingerprint -sha256
```

### 安全最佳实践

- 使用强随机密码
- 确保私钥安全
- 使用 `127.0.0.1` 而不是 `0.0.0.0` 进行仅限本地访问
- 使用防火墙规则来限制访问
- 为敏感服务启用客户端证书身份验证
- 将 Vision 与 Reality 结合使用可实现最大程度的隐私保护

### 性能技巧

- 对 TLS-in-TLS 场景启用 `vision: true`
- 使用 `tcp_settings.no_delay: true` 实现低延迟
- 设置 `quic_settings.num_endpoints` 以匹配工作线程
- 对高延迟或有损网络使用 QUIC 传输

### 常见问题

- **“地址已在使用中”**：更改端口或停止冲突服务
- **“权限被拒绝”**：端口 < 1024 需要 root/admin
- **Reality 连接失败**：验证密钥匹配、UUID 匹配、SNI 匹配服务器的 real_targets 密钥
- **Vision 不起作用**：确保内部协议为 VLESS
- **配置验证失败**：使用 `--dry-run` 运行以获取详细错误
