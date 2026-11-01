---
title: "Vision (XTLS-Vision)"
description: "shoes vision（xtls-vision）配置。"
---

Vision 通过检测内部 TLS 流量并切换到直接模式以实现零复制性能，优化 TLS-in-TLS 场景。

**要求：**
- 内部协议必须是 VLESS
- 适用于 TLS 和 Reality

```yaml
# TLS + Vision
protocol:
  type: tls
  tls_targets:
    "example.com":
      cert: cert.pem
      key: key.pem
      vision: true
      alpn_protocols: ["http/1.1"]
      protocol:
        type: vless
        user_id: "uuid"

# Reality + Vision
protocol:
  type: tls
  reality_targets:
    "www.google.com":
      private_key: "..."
      short_ids: ["..."]
      dest: "www.google.com:443"
      vision: true
      protocol:
        type: vless
        user_id: "uuid"
```
