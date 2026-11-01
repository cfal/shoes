---
title: "Sudoku TCP 掩码"
description: "shoes 数独 tcp 掩码配置。"
---

`sudoku_mask` 是 TCP 客户端和服务器的外部协议包装器。它实现 Xray FinalMask Sudoku，而不是独立的 Sudoku 隧道协议。它转换 TCP 承载层字节而不更改内部代理协议。掩码必须形成每个客户端跃点或服务器监听器的连续最外层前缀。在配置验证期间，任何非掩码协议下的掩码都会被拒绝。本机 UDP 和 QUIC 跳拒绝其协议树中任何位置的掩码，包括 XHTTP 内部。在受支持的 TCP 代理流内转发的 UDP/XUDP 仍受支持。

```yaml
# Outbound example: wire -> Sudoku -> TLS -> VLESS
address: proxy.example:443
transport: tcp
protocol:
  type: sudoku_mask
  password: "shared-mask-password"  # Default: empty; exact bytes, not trimmed
  ascii: prefer_entropy             # Default; also entropy, prefer_ascii, ascii
  padding_min: 0                    # Default: 0 percent
  padding_max: 0                    # Default: 0 percent
  protocol:
    type: tls
    protocol:
      type: vless
      user_id: "550e8400-e29b-41d4-a716-446655440000"
```

对于入站，请在常用服务器协议配置中使用相同的掩码选项，例如 `sudoku_mask -> tls` 和包含 VLESS 的 TLS `default_target`。默认TLS/REALITY SNI仍然来自出站地址。客户端写入经典编码，读取打包编码；服务器使用相反的方法。没有协商、标头、对称模式或自动密码/布局不匹配检测。将两个对等点配置在一起。

两个角色的选项相同：

| 字段 | 行为 |
| --- | --- |
| `ascii` | 不区分大小写、经过修剪的模式名称。 ASCII 模式会忽略自定义表，甚至是无效的表。 |
| `custom_table` | 可选的八字符布局，包含两个 `x`、两个 `p` 和四个 `v`，例如`xpxvvpvv`。空意味着熵布局。 |
| `custom_tables` | 非空列表覆盖`custom_table`；规范化的重复项将按首次看到的顺序删除。布局按经典字节或打包六位组旋转，包括跨写入。 |
| `padding_min`、`padding_max` | 无符号 32 位百分比，限制为 100；如果需要，最大值会提高到最小值。每个方向在其生命周期中选择一个包含概率。 |

自定义模式是小写的、经过修剪的，并删除了空格。 `custom_tables` 中的空条目选择熵。接受驼峰式别名 `customTable`、`customTables`、`paddingMin` 和 `paddingMax`。未知字段验证失败。

放置位置与 X 射线匹配，根部最接近导线：

- `mask -> TLS/REALITY -> VLESS`、`mask -> WebSocket -> VLESS` 和 `mask -> TLS/REALITY -> XHTTP -> VLESS` 与 Xray 的线外放置相匹配。
- `TLS -> mask -> VLESS`、`TLS -> mask -> XHTTP` 和 `XHTTP -> mask -> VLESS` 被拒绝。掩码不能插入 TLS、WebSocket 或 XHTTP 逻辑会话内部。
- XHTTP 掩码在 TLS/REALITY 之前包裹每个 TCP 承载层（如果已配置）。掩码状态在载体的生命周期内跨池请求持续存在；新的承载层以新的状态开始。
- 连续的外部掩码按嵌套顺序组成，包括在后面的链跳和池中。 Xray的公共掩码列表`[A, B]`对应于包含`A`的shoes根`B`。为每个阶段使用不同的匹配选项。

现有的 Vision 和 NaiveProxy 直接子约束仍然适用于外部掩码内部。掩码在 Vision DIRECT 期间保持活动状态并禁用原始 TCP 熔接。 REALITY 外部的遮罩也可以防止未遮罩的探测器达到其通常的伪装后备状态。屏蔽的 TLS 监听器无法处理未屏蔽的 ACME TLS-ALPN-01 挑战。

**安全性和成本：**这是混淆，而不是加密或身份验证。打包下行链路没有密码密钥； classic 的 Go 兼容的 shuffle 减少了种子空间。保留实际的运输安全。经典上行链路在没有填充的情况下将数据扩展为 4 倍，在 10% 时约为 4.5 倍，每次写入最多扩展 9 倍加一个字节。压缩下行链路接近 4/3 倍（无填充）；小写入会产生额外的终止字节。每个掩码保留 32 KiB 读取缓冲区和 32 KiB 写入缓冲区，以及编解码器状态。堆叠复合扩展和内存。不承诺加速或流量分类阻力。
