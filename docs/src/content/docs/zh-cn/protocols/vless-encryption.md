---
title: "VLESS 加密"
description: "本机 VLESS 加密、Vision 组合和恢复限制。"
---

生成匹配的客户端 `encryption` 和服务器 `decryption` 字符串：

```sh
shoes generate-vless-encryption
shoes generate-vless-encryption --auth x25519 --auth mlkem768 --mode random
shoes generate-vless-encryption --auth x25519 --rtt 1rtt --lifetime 0s
```

默认使用 ML-KEM-768 身份验证、`native` 外观以及最长 600 秒票证生命周期的可恢复会话。重复的`--auth`选项形成有序的钥匙链；保持两端的顺序。私人凭证仅由生成器打印，应被视为密码。

将生成的设置放在 VLESS 协议本身上。本机 Vision 在同一级别使用 `vision: true`。将本机 VLESS 包装在 TLS 或 REALITY 中时，将 **outer** `vision` 标志保留为 false。 Native DIRECT 仅删除本机记录加密；它永远不会绕过外部 TLS、REALITY、WebSocket、XHTTP 或 QUIC 传输。现有的禁用加密的 Vision 配置保持其外部 TLS/REALITY 标志不变。请参阅[本机示例](/zh-cn/examples/vless_encryption/)。

外观`native`、`xorpub`和`random`共享相同的加密协议。 `xorpub` 屏蔽密钥交换继电器； `random` 还屏蔽记录标头，包括 Vision DIRECT 之后的应用程序 TLS 标头。随机模式不能使用TCP熔接。新的交易所结合了短暂的 ML-KEM-768 和 X25519； Vision DIRECT 随后依赖于应用程序自己的 TLS，这不一定是后量子的。本机加密适用于固定的 Xray 和 Mihomo 对等体，而不是单盒。空设置和 `none` 保留未加密的 VLESS。服务器`encryption`和客户端`decryption`被拒绝；使用正确一侧的设置而不是交换生成的字符串。

本机解密拒绝 VLESS 回退。本机Vision拒绝H2MUX；加密的VLESS没有Vision支持H2MUX。 Command-2 UDP 使用空流，而 XUDP 可能使用 Vision。失败的加密连接不会以明文形式静默重试或自动重播到目标。

服务器 `encryption_limits` 默认为 `max_sessions: 4096`、`max_replays: 262144` 和 `max_replays_per_session: 65536`。一切都必须是积极的。预期恢复率乘以最大票证生命周期加上 120 秒保留宽限期的大小重播限制。当会话/重播占用率达到 75% 时，新连接将收到零生命周期票证，并通过新的握手保持可用。在硬重放限制下，整个请求票证失效；恢复失败，下一个独立连接执行新的握手。仅当会话和重播占用率均低于 75% 时，才会发出新的可恢复票证。重复的恢复不会重复目标 I/O。票证状态在一个逻辑监听器的地址之间共享，而不是在不同的协议目标之间共享。重新加载重置票证状态；现有的流保留其加密状态。 TLS/REALITY/QUIC 恢复是独立的。

回滚需要回滚配置以及二进制文件：较旧的 shoes 版本会默默地忽略本机加密字段。相反，之前忽略的没有本机加密的 VLESS 级 `vision: true` 现在会产生迁移错误，而不是静默禁用 Vision。
