---
title: "QUIC 套接字缓冲区"
description: "shoes quic 套接字缓冲区配置。"
---

`global_settings.quic_socket_buffer` 请求每个 QUIC 监听器、出站 QUIC 代理端点和 DNS-over-HTTP/3 套接字的 UDP 接收和发送缓冲区大小。默认为 **8388608 字节 (8 MiB)**；允许的值为 65536 到 16777216 字节。这是每个套接字，而不是每个 QUIC 连接，并且与 QUIC 流量控制窗口和用户空间缓冲区准入限制分开。普通 UDP 转发套接字保留其现有的缓冲区大小。

```yaml
- global_settings:
    quic_socket_buffer: 8388608
```

请求是尽力而为的：如果操作系统限制或拒绝大小，则启动将使用可用缓冲区继续。 shoes 检查结果大小，并在请求未得到满足或无法验证时在每个进程的每个接收/发送方向最多发出一次警告。较小的缓冲区可能会限制突发期间的吞吐量。

在Linux上，管理员可以允许`net.core.rmem_max=8388608`和`net.core.wmem_max=8388608`的默认请求； shoes 不会更改 sysctls 或需要提升权限来进行缓冲区调整。 Linux 报告双倍请求的缓冲区大小以用于记帐开销； shoes 在检查结果时对此进行归一化。这些限制不会预先分配其最大内存，但排队流量会消耗所有端点的内存。提高内核上限不会调整现有套接字的大小。配置重新加载重新创建 QUIC 监听器并可以断开其活动会话；参见[热重载](/zh-cn/operations/reload/)。
