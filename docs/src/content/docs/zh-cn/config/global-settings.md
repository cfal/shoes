---
title: "全局设置"
description: "默认 DNS、准入限制、远程规则缓存、QUIC 缓冲区和重新加载宽限期。"
---

所有配置文件中最多使用一个 `global_settings` 条目。省略的准入上限不受限制；传输窗口和缓冲区具有有限的默认值。省略、空或空的 `global_settings` 条目使用这些默认值。

这是一个配置片段，而不是监听器：

```yaml
- global_settings:
    max_connections: 1024
    max_streams_per_connection: 128
    reload_grace_secs: 300
    rule_cache_dir: ./rule-cache
```

`rule_cache_dir` 是可选的。省略它或将其设置为 `null` 以仅在内存中保留远程规则。一个配置的目录为所有远程源提供服务；不接受每个源缓存目录和独立的 `rule_cache_dir` 条目。它的路径是相对于声明配置文件的。有关所有权、权限、引导和重新启动要求，请参阅[远程规则源](/zh-cn/routing/remote-sources/)。

`global_limits` 仍然是兼容性别名，但会记录警告并将被弃用。将其重命名为 `global_settings`。两个名称均计入相同的单条目限制，即使对于空条目也是如此。序列化始终使用 `global_settings`。

<a id="default-dns"></a>
## 默认 DNS

`default_dns` 接受与监听器的 `dns` 相同的对象：`servers` 可以引用命名组或配置内联上游，还可以指定可选的 `fake_ip` 设置。
`default_dns` 对象在省略或清空 `servers` 时使用底层系统解析器，仅配置 Fake IP 设置时也是如此。

```yaml
- global_settings:
    default_dns:
      servers: secure-dns
```

监听器、TUN 条目和 WireGuard 入站在省略 `dns` 或将其设为 null 时继承此默认值。显式的 `dns` 对象会完全替换默认值，不会按字段合并。在任何显式对象中，省略或清空 `servers` 都会使用底层系统解析器，不会再次继承全局默认值。因此，`dns: {}` 可以退出继承。系统解析器的缓存行为参见[原生 DNS](/zh-cn/dns/native/)。

内联默认配置会创建一个共享的解析器组。如果启用 Fake IP，所有继承该配置的入站将共享一个映射池和状态文件，其所有者为 `global_settings`，不依赖监听器身份。

独立的 DNS 引导、规则下载、ACME、WireGuard 对等端准备和控制器探测不会继承此设置。上游选项和引导要求参见[DNS 配置](/zh-cn/dns/configuration/)。

<a id="admission-caps"></a>
## 准入上限

每个上限接受正整数，或省略/空以表示无限。零被拒绝。 `max_streams_per_connection` 另外不能超过 65,535。

| 字段 | 适用于 |
| --- | --- |
| `max_connections` | 承认整个流程中的连接 |
| `max_connections_per_ip` | 每个对等点承认的连接 IP |
| `max_streams` | 承认整个流程的逻辑流 |
| `max_streams_per_connection` | 一个连接内的逻辑流 |
| `max_udp_destinations` | 承认的 UDP 目的地 |
| `quic_memory_bytes` | QUIC 内存接纳预算，以字节为单位 |

准入预算并不是对总流程 RSS 的衡量。降低上限不会撤销现有的预订；新的工作将被阻止，直到使用允许为止。请参阅[重新加载行为](/zh-cn/operations/reload/)。

## 缓冲区和重新加载

下面的大小是整数字节，而不是 `2MiB` 等字符串。

| 字段 | 默认 | 接受范围 |
| --- | --- | --- |
| `quic_receive_window` | 2,097,152 | 65,536-67,108,864 |
| `quic_send_window` | 2,097,152 | 65,536-67,108,864 |
| `quic_stream_window` | 262,144 | 16,384-67,108,864 |
| `quic_dns_memory_bytes` | 16,777,216 | 1,048,576-1,073,741,824 |
| `quic_socket_buffer` | 8,388,608 | 65,536-16,777,216 |
| `reload_grace_secs` | 300秒 | 0-86,400 秒 |

`quic_dns_memory_bytes` 是 DNS 库的私有 HTTP/3 传输的准入估计，而不是硬缓冲区限制。 `quic_socket_buffer` 请求操作系统套接字缓冲区大小；操作系统可以授予的权限更少。请参阅[QUIC 套接字缓冲区](/zh-cn/config/quic-sockets/)。

未知字段和重复的全局设置条目将被拒绝。每个协议的限制（包括 [XHTTP](/zh-cn/protocols/xhttp/)、[TUN](/zh-cn/config/tun/#resource-limits-and-device-framing) 和 [WireGuard](/zh-cn/protocols/wireguard/)）仍然是单独的设置。
