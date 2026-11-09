---
title: "全局设置"
description: "默认 DNS、可选 NTP、准入限制、远程规则缓存、QUIC 缓冲区和重新加载宽限期。"
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

`default_dns` 接受与监听器的 `dns` 相同的对象：`servers` 可以引用命名组或配置内联上游，还可以指定可选的静态 `hosts` 和 `fake_ip` 设置。
`default_dns` 对象在省略或清空 `servers` 时，对未命中静态映射的名称使用底层系统解析器，仅配置 `hosts` 或 Fake IP 设置时也是如此。

```yaml
- global_settings:
    default_dns:
      servers: secure-dns
```

监听器、TUN 条目和 WireGuard 入站在省略 `dns` 或将其设为 null 时继承此默认值。显式的 `dns` 对象会完全替换默认值，不会按字段合并。在任何显式对象中，省略或清空 `servers` 都会使用底层系统解析器，不会再次继承全局默认值。因此，`dns: {}` 可以退出继承。系统解析器的缓存行为参见[原生 DNS](/zh-cn/dns/native/)。

内联默认配置会创建一个共享的解析器组。如果启用 Fake IP，所有继承该配置的入站将共享一个映射池和状态文件，其所有者为 `global_settings`，不依赖监听器身份。

独立的 DNS 引导、NTP、规则下载、ACME、WireGuard 对等端准备和控制器探测不会继承此设置。上游选项和引导要求参见[DNS 配置](/zh-cn/dns/configuration/)。

## NTP

可选的应用内时间校正，适用于 shoes 无权修改系统时钟的环境。省略 `ntp` 或设为 `null` 即禁用，不会发送 NTP 请求。提供配置对象即启用，没有 `enabled` 字段。

```yaml
- global_settings:
    ntp:
      server: time.cloudflare.com:123
      interval_secs: 1800
      timeout_secs: 5
```

| 字段 | 默认值 | 有效值 |
| --- | --- | --- |
| `server` | 必填 | 非空主机名或 IP，必须显式指定 UDP 端口，通常为 `123`；IPv6 使用 `[address]:port` |
| `interval_secs` | 1800 | 整数秒，60-86,400 |
| `timeout_secs` | 5 | 整数秒，1-30 |

应用时钟为 **系统时间 + 最近一次测得的有符号偏移量**。NTP 测量始终使用未经校正的系统时间。shoes 不会写入系统时钟，也不需要设置时间的权限。REALITY、VMess、Shadowsocks 2022 和 rustls 证书验证（包括基于 TLS 的 DNS 和 QUIC）使用校正后的时间。日志及其他协议保持现有时钟。证书源在加载、接受新签发证书及选择要提供的证书时进行的有效期检查，以及证书续订调度，仍使用系统时钟。因此，即使 NTP 同步成功，错误的系统时间仍可能导致证书被拒绝或无法提供。REALITY 的 `max_time_diff` 默认值和 null 语义不变。

运行时监听器、WireGuard 和 TUN 启动前，会完成一次有超时限制的同步尝试，超时包含 DNS 解析和 UDP 交换。失败不会阻止启动：首次启动使用零偏移，修改 NTP 配置时保留之前的校正值。刷新失败也保留最近的偏移，并在 `interval_secs` 后重试。作为保守策略，收到 `DENY`、`RSTR` 或 `RATE` Kiss-of-Death 响应后，停止轮询，直到修改 NTP 配置或重启服务。其他 stratum 为零的响应（如 `INIT` 或 `STEP`）会被丢弃，但不会阻止尝试其他地址或定期重试。仅接受普通的 48 字节 NTP 响应，不支持扩展字段或认证尾部。

NTP 通过 shoes 的受保护、遵循路由策略的 UDP 套接字直接发送，不经过代理链。主机名使用原生 DNS，或受管 TUN 的引导 DNS，不继承 `default_dns`。当前或保留的 Fake IP 地址池、受保护的 TUN 端点和受管 TUN 子网不能用作 NTP 目的地。嵌入式 VPN 环境建议使用 IP 地址，避免依赖经过 VPN 自身的 DNS。

**限制和信任边界：**

- 这是未经认证的 UDP NTP，不是 NTS。服务器或链路上的攻击者可以改变协议时间及 TLS 证书有效期判断。请使用可信且可达的服务器和网络。
- 准备阶段的加密 DNS 引导、HTTPS 规则下载及证书准备仍早于首次同步。NTP 使用 IP 地址只能避免自身的 DNS 依赖，不能修复这些更早的失败。`check` 和 `--dry-run` 仅验证 NTP 配置，不解析或查询服务器。
- 系统时钟跳变会立即影响应用时间，直到下一次成功刷新。偏移量不是独立时钟；避免与会跳变系统时间的其他同步服务同时使用。
- 时间向后校正（包括禁用 NTP 或回滚）可能暂停 VMess 入站认证，直到时间追上之前的高水位。暂停可能持续整个回退时长，而非仅协议时间窗口。重放缓存不会被清空，同一进程内 FFI 停止后重启也不会清空。
- Shadowsocks 2022 的盐缓存按单调时间过期。足够大的时间回退可能让旧握手在盐缓存过期后重新落入有效时间窗口。系统时钟回退也有同样限制。协议窗口宽度不变；NTP 不能消除时间跳变带来的重放风险。
- 支持通常的时钟偏差及 2036 年 NTP 回绕，不保证任意错误日期恢复。原始日期早于 1970 年时同步失败；超过约 68 年的偏移可能存在歧义。偏移量不跨进程重启持久化。

参见[重载行为](/zh-cn/operations/reload/)及完整的 [`ntp.yaml` 示例](/zh-cn/examples/ntp/)。

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
