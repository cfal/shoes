---
title: "DNS配置"
description: "选择解析器、可重用组、引导程序和代理路由。"
---

服务器、WireGuard 监听器或 TUN 条目可以选择内联解析器或命名的 `dns_group`。省略 `dns` 或将其设为 null 时，若设置了 `global_settings.default_dns` 则继承它，否则使用本机系统解析器；请参阅[本机 DNS 新鲜度](/zh-cn/dns/native/) 了解其缓存行为。仅当需要合成地址映射时才使用[Fake DNS](/zh-cn/dns/fake/)。

显式的 `dns` 对象（包括 `dns: {}`）会替换默认值；优先级和适用范围参见[全局设置](/zh-cn/config/global-settings/#default-dns)。

**完整示例：** [dns_tuning.yaml](/zh-cn/examples/dns_tuning/)。其代理地址和凭据需要特定于部署的值。

```yaml
- dns_group: secure-dns
  dns_servers:
    - url: tls://1.1.1.1
      server_name: cloudflare-dns.com
      timeout_secs: 5

- address: "127.0.0.1:1080"
  protocol: {type: socks}
  dns: {servers: secure-dns}
```

`dns.servers` 和组的 `dns_servers` 各自接受一个服务器或一个列表。 `dns.server` 和 `dns_server` 是单数别名。纯字符串可以是命名组引用，也可以是解析器 URL。解析器 URL 支持 `system`、`udp://`、`tcp://`、`tls://`（DNS-over-TLS）、`https://`（DNS-over-HTTPS）和 `h3://` （DNS-over-HTTP/3）。默认端口分别为 53、53、853、443 和 443。 URL 对象接受以下选项：

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `url` | 必填 | 解析器端点或 `system` |
| `server_name` | 网址主机名 | TLS/HTTPS/H3 的 TLS 名称覆盖 |
| `bootstrap_url` | 系统解析器 | IP-文字 DNS URL、`system` 或用于解析端点/代理主机名的命名 DNS 组 |
| `client_chain` / `client_chains` | 直接 | 用于到达此 DNS 上游的代理链 |
| `ip_strategy` | `ipv4_then_ipv6` | 地址族查询顺序 |
| `timeout_secs` | 5 | 整个查找超时； `0` 禁用它 |
| `connect_timeout_secs` | 5 | 连接设置超时 |
| `attempts` | 1 | 查询重试次数 |
| `native_cache_secs` | 0 | 仅限系统应用程序记忆窗口；参见[原生DNS](/zh-cn/dns/native/) |

`ip_strategy` 还接受 `ipv4_only`、`ipv6_only`、`ipv4_and_ipv6` 和 `ipv6_then_ipv4`。选项对象拒绝未知字段。非系统上游无法设置 `native_cache_secs`，甚至为零。 `bootstrap_url` 本身不得包含主机名；命名组可用于多步引导，但循环被拒绝。

TCP 和 TLS 丢弃已失效查询的响应后，会继续处理缓冲区中的其他响应。这不会增加重试次数或延长配置的超时时间。

TCP、TLS和HTTPS上游可以使用代理链。 UDP 和 H3 上游仅是直接的，但直接链可以设置接口绑定； `system` 不支持客户端链。 WireGuard 路由的 DNS 需要字面上的上游 IP，而不需要 `bootstrap_url`。请参阅[远程规则源](/zh-cn/routing/remote-sources/) 了解更严格的启动引导规则。

`client_chain` 和 `client_chains` 是完全等价的别名，使用[路由链语法](/zh-cn/routing/rules/#client-chains)：`[a, b]` 表示顺序跃点，而 `[{chain: [a]}, {chain: [b]}]` 表示备选路径。命名客户端组保留其完整路径选项和选择策略。

**迁移：** DNS 以前将普通列表解释为备选路径，现在将其解释为顺序跃点，不提供兼容模式或警告。要保留备选路由，请使用显式链包装或命名组。

<a id="transport-recovery"></a>
## 传输恢复

DoH 传输失败会关闭失效连接及其活动套接字和后台驱动。后续查询可在不重启 Shoes、接口和路由不变的情况下重新连接。并发替换会合并；旧连接的延迟错误不会关闭新连接。新连接遵循当前选择器选项，不改变 Fake-IP 映射、流量捕获或无关代理传输。

查询遇到可恢复的传输错误时，会返回该错误并停用当前解析器实例。刷新层不会重试当前查询或立即重建；下一次查询才会按需重建解析器，并发查询共享一次重建。重建失败会直接返回给该查询，后续查询仍可再次尝试重建。

配置的上游尝试次数、缓存连接重连和传输回退保持不变，并与按需重建共享原始请求截止时间。仍在进行的连接建立过程会保留至其自身的截止时间，供后续查询使用，不会额外重试当前查询或停用解析器。较短的调用方截止时间或查询取消不会关闭共享握手或健康连接。

NXDOMAIN、NODATA、SERVFAIL、HTTP 状态错误、证书或身份验证失败以及本地资源压力不会触发解析器替换。永久错误仍会返回，不会回退到直连 DNS 或降低安全校验。底层共享承载连接需要独立恢复；XHTTP H2 使用 [接收空闲 PING 检查](/zh-cn/protocols/xhttp/#client)。恢复不会续接失效的应用 TCP 会话或重放应用数据。

<a id="static-hosts"></a>
## 静态 Hosts

在命名的 DNS 组或内联 `dns` 对象中添加 `hosts`，也可用于
`global_settings.default_dns`。映射仅属于所选解析器，不是进程全局设置，
也不局限于某个出站代理。

**完整示例：** [dns_static_hosts.yaml](/zh-cn/examples/dns_static_hosts/)。

```yaml
- dns_group: alibaba-dns
  hosts:
    ga-bp1v2ogcl3ajd13hmjzrn.aliyunga0018.com:
      - 47.238.137.75
      - 47.238.193.242
  dns_servers: https://1.1.1.1/dns-query

- address: "0.0.0.0:1080"
  protocol: {type: socks}
  dns: {servers: alibaba-dns}
```

每个值可以是单个 IP 或非空 IP 列表。主机名精确匹配，忽略大小写及末尾的一个点。
使用 ASCII 或 punycode 名称；不支持通配符或主机名别名。空列表、规范化后重复的名称、
未指定地址（`0.0.0.0`、`::`）以及与活动或保留的 Fake DNS 地址池、受保护 TUN
端点重叠的地址会被拒绝。重复 IP 会被删除，其余地址保持原顺序。
启用 `dns_hijack` 或 `auto_route` 时，即使未启用 Fake DNS，TUN 端点也受保护；
`check` 和 `--dry-run` 同样会拒绝这些冲突。

映射用于该解析器负责的上游代理端点、本地目标及路由查找，以及截获的 DNS 查询。
以主机名发送给远程代理的目标仍由远端解析。代理主机名、TLS SNI、XHTTP Host、
证书校验和凭据保持不变。

静态条目优先于系统 hosts、上游缓存和 Fake DNS。连接查找按配置顺序返回全部地址；
上游的 `ip_strategy` 不过滤显式 hosts 条目。各传输保留原有候选地址选择及重试行为，
多个 IP 不意味着所有协议都有相同的故障切换机制。与原有行为相同，依赖 IP 的路由
可能只为后续连接保留第一个地址。

命中条目的 A/AAAA 查询仅返回对应地址族；缺少该地址族时返回空的成功响应
（NOERROR/NODATA），不查询上游、不分配假 IP。响应 TTL 为 60 秒，不声明 DNSSEC
认证。未命中名称及 HTTPS/SVCB 等其他查询类型保持原有行为，仍可能查询上游。

内联 hosts 可覆盖命名组：`dns: {servers: alibaba-dns, hosts: {...}}`。
组组合继承 hosts；本组条目优先，多个引用之间较早引用的条目优先。
覆盖 Fake DNS 组时仍须遵守现有组合规则，显式指定 `fake_ip` 策略，并创建独立上下文。
若要共享地址池，应将 `hosts` 放在被引用的组上，并直接引用该组，不添加内联覆盖。

内联 hosts 未指定 `servers` 时，未命中的名称使用带缓存的本机解析器。
显式 `dns` 对象仍会替换而非合并 `global_settings.default_dns`。
DNS 上游自身的主机名及其代理链使用独立的 `bootstrap_url` 策略；需要静态引导时，
在该字段选择带有 hosts 的命名组。hosts 不绕过依赖循环或上游配置校验。

重新加载配置后，新请求使用新映射；已有连接及应用 DNS 缓存可能继续使用旧地址。
删除 `hosts` 并重新加载即可恢复正常解析，无需修改系统 hosts 文件或 Hickory 依赖。
