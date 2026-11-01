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

TCP、TLS和HTTPS上游可以使用代理链。 UDP 和 H3 上游仅是直接的，但直接链可以设置接口绑定； `system` 不支持客户端链。 WireGuard 路由的 DNS 需要字面上的上游 IP，而不需要 `bootstrap_url`。请参阅[远程规则源](/zh-cn/routing/remote-sources/) 了解更严格的启动引导规则。

`client_chain` 和 `client_chains` 是完全等价的别名，使用[路由链语法](/zh-cn/routing/rules/#client-chains)：`[a, b]` 表示顺序跃点，而 `[{chain: [a]}, {chain: [b]}]` 表示备选路径。命名客户端组保留其完整路径选项和选择策略。

**迁移：** DNS 以前将普通列表解释为备选路径，现在将其解释为顺序跃点，不提供兼容模式或警告。要保留备选路由，请使用显式链包装或命名组。
