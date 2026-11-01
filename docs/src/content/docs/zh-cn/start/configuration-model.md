---
title: "配置模型"
description: "shoes 如何组织 YAML 配置条目。"
---

参考页面中的字段示意片段会使用 `string` 和 `...` 等占位符，不是完整的可运行配置。请从[完整示例](/zh-cn/start/examples/)复制文件并按需修改。

配置文件是由一个或多个配置项组成的 YAML 数组。配置项可以是：

- [服务端](/zh-cn/config/server/)：代理监听器及其协议栈。
- [TUN](/zh-cn/config/tun/)：用于透明代理的 IP 数据包设备。
- [客户端组](/zh-cn/routing/groups/#client-group)：可重用的完整上游路径选项。
- [规则组](/zh-cn/routing/groups/#rule-group)：可重用的路由规则。
- [规则源组](/zh-cn/routing/groups/#rule-source-group)：可重用的无操作匹配表达式和本地或远程源。
- [DNS 组](/zh-cn/dns/configuration/)：供多个配置项引用的命名 DNS 配置。
- [命名 PEM](/zh-cn/security/named-pems/)：可复用的证书或密钥数据。
- [证书来源](/zh-cn/security/certificates/)：文件支持或托管证书。
- [全局设置](/zh-cn/config/global-settings/)：进程范围准入、远程规则缓存和 QUIC 缓冲区设置。
- [Clash 控制器](/zh-cn/routing/clash-controller/)：控制器监听器设置。
- [缓存文件](/zh-cn/routing/clash-controller/#persistence)：持久控制器状态。

配置项由各自的顶级配置键识别，而不是使用统一的顶级 `type`。`protocol` 内的 `type` 用来选择协议。多个配置文件会一起加载，因此命名组可以跨文件引用。

```yaml
# Server configs have 'address' or 'path', except proxied WireGuard servers
- address: "0.0.0.0:8080"
  protocol: ...

# TUN configs have 'device_name' or 'device_fd'
- device_name: "tun0"
  address: "10.0.0.1"
  ...

# Client config groups have 'client_group'
- client_group: my-upstream
  client_chains: ...

# Rule config groups have 'rule_group'
- rule_group: my-rules
  rules: ...

# Action-free source groups have 'rule_source_group'
- rule_source_group: my-sources
  rules: ...

# Named PEMs have 'pem'
- pem: my-cert
  path: /path/to/cert.pem
```
