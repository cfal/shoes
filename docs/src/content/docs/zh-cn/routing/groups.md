---
title: "命名组"
description: "shoes 命名组配置。"
---

<a id="client-group"></a>
### 客户端组

**完整示例：** [chain_groups.yaml](/zh-cn/examples/chain_groups/) 演示完整路径备选项和手动选择。部署前请调整其中的地址和凭据。

`client_chain` 和 `client_chains` 接受与路由相同的顺序路径和备选路径语法。普通的 `[a, b]` 定义一条顺序路径；显式链包装的列表定义由组策略选择的独立备选路径。路径中的组引用会贡献其完整选定路径，因此备选路径可以有不同的跳数。每个阶段可使用组引用、内联客户端或 `{pool: [...]}`。组的链包装不接受未知字段。旧版组字段 `client_proxy` / `client_proxies` 的列表仍表示备选成员，但会产生弃用警告；请参阅[迁移示例](/zh-cn/routing/rules/#legacy-proxy-fields)。

以下片段引用了在其他位置定义的组：

```yaml
- client_group: a1-selected-nl
  client_chains:
    - chain: [a1-selected, nl-hop]

- client_group: geo-reddit-selected
  type: selector
  default: a1-selected-nl
  client_chains:
    - {chain: [a1-selected]}
    - {chain: [a1-selected-nl]}
    - name: via-us
      chain: [a1-selected, us-hop]
    - {chain: [direct]}
```

未命名的单跳包装保留其引用组或内联客户端的身份。选择器成员若为内联客户端、池包装或多跳路径，必须显式命名。其他策略会按定义位置为未命名路径生成标签；需要稳定的控制器身份时应显式命名。标签不会引入新的路由引用命名空间。控制器将命名路径公开为 `Relay` 节点，支持完整路径延迟探测，并按末跳判断 UDP 能力。

轮询先选择直接备选项，再选择其后代。每处引用都有独立的 TCP 和 UDP 计数器，包括非末尾的选择节点。重复的轮询条目增加被选中的次数；选择器和 URL 测试的成员必须互不相同。包含十个成员的嵌套组在外层的权重与一个内联客户端相同，而不是其十倍。每个新流只获取一次手动选择快照，并固定完整的选定路径。如果为 UDP 选中了仅支持 TCP 的路径，流会失败，而不会改选其他选择器成员。现有流、UDP 关联和承载层重拨保留各自固定的路径。

相同的组合可用于路由、DNS、WireGuard 对等端链、ShadowTLS 握手链和 REALITY 目标链。Direct、WireGuard 和 XHTTP H3 客户端只能位于物理第零跳。UDP/H3 DNS 仍要求仅含直连的路由。解析会拒绝循环、超过 16,384 个展开节点、超过 64 层嵌套选择或超过 64 跳的路径。固定的单跳轮询别名不增加选择深度。健康状态的规模由声明的组和成员数量决定，而不是由路由组合数量决定。

```yaml
- client_group: my-upstream
  client_chains:              # Define alternatives in this group
    - chain:
        - address: "proxy1.example.com:1080"
          protocol:
            type: socks
    - chain:
        - address: "proxy2.example.com:1080"
          protocol:
            type: socks

# Reference in rules
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream  # Reference by name
```

<a id="rule-group"></a>
### 规则组

`rule_group` 包含有序策略；省略`action`仍然表示`allow`。 `rule_source_group` 包含无操作匹配表达式和本地或远程源。声明决定了动作的类型，而不是动作的存在。空组将被拒绝。两种类型共享一个命名空间，包括内置名称。 `rule` 是 `rules` 的别名；要么直接接受一项，要么接受非空列表。

策略组从 `rules` 或 `override_rules` 引用，保留顺序、操作和路由选项。源组仅通过 `masks: {rule_source_group: name}` 和调用者的操作进行引用。跨种类引用是错误的：动作永远不会被丢弃或发明。源组可以引用其他源组；循环和过度嵌套将被拒绝。策略组不能引用其他策略组。

```yaml
- rule_group: standard-rules
  rules:
    - masks: ["192.168.0.0/16"]
      action: allow
      client_chain:
        protocol:
          type: direct
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: my-upstream

# Reference in server config
- address: "0.0.0.0:8080"
  protocol:
    type: http
  rules: standard-rules        # Reference by name
```

<a id="rule-source-group"></a>
### 规则源组

源组在策略的 `masks` 内部引用，因此策略提供操作。它们可能引用其他源组，但不引用策略组。有关格式、刷新和缓存的信息，请参阅[本地规则源](/zh-cn/routing/rules/#local-rule-sources) 和[远程规则源](/zh-cn/routing/remote-sources/)。
