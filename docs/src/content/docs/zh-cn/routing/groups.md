---
title: "命名组"
description: "shoes 命名组配置。"
---

<a id="client-proxy-group"></a>
### 客户端代理组
```yaml
- client_group: my-upstream
  client_proxies:              # Define proxies in this group
    - address: "proxy1.example.com:1080"
      protocol:
        type: socks
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
