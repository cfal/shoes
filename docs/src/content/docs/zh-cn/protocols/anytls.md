---
title: "AnyTLS"
description: "shoes anytls 配置。"
---

**完整示例：** [anytls.yaml](/zh-cn/examples/anytls/)。在部署之前调整地址和机密。

下面的字段草图包含占位符，而不是可运行的值。配置部署时使用完整的示例。

<a id="server"></a>
## 服务端

```yaml
protocol:
  type: anytls
  users:                       # One or more users
    - name: string?            # Optional display name
      password: string         # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding (e.g., ["stop=8", "0=30-30"])
  fallback: string?            # Optional fallback destination for failed auth
```

AnyTLS是一种基于TLS的具有流量混淆的复用代理协议。应在 TLS 或 Reality 内使用。


<a id="client"></a>
## 客户端

```yaml
protocol:
  type: anytls
  password: string             # User password
  udp_enabled: true            # Default: true (enables UDP over TCP)
  padding_scheme: [string]?    # Optional custom padding scheme
  idle_session_check_interval_secs: 30
  idle_session_timeout_secs: 30
  min_idle_session: 0
  disable_reuse: false
```

TCP 和 UDP-over-TCP 共享空闲会话池。每个请求专门检查其所选代理路由的最近返回的会话；当没有空闲会话时，并发请求会创建额外的会话。热重用可以避免新的套接字和传输握手，包括在代理链和包装传输中。

空闲检查使 `min_idle_session` 之外最旧的会话过期。该最小值是客户端路由上的保留下限，而不是预热或连接上限。两种间隔设置均使用整数秒；等于或低于 5 的值选择默认值 30 秒。 `disable_reuse` 在每条流结束后关闭会话。活动流量不会过期，并且可以在配置重新加载后耗尽；当其拥有的客户端实例停用时，空闲会话关闭。有效的服务器填充更新适用于客户端当前和未来的会话，而无需重新启动填充计数器。

干净的对等 FIN 会停止转发该流的上传。延迟上传的字节将被丢弃，以便中继可以完成耗尽缓冲的响应数据，而不会影响下一个会话租用。本地关闭和拒绝流打开仍然拒绝写入。
