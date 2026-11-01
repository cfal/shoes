---
title: "WireGuard"
description: "shoes wireguard 配置。"
---

**完整示例：** [wireguard_server.yaml](/zh-cn/examples/wireguard_server/)。在部署之前调整地址和机密。

WireGuard 在普通客户端和服务器配置中使用 `protocol: {type: wireguard}`。它通过用户空间 GotaTun 设备和 smoltcp 堆栈承载 TCP/UDP 流，而不是 TCP 流包装器。 Unix 构建支持 WireGuard； Windows 拒绝它。

请参阅[服务器](/zh-cn/examples/wireguard_server/)和[客户端](/zh-cn/examples/wireguard_client/)示例。部署前必须更换其演示密钥。使用 `wg genkey` 生成私钥，并使用 `wg pubkey` 导出其公钥。切勿共享私钥。

| 字段 | 含义 |
| --- | --- |
| `private_key` | Base64 编码的 32 字节私钥 |
| `addresses` | 非空本地隧道 CIDR；每个家庭最多一个地址 |
| `peer_client_chain` | 可选的客户端链将加密的 UDP 数据包传送给对等方；接受正常的组、内联和池语法 |
| `mtu` | 内部IP MTU，默认1408；支持范围 1280-1420 |
| `resource_limits` | [与 TUN 相同的字段](/zh-cn/config/tun/#resource-limits-and-device-framing)，具有有限的 WireGuard 默认值 |

WireGuard 默认为 32 MiB TCP 内存预算、256 个 TCP 连接、1,024 个 UDP 会话、4,096 个 UDP 目标、每个会话 64 个目标以及 8 MiB UDP 队列。其 TCP 缓冲区大小仍为 32 KiB。显式值会覆盖这些默认值； TUN 限制约束仍然适用。

这些字段位于 `protocol` 内部。 WireGuard 意味着 UDP； `transport: udp` 是可选的。 TCP/QUIC 传输及其套接字设置被拒绝。

客户端有一个远程对等点。它的普通 `address` 标识该对等点； `public_key`、可选的 `pre_shared_key`、`allowed_ips` 和 `persistent_keepalive` 直接属于 `protocol`，而不是 `peers` 列表：

```yaml
- client_group: vpn
  client_chains:
    - address: "vpn.example:51820"
      protocol:
        type: wireguard
        private_key: "<client-private-key>"
        public_key: "<server-public-key>"
        addresses: ["10.77.0.2/32"]
        allowed_ips: ["0.0.0.0/0"]
        persistent_keepalive: 25
```

省略的客户端`allowed_ips`默认为`["0.0.0.0/0", "::/0"]`；明确的空列表拒绝。 `addresses` 仍然是必需的。没有本地隧道地址的地址族的路由无法关闭。这些设置不会安装主机路由。对于多个上游，配置单独的客户端或组池。

服务器有一个非空的 `protocol.peers` 列表。每个对等点都需要 `public_key` 和显式非空 `allowed_ips`。可选字段为 `pre_shared_key`、`endpoint: "host:port"` 和 `persistent_keepalive`（以秒为单位）（零将禁用它）。对于向直接侦听服务器发起的对等点，省略 `endpoint`：

```yaml
- address: "0.0.0.0:51820"
  protocol:
    type: wireguard
    wireguard_name: gateway
    private_key: "<server-private-key>"
    addresses: ["10.77.0.1/32"]
    peers:
      - public_key: "<client-public-key>"
        allowed_ips: ["10.77.0.2/32"]
  rules:
    - masks: ["192.168.10.0/24"]
      action: allow
```

对等主机名在准备期间通过本机引导程序 DNS 进行解析，并在重新加载时刷新。直接模式在启动时选择与绑定套接字兼容的第一个解析地址。经过身份验证的 WireGuard 漫游可以更新活动对等方地址，而无需在直接模式下重新加载。拒绝不同对等点之间允许的前缀重叠、重复密钥和自对等互连。为每个客户端分配不同的隧道地址。

服务器 `address` 必须是一个文字 UDP 套接字地址，具有非零端口，而不是主机名、端口范围或 Unix 套接字路径。 `0.0.0.0:51820` 仅监听 IPv4； `[::]:51820` 在支持的情况下使用双栈套接字。直接客户端绑定临时双栈通配符，当 IPv6 不可用时使用 IPv4 回退。外插座保留移动插座保护和接口绑定。可选的 `bind_interface` 对于客户端属于客户端配置级别，对于服务器属于 `protocol` 内部； Linux/Android/紫红色支持。未创建操作系统接口、路由、防火墙规则或 NAT 规则。

服务器需要显式非空顶级 `rules`，并且可以指定顶级 `dns` 和 `sniff`。缺少、无效或为空的规则拒绝； `rules: block-all` 有效。 `protocol.wireguard_name` 为服务器提供稳定、区分大小写的标识。当省略、为 null 或为空时，服务器的公钥将提供其身份。重复的名称或重复的未命名公钥身份会拒绝配置，即使具有不同的侦听地址。基于名称的身份和基于密钥的身份是分开的。客户端重复数据删除保持不变。重新排序服务器或添加客户端不会更改服务器身份或私有 Fake DNS 所有权。使用显式名称在密钥轮换期间保留所有权；更改有效身份会创建不同的上下文，并且现有状态文件会拒绝新所有者。规则使用正常的目标掩码、覆盖和客户端链。客户端接受对其传出流的回复，而不是未经请求的入站流。目标规则不提供超出加密密钥源验证的对等授权。经过身份验证的对等方可以访问网关的本地服务，除非规则阻止它们。服务器示例阻止环回和链路本地目的地；当对等方不应访问网关的 LAN 时，也会限制专用网络。

使用第一跳的客户端组，或将完整的客户端配置内联：

```yaml
client_chain:
  - vpn
  - address: "10.77.0.10:1080"
    protocol: {type: socks}
```

第二跳是可选的。 WireGuard 不能出现在 TLS/WebSocket 内部或后面的跃点。丢失的路由、地址族、故障端点或不可用的对等点永远不会导致直接回退。

要将代理**置于** WireGuard 之前，请在其协议内配置 `peer_client_chain`：

```yaml
peer_client_chain:
  - address: "relay.example:443"
    protocol:
      type: tls
      protocol:
        type: vless
        user_id: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
        udp_enabled: true
```

有效路径为 `shoes -> peer client chain -> WireGuard peer -> optional inner proxy chain -> destination`。路由规则仍在第 0 跳选择 WireGuard。参见[完整的绕行示例](/zh-cn/examples/wireguard_outer_chain/)。

对等链使用正常的内联、命名组和池语法。他们的最后一跳必须支持UDP；较早的跃点可能仅是 TCP。 VLESS、VMess 和兼容的 Shadowsocks/AnyTLS UDP-over-TCP 配置有效。 shoes'SOCKS出站仅实现了CONNECT，而Trojan出站UDP未实现，因此两者都不能是最终UDP跳。池选择具有 UDP 能力的最终成员。选择在协会的生命周期内保持固定；重新连接可能会选择另一个成员。

一个持久关联由所有内部流共享到每个解析的对等目的地；具有相同解析目的地的对等体共享关联。没有打开本机 WireGuard UDP 监听器。在第一个承载层客户端上配置物理接口绑定，而不是 WireGuard 套接字。代理服务器必须省略其顶级侦听 `address` 并在每个对等方上指定 `endpoint` 和非零 `persistent_keepalive`。它发起握手以建立返回映射，然后其普通 `rules` 处理传入隧道流。它不能通过代理接受任意公共对等点。请参阅[代理服务器示例](/zh-cn/examples/wireguard_proxied_server/)。 `peer_client_chain` 与服务器侦听地址或 WireGuard 套接字接口绑定冲突。当出站内部流需要握手时，没有 keepalive 的客户端会发起握手。

绕行的目的地对于配置生成是固定的。它们的消息流不公开源地址，因此不支持任意对等地址漫游。对等主机名更改需要重新加载。对等和外部代理引导程序使用独立于路由 DNS 和服务器的 `dns` 的本机 DNS。确保主机 DNS 和主机路由本身不需要建立隧道。

外部连接和阻止写入尝试在 10 秒后超时。失败的流会重试，延迟时间从 250 毫秒到 10 秒，永远不会回退到直接 UDP。离线/溢出数据包被丢弃而不是无限期地缓冲； WireGuard 和内部 TCP 执行正常重试。使用 `persistent_keepalive` 维护空闲代理 UDP 映射。没有流错误的静默黑洞仍然是 UDP 损失。队列最多可容纳每个目标 64 个数据包和 64 个聚合接收数据包，外部数据报限制为 2048 字节，高于支持的内部 MTU 加上 WireGuard 开销。关闭等待工人释放他们的协会。

对等链本身可以从另一个 WireGuard 客户端开始。依赖关系首先启动，无论声明顺序如何；自我依赖和间接循环（包括池替代方案）被拒绝。直接 WireGuard-in-WireGuard 承载层需要 `round_up(inner_mtu, 16) + 80 <= carrier_mtu`，保守地考虑 IPv6、UDP 和 WireGuard 开销。例如，内部 MTU 1280 适合承载层 MTU 1408。承载层分段数据包之后的 TCP 代理则相反。外部路径MTU仍然需要承载层调整； UDP-over-TCP 可以引入队头阻塞。

即使在不同组或内联位置之间复制，相同的客户端在每个配置生成中共享一台设备。身份是配置的对等地址、派生的客户端公钥和服务器公钥，而不是已解析或漫游地址。 WireGuard 默认值和等效的密钥/地址/路由编码，加上承载层接口和 TCP 套接字默认值，在比较之前进行标准化。本地地址前缀被规范化为主机前缀；路由前缀保留其含义。其他承载层协议设置按照配置进行比较。相同身份的冲突地址、路由、PSK、MTU、限制、接口或对等链会被拒绝，而不是默默地合并。不同的身份和服务器保持独立。未使用的客户端组不打开任何套接字。未引用的 WireGuard 路由的 DNS 组已验证但未准备；通过服务器或 TUN `dns` 字段选择组会激活其设备。

DNS 保持独立配置。仅定义 WireGuard 客户端不会对应用程序的默认本机 DNS 进行隧道传输。显式 TCP DNS、DoT 和 DoH 客户端链可以使用 WireGuard 和文字上游 IP。在需要时使用 `server_name` 进行 TLS 身份验证。 UDP DNS、HTTP/3 DNS、WireGuard 链上的主机名上游以及 WireGuard 路由的 DNS 组上的引导依赖项被拒绝。端点引导程序本身是本机 DNS，而不是通过尚未激活的隧道的 DNS。

这是 TCP/UDP 代理，而不是任意 IP 路由。远程目标看到网关的传出代理连接，而不是原始客户端的源地址。非 shoes 网关必须为其后面的目的地提供所需的路由和转发或 NAT。未实现 ICMP 转发、IP 片段重组、点对点 IP 转发、WARP 保留字节和 wg-quick 导入。

在传输解析之前，会丢弃碎片输入和不支持的 IPv6 扩展链。 TCP 通告从 MTU 派生的 MSS。大于 MTU 减去 28 字节 (IPv4) 或 48 字节 (IPv6) 的出站 UDP 写入将被丢弃并计数，而不关闭流；它们永远不会被截断。 UDP 队列预算耗尽也会丢弃单个写入。在 MTU 1408 下，有效负载限制为 1380 和 1360 字节。入站转发中过大的 UDP 响应将被丢弃。大型 DNS 回复应使用基于 TCP 的传输。降低受限底层的 MTU；不提供自动路径 MTU 发现。从高于本地 MTU 的对等方收到的数据包也会被丢弃。配置双方匹配的MTU，包括默认为1420的对等体，而不是shoes'1408； TCP MSS 协商不保护 UDP 流量。

默认准入限制为 256 个 TCP 连接、32 KiB TCP 缓冲区、32 MiB TCP 缓冲区预算、1024 个 UDP 会话、4096 个 UDP 目的地、每个入站 UDP 会话 64 个目的地以及 8 MiB 排队UDP 有效负载。 UDP 转发和出站关联具有单独的有界池。缺失或空限制字段使用 WireGuard 默认值，而不是无限制的 TUN 默认值。数据包和命令队列的上限为 64。这些预算涵盖建模的 shoes 拥有的状态，而不是总进程 RSS 或所有 GotaTun 状态。

TCP 缓冲区绑定通告的接收窗口和隧道中的传输数据。 32 KiB 窗口将单个流量限制为大约 5 Mbit/s（50 ms RTT 时）或 2.6 Mbit/s（100 ms RTT），高于其他瓶颈。对于更高带宽、更高延迟的链接，请将 `resource_limits.tcp_buffer_size` 设置为 262144 (256 KiB)。每个流有四个缓冲区预算，因此在该大小下保留 256 个连接还需要 `tcp_memory_bytes: 268435456` (256 MiB)；默认 32 MiB 预算仅允许 32 个连接。根据测量的 RTT、吞吐量和可用内存进行调整，而不是无条件地增加缓冲区。

定期日志报告端点流量/丢弃计数以及每个对等方的公钥、握手期限和字节计数器。私钥和 PSK 已被编辑。

准备失败保留旧配置。重新加载激活会停止现有隧道流并重建端点；会话不会迁移。激活期间绑定失败会触发回滚到之前的配置，但断开的隧道会话不会恢复。如果回滚失败，shoes 将以状态 1 退出。关闭会等待缓冲的 UDP 任务在重新绑定之前释放其套接字。无需清理主机路由。
