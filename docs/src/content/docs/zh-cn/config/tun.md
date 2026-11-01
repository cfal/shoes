---
title: "TUN 配置"
description: "shoes TUN 配置参考。"
---

TUN（网络TUNnel）设备在IP层（第3层）运行，允许shoes充当透明VPN。

```yaml
# Linux: Create TUN device by name
device_name: string            # Device name (e.g., "tun0")
address: string                # Device IP address (e.g., "10.0.0.1")
netmask: string?               # Netmask (e.g., "255.255.255.0")
destination: string?           # Gateway/destination (Linux only)

# iOS/Android: Use existing file descriptor
device_fd: int                 # FD from VpnService (Android) or NEPacketTunnelProvider (iOS)

# Common settings
mtu: 1500                      # Default: 1500 (Linux), 9000 (Android), 4064 (iOS)
tcp_enabled: true              # Default: true
udp_enabled: true              # Default: true
icmp_enabled: true             # Default: true
dns_hijack: true               # Optional: intercept TCP/UDP port 53 independently of fake-IP

# Routing rules
rules: [RuleConfig]
```

**平台说明：**
- **Linux**：需要 root 或 `CAP_NET_ADMIN`。创建具有指定名称/地址的设备。
- **Android**：使用 `VpnService.Builder.establish()` 中的 `device_fd`。通过 VpnService 配置的路由。
- **iOS**：使用 `NEPacketTunnelProvider.packetFlow` 中的 `device_fd`。

<a id="resource-limits-and-device-framing"></a>
## 资源限制与设备帧格式

`resource_limits` 是 TUN 配置中的可选对象。未设置的准入限制表示不限制；显式设置的准入限制必须为正数。

| 字段 | 默认 | 约束 |
| --- | --- | --- |
| `tcp_buffer_size` | 32,768 字节 | 1,024-16,777,216 字节 |
| `tcp_memory_bytes` | 无限 | 至少四倍`tcp_buffer_size` |
| `max_tcp_connections` | 无限 | 正整数 |
| `max_udp_sessions` | 无限 | 正整数 |
| `max_udp_destinations` | 无限 | 正整数 |
| `max_udp_destinations_per_session` | 无限 | 正整数 |
| `max_udp_queued_bytes` | 无限 | 至少 65,535 字节 |

当 TCP 内存和连接上限均设置时，将应用较低的有效连接计数。这些限制与[进程范围的准入](/zh-cn/config/global-settings/#admission-caps) 是分开的。

`segmentation_offload` 控制 shoes 创建的 Linux 设备上的 TCPv4 发送分段卸载。省略时会自动尝试启用；如果初始化失败，则回退到普通数据包。`false` 禁用卸载，`true` 则要求启动时必须启用。提供 `device_fd`、使用数据包信息头或在非 Linux 设备上显式启用时，配置会被拒绝。IPv6 仍使用普通的 MTU 大小数据包。

shoes 在 iOS 和 macOS 上创建的设备始终使用四字节数据包信息头，且无法关闭。对于外部提供的 `device_fd`，`packet_information` 在 iOS/macOS 上默认为 `true`，在其他平台上默认为 `false`。如果 iOS 或 macOS 应用提供不含此头的 FD，包括从 packet-flow API 桥接的 FD，必须显式设置 `packet_information: false`。该设置不会配置主机 VPN 服务中的路由。

**示例（Linux）：**
```yaml
- device_name: "tun0"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1500
  tcp_enabled: true
  udp_enabled: true
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        address: "proxy.example.com:443"
        protocol:
          type: tls
          protocol:
            type: vless
            user_id: "uuid"
```

### 托管 Linux 桌面捕获

`auto_route: true` 为 shoes 进程提供一个非持久性 TUN、私有路由表、策略规则、nftables 表和可选的每链路 DNS 配置的所有权。它使用 conntrack 感知输出标记捕获主机发起的 TCP/UDP。除非 `auto_redirect: true` 选择内核 TCP REDIRECT，否则两种协议均使用现有的 TUN 引擎。系统 `nft` 可执行文件仅针对控制平面更改和协调运行，而不针对每个数据包或连接运行。

请参阅[桌面示例](/zh-cn/examples/tun_desktop/) 和[master 上的 systemd 单元](https://github.com/cfal/shoes/blob/master/examples/shoes-desktop.service)。这些是手动部署示例，不是发布存档安装的文件。该单元需要 `/usr/local/bin/shoes` 处的二进制文件和 `/etc/shoes/desktop.yaml` 处的配置；将其安装为 `/etc/systemd/system/shoes-desktop.service` 以在 systemd 下运行。配置示例转发DIRECT；在将其用作代理之前，将其 `rules` 替换为所需的代理策略。

```yaml
- device_name: shoes0
  auto_route: true
  auto_redirect: true
  addresses: [10.233.0.1/30, 'fd73:686f:6573::1/126']
  bootstrap_dns: ['1.1.1.1:53', '9.9.9.9:53']
  auto_dns: true
  dns_hijack: true
  dns:
    servers: ['udp://1.1.1.1', 'tcp://1.1.1.1']
  rules: allow-all-direct
```

| 字段 | 行为管理 |
|---|---|
| `auto_route` | 启用进程拥有的Linux捕获；默认`false` |
| `auto_redirect` | 使用内核TCP REDIRECT；需要 `auto_route`；默认`false` |
| `addresses` | 每个家庭一台本地CIDR；不能与手动 `address`、`netmask`、`destination` 或随附的 FD 结合使用 |
| `route_address` | 捕获的目标 CIDR；默认`[0.0.0.0/0, '::/0']` |
| `route_exclude_address` | 明确的目的地排除，包括DNS；默认为空 |
| `bootstrap_dns` | 必需的文字真实 DNS 套接字地址，绝不是环回存根或 TUN 子网 |
| `auto_dns` | 尝试在拥有的链接上发布暂时的 systemd 解析的设置；默认`true` |
| `dns_hijack` | 拦截TCP/UDP端口53；管理时默认为 `true`，否则遵循 fake-IP 策略 |
| `linux.table` | 私有路由表；默认`12000` |
| `linux.rule_priority` | 策略规则优先；默认`12000` |
| `linux.capture_mark` | 捕获位；默认`536870912`（`0x20000000`） |
| `linux.bypass_mark` | shoes套接字旁路位；默认`1073741824`（`0x40000000`） |
| `linux.mark_mask` | 组合保留位；默认`1610612736`（`0x60000000`） |

要求：Linux、`/dev/net/tun`、具有 JSON 支持的可信系统 `nft` 以及网络管理权限。自动 DNS 还需要一个正在运行的 systemd-resolved、具有 JSON 支持的 `busctl`，以及配置拥有链接的授权。自动 DNS 设置和清理是尽力而为的，具有有限的帮助程序调用。缺少服务、失败的命名空间检查和配置错误会产生警告而不是停止捕获。失败的设置可能会留下部分每个链接的设置，直到清理为止；在这种情况下，不保证系统 DNS 通过 shoes 路由。外部更改后不会持续监视或恢复解析器设置，并且解析器重新启动不会停止代理。命名空间检查假设一个标准的本地系统总线，其监听器和守护进程共享一个 PID 命名空间，并为该命名空间安装了 procfs；已解决必须共享 shoes 的网络命名空间。定制总线安排应使用 `auto_dns: false`。重新启动解析器或系统总线后，重新启动shoes以重新应用自动DNS。提供的服务以 root 身份运行，具有有限的功能集。仅 shoes 上的文件功能不会向 `nft` 子项授予权限或授权已解决的更改。

将 `auto_dns: false` 用于外部管理的 DNS。 shoes 永远不会重写 `/etc/resolv.conf`。当托管模式处于活动状态时，引导程序和本机分辨率使用受保护的 shoes 套接字；监听器绑定地址必须是文字 IP。真DNS不需要假IP。自动 DNS 需要在其相邻虚拟 DNS 端点的每个接口地址之后进行拦截和空间。设置在入口工作线程启动后发布，无需单独的 DNS 就绪探针。拥有的链接禁用 DNS-over-TLS、DNSSEC 验证、LLMNR 和 mDNS；上游加密和DNS策略属于shoes的`dns`配置。即使其他管理器在 shoes 运行时更改了这些设置，清理也会尝试恢复拥有的接口上的每个链接设置。删除拥有的 TUN 也会放弃其瞬态解析器设置。其他链接不变。托管 TUN 子网保留用于入口：拒绝将连接转发回该子网，本地 DNS 处理除外。

初始路由必须在 OUTPUT 捕获之前存在，因此每个配置的系列都需要一个没有源或 TOS 约束的底层主表默认路由。对于明确的仅 IPv4 捕获，仅配置 IPv4 地址和 `route_address: [0.0.0.0/0]`；然后 IPv6 仍然是原生的。这不是 IPv6 阻止策略。

环回、本地目标、多播、广播、本地链路目标和连接的网络仍然是本机的。除非明确排除，否则连接网络的 DNS 会被拦截。对入站服务的回复仍然是本地的。现有跟踪的本机流保持本机状态，包括未回复的 UDP；捕获的流保留其选择。被外部 NOTRACK 规则排除在 conntrack 之外的流量仍然是本地的。新的 TCP 捕获仅在连接建立时开始。选择捕获的无效 conntrack 数据包将被丢弃。在启用 conntrack 之前创建的 UDP 流无法可靠地识别，并且可能会重置。显式绑定到物理设备的应用程序在两种模式下都保持本机状态；支持地址绑定的 TCP/UDP 客户端。 REDIRECT 需要每个 TUN 子网中有一个未使用的相邻虚拟对等点。其私有路由使用该对等点作为下一跳，并且只有通过该对等点路由的流量才会被重定向。到对等点本身的流量（包括虚拟 DNS）保留在 TUN 引擎上。外国标记的流量由现有政策决定。不支持的协议仍然是原生的； ICMP 处理是现有的合成回显行为，而不是远程 ICMP 转发。这是主机捕获，而不是网关或容器转发。

冲突的表、优先级、标记保留或前面的非本地策略规则会导致启动拒绝。其他 VPN 和防火墙管理器需要明确的共存验证； shoes 不会覆盖外部防火墙的决定。 REDIRECT 还拒绝使用其虚拟对等点作为网关的本机路由和不透明的下一跳对象路由。捕获的回复在标记感知反向路径过滤之前携带捕获标记。不承诺通用 VPN、防火墙、解析器管理器或分发兼容性。

重新加载会保留接口、捕获和重定向监听器身份。网络拓扑更改需要重新启动，并且在退休工作人员之前会被拒绝。普通工作线程重新加载可以重置现有连接并短暂中断流量，但不会禁用捕获。失败的候选者将回滚同一网络租约。意外的所属路由更改或丢失的专用防火墙表会导致有序关闭。解析器设置更改则不会。

shoes 独家拥有其名为 `inet` nftables 表的代币，包括其所有内容。不要向该表添加规则、链或集：其中的外部更改既不会被审核也不会被保留。清理会删除确切拥有的表，即使其内容已更改；其他表保持不变。连接网络集通过 nftables 自动更新并缓存在内存中，而不是记录为防火墙快照。

关闭会删除捕获并在退出入口之前尝试 DNS 清理。 SIGKILL 无法运行清理：服务的 `ExecStopPost` 调用 `shoes cleanup-tun`，并且下一个托管启动也会协调陈旧状态。恢复使用 `/run/shoes` 下的私有命名空间范围的日志来跟踪清理身份和挂起的操作，而不是防火墙策略。接口和路由所有权检查仍然严格；冲突的更改被拒绝，并报告错误。可能会出现暂时中断和连接丢失的情况。缓存的虚假地址可能比关闭后仍然存在。没有终止开关，没有上游故障时的自动直接回退，也没有不间断的故障开放保证。杰出的帮助程序进程会保留命名空间锁，因此恢复会失败，而不是与仍然可以提交的帮助程序竞争。该服务在 `ExecStopPost` 之前终止剩余的助手；独立操作员必须让它们完成或停止它们，然后再重试清理。该服务重试没有启动速率限制，包括在配置的系列正在等待其基础默认路由时。目前，协调期间的读取失败会触发清理和受监督的重新启动，而不是就地修复。清理错误会保留日志以便重试。在删除拥有的表之前，过时的 TCP REDIRECT 规则可以继续拒绝连接。
