---
title: "Clash控制器"
description: "shoes clash 控制器配置。"
---

CLI 可以公开 Clash API 的记录子集。除非配置了监听器，否则控制器将被禁用。它不会改变现有组的循环行为。

```yaml
- clash_api_address: "0.0.0.0:9090"
  secret: "replace-with-a-strong-secret"
  cors_origins: ["https://dashboard.example.com"]

- clash_api_path: "/run/shoes/clash.sock"
  secret: "replace-with-a-local-secret"

- cache_file_path: "./cache.db"
```

`clash_api_address` 使用普通服务器地址语法接受一个地址或一个列表。每个条目使用 `clash_api_address` 或 `clash_api_path`。多个条目共享选择器、连接、计数器和资源预算；他们不是单独的租户。每个都有自己的秘密和浏览器起源。监听器定义和 `cache_file_path` 需要重新启动才能更改。

每个监听器都需要非空密钥。HTTP 使用 `Authorization: Bearer <secret>`；支持的 WebSocket 升级请求也可以使用 `?token=`。浏览器来源必须与 `cors_origins` 完全匹配，除非 `cors_origins: ["*"]` 明确允许所有来源，包括不透明来源（`null`）。该要求适用于 HTTP 和 WebSocket 请求，且不会关闭身份验证。尽可能指定确切来源；使用 `*` 时，任意网站都能尝试发起经过身份验证的请求，因此应使用足够长的随机密钥。默认的空列表允许不带 Origin 标头的已认证客户端，但拒绝带 Origin 标头的请求。只有单独的 `*` 才是通配符；不接受字面值 `null`。可选的 `allow_private_network: true` 会为允许的来源启用专用网络预检响应，并不能绕过混合内容限制。应使用防火墙和外部 TLS 终止保护 TCP。Unix 套接字必须使用现有的仅所有者可访问目录中的绝对路径，并以 `0600` 权限创建。浏览器要访问 Unix 套接字，需要 HTTP 反向代理。

明确选择手动选择：

```yaml
- client_group: outbound
  type: selector
  default: east
  client_proxies:
    - name: east
      address: "east.example.com:1080"
      protocol: {type: socks}
    - name: west
      address: "west.example.com:1080"
      protocol: {type: socks}
```

规则继续使用`client_chain: outbound`。选择器选择直接命名的成员或引用的组；内联选择器成员需要 `name`。组判别式为 `type`：`round-robin`（默认值）、`selector` 或 `url-test`。删除的 `strategy` 字段和未知类型都是错误。保留嵌套循环权重、重复成员资格和现有 UDP 过滤。不支持 UDP 的选定分支会导致新的 UDP 流失败，而不是静默回退。选择更改仅影响新流；现有流、UDP 目的地、DNS 连接和 WireGuard 关联将保持固定状态，直到重新打开。可选的客户端和服务器/TUN `name` 字段提供稳定的仪表板身份。生成的匿名名称仅对于未更改的定义站点来说是稳定的。

自动选择不需要控制器监听器或缓存文件：请参阅 [URL 测试示例](/zh-cn/examples/url_test/) 了解完整文件。

```yaml
- client_group: fastest
  type: url-test
  url: "https://probe.example.com/generate_204"
  interval: 300       # seconds, 1..86400
  timeout: 5000       # milliseconds, 1..60000, no longer than interval
  tolerance: 50       # milliseconds, 0..65535
  lazy: true
  client_proxies:
    - name: east
      address: "east.example.com:1080"
      protocol: {type: socks}
    - name: west
      address: "west.example.com:1080"
      protocol: {type: socks}
```

`url-test`只需要`url`；上面的值是其他默认值。探测策略拒绝的文字 URL 地址（包括环回、链路本地、多播、未指定和综合基准地址）是配置错误。本地解析的主机名在探测时遵循相同的目标策略。与配置或保留的假 IP 范围重叠的文字 URL 也会被拒绝。 `default` 仅是选择器。 `url`、`interval`、`timeout`、`tolerance` 和 `lazy` 仅用于 url 测试。成员必须是非空且不同的；支持对嵌套组的引用。建议为自动内联成员使用显式名称。

选择对配置的 URL 使用符合该跃点和传输条件的成员中最快的新鲜健康结果。健康的现任成员将保持选中状态，除非另一个成员将其延迟改善超过 `tolerance`。 TCP和UDP有单独的现任；即使其最快的 TCP 成员不支持 UDP，自动组也可以选择支持 UDP 的替代方案。嵌套手动选择器仍然限制资格，中间链跳只需要 TCP 支持。更改选择会影响新连接，而不是已建立的流或关联。

激活后有一项初始检查，包括针对懒惰组的检查。此后，`lazy: true` 仅检查上一次间隔期间新转发连接使用的组。探头、仪表板读数和 WireGuard 载体维护永远不会算作使用。通过 WireGuard 端点的新出站连接会唤醒其承载层组（包括嵌套承载层），而无需更改其现有关联。仅入站端点和长期流需要 `lazy: false` 进行连续检查。 `lazy: false` 也会检查空闲组。早于 `2 * interval + timeout` 的样本已过时，无法因延迟而获胜。如果没有新的健康结果（启动、全部失效、过时或本地不可用的探针），请保留合格的现任成员，或按配​​置顺序选择第一个合格的成员。这是尽力而为的路由，而不是故障关闭路由。

明确的远程连接错误请求限速重新检查（最多每秒一次）；它们不会根据不同的用户目标将配置的 URL 标记为无效。局部超载和不受支持的操作不会损害健康。 HTTP/2 适配器保留此分类的匹配传输错误原因。当协议用通用取消替换故障时，这是最好的努力：例如，XHTTP 上传取消可能会丢失原始原因并计为远程故障。用户有效负载永远不会在候选者之间重试。探针使用 HTTP HEAD 并接受任何 HTTP 响应状态，无需重定向； HTTPS 证书已验证。本地探测查找使用受保护的系统 DNS，而不是服务器配置的 DNS 组。具有相同规范化 URL 和通配符/默认预期状态的 API 探测也会更新选择。其他 URL 和显式状态期望无法覆盖它。

定期探针和 API 探针共享 16 个探针限制。每个周期的超时时间包括准入/排队时间；截止日期前未入院的成员保留其先前的健康状况。排队后的截止日期到期是不确定的，并且还可以保留之前的健康状况；成功的探测和显式的远程错误仍然会更新它。没有全预算尝试的成员，然后是最早的全预算尝试，在每一轮中领先，与健康状况无关。本地故障不能独占这些时隙，并且排队的尝试可以在稍后的回合中收到完整的预算。固定成员轮流准入。最早未排队准入的到期组将获得优先权，稳定的目录顺序打破了平局。在持续饱和的情况下，减少组大小，增加超时/间隔，或期望未探测/过时的成员。调度粒度为一秒，组内轮次不重叠；当一轮慢速飞行时，其他小组可以奔跑。激活/重新加载会取消旧的工作并拒绝过时的结果；中断的回合在其生成恢复后立即符合资格。新的承诺一代从未经检测的健康开始。

控制器报告 `type: URLTest`、有效 TCP `now`、可选 `udpNow`、`testUrl` 和选定成员 `health`（`unprobed`、`healthy`、`dead` 或 `stale`）。它的`alive`仅适用于新鲜健康的结果。自动组的手动选择 PUT 被拒绝；自动选择既不固定也不持久。叶历史记录仍限于每个 URL 的 10 个样本和 8 个 URL。自动选择保留其配置的 URL 样本和完整预算尝试时间戳，与 API 驱逐无关；对于每个已过滤和未过滤的探测，每个成员的其他尝试 URL 上限为 8 个。自动检查将每个直接成员作为独立的出站进行测试，而不是每个周围的链或目的地。 FFI 不支持 URL 测试组。

<a id="persistence"></a>
## 持久化

所有输入文件中只允许有一个 `cache_file_path`。它的缺失会导致持久性失效；相对路径根据进程工作目录进行解析。该文件是 shoes 特定版本的 JSON，而不是 sing-box/Mihomo 数据库。父目录必须存在，并且 Unix 缓存/锁定文件必须是私有的。显式 API 选择优先于 `default`，然后是第一个成员。启动/重新加载从不保存默认值或重写 YAML。每个接受的选择 PUT 都会在发布新选择之前保存。失败的保存使路由保持不变。原子替换后的错误可能会在磁盘上留下未确认的选择；日志报告了这种持久性的不确定性。已删除组的已保存条目将被保留。读取和写入均限制为 1 MiB；仅当 shoes 停止时删除过时的条目。

## API行为

支持的端点：`/version`、只读 `/configs`、`/proxies`、`/group`、选择器 PUT、节点/组 `/delay`、只读 `/rules`、`/connections` 快照和 DELETE 取消，以及 WebSocket/NDJSON `/traffic`、`/memory` 和 `/logs`。提供者集合返回`{"providers":{}}`。流量计数器测量出站应用程序负载，而不是标头、填充或重传。排除探针、内部DNS/承载层流量以及未经身份验证的伪装/后备转发；合成假 DNS 答案和 ICMP 不表示为连接。连接速度由仪表板从连续的字节计数器得出。过程/GeoIP 数据不是捏造的。

Clash API 条目（`clash_api_address` 或 `clash_api_path`）上的可选 `connection_notes: true` 通过 HTTP 和 WebSocket 将设置注释添加到活动 `/connections` 对象。默认为 false；更改它需要重新启动。如果任何控制器启用它，所有控制器都会公开注释。在 zashboard 中，打开连接的详细信息并选择 **Raw** 以检查 `notes`（`elapsedUs`、`phase`、`text`）及其现有的生成、目标、选定的链和规则元数据。

注释描述了准备、路由选择、入站解析器调用和出站设置。它们是尽力而为的：拒绝/失败的设置和关闭的连接没有保留的历史记录或单独的调试端点。仪表板可能会保留以前采样的连接，但可能会错过短暂的连接。 DNS 注释涵盖现有路由/拨号呼叫边界，而不是解析器缓存/上游内部结构或远程 DNS。未观察到初始 UDP 预检查和本地 DNS 处理。注释包含主机名和地址，而不包含有效负载、凭据或错误消息；错误仅使用其类型。它们可能会泄露 API 未公开的出站代理服务器主机名和 IP 地址。

最多 256 个连接（包括挂起的设置）同时收集注释。每个缓冲区保存 32 个事件，每个事件最多包含 128 个 UTF-8 字节文本，以及读取时的溢出摘要。当所有插槽都被占用时，新连接会跳过音符。每个缓冲区最多保留 8 KiB，总计 2 MiB，不包括分配器/RSS 开销和快照副本/JSON。当最后一个读取器完成时，关闭或放弃连接会释放其缓冲区。预算在重新加载之间共享。禁用注释后，不会分配任何注释缓冲区或解析器包装器。启用后，注释会添加设置工作和快照复制/序列化：即使没有订阅者，控制器也会每秒采样； HTTP 请求和自定义间隔 WebSocket 订阅可以请求其他快照。

延迟测试通过实际出站发送 HTTP HEAD，验证 HTTPS 证书，并且从不遵循重定向。叶子测试是独立的，而不是对包含该叶子的每个链进行测试。未使用的 WireGuard 节点保持不活动状态，并且在被转发或 DNS 规则引用之前无法探测。直接探测目标不能是环回、链路本地、未指定、多播或合成假 IP 地址。远程代理可能会以不同的方式解析名称：这是经过身份验证的管理网络访问，而不是用于不受信任的用户的 API。

兼容性目标是 zashboard 修订版 `6225aac84439425ae4f4493437b110a314753436`，而不是完整的 Mihomo 奇偶校验。仅提供规则模式，不提供合成 `GLOBAL`。在仪表板后端设置中使用 `disableUpgradeCore=1`。不受支持的控件仍然可见：配置编辑、API 重新加载/重启、升级、提供程序更新、规则禁用、DNS/缓存维护和仪表板存储同步返回显式错误，绝不假装成功。不包括 UI 下载/托管。控制器/缓存条目被 FFI 拒绝。

请参阅[完整示例](/zh-cn/examples/clash_api/)。控制器连接共享限制为 64 个，订阅 16 个，探测 16 个，绑定套接字 16 个。请求头必须在接受或前面的响应后 15 秒内完成；普通请求机构有 10 秒的截止时间和 64 KiB 的限制。已建立的订阅不受标头空闲到期的影响，并且具有有限的队列/写入截止时间。响应大小限制为 32 MiB。超大连接快照关闭其 WebSocket，代码为 1009，原因为 `response exceeds 32 MiB`；跟踪将继续，而不会截断连接列表。配置控制器、`cache_file_path` 或任何选择器/url 测试组可启用目录及其 16,384 个节点限制。名称必须非空、唯一、最多 256 个字节，并且不包含控制字符。 `DIRECT`、`REJECT` 和 `GLOBAL` 保留。配置准备拒绝大于 32 MiB 的 `/rules` 或基本 `/proxies` 响应。组延迟请求支持最多 1,024 个直接成员。
