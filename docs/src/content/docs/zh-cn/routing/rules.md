---
title: "规则系统"
description: "shoes 规则系统配置。"
---

规则决定传入连接的路由方式。

<a id="tls-sni-路由"></a>

<a id="tcp-hostname-sniffing"></a>
### TCP 主机名嗅探

在服务器上设置 `sniff: true`（包括 WireGuard）或 TUN 配置，以使用可见的 TLS ClientHello SNI 或明文 HTTP/1.0 和 HTTP/1.1 Host 作为主机名规则。默认为 `false`。该选项适用于逻辑 TCP 流，包括复用和 QUIC 承载的 TCP，而不是 UDP/QUIC 初始数据包、HTTP/2 或 HTTP/3 应用标头或外部 TLS 承载层握手。嵌套的 `override_rules` 继承该设置。

当存在主机名规则时，嗅探适用于文字 IP 目标，包括恢复的 Fake DNS 映射。不会嗅探显式提供的主机名。仅对于主机名规则，嗅探到的主机名优先于恢复的 DNS 名称。 IP/CIDR 掩码和出站目的地仍使用原始真实 IP 或恢复的 DNS 主机名，包括通过代理链。 IP 规则在需要时解析恢复的主机名，而不是嗅探的名称。显式规则 `override_address` 仍然可以更改目的地。

捕获是尽力而为的，仅限于 300 毫秒和 64 KiB 的有线数据。未知、格式错误、过大或不完整的 TLS 或 HTTP 使用原始 IP 或恢复的 DNS 主机名回退到普通路由；捕获的字节按原样重播。传输错误仍然会终止连接。服务器优先的应用程序可能会导致完全延迟。当需要更多客户端字节时，响应门控协议在路由/拨号之前发送成功；稍后的故障会关闭或重置流，而不是发送另一个状态。

HTTP 检验在任何目标端口接受来源形式请求 (`GET /path HTTP/1.1`) 和 `OPTIONS *`。它需要一个完整的 CRLF 分隔的标头部分，其中只有一个有效的主机和最多 128 个字段。主机名与可选终端 DNS 点匹配，不区分大小写；数字端口经过验证，但不会更改目标或规则匹配端口。 IP-文字主机值、重复主机字段、绝对格式请求和 CONNECT 请求不产生提示。不解析或等待请求主体。

探针在代理设置后看到应用程序字节：不会嗅探外部 CONNECT 标头。隧道内的明文请求会暴露 Host；内部 HTTPS 连接仍然仅暴露可见的 TLS SNI。正常的 HTTP 转发代理请求在到达探测器之前会被重写为原始格式。

每个逻辑 TCP 流都会发生一次路由。具有不同主机值的后续保持活动或管道请求以及 HTTP 升级后的流量将保留在第一条路由上，而无需再次进行主机名检查。现有的 `sniff: true` 配置现在也使用 HTTP 主机；省略或错误的设置不变。请参阅 [HTTP 主机](/zh-cn/examples/http_host_sniffing/) 和 [TLS SNI](/zh-cn/examples/sni_sniffing/) 示例。

SNI和主机是客户端控制的，不是经过身份验证的身份或域防火墙。将强制 IP 拒绝规则放在主机名允许之前。使用 ECH，只有可见的外部名称可用，而不是加密的内部主机名。对于假 DNS 流，该外部名称优先于主机名规则的恢复主机名。当路由必须遵循恢复的名称时禁用 `sniff`，或者为 ECH 公共名称配置规则。

### 规则配置
```yaml
rules:
  - masks: Mask | [Mask]      # Strings, typed predicates, file sources, or group references
    no_resolve: boolean?      # Default false; known IPs still participate
    action: allow | block     # Default allow
    # For action: allow
    override_address: string?  # Optional address override
    client_chain: ClientChain | [ClientChain]  # Proxy chain(s) for routing
```

<a id="client-chains"></a>
### 客户端链

客户端链定义流量如何通过上游代理路由。每条链都是一系列“跃点”——流量按顺序通过的代理。

在规则、客户端组和 DNS 服务器选项中，`client_chain` 与 `client_chains` 是完全等价的别名。结构由字段值决定，而不是由字段名的单复数决定：`[a, b]` 和 `{chain: [a, b]}` 都表示顺序跃点。备选路径使用 `[{chain: [a]}, {chain: [b]}]`。嵌套列表（`[[a], [b]]`）也表示备选链；建议使用显式包装以便阅读。

DNS 以前将普通列表解释为备选路径，现在将 `[a, b]` 解释为顺序路径，与路由保持一致，不提供兼容模式或警告。DNS 备选路径必须使用显式链包装或命名组。系统 DNS 仍不接受客户端链；UDP/H3 DNS 仍要求仅含直连的路径。

```yaml
# Single proxy (simplest form)
client_chain: my-proxy-group           # Reference a named group
client_chain:                          # Or inline config
  address: "proxy.example.com:1080"
  protocol:
    type: socks

# Multi-hop chain (traffic goes: client -> hop1 -> hop2 -> target)
client_chain:
  chain:
    - first-proxy-group
    - second-proxy-group

# Multiple chains (round-robin selection)
client_chains:
  - chain: [us-proxy-group]            # Chain 1: single hop
  - chain: [proxy1, proxy2]            # Chain 2: multi-hop

# Load balancing at a hop (pool)
client_chain:
  chain:
    - pool: [us-proxies, eu-proxies]   # Round-robin between pool members
    - final-proxy
```

<a id="legacy-proxy-fields"></a>
### 旧版代理字段

`client_proxy` 和 `client_proxies` 仍可用于规则、客户端组和 ShadowTLS 远程握手，但会产生弃用警告。原有行为保持不变：旧版列表表示备选项，而不是顺序跃点。使用 `RUST_LOG=warn` 或更详细的日志级别可查看这些警告。

单个 `client_proxy: upstream` 可改为 `client_chain: upstream`。对于列表，仅更改字段名会改变行为。以下片段假设组 `a` 和 `b` 已在其他位置定义：

```yaml
# Old rule: client_proxies: [a, b]
# Equivalent rule, retaining one-hop round-robin alternatives:
client_chain:
  chain:
    - pool: [a, b]

# Old group: client_proxies: [a, b]
# Equivalent group, retaining separate policy members:
client_group: outbound
client_chains:
  - chain: [a]
  - chain: [b]
```

对于 ShadowTLS 远程握手，使用 `client_chain: [{pool: [a, b]}]` 替换旧版代理列表。不要同时指定旧版和新版字段。

### 掩码语法
```yaml
# IP/CIDR masks
masks: "0.0.0.0/0"             # Any destination, including hostnames and IPv6
masks: "::/0"                  # Same legacy universal predicate
masks: "192.168.0.0/16"        # Subnet
masks: "10.0.0.1:80"           # Specific IP and port

# Hostname masks
masks: { subdomains: [google.com] } # Descendants, excluding the apex
masks: "example.com"           # Name and all descendants

# Multiple masks
masks:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "internal.com"
```

### 内置规则组
- `allow-all-direct` - 允许所有连接，直接路由
- `block-all` - 阻止所有连接

### 类型化目标谓词

`masks` 接受旧字符串、类型化谓词、文件源和无操作组引用。列表使用 OR 将其条目组合起来。谓词对象包含一个运算符：`all`、`any`、`not` 或叶子。相同的形式在 `all`/`any`/`not` 内递归工作；字符串始终保留旧掩码，而不是组名称或路径。类型化叶子内的列表是替代方案。

将混合的旧版掩码和导入的组保留在一个 OR 列表中：将它们拆分为单独的策略可以更改排序的 DNS 评估。

```yaml
rules:
  - masks:
      all:
        - domain_suffix: [example.com]
        - destination_port: [443]
    action: allow
  - masks: { any_destination: true }
    action: block
```

叶子：`domain`（精确）、`domain_suffix`（顶点和后代）、`subdomains`（仅限后代）、`domain_pattern`（`*` 匹配一个标签）、`domain_keyword`、`domain_regex`、`ip_cidr`、`destination_port`、 `destination_port_range`（包括`"8000:9000"`）和`any_destination: true`。本机域文字和关键字不区分大小写。正则表达式是非锚定的并且区分大小写，除非它们启用大小写折叠；不支持反向引用、环视和非 ASCII 模式。键入的端口为 1-65535。空集不匹配任何内容；空的 `all`/`any` 节点将被拒绝。

政策仍采用先匹配的顺序。在一个策略内，已知的 OR 匹配或 AND 未命中可以避免 DNS，无论谓词顺序如何。较早的未解决的策略不能被较晚的域规则绕过。 IP 谓词使用选定的本地 DNS 答案，将其固定以进行直接拨号；查找失败会中止路由。在此固定之后，直接多地址回退将被禁用。主机名转发代理协议仍可能在出口处独立解析。

规则上的 `no_resolve: true` 禁止启动 DNS，但消耗已提供/解析的地址。如果没有地址，IP 谓词仍然未知，包括在 `not` 下；即使其操作是 `block`，不可判定的策略也会失败。没有主机名的域谓词是 false，包括没有嗅探提示的文字 IP 连接。不执行反向DNS。

迁移：旧版 `*.x` 和 `.x` 掩码在启动和重新加载时被拒绝；将它们显式替换为 `subdomains` 或 `domain_pattern`。裸露的掩码仍然包括顶点和后代。旧版 `/0` 掩码在没有 DNS 的情况下仍保持通用，但类型 `ip_cidr: ["::/0"]` 仅限 IPv6，并且需要 IP。其他旧版 IPv6 掩码不再通过数字重叠来匹配 IPv4；仅映射的旧掩码标准化为 IPv4，并带有警告。显式类型化映射 IPv6 谓词必须使用 IPv4 拼写。即使使用全部规则，现在也会拒绝提供的无效主机名（包括非 ASCII、空格、空标签和过长）；使用 A-label/punycode 名称。无效的嗅探提示将被忽略。匹配会去除一个根点并小写 ASCII，而不更改拨号目标。

<a id="local-rule-sources"></a>
### 本地规则源

声明一个包含匹配表达式和文件路径的无操作 `rule_source_group`，或者在 `masks` 下或与 `action` 一起加载内联文件。在重新加载停止现有监听器之前，在验证期间读取和编译源，包括 `--dry-run`。无效来源拒绝该候选人。自动重新加载监视导入的文件和配置。可解析的被拒绝的候选者会监视其源路径，因此创建或修复丢失的文件可以恢复，而无需再次进行配置编辑。活动源将持续受到监视，直至替代源激活。 `--no-reload` 禁用自动完全重新加载； SIGHUP 仍会重新加载，并且实时服务器证书轮换仍保持启用状态。已建立的连接将保留其原始规则，直至耗尽。新的路由缓存属于新的配置；假DNS池单独保存。

```yaml
- rule_source_group: blocked
  rules:
    - lists/domains.srs
    - path: lists/addresses.json
      format: singbox_json
    - domain_suffix: [ads.example, tracking.example]
    - all:
        - domain_suffix: [restricted.example]
        - destination_port: [443]

- address: "0.0.0.0:1080"
  protocol: {type: socks}
  rules:
    - masks: {rule_source_group: blocked}
      action: block
    - masks: {path: lists/extra.srs}
      action: block
    - path: lists/another.srs
      action: block
    - masks:
        - "192.168.0.0/16"
        - "internal.example"
        - path: lists/direct.txt
          behavior: domain
      action: allow
```

源和组也由类型化谓词组成：

```yaml
rules:
  - masks:
      all:
        - rule_source_group: blocked
        - destination_port: [443]
        - not: {path: lists/exceptions.srs}
    action: block
```

源组或它们的条目在一起，包括本机谓词、`all`、`any`、`not`、源组引用和文件源。源是组 `rules` 内的路径字符串，或者是具有 `path` 和可选 `format`、`behavior`、`code` 和 `attributes` 的对象。 `masks`下的内联源需要对象形式；掩码字符串始终是 IP/CIDR/主机名。例如，`masks: blocked` 匹配该主机名，而不是上面的组。任何文件系统或名称存在启发式都不会改变这一点。

操作和路由选项属于引用策略，而不是源。省略`action`仍然表示`allow`；不采取任何行动的团体并不意味着封锁。源对象拒绝操作字段，并且不能与谓词运算符混合。具有相同规范路径和解码选项的源共享一组编译集，包括跨命名组和内联使用。 DAT 代码和属性名称不区分大小写；属性顺序和重复项不影响共享。对于 MRS，省略和显式提供的 `behavior` 值使用单独的缓存条目。每一代最多接受 1,024 个不同的来源。

显式 `format` 覆盖检测。否则，SRS 和 Zstd 签名选择 SRS 和 MRS 解码器，后跟不区分大小写的 `.srs`、`.mrs`、`.json`、`.yaml`/`.yml` 和 `.txt` 后缀。 Zstd 数据仍必须包含有效的 MRS 负载。未知格式需要显式 `format`； DAT 始终需要 `geosite_dat` 或 `geoip_dat`。 YAML/文本仍然需要`behavior`。

源路径与声明配置文件相关，包括嵌套谓词和协议覆盖内的内联源，即使组合了多个配置也是如此。 FFI 字符串配置需要绝对源路径。现有的 PEM `cert`/`key` 路径保持相对于工作目录；绝对路径避免混合这些约定。

SRS 版本 1-5 和单盒源版本 1-5 支持目标域、后缀、关键字、正则表达式、IP、端口、反转和嵌套逻辑规则。不支持的字段、标签和版本无法通过验证，包括内部反向表达式。源地址替代项形成 OR；目标端口限制该 OR。空的顶级集合不匹配任何内容。空的个别规则无效。保留单框文字拼写：大写域/后缀/关键字条目无法匹配规范化的小写查询并产生警告。正则表达式模式保留自己的大小写标志；仅接受有界 ASCII Rust 正则表达式子集。

文件大小限制为 64 MiB，有效负载增加到 256 MiB，编译的保守分配预算为 512 MiB。每个来源仅限 200 万个条目。源之间释放临时解码/构建费用；保留的索引计入生成预算，包括在缓存、下载或本地源解码之前保留的远程索引。刷新候选者排除被替换源的旧索引。该预算不包括旧/新一代重叠，并且不限制处理 RSS。引用扩展谓词访问也有保守的 200 万编译预算，计算重复的组引用和调用者组合。这些是安全上限，而不是移动内存保证。运行时正则表达式缓存对于每个工作进程和生成是独立的；捕获跟踪已禁用，每个惰性 DFA 缓存的上限为 256 KiB。正则表达式组最多接受 512 KiB 的模式文本，并具有与语法成比例的编译保留。不支持 GeoIP `.db` (MMDB) 文件；请改用 sing-geoip 中的国家/地区 SRS 文件。

Mihomo 提供程序使用 `format: mihomo_yaml`（`payload` 字符串列表）、`format: mihomo_text`（每行一个条目、空行和 `#`/`//` 注释被忽略；接受一个前导 UTF-8 BOM）或 `format: mrs`。 YAML/文本需要 `behavior: domain`、`ipcidr` 或 `classical`。 MRS仅支持域/IP；可选配置的行为必须与其标头匹配。 MRS 接受一个 zstd 帧，最多有 8 MiB 窗口。 YAML支持仅包含`payload`的一个映射中的块和流序列；标签、锚点、别名和多个文档都会被拒绝。事件之间的解析器预读限制为 128 KiB，包括注释和空格。

域提供商将裸露的确切名称、`+.example.com`（顶点和所有后代）、`.example.com`（仅后代）和 `*` 区分为一个完整的非空标签。文字标签不区分大小写。经典提供程序接受 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`IP-CIDR`、`IP-CIDR6` 和 `DST-PORT`。条目是替代项，而不是成对的独立列表。 IP 条目可能以 `,no-resolve` 结尾；目标端口接受 `80/443/8000-9000`。其他运算符/选项验证失败。经典关键字和正则表达式不区分大小写，并保留内联正则表达式大小写覆盖。与某些 Mihomo 经典路径不同，shoes 将传入查询名称规范为小写。

X 射线地理数据使用显式 `format: geosite_dat` 或 `format: geoip_dat`，以及所需的不区分大小写的 `code: CN` 类别选择器。 GeoSite 可以选择接受 `attributes: [ads]`：每个列出的属性必须在域上具有 true 布尔值。与 Xray 的关键存在过滤器不同，假、整数和仅关键属性不满足此过滤器。内联 `@` 选择器和其他选择语法将被拒绝。 GeoIP 支持 `reverse_match` 和单独的 IPv4/IPv6 成员资格。加载器扫描protobuf帧，而不解码未选择的类别体；所选条目拒绝未知字段/枚举和不支持的正则表达式语法。 DAT 与 sing-geoip 版本中的 MMDB `.db` 文件无关。

### 规则示例
```yaml
rules:
  # Direct connection for local networks
  - masks: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    action: allow
    client_chain:
      protocol:
        type: direct

  # Block specific domains
  - masks:
      any:
        - subdomains: [ads.example.com]
        - domain_suffix: [tracking.example.com]
    action: block

  # Route through upstream proxy
  - masks: "0.0.0.0/0"
    action: allow
    client_chain:
      address: "proxy.example.com:1080"
      protocol:
        type: socks
```
