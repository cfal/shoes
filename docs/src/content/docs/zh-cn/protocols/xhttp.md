---
title: "XHTTP / SplitHTTP"
description: "XHTTP 客户端和服务器配置、模式、限制和互操作性。"
---

**完整示例：** [xhttp.yaml](/zh-cn/examples/xhttp/)。在部署之前生成证书并替换演示凭据。

`type: splithttp` 是 `type: xhttp` 的别名。 XHTTP 包装了一个内部代理协议，该协议仍然处理身份验证和目的地。完整的示例涵盖了所有三种模式以及 H1、H2 和 H3。

<a id="server"></a>
## 服务端

将 `type: xhttp` 放置在监听器的 `protocol` 中：对于明文 H1/h2c，直接放在 TCP 上；对于 H3，直接放在 QUIC 上；或者对于 H1/H2，放在 TLS/REALITY 目标内。 `protocol` 是必需的内部服务器协议。 `path`、`host`和`matching_headers`选择接受哪些请求； `mode: auto` 默认接受所有支持的模式。添加 `limits` 以限制公开监听器上的会话、请求和缓冲字节。

<a id="client"></a>
## 客户端

将 `type: xhttp` 放置在客户端跃点的 `protocol` 中。 `protocol` 是必需的内部客户端协议。使用客户端 `headers` 匹配服务器的 `path`、`host` 和任何所需的 `matching_headers` 值。默认值为 `mode: auto`、`http_version: auto`、`download_idle_timeout_secs: 900` 和 `packet_pipeline_depth: 30`。客户端`pool`默认3个H2/H3连接，最多64个H1连接，60秒空闲超时。

## 模式与传输

- `http_version: auto`：H1为明文TCP，H2为TLS/REALITY，H3为QUIC。 `http/1.1` 的显式 TLS ALPN 选择 H1。显式明文H2使用h2c先验知识，而不是HTTP升级。
- 客户端`mode: auto`：正常打包，REALITY下流一。服务器默认接受所有模式。 Stream-one 使用一个请求； Stream-up 使用单独的流式上传/下载请求； packet-up 使用有界 POST。
- Packet-up 无法传输上传 EOF。当目标必须在响应之前接收 EOF 时，请使用流模式。上传关闭和数据包确认后，客户端 `download_idle_timeout_secs` 绑定仅下载尾部（默认为 900 秒或 15 分钟；必须为正值）。下载转发和成功的本地读取会重置此计时器。 到期时报告超时，而不是成功的 EOF。对等 EOF 或删除流会立即将其关闭。空闲超时不能证明排队上传已交付；应考虑目标端可能预期的暂停。流媒体需要无缓冲代理。 H1 Stream-one 在其响应结束时关闭整个 HTTP 连接；使用 H2/H3 或流式传输进行远程优先半关闭。在流式传输/自动服务器模式下，正常下载 EOF 允许在 30 秒内附加无人认领的流式上传；之后回收仍未附加的上传。数据包上传不会享受此宽限期。
- H1/H2 保留选定的上游代理链。 H3 必须是第一个代理跃点；它重用现有的 QUIC/H3 依赖项，而不是 Hysteria2 框架。
- 服务器 `matching_headers` 需要每个请求上的每个配置标头，包括选项，因此没有它们的浏览器预检将被拒绝。名称不区分大小写；值必须完全匹配并且仅出现一次，空值需要存在一个空标头。检查失败的请求在每个 HTTP 版本上都会得到一个简单的 404，没有会话许可或正文读取；共享 H2/H3 连接的其他请求不受影响。将客户端的`headers`配置为相同的值，例如服务器上的`matching_headers: { X-Tunnel-Key: "replace-me" }`和客户端上的`headers: { X-Tunnel-Key: "replace-me" }`。设置`extra`的Xray客户端必须将`headers`放在`extra`内；当 `extra` 存在时，Xray 会忽略顶级 `headers`。值也可以是一个列表，例如 `X-Tunnel-Key: [old, new]`，以在轮换机密时接受其中任何一个。使用`host`，而不是`matching_headers`，来匹配Host/`:authority`。
- XHTTP 错误响应很简单：状态代码和空正文，没有填充、缓存或 CORS 标头。
- `host` 独立于 TLS SNI 覆盖 HTTP 权限。默认 Referer 填充、路径/查询处理、数据包大小/节奏和流式保持活动遵循现代 Xray。 `limits`可以绑定会话、缓冲字节和请求；默认情况下，设置/标头截止时间和数据包不活动仍然受到限制。没有显式 `sni_hostname` 的内部 TLS 客户端不会发送有线 SNI，但仍然根据代理跃点地址验证证书。 `pool` 限制连接和空闲保留。分程航段可以在同一选定路线上使用不同的承载层。 H2/H3 准入尊重对等流容量；正在排空的承载层保留其连接槽。满池会拒绝新会话，而不是超出其配置的上限。拆分模式需要至少两个有效请求通道：两个 H1 连接，或用于 H2/H3 的 `pool.max_connections * effective_requests_per_connection >= 2`。当配置 `limits.max_requests_per_connection` 和 `global_settings.max_streams_per_connection` 时，每个连接的有效限制为 `limits.max_requests_per_connection` 和 `global_settings.max_streams_per_connection` 中较小的一个。对等流限制会进一步降低运行时容量。 Stream-one只需要1个lane，包括REALITY的自动模式。
- 服务器 `x_padding_bytes` 是一个接受范围，与 `server_max_header_bytes` 无关（默认为 8192）。广泛的范围可以接受使用较小填充的客户，而无需提高标头上限。要使用更大的 Referer 填充，请提高上限以适合填充加上 URL、其他标头和 HTTP 版本帧开销。当请求超出该上限时，该范围内的填充仍会被拒绝。
- `packet_timeout_secs` 默认为 300 秒并测量不活动状态，而不是 POST 的总生命周期。在服务器上，每个 POST 的正文必须不断接收非空字节。当内部流消耗上传字节或丢失的下一个数据包的原始接收者接收字节时，准入等待保持活动状态。重复的正文、空数据包、下载流量和资源唤醒不计为进度。在客户端，计时器仅涵盖主体传输：H2/H3 传输接受，或切换到 Hyper 的有界 H1 写入缓冲区。发送正文后，ACK 没有数据包或响应标头截止时间。 HTTP 200 确认接受服务器的有界数据包队列（如 Xray 中），而不是传送到目的地。排队的字节保留其预算许可，直到被消耗。承载层就绪和请求标头保留 `response_header_timeout_secs`；其他请求类型也保留它作为响应标头。 `setup_timeout_secs` 不变。从不确认的实时对等点可以保留有限的客户端资源，直到流被丢弃或传输失败。
- XHTTP 客户端和服务器准入上限是可选的：`limits.max_sessions`、`max_pending_sessions`、`max_requests`、`max_requests_per_session`、`max_buffered_bytes` 和 `max_session_buffered_bytes` 默认为无限制。省略或 `null` 上限是无限的，但设置聚合字节或请求上限还可以在省略相应会话上限或 `null`：`min(max_buffered_bytes, 4194304)`字节或 128 个请求时提供每个会话的保护。当较低时，总上限仍然适用。这保留了有序数据包的净空并限制了一个会话的准入服务员。显式会话上限会覆盖这些回退。值必须为正（`max_requests_per_session` 必须至少为 2）。 `limits.max_requests_per_connection` 默认为 250。显式全局限制仍然适用。数据包大小、重新排序窗口、超时和传输流控制窗口仍然受到限制。如果没有准入或字节上限，过载会消耗更多内存；当需要资源隔离时配置显式上限。
- H2/H3 分组遵循 Xray 的定速、写门控管道：下一个 POST 可能会在前一个正文传输后开始，而无需等待其 ACK。客户端 `packet_pipeline_depth` 默认为 30（最小 1），与参考节点的默认重新排序深度匹配。该窗口仅通过连续的 ACK 前进，因此后面的 ACK 无法在停滞的对等方处积累无限的序列间隙。较大的深度需要相应较大的对等重新排序队列。显式服务器请求限制必须适应有效的客户端 POST 深度加上服务器 `limits.max_requests_per_session` 中的一个预留头槽（默认 H2/H3 客户端深度为 31）。使用较小的服务器上限时降低客户端深度； shoes 不会重放拒绝的 POST。池、字节和客户端请求限制可能会减少有效深度。每个 H2/H3 打包会话最多可容纳有效 POST 深度加上共享池中的 1 个下载槽（默认深度为 31 个槽）。延迟的 ACK 保留这些时隙；几个停滞或高延迟的会话可能会填满池并拒绝新的会话，包括前往健康目的地的会话。有效客户端 `limits.max_requests_per_session` 是一个额外的上限：一个插槽用于下载部分。 `limits.max_requests` 配置后，会跨客户端实例限制未完成的 POST。到达任一客户端绑定都会给本地写入器带来背压。池限制可能会进一步限制并发性。 H1 在可重用的上传连接以及下载连接上保留一个 ACK​​ 门控 POST；它不会打开机会性上传连接或使用原始 HTTP/1 管道。使用 H2/H3 实现高延迟数据包吞吐量。未发送的字节仍受任何配置的字节预算的影响；在等待 ACK 时，不会保留成功传输的正文。当配置或派生会话字节上限时，未完成的 POST 有效负载大小也会计入单独的逻辑信用限制，从而限制对等端积压，而不保留发送的分配或消耗下载的内存限额。微小写入会合并为最多 16 KiB 的分配，同时传输现有字节许可，避免每次写入元数据和小数据帧放大，而不会限制数据报大小的写入。在服务器上，有效的 `limits.max_requests_per_session` 绑定跨承载层的实时数据包请求，包括空体、重复项和准入等待者。为丢失的头数据包保留一个时隙。显式 `limits.max_requests` 还绑定了服务中所有活动的 HTTP 请求处理程序，包括等待者和流请求，并且对于分割服务器模式必须至少为 2。身体泵仅在数据包字节/重新排序接纳后启动；等待数据包不会每个都占用额外的四槽应用程序管道。 H2 使用 `REFUSED_STREAM` 拒绝从未承认的多余 POST，从而保留现有会话。固定的 Xray 传输可以通过有限的退避重放这些请求； HTTP 503 无法提供该恢复。拒绝不是无限拖延保证或通用重试机制：shoes不重播提交的POST，Mihomo不提供Xray的可重播主体。 H1/H3 每会话溢出仍会终止会话。硬限制和不活动到期仍然是后盾，而不是任意过载下无损操作的承诺。附加会话等待超出默认 30 个数据包重新排序窗口的较晚前置会话，具体取决于数据包不活动状态以及任何配置或派生的请求上限。未连接的会话仍然拒绝窗口外的数据包。为所需的带宽延迟乘积和数据包队列预算 `max_session_buffered_bytes`，而不是固定的 POST 并发乘数。服务器下载管道具有相同大小的独立容差，因此完整的数据包队列无法在本地阻止先写后读握手。所有管道仍然共享全局字节预算。较小的预算仍然有效，但并行机构可以在前任机构完成之前耗尽共享交通信贷。字节上限不提供每个会话的传输隔离：停滞的消费者或全局字节预算耗尽也可能阻止同一承载层上的其他会话。服务器数据包不活动超时仍然会导致等待停止。进展缓慢的会话可以无限期地保留全局字节预算容量和共享承载层流量控制信用，因此其他会话可能会超时。
- H2 接收窗口默认为每个流 4 MiB，通过 `limits.h2_stream_window_bytes` 和 `limits.h2_connection_window_bytes` 每个连接 8 MiB。流窗口受有效（配置或派生）会话字节限制和任何配置的全局字节限制的限制。连接窗口受到显式全局字节限制的限制，HTTP/2 的强制最小值为 65535 字节。增加更高带宽延迟产品的窗口和有效字节限制。设置全局字节上限时，4 MiB 以上的流窗口还需要 4 MiB 以上的显式 `limits.max_session_buffered_bytes`。传输缓冲区是应用程序占用字节的附加内容：窗口限制适用于每个承载层，而不是总 RSS。暴露的服务器也需要连接限制。
- 服务器将初始 TCP HTTP 标头/前言限制为传输设置后的四秒（或更短的配置设置超时）。 H1 保持活动空闲期和后续部分标头没有截止时间。对于暴露的监听器，设置 `global_settings.max_connections` 和 `global_settings.max_connections_per_ip`。
- 当 Go GC 丢弃具有未读响应的池连接时，Xray 的 H1 packet-up 上传程序（在 26.10.10 版本中观察到）可能会丢失管道请求。因此，尽管服务器背压有限，向慢速目标持续上传仍可能失败。对此类客户端，应优先使用 H2/H3 或流式模式；禁用 GC 不是生产环境中的修复方案。
- 不支持高级放置/填充混淆、自定义会话 ID、单独下载、完整 XMUX 策略以及 XHTTP 上的旧版 Vision。不支持的选项会被拒绝，而不是默默地忽略。不暗示公共 CDN 兼容性。
- REALITY XHTTP 通过 H2 与 Xray 26.10.29 双向互操作，包括所有三种模式和 `auto`。根据掩护目标，REALITY 优先使用 X25519MLKEM768，并以 X25519 作为后备。可选的 `mldsa65_seed` 和 `mldsa65_verify` 适用于外层 REALITY 配置，与 XHTTP 独立；参见 [REALITY 客户端配置](/zh-cn/protocols/reality/)。
