---
title: "命令行"
description: "shoes 命令行配置。"
---

```bash
shoes [OPTIONS] <config.yaml> [config.yaml...]

OPTIONS:
  -t, --threads NUM    Worker threads (default: CPU count)
  -l, --log-file PATH  Log to a file; repeatable ("-" means stderr)
  -d, --dry-run        Validate config and certificates without starting listeners
  --no-reload          Disable automatic reloads on file changes
  -V, --version        Print version information

COMMANDS:
  check <config.yaml>                            Alias for --dry-run
  version                                        Alias for --version
  cleanup-tun                                    Recover managed-TUN state (Linux only)
  generate-reality-keypair                       Generate Reality X25519 keypair
  generate-reality-mldsa65-keypair                Generate optional Reality ML-DSA-65 keys
  generate-shadowsocks-2022-password <cipher>    Generate Shadowsocks 2022 password
  generate-vless-user-id                         Generate a VLESS/VMess UUID v4
  generate-vless-encryption [options]            Generate matched VLESS encryption credentials
```

`generate-vless-encryption` 接受重复的 `--auth x25519|mlkem768`、`--mode native|xorpub|random`、`--rtt 0rtt|1rtt` 和 `--lifetime 600s|N-Ms|0s`。请参阅[VLESS 加密](/zh-cn/protocols/vless-encryption/)。即使使用 `--no-reload`，SIGHUP 也会重新加载配置； SIGINT/SIGTERM 停止监听器，无需等待 TCP 重新加载耗尽。

`check` 和 `--dry-run` 退出，状态 0 表示配置有效，状态 1 表示错误。它们不打开监听器、创建文件观察器或执行 DNS 引导程序网络。成功检查后，仍然可能出现运行时故障，例如不可用的绑定地址。

### 配置诊断

检查启动时将使用的同一组文件：

```bash
shoes check groups.yaml listeners.yaml
```

配置解码失败可识别输入文件和条目的从零开始的 `config[N]` 索引。规则组解码还识别 `rules[N]`（或单个对象的 `rules`）。例如，第三个条目的第二个规则源中不支持的字段报告 `config[2]`、`rules[1]` 和未知字段。 YAML 语法和重复键错误保留解析器的原始诊断和行/列信息（如果可用），而不是添加条目前缀。对于 `config[N]` 解码错误，尾随行/列（如果有）标记文件顶级列表的开始，而不是条目 N 或失败字段；使用该上下文的 `config[N]` 和 `rules[N]` 路径。

证书加载和语义验证期间的错误命名输入文件集，而不是推断的单一罪魁祸首：组引用可以跨文件。检查使用本机验证路径，包括图形和传输组合检查。命名的 PEM 条目仅接受 `pem` 并且恰好是 `path` 或 `data` 之一；未知字段会被拒绝而不是被忽略。 TCP 设置同样拒绝未知字段；他们唯一的当前字段是 `no_delay` （默认 `true`）。

诊断不包括完整的 YAML 摘录。它们不是经过编辑的配置导出：用户定义的名称、路径和一些无效值可能会出现在错误中。在共享诊断之前先查看诊断结果。不提供标准化配置输出。

离线回归覆盖对 `src/config/tests.rs` 中列出的精选示例子集运行本机准备检查。其他示例可能需要特定于部署的证书、密钥、文件或平台支持；单独解析示例并不能建立运行时有效性。

编辑器模式生成不属于本参考的一部分。本机解析器和验证器对于接受的配置仍然具有权威性。
