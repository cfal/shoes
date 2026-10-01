# Alpine x86_64 shoes REALITY 自动安装

依据官方 [README 的 Reality Server 示例](https://github.com/cfal/shoes#reality-server) 和发布包格式制作。默认安装到 `/root/shoes`，监听 TCP 443。

将 [install-shoes-reality.sh](../scripts/install-shoes-reality.sh) 下载或上传到 VPS，以 root 执行：

```sh
sh install-shoes-reality.sh
```

脚本自动完成：

1. 执行 `mkdir -p /root/shoes` 并进入该目录；缺少工具时使用 `apk add --no-cache` 安装依赖。
2. 下载官方 v0.2.7 的 `shoes-x86_64-unknown-linux-musl.tar.gz`，核对 GitHub 发布资产的 SHA-256，解压并执行 `chmod +x shoes`。已有 `shoes` 时沿用该文件。
3. 通过 `/proc/sys/kernel/random/uuid` 生成 UUID，通过 `shoes generate-reality-keypair` 生成密钥对，并生成随机 short ID。
4. 优先检查 `www.microsoft.com`，然后检查 Bing、Cloudflare、Apple、Amazon、Yahoo、GitHub、Google。候选域名必须通过 IPv4 ping 和经过证书校验的 TLS 1.3 连接检查。
5. 自动将 UUID、私钥和选中的域名写入 `config.yaml`，并执行 `shoes --dry-run` 验证；无需打开 `vi`。
6. 使用 `setsid`、输入输出重定向将 shoes 放入后台。通过进程所属二进制、配置路径和该进程实际监听的端口确认启动；未就绪时最多重试三次。
7. 启动后重新 ping 域名，并通过本地 shoes 验证 TLS 转发。检查失败时仅停止本脚本管理的 shoes，换下一个域名并重新启动。
8. 显示 UUID、公钥、SNI、short ID 和端口。客户端使用 VLESS / TCP / REALITY，flow 留空，服务器地址填写 VPS 公网 IP。

这是一次安装和启动后的检查；服务在 VPS 重启后需要再次启动。服务运行期间可再次执行脚本重新检查目标域名，UUID 和密钥会保持不变。

查看状态、停止服务：

```sh
sh install-shoes-reality.sh status
sh install-shoes-reality.sh stop
```

自定义端口或候选域名：

```sh
SHOES_PORT=8443 sh install-shoes-reality.sh
SHOES_DOMAINS='www.microsoft.com www.cloudflare.com www.bing.com' sh install-shoes-reality.sh
```

默认文件：

| 文件 | 用途 |
| --- | --- |
| `/root/shoes/shoes` | 官方 musl 二进制 |
| `/root/shoes/shoes-x86_64-unknown-linux-musl.tar.gz` | 下载并校验的压缩包 |
| `/root/shoes/config.yaml` | 自动生成的 REALITY 配置 |
| `/root/shoes/shoes.log` | 后台日志 |
| `/root/shoes/.shoes-reality/identity` | UUID、密钥和 short ID，权限 600 |
| `/root/shoes/.shoes-reality/shoes.pid` | 本脚本启动进程的 PID |

配置和密钥文件使用权限 600；私钥不会在结果中显示。已有非本脚本管理的 `config.yaml` 时脚本会退出，以便保留原配置。端口被其他程序占用时会退出，不会结束其他程序。VPS 防火墙及提供商安全组需要允许客户端访问你选择的 TCP 端口。

部分热门站点会拒绝 ICMP；按要求，脚本会跳过 ping 不通的候选，即使其 HTTPS 可用。若全部失败，脚本返回失败及具体检查文件路径，而不会报告安装后可连接。

## 验证记录

官方发布包 v0.2.7 的 musl 资产已依据 GitHub 展示的 SHA-256 验证。测试在官方 Alpine 3.22.6 rootfs 构建的隔离容器中运行，使用真实 shoes 二进制和受控 TLS 1.3 服务；故障注入覆盖首次启动失败和启动后域名失效。

当前云代理拒绝 Alpine 软件源访问，因此测试中的 `apk` 安装阶段用预置工具替代；这不等同于已在你的 VPS 上运行 `apk`。实际热门域名的 ping、TLS 连接及 VPS 端口放行情况由脚本在 VPS 现场验证。

sing-box 客户端已使用脚本生成的 UUID、公钥及 short ID 完成真实 VLESS + REALITY 请求。就绪检查中的 OpenSSL 连接属于普通 TLS 探测，因此服务日志中可能出现 `Auth failed ... forwarding to dest`，表示按设计转发至伪装目标。
