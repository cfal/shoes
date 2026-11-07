---
title: "安装"
description: "安装 shoes，并确认文档与配置所对应的版本。"
---

## 发行版二进制文件

从 [GitHub Releases](https://github.com/cfal/shoes/releases) 下载适合操作系统和架构的压缩包。解压后将 `shoes` 可执行文件放入 `PATH`。请阅读对应版本的说明，确认支持的平台、校验和与安装要求。

```sh
shoes --version
```

本站页眉显示文档对应的源代码版本。开发版文档可能包含最新发行版尚未提供的功能。使用旧版本时，请查阅其 Git 标签中的文档，不要假定本站的所有字段都受该版本支持。

## 从源代码构建

当前源代码需要 Rust 1.99.1 或更高版本。切换到要运行的修订版本，并使用仓库提交的依赖锁文件构建：

```sh
git clone https://github.com/cfal/shoes.git
cd shoes
# Select the release tag or source commit you intend to run before building.
cargo build --release --locked
./target/release/shoes --version
```

在内存受限的机器上设置 `CARGO_BUILD_JOBS=1`。生成的二进制文件位于 `target/release/shoes`。Unix 平台上的 WireGuard 构建包含受 MPL-2.0 许可约束的 GotaTun 代码；分发者必须保留仓库中的依赖声明和相应的源代码信息。

将构建好的可执行文件放入 `PATH`。如果从仓库根目录运行，也可以在后续指南中使用 `./target/release/shoes` 代替 `shoes`。

### 构建元数据

即使使用 `--release` 或从发行版标签构建，本地构建仍包含提交哈希。官方发布流程显式设置
`SHOES_RELEASE_TAG`，其值为 `v` 加上软件包版本。标签不匹配或已知工作区存在修改时，
构建会失败。此标记只是构建标签，并非产物来源的证明。

没有 Git 元数据的构建（包括 Docker 构建上下文和源代码归档）可以通过
`SHOES_BUILD_REVISION` 提供 12-64 位十六进制 Git 修订哈希，并可附加 `.dirty`。
若 Git 和显式修订信息均不可用，非发行版构建将显示 `+unknown`。这两个输入都是构建时
环境变量，仓库的 `Cross.toml` 也会转发它们；运行 Shoes 时设置它们不会产生影响。
Docker 构建通过同名的 `--build-arg` 参数接收这些值。

在已有源代码目录中添加或删除 Git 元数据，或不通过 Git 恢复已删除的跟踪文件后，
请先运行 `cargo clean -p shoes` 再重新构建。
如果二进制文件构建时存在已跟踪文件的修改，本地冒烟检查所指定的修订信息必须包含
`.dirty`；不指定修订信息时，检查允许本地开发构建的两种形式。

继续阅读[首次配置](/zh-cn/start/first-config/)。
