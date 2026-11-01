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

继续阅读[首次配置](/zh-cn/start/first-config/)。
