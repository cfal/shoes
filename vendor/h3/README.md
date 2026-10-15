# h3

An async HTTP/3 implementation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/hyperium/h3/workflows/CI/badge.svg)](https://github.com/hyperium/h3/actions?query=workflow%3ACI)
[![Discord chat](https://img.shields.io/discord/500028886025895936.svg?logo=discord)](https://discord.gg/q5mVhMD)

This crate provides an [HTTP/3][spec] implementation that is generic over a provided QUIC transport. This allows the project to focus on just HTTP/3, while letting users pick their QUIC implementation based on their specific needs. It includes client and server APIs. Check the original [design][] for more details.

[spec]: https://www.rfc-editor.org/rfc/rfc9114
[design]: docs/PROPOSAL.md

## Status

The `h3` crate is still very experimental. While the client and servers do work, there may still be bugs. And the API could change as we continue to explore. That said, we eagerly welcome contributions, trying it out in test environments, and using at your own risk.

The eventual goal is to use `h3` as an internal dependency of [hyper][].

[hyper]: https://hyper.rs

### Duvet
This create uses the [duvet crate][] to check compliance of the [spec][].  
The generated [report][] displays the current status of the requirements of the spec.  

Get more information about this tool in the [contributing][] document.

[duvet crate]: https://crates.io/crates/duvet
[spec]: https://www.rfc-editor.org/rfc/rfc9114
[report]: https://hyper.rs/h3/ci/compliance/report.html#/
[contributing]: CONTRIBUTING.md

## Features

* HTTP/3 client and server implementation
* Async only API
* QUIC transport abstraction via traits in the [`quic`](./h3/src/quic.rs) module
* Runtime independent (h3 does not spawn tasks and works with any runtime)
* Supported QUIC implementations to date are
  [Quinn](https://github.com/quinn-rs/quinn) ([h3-quinn](./h3-quinn/))
  , [s2n-quic](https://github.com/aws/s2n-quic)
  ([s2n-quic-h3](https://github.com/aws/s2n-quic/tree/main/quic/s2n-quic-h3))
  and [MsQuic](https://github.com/microsoft/msquic)
  ([h3-msquic-async](https://github.com/masa-koz/msquic-async-rs/tree/main/h3-msquic-async))

## Overview

* **h3** HTTP/3 implementation
* **h3-quinn** QUIC transport implementation based on [Quinn](https://github.com/quinn-rs/quinn/)

## Getting Started

The [examples](./examples) directory can help get started in two ways:

- There are ready-to-use `client` and `server` binaries to interact with _other_ HTTP/3 peers. Check the README in that directory.
- The source code of those examples can help teach how to use `h3` as either a client or a server.

### Server

You can find a full server example in [`examples/server.rs`](./examples/server.rs)

### Client

You can find a full client example in [`examples/client.rs`](./examples/client.rs)

## QUIC Generic

As mentioned, the goal of this library is to be generic over a QUIC implementation. To that effect, integrations with QUIC libraries exist:

- [`h3-quinn`](./h3-quinn/): in this same repository.
- [`s2n-quic-h3`](https://github.com/aws/s2n-quic/tree/main/quic/s2n-quic-h3)
- [`h3-msquic-async`](https://github.com/masa-koz/msquic-async-rs/tree/main/h3-msquic-async)

## Interoperability

This crate as well as the quic implementations are tested ([quinn](https://github.com/quinn-rs/quinn-interop), [s2n-quic](https://github.com/aws/s2n-quic/tree/main/scripts/interop), [MsQuic](https://github.com/microsoft/msquic/tree/main/src/tools/interop)) for interoperability and performance in the [quic-interop-runner](https://github.com/marten-seemann/quic-interop-runner).
You can see the results at (https://interop.seemann.io/).

## License

h3 is provided under the MIT license. See [LICENSE](LICENSE).
