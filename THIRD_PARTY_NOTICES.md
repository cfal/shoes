# WireGuard Dependency Notices

Unix builds, including Android and iOS libraries, link GotaTun 0.10.1, an
implementation of the WireGuard protocol. GotaTun is copyright Mullvad VPN AB
and incorporates work copyright Cloudflare, Inc. Its source files are covered
by the Mozilla Public License 2.0 and the notices reproduced in
`licenses/MPL-2.0.txt` and `licenses/gotatun-CLOUDFLARE.txt`.

The unmodified corresponding source is available at:

- https://crates.io/api/v1/crates/gotatun/0.10.1/download
- https://github.com/mullvad/gotatun/tree/v0.10.1

Recipients may obtain, modify, and redistribute the covered source under the
MPL 2.0. Shoes does not modify GotaTun's source. Shoes' own source remains under
its existing MIT license. Distributors of modified GotaTun builds must also
provide the corresponding modified covered source and retain these notices.
Embedding a Shoes static or dynamic library does not remove these obligations.

This notice supplements, rather than replaces, the licenses and notices of
other dependencies recorded in Cargo.lock and their source distributions.
