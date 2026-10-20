# Dependency Notices

`licenses/dependencies.txt` reproduces the license texts and attributions for
Shoes' production and build dependencies, including transitive dependencies
across all target platforms. A given binary may link only a subset of them.
The release tarballs, Android AAR (`classes.jar/META-INF/shoes`) and iOS
XCFramework include this bundle and the additional GotaTun and anytls-rs
notices below.

Regenerate the bundle after changing Cargo.lock, using cargo-about 0.9.2:

```sh
cargo install --locked cargo-about@0.9.2
python3 scripts/generate-release-notices.py
cargo fetch --locked
python3 scripts/test-release-notices.py
```

Generation requires network access for the checksummed upstream blake2b_simd
license clarification. The generator rejects warnings, including failed
clarifications, without replacing the existing bundle.

`about.toml` records the license choices and verified clarifications. CI checks
that regeneration is clean and that every production/build dependency appears.
`scripts/check-release-notices.py <artifact>` checks the exact notice bytes in
a release tarball, AAR, or XCFramework directory; release scripts invoke it
before distributing artifacts. Do not remove the bundle when redistributing.

## WireGuard Source

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

These source-availability details supplement the reproduced dependency licenses.

## AnyTLS Source

Portions of the AnyTLS implementation in `src/anytls/`, including the padding
scheme, frame definitions, settings map and stream tests, are derived from
anytls-rs (https://github.com/jxo-me/anytls-rs), which is distributed under the
following license:

```text
MIT License

Copyright (c) 2024 Mickey and AnyTLS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
