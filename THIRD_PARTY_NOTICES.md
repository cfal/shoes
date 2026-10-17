# Dependency Notices

`licenses/dependencies.txt` reproduces the license texts and attributions for
Shoes' production and build dependencies, including transitive dependencies
across all target platforms. A given binary may link only a subset of them.
The release tarballs, Android AAR (`classes.jar/META-INF/shoes`) and iOS
XCFramework include this bundle and the additional GotaTun notices below.

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
