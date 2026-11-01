---
title: Installation
description: Install shoes and check which version your configuration targets.
---

## Release binaries

Download the archive for your operating system and architecture from
[GitHub Releases](https://github.com/cfal/shoes/releases). Extract it and put
the `shoes` executable on your `PATH`. Read that release's notes for supported
platforms, checksums, and installation requirements.

```sh
shoes --version
```

This site's header identifies the documented source revision.
Development documentation can describe features absent from the latest release.
For an older release, use the documentation included at its Git tag rather than
assuming every field on this site is supported.

## Build from source

The current source requires Rust 1.99.1 or newer. Build the revision you intend
to run, using its committed dependency lockfile:

```sh
git clone https://github.com/cfal/shoes.git
cd shoes
# Select the release tag or source commit you intend to run before building.
cargo build --release --locked
./target/release/shoes --version
```

Use `CARGO_BUILD_JOBS=1` on memory-constrained machines. The resulting binary
is `target/release/shoes`. Unix WireGuard builds include MPL-2.0-covered GotaTun
code; distributors must retain the repository's dependency notices and
corresponding source information.

Put the built executable on your `PATH`, or replace `shoes` in the following
guides with `./target/release/shoes` when running from the repository root.

Continue with [your first configuration](/start/first-config/).
