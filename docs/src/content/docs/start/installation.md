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

### Build metadata

Local builds include their commit hash even when built with `--release` or from
a release tag. Official release workflows explicitly set `SHOES_RELEASE_TAG` to
`v` followed by the package version; mismatches and known dirty checkouts fail
the build. This is a build label, not proof of artifact provenance.

Git-less builds, including Docker build contexts and source archives, can supply
`SHOES_BUILD_REVISION` as a 12-64 digit hexadecimal Git revision, optionally
followed by `.dirty`. Without Git or an explicit revision, non-release builds
show `+unknown`. Both inputs are build-time environment variables, also forwarded
by the repository's `Cross.toml`; setting them when running Shoes has no effect.
Docker builds accept the same names as `--build-arg` values.

After adding or removing Git metadata from an existing source tree, or restoring
a deleted tracked file without Git, run `cargo clean -p shoes` before rebuilding.
Local smoke checks require any explicit
revision to include `.dirty` when the binary was built from tracked changes;
omit the revision input to accept either local development form.

Continue with [your first configuration](/start/first-config/).
