# Repository Guidelines

## Project Structure & Module Organization

`shoes` is a Rust 2024 multi-protocol proxy. Source lives in `src/`; protocol modules implement transport adapters while `src/routing/`, `src/tcp/`, and `src/resolver/` provide shared forwarding services. Configuration types, validation, and lowering live in `src/config/`. Integration cases and fixtures live in `tests/`, with shared helpers in `tests/support/`. Examples belong in `examples/`; user documentation is under `docs/`.

## Build, Test, and Development Commands

Use the Rust version required by `Cargo.toml` (currently 1.99.1).

- `cargo build --locked`: compile the library and executable.
- `cargo run --locked -- --help`: inspect CLI options before starting a local configuration.
- `cargo test --workspace --locked --lib --bins`: run the default unit suites.
- `cargo test --locked --features integration-tests --test integration`: run integration scenarios.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: run the CI lint checks.

Set `CARGO_BUILD_JOBS=1` on memory-constrained hosts. See `tests/README.md` for suites requiring external peers or privileges.

## Coding Style & Naming Conventions

Use rustfmt, four-space indentation, `snake_case` functions/modules, and `PascalCase` types. Reuse shared ingress, routing, resource budgets, and listener lifecycle management when adding protocols. Keep secrets out of errors and logs. Validate unsupported configuration combinations before opening listeners.

## Testing Guidelines

Use `#[test]` and `#[tokio::test]`; name tests after observable behavior. Cover malformed inputs, authentication, cancellation, and wire compatibility for protocol changes. Cargo disables automatic test discovery: register new integration targets in `Cargo.toml` and case modules in their suite entry point. Verify filtered test runs execute a nonzero number of tests. No numeric coverage threshold is specified.

## Commit & Pull Request Guidelines

Recent history includes merge commits and short fix subjects; no strict commit format is evident. Prefer concise, imperative subjects identifying the affected component. PRs should describe resulting behavior, linked issues, configuration changes, and exact validation commands. Include interoperability evidence when changing wire formats, and screenshots for visible interface changes.
