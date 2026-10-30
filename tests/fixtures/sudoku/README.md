# Sudoku Wire Fixtures

`go_rng.json` records Go 1.27.3 legacy `math/rand` output and complete
288-element permutations. Generate with:

```sh
GOMAXPROCS=1 go run -p 1 tests/fixtures/sudoku/go_rng.go
```

`xray.json` records bytes emitted through Xray's exported classic/packed
connection APIs, with separate writes of 1, 2, 3, 13, 14 and 256 bytes. Samples
cover entropy, ASCII, custom layout rotation, mixed entropy/custom rotation,
passwords including whitespace, zero/100% padding and a 5-15% range.

Reference: XTLS/Xray-core `0afec66085a85191e9dd2a4a6646c7c9a94688d1`,
v26.10.29, which was used to capture these samples. Its Sudoku source tree is
byte-identical to the previously pinned `1b1647cd`, v26.10.21.
From that Xray checkout:

```sh
GOMAXPROCS=1 go run -p 1 /path/to/shoes/tests/fixtures/sudoku/xray.go
```

Runtime random choices intentionally vary. These fixtures pin decoding, not
the encoder's random sequence. They contain generated wire observations, not
implementation tables or source from Xray.

For the reverse check, export Rust samples and pass them to the same reference:

```sh
SUDOKU_RUST_VECTORS="$HOME/tmp/sudoku-rust.json" CARGO_BUILD_JOBS=1 \
  cargo test --locked --lib export_rust_wire_samples -- --ignored
# In the Xray checkout:
GOMAXPROCS=1 go run -p 1 /path/to/shoes/tests/fixtures/sudoku/xray.go \
  -verify "$HOME/tmp/sudoku-rust.json"
```

Go's cooked seeding constants are the only embedded upstream implementation
data; their BSD-3-Clause attribution is in `THIRD_PARTY_NOTICES.md`.
