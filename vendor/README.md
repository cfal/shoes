# Vendored Dependencies

## h3 0.0.8

Source: the published [h3 0.0.8 crate](https://crates.io/crates/h3/0.0.8),
from upstream commit
[`22c1aa3f44d1463cd7644c8f654fffc9a6da305c`](https://github.com/hyperium/h3/tree/22c1aa3f44d1463cd7644c8f654fffc9a6da305c/h3).
The upstream MIT license is preserved in `h3/LICENSE`. Source files and package
manifests are unchanged except for the patch below. Registry metadata and the
crate's standalone lockfile are omitted.

Local patch: `RequestStream::poll_recv_data` in `h3/src/connection.rs` skips
zero-length DATA frames instead of returning `None` (body EOF). This is required
for XHTTP's idle cancellation probes, and also prevents truncation when a peer
sends valid empty DATA frames. The fix applies to both request and response
bodies. Cargo's workspace-level patch also covers transitive users of h3.

Regression coverage lives in Shoes' XHTTP tests; the upstream tests are preserved
but require h3's original workspace layout. Run:

```sh
CARGO_BUILD_JOBS=1 cargo test --locked --lib --features ffi h3_ -- --test-threads=1
```

Remove this patch and directory after upgrading to an upstream version that
passes the empty-DATA and idle-stream regressions. No fixed upstream version was
available when this patch was added. Only then remove the root package's
`publish = false` guard: Cargo strips `[patch.crates-io]` and nested packages when
publishing, so a registry installation would otherwise lose this fix.
