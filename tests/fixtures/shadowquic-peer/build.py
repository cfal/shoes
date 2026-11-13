#!/usr/bin/env python3
"""Build an external reference peer without adding local paths to Shoes' manifest."""
import json
import pathlib
import subprocess
import sys
import tempfile

reference = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[2]).resolve()
with tempfile.TemporaryDirectory(prefix="shoes-shadowquic-peer-") as temporary:
    root = pathlib.Path(temporary)
    (root / "src").mkdir()
    (root / "src/main.rs").write_text(pathlib.Path(__file__).with_name("main.rs").read_text())
    (root / "Cargo.toml").write_text(
        '[package]\nname = "shoes-shadowquic-reference-peer"\nversion = "0.0.0"\nedition = "2024"\n'
        '[dependencies]\nshadowquic = { path = ' + json.dumps(str(reference / "shadowquic")) +
        ', default-features = false, features = ["shadowquic-quinn", "aws-lc-rs"] }\n'
        'tokio = { version = "1", features = ["full"] }\n'
    )
    subprocess.run(["cargo", "build", "--manifest-path", str(root / "Cargo.toml"), "--target-dir", str(output)], check=True)
print(output / "debug/shoes-shadowquic-reference-peer")
