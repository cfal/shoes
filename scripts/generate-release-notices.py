#!/usr/bin/env python3
"""Generates dependency notices without accepting cargo-about's warning fallbacks."""

import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def generate(output):
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        candidate = Path(tmp) / "dependencies.txt"
        result = subprocess.run([
            "cargo", "about", "-L", "warn", "generate", "--locked", "--all-features",
            "--fail", "scripts/licenses.hbs", "-o", str(candidate),
        ], cwd=ROOT, stderr=subprocess.PIPE, text=True)
        # Failed clarifications warn and fall back even with --fail.
        if result.returncode or result.stderr:
            raise RuntimeError(
                result.stderr or f"cargo-about exited with status {result.returncode}"
            )
        candidate.replace(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=ROOT / "licenses/dependencies.txt")
    args = parser.parse_args()
    try:
        generate(args.output.resolve())
    except (OSError, RuntimeError) as error:
        parser.exit(1, f"{error}\n")
