#!/usr/bin/env python3
"""Checks a packaged CLI, optionally through a cross-target runner."""

import argparse
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def smoke(command):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    result = subprocess.check_output([*command, "--version"], cwd=ROOT, timeout=60)
    if result.strip() != f"shoes {version}".encode():
        raise ValueError(f"Unexpected binary version: {result!r}")
    subprocess.run(
        [*command, "check", "--threads", "1", "examples/socks_basic.yaml"],
        cwd=ROOT, check=True, timeout=60,
    )
    # Key generation exercises the target's native crypto implementation, not just CLI parsing.
    subprocess.run(
        [*command, "generate-reality-keypair"],
        cwd=ROOT, check=True, timeout=60, stdout=subprocess.DEVNULL,
    )
    print("Packaged binary smoke passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="binary command, including any runner")
    args = parser.parse_args()
    if not args.command:
        parser.error("a binary command is required")
    smoke(args.command)
