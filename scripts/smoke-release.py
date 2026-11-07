#!/usr/bin/env python3
"""Checks a packaged CLI, optionally through a cross-target runner."""

import argparse
from pathlib import Path
import subprocess

from build_version import check_version

ROOT = Path(__file__).resolve().parents[1]


def smoke(command):
    check_version(command)
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
