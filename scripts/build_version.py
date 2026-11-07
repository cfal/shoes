"""Checks the public version contract for packaged binaries."""

import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def check_version(command):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    release_tag = os.environ.get("SHOES_RELEASE_TAG", "")
    revision = os.environ.get("SHOES_BUILD_REVISION", "")
    expected = re.escape(f"shoes {version}")
    if release_tag:
        if release_tag != f"v{version}":
            raise ValueError("Release tag does not match package version")
    elif revision:
        if not re.fullmatch(r"[0-9a-fA-F]{12,64}(?:\.dirty)?", revision):
            raise ValueError("Invalid SHOES_BUILD_REVISION")
        suffix = f"+g{revision[:12].lower()}"
        if revision.endswith(".dirty"):
            suffix += ".dirty"
        expected += re.escape(suffix)
    else:
        expected += r"\+(?:g[0-9a-f]{12}(?:\.dirty)?|unknown)"

    short = subprocess.check_output([*command, "-V"], cwd=ROOT, timeout=60).decode()
    if not re.fullmatch(expected + r"\n", short):
        raise ValueError(f"Unexpected binary version: {short!r}")
    long = subprocess.check_output([*command, "--version"], cwd=ROOT, timeout=60).decode()
    target = re.escape(os.environ["TARGET"]) if os.environ.get("TARGET") else r"\S+"
    if not re.fullmatch(re.escape(short) + rf"target: {target}\ncompiler: rustc [^\r\n]+\n", long):
        raise ValueError(f"Unexpected build metadata: {long!r}")
    alias = subprocess.check_output([*command, "version"], cwd=ROOT, timeout=60).decode()
    if alias != long:
        raise ValueError("version and --version disagree")
