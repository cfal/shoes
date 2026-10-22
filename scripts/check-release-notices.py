#!/usr/bin/env python3
"""Checks that release artifacts reproduce the repository's dependency notices."""

import argparse
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def expected_notices():
    names = (
        "THIRD_PARTY_NOTICES.md", "licenses/dependencies.txt",
        "licenses/MPL-2.0.txt", "licenses/gotatun-CLOUDFLARE.txt",
    )
    return {name: (ROOT / name).read_bytes() for name in names}


def check(artifact):
    expected = expected_notices()
    with tarfile.open(artifact) as archive:
        actual = {name: archive.extractfile(name).read() for name in expected}
    for name, contents in expected.items():
        if actual[name] != contents:
            raise ValueError(f"{artifact}: incorrect {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="release tarball")
    check(parser.parse_args().artifact)
