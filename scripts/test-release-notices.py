#!/usr/bin/env python3
"""Exercises dependency-notice generation and release tarball verification."""

import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "notices", Path(__file__).with_name("check-release-notices.py")
)
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)

GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "generate_notices", Path(__file__).with_name("generate-release-notices.py")
)
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
GENERATOR_SPEC.loader.exec_module(GENERATOR)

# SPDX's ISC fallback names its publisher rather than the dependency's authors.
PLACEHOLDER_ATTRIBUTION = re.compile(
    r"<(?:year|copyright holders?|owner)>|YEAR by AUTHOR EMAIL"
    r"|Copyright \(c\) 2004-2010 by Internet Systems Consortium, Inc\.",
    re.IGNORECASE,
)


class ReleaseNoticesTests(unittest.TestCase):
    def test_generation_preserves_bundle_on_warning_or_failure(self):
        for status, stderr in [(0, ""), (0, "WARN checksum mismatch"), (1, ""), (1, "failed")]:
            with self.subTest(status=status, stderr=stderr), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "dependencies.txt"
                output.write_text("original")

                def run(command, **kwargs):
                    Path(command[-1]).write_text("generated")
                    return subprocess.CompletedProcess(command, status, stderr=stderr)

                with mock.patch.object(GENERATOR.subprocess, "run", side_effect=run):
                    if status or stderr:
                        with self.assertRaises(RuntimeError):
                            GENERATOR.generate(output)
                        self.assertEqual(output.read_text(), "original")
                    else:
                        GENERATOR.generate(output)
                        self.assertEqual(output.read_text(), "generated")

    def test_bundle_has_no_placeholder_attributions(self):
        bundle = (NOTICES.ROOT / "licenses/dependencies.txt").read_text()
        for block in bundle.split("\nLicense: ")[1:]:
            heading = block.splitlines()[0]
            if heading.endswith(("(MIT)", "(BSD-2-Clause)", "(BSD-3-Clause)", "(ISC)", "(0BSD)")):
                with self.subTest(license=heading):
                    text = block.partition("\n\n")[2]
                    self.assertNotRegex(text, PLACEHOLDER_ATTRIBUTION)

    def test_placeholder_detection_includes_spdx_isc_publisher(self):
        for text in [
            "Copyright (c) <year> <copyright holders>",
            "Copyright (c) <year> <owner>",
            "Copyright (C) YEAR by AUTHOR EMAIL",
            'Copyright (c) 2004-2010 by Internet Systems Consortium, Inc. ("ISC")\n'
            "Copyright (c) 1995-2003 by Internet Software Consortium",
        ]:
            with self.subTest(text=text):
                self.assertRegex(text, PLACEHOLDER_ATTRIBUTION)

    def test_bundle_covers_production_dependency_graph(self):
        cargo_options = [
            "--locked", "--offline", "--all-features",
            "--manifest-path", str(NOTICES.ROOT / "Cargo.toml"),
        ]
        # Cargo tree excludes features enabled only by dev dependencies, unlike metadata.
        tree = subprocess.check_output([
            "cargo", "tree", *cargo_options, "--target", "all",
            "--edges", "normal,build", "--prefix", "none", "--format", "{p}",
        ], text=True)
        production = {tuple(line.split()[:2]) for line in tree.splitlines()}
        metadata = json.loads(subprocess.check_output([
            "cargo", "metadata", *cargo_options, "--format-version", "1",
        ]))
        gotatun_versions = [p["version"] for p in metadata["packages"] if p["name"] == "gotatun"]
        self.assertEqual(len(gotatun_versions), 1)
        version = gotatun_versions[0]
        source_notice = (NOTICES.ROOT / "THIRD_PARTY_NOTICES.md").read_text()
        for required in [
            f"GotaTun {version},",
            f"https://crates.io/api/v1/crates/gotatun/{version}/download",
            f"https://github.com/mullvad/gotatun/tree/v{version}",
        ]:
            self.assertIn(required, source_notice)
        bundle = (NOTICES.ROOT / "licenses/dependencies.txt").read_text()
        original_notices = {
            "curve25519-dalek": ["LICENSE"], "x25519-dalek": ["LICENSE"],
            "ip_network": ["LICENSE"], "ip_network_table": ["LICENSE"],
            "aws-lc-sys": ["LICENSE"], "aws-lc-rs": ["LICENSE"],
            "tikv-jemalloc-sys": ["jemalloc/COPYING"], "moka": ["NOTICE"],
            "ring": [
                "LICENSE-BoringSSL", "LICENSE-other-bits",
                "src/polyfill/once_cell/LICENSE-MIT", "third_party/fiat/LICENSE",
            ],
            "h3": ["../LICENSE"], "h3-quinn": ["../LICENSE"],
            "netlink-packet-core": ["LICENSE-MIT"], "netlink-proto": ["LICENSE-MIT"],
            "netlink-sys": ["LICENSE-MIT"], "rtnetlink": ["LICENSE-MIT"],
        }
        for package in metadata["packages"]:
            if (package["name"], "v" + package["version"]) not in production:
                continue
            if package["source"] is not None:
                entry = f"Package: {package['name']} {package['version']}\n"
                self.assertTrue(entry in bundle, f"Missing {entry.strip()}")
            for notice in original_notices.get(package["name"], []):
                source_license = Path(package["manifest_path"]).parent / notice
                self.assertTrue(
                    source_license.read_text().strip() in bundle,
                    f"Missing original {notice} for {package['name']}",
                )

    def test_artifacts_reject_missing_and_modified_notices(self):
        expected = NOTICES.expected_notices()
        for kind, mode in [("tar", "w"), ("tar.gz", "w:gz")]:
            for mutation in [None, "missing", "modified"]:
                with self.subTest(kind=kind, mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                    entries = expected.copy()
                    name = "licenses/dependencies.txt"
                    if mutation == "missing":
                        del entries[name]
                    elif mutation == "modified":
                        entries[name] = b"incomplete notice"
                    artifact = Path(tmp) / ("release." + kind)
                    with tarfile.open(artifact, mode) as archive:
                        for name, contents in entries.items():
                            info = tarfile.TarInfo(name)
                            info.size = len(contents)
                            archive.addfile(info, io.BytesIO(contents))
                    if mutation is None:
                        NOTICES.check(artifact)
                    else:
                        with self.assertRaises((KeyError, ValueError)):
                            NOTICES.check(artifact)


if __name__ == "__main__":
    unittest.main()
