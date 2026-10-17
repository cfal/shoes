#!/usr/bin/env python3
"""Exercises notice verification without requiring mobile build toolchains."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location(
    "notices", Path(__file__).with_name("check-release-notices.py")
)
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)


class ReleaseNoticesTests(unittest.TestCase):
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
        bundle = (NOTICES.ROOT / "licenses/dependencies.txt").read_text()
        original_notices = {
            "curve25519-dalek": "LICENSE", "x25519-dalek": "LICENSE",
            "ip_network": "LICENSE", "ip_network_table": "LICENSE",
            "aws-lc-sys": "LICENSE", "aws-lc-rs": "LICENSE",
            "tikv-jemalloc-sys": "jemalloc/COPYING", "moka": "NOTICE",
        }
        for package in metadata["packages"]:
            if (package["name"], "v" + package["version"]) not in production:
                continue
            if package["source"] is not None:
                entry = f"Package: {package['name']} {package['version']}\n"
                self.assertTrue(entry in bundle, f"Missing {entry.strip()}")
            if package["name"] in original_notices:
                source_license = (
                    Path(package["manifest_path"]).parent / original_notices[package["name"]]
                )
                self.assertTrue(
                    source_license.read_text().strip() in bundle,
                    f"Missing original license for {package['name']}",
                )

    def test_artifacts_reject_missing_and_modified_notices(self):
        expected = NOTICES.expected_notices()
        for kind in ["tar", "aar", "xcframework"]:
            for mutation in [None, "missing", "modified"]:
                with self.subTest(kind=kind, mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                    entries = expected.copy()
                    name = "licenses/dependencies.txt"
                    if mutation == "missing":
                        del entries[name]
                    elif mutation == "modified":
                        entries[name] = b"incomplete notice"
                    artifact = Path(tmp) / ("release." + kind)
                    if kind == "tar":
                        with tarfile.open(artifact, "w") as archive:
                            for name, contents in entries.items():
                                info = tarfile.TarInfo(name)
                                info.size = len(contents)
                                archive.addfile(info, io.BytesIO(contents))
                    elif kind == "aar":
                        jar = io.BytesIO()
                        with zipfile.ZipFile(jar, "w") as classes:
                            for name, contents in entries.items():
                                classes.writestr("META-INF/shoes/" + name, contents)
                        with zipfile.ZipFile(artifact, "w") as aar:
                            aar.writestr("classes.jar", jar.getvalue())
                    else:
                        for name, contents in entries.items():
                            path = artifact / name
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(contents)
                    if mutation is None:
                        NOTICES.check(artifact)
                    else:
                        with self.assertRaises((KeyError, FileNotFoundError, ValueError)):
                            NOTICES.check(artifact)


if __name__ == "__main__":
    unittest.main()
