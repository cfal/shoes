#!/usr/bin/env python3
"""Exercises dependency-notice generation and release tarball verification."""

import importlib.util
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
from urllib.parse import urlsplit

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


class RustCopyrightParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.packages = set()

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            url = urlsplit(dict(attrs).get("href", ""))
            parts = url.path.strip("/").split("/")
            if url.netloc == "crates.io" and len(parts) == 3 and parts[0] == "crates":
                self.packages.add((parts[1], parts[2]))


class ReleaseNoticesTests(unittest.TestCase):
    def assert_supplement_license(self, supplement, identity, source, text):
        packages = dict(section.split("\n", 1) for section in re.split(r"(?m)^Package: ", supplement)[1:])
        name = " ".join(identity)
        self.assertIn(name, packages)
        sources = dict(section.split("\n", 1) for section in re.split(r"(?m)^Source: ", packages[name])[1:])
        self.assertIn(source, sources)
        self.assertEqual(text.strip(), sources[source].strip(), source)

    def test_duplicate_license_cannot_hide_missing_package_block(self):
        supplement = (
            "Package: first 1.0\n\nSource: vendor/first-1.0/LICENSE\n\nShared license\n\n"
            "Package: second 1.0\n\nSource: vendor/second-1.0/LICENSE\n\nShared license\n"
        )
        identity = ("second", "1.0")
        source = "vendor/second-1.0/LICENSE"
        self.assert_supplement_license(supplement, identity, source, "Shared license")
        missing = supplement.split(f"Source: {source}")[0]
        with self.assertRaises(AssertionError):
            self.assert_supplement_license(missing, identity, source, "Shared license")

    def test_sysroot_dependencies_have_matching_notices(self):
        version = tomllib.loads((NOTICES.ROOT / "Cargo.toml").read_text())["package"]["rust-version"]
        sysroot = Path(subprocess.check_output([
            "rustup", "run", version, "rustc", "--print", "sysroot",
        ], text=True).strip())
        library = sysroot / "lib/rustlib/src/rust/library"
        self.assertTrue(library.exists(), f"Install rust-src for Rust {version}")
        html = (NOTICES.ROOT / f"licenses/rust-{version}-COPYRIGHT-library.html").read_text()
        original = (sysroot / "share/doc/rust/COPYRIGHT-library.html").read_text()
        self.assertEqual(html.splitlines(), [line.rstrip(" \t") for line in original.splitlines()])
        parser = RustCopyrightParser()
        parser.feed(html)
        supplement = (NOTICES.ROOT / f"licenses/rust-{version}-sysroot-supplement.txt").read_text()
        packages = tomllib.loads((library / "Cargo.lock").read_text())["package"]
        for package in packages:
            identity = (package["name"], package["version"])
            if "source" not in package or identity in parser.packages:
                continue
            with self.subTest(package=identity):
                self.assertIn(f"Package: {identity[0]} {identity[1]}\n", supplement)
                vendor = library / "vendor" / "-".join(identity)
                notices = [path for path in vendor.iterdir() if path.is_file() and
                           any(word in path.name.upper() for word in ("LICENSE", "COPYING", "COPYRIGHT", "NOTICE"))]
                self.assertTrue(notices, f"No vendored license files for {identity}")
                for path in notices:
                    self.assert_supplement_license(
                        supplement, identity, str(path.relative_to(library)), path.read_text(),
                    )
        attribution = (library / "core/src/slice/memchr.rs").read_text().splitlines()[1]
        self.assertIn(attribution, supplement)
        builtins = (NOTICES.ROOT / f"licenses/rust-{version}-compiler-builtins.txt").read_text()
        for relative in ("LICENSE.txt", "libm/LICENSE.txt"):
            self.assertIn((library / "compiler-builtins" / relative).read_text().strip(), builtins)

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
        gotatun_packages = [p for p in metadata["packages"] if p["name"] == "gotatun"]
        self.assertEqual(len(gotatun_packages), 1)
        gotatun = gotatun_packages[0]
        source = urlsplit(gotatun["source"].removeprefix("git+"))
        self.assertEqual(source.scheme, "https")
        self.assertEqual(source.netloc, "github.com")
        self.assertEqual(source.path, "/mullvad/gotatun")
        self.assertRegex(source.fragment, r"^[0-9a-f]{40}$")
        source_notice = (NOTICES.ROOT / "THIRD_PARTY_NOTICES.md").read_text()
        for required in [
            f"GotaTun {gotatun['version']}",
            f"https://github.com/mullvad/gotatun/tree/{source.fragment}",
            f"https://github.com/mullvad/gotatun/archive/{source.fragment}.tar.gz",
        ]:
            self.assertIn(required, source_notice)
        for name in ["gotatun-crypto", "gotatun-packet"]:
            packages = [p for p in metadata["packages"] if p["name"] == name]
            self.assertEqual(len(packages), 1)
            self.assertEqual(packages[0]["source"], gotatun["source"])
        gotatun_root = Path(gotatun["manifest_path"]).parent.parent
        for original, bundled in [
            ("LICENSE", "MPL-2.0.txt"),
            ("LICENSE-CLOUDFLARE", "gotatun-CLOUDFLARE.txt"),
        ]:
            self.assertEqual(
                (gotatun_root / original).read_bytes(),
                (NOTICES.ROOT / "licenses" / bundled).read_bytes(),
            )
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
        self.assertTrue({
            "LICENSE", "licenses/musl-1.2.5.txt",
            "licenses/rust-1.99.1-COPYRIGHT-library.html",
            "licenses/rust-1.99.1-compiler-builtins.txt",
            "licenses/rust-1.99.1-sysroot-supplement.txt",
        }.issubset(expected))
        for kind, mode in [("tar", "w"), ("tar.gz", "w:gz")]:
            cases = [(None, None)] + [
                (name, mutation) for name in expected for mutation in ["missing", "modified"]
            ]
            for name, mutation in cases:
                with self.subTest(kind=kind, name=name, mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                    entries = expected.copy()
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
