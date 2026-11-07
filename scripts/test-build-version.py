#!/usr/bin/env python3
"""Tests build metadata and Cargo invalidation without compiling Shoes dependencies."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BuildVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = Path.home() / "tmp"
        scratch.mkdir(exist_ok=True)
        cls.temporary = tempfile.TemporaryDirectory(prefix="shoes-version-", dir=scratch)
        cls.root = Path(cls.temporary.name)
        cls.script = cls.root / "build-script"
        subprocess.run(["rustc", "--edition=2024", str(ROOT / "build.rs"), "-o", str(cls.script)], check=True)
        cls.compiler = subprocess.check_output(["rustc", "--version"], text=True).strip()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        self.repo.mkdir()
        self.env = dict(os.environ, CARGO_MANIFEST_DIR=str(self.repo), CARGO_PKG_VERSION="1.2.3",
                        TARGET="aarch64-unknown-linux-musl", RUSTC=shutil.which("rustc"),
                        SHOES_RELEASE_TAG="", SHOES_BUILD_REVISION="", CARGO_BUILD_JOBS="1",
                        CARGO_TERM_COLOR="never",
                        CARGO_TARGET_DIR=str(Path(self.directory.name) / "target"))
        self.env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        self.env.pop("RUSTFLAGS", None)
        shutil.copyfile(ROOT / "build.rs", self.repo / "build.rs")
        (self.repo / "tracked").write_text("original\n")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True).strip()

    def initialize(self, *options):
        self.git("init", "-q", "-b", "main", *options)
        self.git("config", "user.name", "Version Test")
        self.git("config", "user.email", "version@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("add", ".")
        self.git("commit", "-qm", "Fixture")
        return self.git("rev-parse", "HEAD")

    def metadata(self, **environment):
        result = subprocess.run([str(self.script)], env=dict(self.env, **environment),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return dict(line.removeprefix("cargo:rustc-env=").split("=", 1)
                    for line in result.stdout.splitlines() if line.startswith("cargo:rustc-env="))

    def test_gitless_and_explicit_metadata(self):
        result = self.metadata()
        self.assertEqual(result, {"SHOES_VERSION": "1.2.3+unknown",
                                  "SHOES_TARGET": "aarch64-unknown-linux-musl",
                                  "SHOES_COMPILER": self.compiler})
        for revision in ["a" * 40, "b" * 64 + ".dirty"]:
            suffix = ".dirty" if revision.endswith(".dirty") else ""
            self.assertEqual(self.metadata(SHOES_BUILD_REVISION=revision)["SHOES_VERSION"],
                             f"1.2.3+g{revision[:12]}{suffix}")
        self.assertEqual(self.metadata(SHOES_RELEASE_TAG="v1.2.3")["SHOES_VERSION"], "1.2.3")

    def test_tagged_checkout_is_not_automatically_official(self):
        revision = self.initialize()
        self.git("tag", "v1.2.3")
        self.assertEqual(self.metadata()["SHOES_VERSION"], f"1.2.3+g{revision[:12]}")
        (self.repo / "untracked").write_text("not part of the build\n")
        self.assertEqual(self.metadata()["SHOES_VERSION"], f"1.2.3+g{revision[:12]}")
        (self.repo / "tracked").write_text("changed\n")
        self.assertEqual(self.metadata()["SHOES_VERSION"], f"1.2.3+g{revision[:12]}.dirty")
        self.assertTrue(self.metadata(SHOES_BUILD_REVISION="a" * 40)["SHOES_VERSION"].endswith(".dirty"))

    def test_invalid_inputs_and_dirty_releases_fail(self):
        self.initialize()
        for environment in [{"SHOES_RELEASE_TAG": "v9.9.9"},
                            {"SHOES_BUILD_REVISION": "abc"},
                            {"SHOES_BUILD_REVISION": "a" * 40 + "\ncargo:rustc-env=BAD=1"},
                            {"SHOES_RELEASE_TAG": "v1.2.3", "SHOES_BUILD_REVISION": "a" * 40 + ".dirty"}]:
            with self.subTest(environment=environment):
                result = subprocess.run([str(self.script)], env=dict(self.env, **environment), capture_output=True)
                self.assertNotEqual(result.returncode, 0)
        (self.repo / "tracked").write_text("changed\n")
        result = subprocess.run([str(self.script)], env=dict(self.env, SHOES_RELEASE_TAG="v1.2.3"), capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_archive_does_not_inherit_parent_repository(self):
        self.initialize()
        archive = self.repo / "archive"
        archive.mkdir()
        self.assertEqual(self.metadata(CARGO_MANIFEST_DIR=str(archive))["SHOES_VERSION"], "1.2.3+unknown")

    def test_missing_git_is_not_mistaken_for_a_release(self):
        self.initialize()
        compiler = shutil.which("rustc")
        if shutil.which("rustup"):
            compiler = subprocess.check_output(["rustup", "which", "rustc"], text=True).strip()
        self.assertEqual(self.metadata(PATH="", RUSTC=compiler)["SHOES_VERSION"], "1.2.3+unknown")
        self.assertEqual(self.metadata(PATH="", RUSTC=compiler, SHOES_BUILD_REVISION="a" * 40)["SHOES_VERSION"],
                         "1.2.3+g" + "a" * 12)

    def cargo_version(self, **environment):
        result = subprocess.run(["cargo", "run", "--offline", "--quiet"], cwd=self.repo,
                                env=dict(self.env, **environment), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def cargo_fixture(self):
        (self.repo / "Cargo.toml").write_text('[package]\nname = "version-fixture"\nversion = "1.2.3"\nedition = "2024"\n')
        (self.repo / "src").mkdir()
        (self.repo / "src/main.rs").write_text('fn main() { println!("{}", env!("SHOES_VERSION")); }\n')
        subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=self.repo, env=self.env, check=True)

    def assert_fresh(self):
        result = subprocess.run(["cargo", "build", "--offline", "--verbose"], cwd=self.repo,
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Fresh version-fixture", result.stderr)

    def test_cargo_rebuilds_on_git_and_environment_changes(self):
        self.cargo_fixture()
        revision = self.initialize()
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.assert_fresh()
        self.git("update-ref", "refs/remotes/origin/unrelated", "HEAD")
        self.git("tag", "unrelated")
        self.git("branch", "other")
        self.assert_fresh()
        self.git("commit", "--allow-empty", "-qm", "Empty commit")
        revision = self.git("rev-parse", "HEAD")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        (self.repo / "tracked").write_text("changed\n")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}.dirty")
        self.git("add", "tracked")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}.dirty")
        self.git("restore", "--source=HEAD", "--staged", "--worktree", "tracked")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        (self.repo / "tracked").unlink()
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}.dirty")
        self.assert_fresh()
        self.git("restore", "tracked")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.git("pack-refs", "--all", "--prune")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.git("commit", "--allow-empty", "-qm", "After packing refs")
        revision = self.git("rev-parse", "HEAD")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.assertEqual(self.cargo_version(SHOES_RELEASE_TAG="v1.2.3"), "1.2.3")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.assertEqual(self.cargo_version(SHOES_BUILD_REVISION="c" * 40), "1.2.3+g" + "c" * 12)
        self.git("checkout", "-q", "--detach", "HEAD~1")
        revision = self.git("rev-parse", "HEAD")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        worktree = self.repo.parent / "worktree"
        self.git("worktree", "add", "-q", "-b", "linked", str(worktree))
        self.repo = worktree
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.git("commit", "--allow-empty", "-qm", "Linked worktree commit")
        revision = self.git("rev-parse", "HEAD")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.assert_fresh()

    def test_reftable_commit_invalidates_metadata(self):
        self.cargo_fixture()
        try:
            revision = self.initialize("--ref-format=reftable")
        except subprocess.CalledProcessError:
            self.skipTest("Git does not support reftable")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")
        self.assert_fresh()
        self.git("commit", "--allow-empty", "-qm", "Reftable empty commit")
        revision = self.git("rev-parse", "HEAD")
        self.assertEqual(self.cargo_version(), f"1.2.3+g{revision[:12]}")


if __name__ == "__main__":
    unittest.main()
