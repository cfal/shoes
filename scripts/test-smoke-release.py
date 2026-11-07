#!/usr/bin/env python3
"""Tests the packaged-binary smoke gate, including failure propagation."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tomllib
import unittest
from unittest import mock

import build_version

SPEC = importlib.util.spec_from_file_location(
    "smoke_release", Path(__file__).with_name("smoke-release.py")
)
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)
VERSION = tomllib.loads((SMOKE.ROOT / "Cargo.toml").read_text())["package"]["version"]


class ReleaseSmokeTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {
            "SHOES_RELEASE_TAG": f"v{VERSION}",
            "SHOES_BUILD_REVISION": "a" * 40,
            "TARGET": "x86_64-unknown-linux-musl",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.short = f"shoes {VERSION}\n".encode()
        self.long = self.short + b"target: x86_64-unknown-linux-musl\ncompiler: rustc 1.99.1 (test)\n"

    def output(self, command, **_kwargs):
        return self.short if command[-1] == "-V" else self.long

    def test_native_and_runner_commands(self):
        for command in [["./shoes"], ["docker", "run", "--rm", "image", "/linux-runner", "armv7", "./shoes"]]:
            with self.subTest(command=command), \
                    mock.patch.object(SMOKE.subprocess, "check_output", side_effect=self.output) as version, \
                    mock.patch.object(SMOKE.subprocess, "run") as run:
                SMOKE.smoke(command)
                self.assertEqual(version.call_args_list, [
                    mock.call([*command, option], cwd=SMOKE.ROOT, timeout=60)
                    for option in ["-V", "--version", "version"]
                ])
                self.assertEqual(run.call_args_list, [
                    mock.call([*command, "check", "--threads", "1", "examples/socks_basic.yaml"],
                              cwd=SMOKE.ROOT, check=True, timeout=60),
                    mock.call([*command, "generate-reality-keypair"],
                              cwd=SMOKE.ROOT, check=True, timeout=60, stdout=subprocess.DEVNULL),
                ])

    def test_wrong_version_stops_before_other_checks(self):
        with mock.patch.object(SMOKE.subprocess, "check_output", return_value=b"shoes 0.0.0\n"), \
                mock.patch.object(SMOKE.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                SMOKE.smoke(["./shoes"])
            run.assert_not_called()

    def test_execution_failure_or_timeout_stops_gate(self):
        for failure in [subprocess.CalledProcessError(1, "shoes"), subprocess.TimeoutExpired("shoes", 60)]:
            for stage in ["version", "config", "crypto"]:
                with self.subTest(stage=stage, failure=type(failure)), \
                        mock.patch.object(SMOKE.subprocess, "check_output", side_effect=self.output) as version, \
                        mock.patch.object(SMOKE.subprocess, "run") as run:
                    if stage == "version":
                        version.side_effect = failure
                    elif stage == "config":
                        run.side_effect = failure
                    else:
                        run.side_effect = [None, failure]
                    with self.assertRaises(type(failure)):
                        SMOKE.smoke(["./shoes"])

    def test_development_and_unknown_versions(self):
        for revision, suffix in [("a" * 40, "+g" + "a" * 12),
                                 ("b" * 40 + ".dirty", "+g" + "b" * 12 + ".dirty"),
                                 ("", "+unknown")]:
            with self.subTest(revision=revision), mock.patch.dict(os.environ, {
                "SHOES_RELEASE_TAG": "", "SHOES_BUILD_REVISION": revision,
            }), mock.patch.object(build_version.subprocess, "check_output", side_effect=self.output):
                self.short = f"shoes {VERSION}{suffix}\n".encode()
                self.long = self.short + b"target: x86_64-unknown-linux-musl\ncompiler: rustc 1.99.1\n"
                build_version.check_version(["shoes"])

    def test_wrong_flavor_revision_target_or_alias_is_rejected(self):
        cases = [
            ({}, [f"shoes {VERSION}+g{'a' * 12}\n".encode()]),
            ({"SHOES_RELEASE_TAG": ""}, [self.short]),
            ({"SHOES_RELEASE_TAG": ""}, [f"shoes {VERSION}+g{'b' * 12}\n".encode()]),
            ({"SHOES_RELEASE_TAG": "v0.0.0"}, []),
            ({}, [self.short, self.long.replace(b"musl", b"gnu")]),
            ({}, [self.short, self.long.replace(b"rustc 1.99.1 (test)", b"")]),
            ({}, [self.short, self.long, self.short]),
        ]
        for environment, output in cases:
            with self.subTest(environment=environment, output=output), \
                    mock.patch.dict(os.environ, environment), \
                    mock.patch.object(build_version.subprocess, "check_output", side_effect=output), \
                    mock.patch.object(SMOKE.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    SMOKE.smoke(["shoes"])
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
