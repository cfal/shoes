#!/usr/bin/env python3
"""Tests the packaged-binary smoke gate, including failure propagation."""

import importlib.util
from pathlib import Path
import subprocess
import tomllib
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "smoke_release", Path(__file__).with_name("smoke-release.py")
)
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)
VERSION = tomllib.loads((SMOKE.ROOT / "Cargo.toml").read_text())["package"]["version"]


class ReleaseSmokeTests(unittest.TestCase):
    def test_native_and_runner_commands(self):
        for command in [["./shoes"], ["docker", "run", "--rm", "image", "/linux-runner", "armv7", "./shoes"]]:
            with self.subTest(command=command), \
                    mock.patch.object(SMOKE.subprocess, "check_output", return_value=f"shoes {VERSION}\n".encode()) as version, \
                    mock.patch.object(SMOKE.subprocess, "run") as run:
                SMOKE.smoke(command)
                version.assert_called_once_with([*command, "--version"], cwd=SMOKE.ROOT, timeout=60)
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
                        mock.patch.object(SMOKE.subprocess, "check_output", return_value=f"shoes {VERSION}\n".encode()) as version, \
                        mock.patch.object(SMOKE.subprocess, "run") as run:
                    if stage == "version":
                        version.side_effect = failure
                    elif stage == "config":
                        run.side_effect = failure
                    else:
                        run.side_effect = [None, failure]
                    with self.assertRaises(type(failure)):
                        SMOKE.smoke(["./shoes"])


if __name__ == "__main__":
    unittest.main()
