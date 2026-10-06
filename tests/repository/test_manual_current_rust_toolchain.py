"""Manual root-workspace checks follow the current compiler, not historical probes."""
from __future__ import annotations

import copy
from pathlib import Path
import re
import tomllib
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
LANES = {
    "h01-h02-next-foundation.yml": "executable-foundation",
    "h02-source-integrity-evidence.yml": "validate-contracts",
}


def current_root_errors(job: dict, compiler: str) -> list[str]:
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    installs = re.findall(r"(?m)^\s*rustup toolchain install (\S+)", commands)
    overrides = re.findall(r"(?m)^\s*rustup override set (\S+)", commands)
    errors = []
    if installs != [compiler]:
        errors.append("root build must install only the current compiler")
    if overrides != [compiler]:
        errors.append("unqualified cargo commands must select the current compiler")
    for gate in ("cargo fmt --all --check", "cargo test --workspace --all-targets --locked",
                 "cargo clippy --workspace --all-targets --locked --no-deps --exclude qrcode -- -D warnings"):
        if gate not in commands:
            errors.append("missing root native gate: " + gate)
    return errors


class ManualCurrentRustToolchainTests(unittest.TestCase):
    def setUp(self):
        self.compiler = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        self.jobs = {name: yaml.safe_load((ROOT / ".github/workflows" / name).read_text())["jobs"][job]
                     for name, job in LANES.items()}

    def test_current_manual_root_builds_use_root_toolchain(self):
        for name, job in self.jobs.items():
            with self.subTest(lane=name):
                self.assertEqual([], current_root_errors(job, self.compiler))

    def test_native_prerequisites_precede_rust_commands(self):
        required = "krb5-kdc krb5-admin-server krb5-user libkrb5-dev pkg-config clang"
        for name, job in self.jobs.items():
            with self.subTest(lane=name):
                steps = job["steps"]
                prerequisite = next(i for i, step in enumerate(steps)
                                    if step.get("name") == "Install MIT Kerberos build and acceptance prerequisites")
                commands = steps[prerequisite]["run"]
                self.assertIn('test "$GITHUB_ACTIONS" = true', commands)
                self.assertIn("sudo apt-get update -qq", commands)
                self.assertIn("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends " + required, commands)
                native = [i for i, step in enumerate(steps)
                          if re.search(r"(?m)^\s*cargo (fmt|test|clippy)\b", step.get("run", ""))]
                self.assertTrue(native)
                self.assertLess(prerequisite, min(native))

    def test_stale_install_or_override_is_rejected(self):
        for selector in ("toolchain install", "override set"):
            for name, original in self.jobs.items():
                job = copy.deepcopy(original)
                for step in job["steps"]:
                    if "run" in step:
                        step["run"] = step["run"].replace(f"rustup {selector} {self.compiler}",
                                                       f"rustup {selector} 1.98.0")
                with self.subTest(lane=name, selector=selector):
                    self.assertTrue(current_root_errors(job, self.compiler))

    def test_missing_selector_is_rejected(self):
        for selector in ("toolchain install", "override set"):
            for name, original in self.jobs.items():
                job = copy.deepcopy(original)
                for step in job["steps"]:
                    if "run" in step:
                        step["run"] = "\n".join(line for line in step["run"].splitlines()
                                                if f"rustup {selector}" not in line)
                with self.subTest(lane=name, selector=selector):
                    self.assertTrue(current_root_errors(job, self.compiler))

    def test_each_native_gate_remains_required(self):
        for command in ("cargo fmt", "cargo test", "cargo clippy"):
            for name, original in self.jobs.items():
                job = copy.deepcopy(original)
                for step in job["steps"]:
                    if "run" in step:
                        step["run"] = "\n".join(line for line in step["run"].splitlines()
                                                if not line.strip().startswith(command))
                with self.subTest(lane=name, command=command):
                    self.assertTrue(current_root_errors(job, self.compiler))


if __name__ == "__main__":
    unittest.main()
