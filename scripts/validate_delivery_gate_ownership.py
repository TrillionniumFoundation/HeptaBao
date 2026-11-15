#!/usr/bin/env python3
"""Keep expensive native gates in one current workflow without weakening them."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / ".github/workflows/codex-openbao-replacement-ci.yml"
TRUST = ROOT / ".github/workflows/workflow-trust-boundary.yml"

REQUIRED_NATIVE_GATES = (
    "cargo +1.98.0 fmt --all -- --check",
    "cargo +1.98.0 test --locked --workspace --all-targets",
    "cargo +1.98.0 clippy --locked --workspace --all-targets --exclude qrcode -- -D warnings",
    "cargo +1.98.0 doc --locked --workspace --no-deps",
)

# Workflow trust must establish the execution boundary and source identity;
# repository qualification owns the expensive current-state and native matrix.
# Keeping these checks here prevents a future security-workflow edit from
# quietly recreating the old duplicate full qualification.
FORBIDDEN_TRUST_GATES = (
    "python scripts/validate_repository_v2.py",
    "python scripts/validate_plan_v1_4_7.py",
    "python scripts/validate_plan_v1_4_6.py",
    "python scripts/validate_plan_v1_4_5.py",
    "python -m unittest discover -s tests/repository",
    "python -m unittest discover -s tests/platform",
    "python -m unittest discover -s tests/oracle",
    "cargo +1.98.0 test --locked --workspace --all-targets",
    "cargo +1.98.0 clippy --locked --workspace --all-targets --exclude qrcode -- -D warnings",
)

KUBERNETES271_CONDITION = (
    "${{ !cancelled() && steps.runtime_ready.outcome == 'success' "
    "&& steps.oracle271_ready.outcome == 'success' && steps.kind_ready.outcome == 'success' }}"
)


def validate_kubernetes_renewal_gate(full: str) -> list[str]:
    """A historical provider-free renewal cannot qualify the current product."""
    errors: list[str] = []
    try:
        steps = yaml.safe_load(full)["jobs"]["qualify"]["steps"]
        selected = [step for step in steps if step.get("id") == "kubernetes271_renewal"]
        if len(selected) != 1:
            return ["full qualification must own one current Kubernetes 2.7.1 renewal gate"]
        gate = selected[0]
        run = gate.get("run", "")
        if gate.get("if") != KUBERNETES271_CONDITION or gate.get("continue-on-error", False):
            errors.append("current Kubernetes renewal prerequisites or failure propagation changed")
        for argument in (
            "set -euo pipefail",
            "timeout 600 python qa/openbao-acceptance/kubernetes_renewal_271_cluster_live.py",
            '--expected-binary-sha256 "$binary_digest"',
            '--candidate-source-root "$PWD"',
            '--source-commit "$EXPECTED_SOURCE"',
            '--source-tree "$(git rev-parse HEAD^{tree})"',
            '--native-build-receipt "$RUNNER_TEMP/heptabao-safe-reports/native-build.json"',
            '--expected-native-build-receipt-sha256 "$receipt_digest"',
            '--kind "$RUNNER_TEMP/heptabao-kind-input/kind"',
            '--work-root "$HB_ORACLE_WORK_ROOT/run" --allow-disposable-cluster',
        ):
            if argument not in run:
                errors.append(f"current Kubernetes renewal lost required invocation: {argument}")
        for key, suffix in (("HB_ORACLE_BINARY", "bao"), ("HB_ORACLE_ARCHIVE", "oracle-official.tar.gz")):
            expected = "${{ runner.temp }}/heptabao-official-oracle271/" + suffix
            if gate.get("env", {}).get(key) != expected:
                errors.append("current Kubernetes renewal must use the pinned 2.7.1 reference")
        for step in steps:
            if "python qa/openbao-acceptance/kubernetes_renewal_live.py" in step.get("run", ""):
                errors.append("historical 2.6.2 provider-free renewal is not a current-product gate")
        builds = [step.get("run", "") for step in steps if step.get("id") == "runtime_ready"]
        if len(builds) != 1 or not all(part in builds[0] for part in (
            'cargo +1.98.0 build --locked -p heptabao-server',
            '"schema": "heptabao.native-build.v1"',
            '(root / "native-build.json").open("x")',
            'assert tree == source["source_tree"]',
        )):
            errors.append("current Kubernetes renewal lost the actual native build receipt")
        elif builds[0].index('cargo +1.98.0 build') > builds[0].index('"heptabao.native-build.v1"'):
            errors.append("native build receipt cannot precede the successful build")
    except (yaml.YAMLError, TypeError, KeyError, AttributeError):
        errors.append("current Kubernetes renewal workflow structure is invalid")
    return errors


def validate(root: Path = ROOT) -> list[str]:
    full = (root / ".github/workflows/codex-openbao-replacement-ci.yml").read_text(encoding="utf-8")
    trust = (root / ".github/workflows/workflow-trust-boundary.yml").read_text(encoding="utf-8")
    errors: list[str] = []
    if '["head","merge"]' not in full:
        errors.append("full qualification no longer covers exact head and prospective merge")
    for gate in REQUIRED_NATIVE_GATES:
        if gate not in full:
            errors.append(f"full qualification lost native gate: {gate}")
        if gate in trust:
            errors.append(f"workflow trust duplicates native gate: {gate}")
    for gate in FORBIDDEN_TRUST_GATES:
        if gate in trust:
            errors.append(f"workflow trust duplicates full-qualification gate: {gate}")
    if "success() || failure()" in full:
        errors.append("full qualification contains unconditional diagnostic continuation")
    if "python scripts/validate_workflow_trust.py" not in trust:
        errors.append("workflow trust lost its trust-policy validator")
    if "Verify actual Git identities before candidate execution" not in trust:
        errors.append("workflow trust lost exact-source identity binding")
    errors.extend(validate_kubernetes_renewal_gate(full))
    return errors


def main() -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: expensive native gates have one fail-fast owner")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
