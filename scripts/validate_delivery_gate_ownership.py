#!/usr/bin/env python3
"""Keep expensive native gates in one current workflow without weakening them."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / ".github/workflows/codex-openbao-replacement-ci.yml"
TRUST = ROOT / ".github/workflows/workflow-trust-boundary.yml"

REQUIRED_NATIVE_GATES = (
    "cargo +1.98.0 fmt --all -- --check",
    "cargo +1.98.0 test --locked --workspace --all-targets",
    "cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings",
    "cargo +1.98.0 doc --locked --workspace --no-deps",
)


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
    if "success() || failure()" in full:
        errors.append("full qualification contains unconditional diagnostic continuation")
    if "python scripts/validate_workflow_trust.py" not in trust:
        errors.append("workflow trust lost its trust-policy validator")
    if "Verify actual Git identities before candidate execution" not in trust:
        errors.append("workflow trust lost exact-source identity binding")
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
