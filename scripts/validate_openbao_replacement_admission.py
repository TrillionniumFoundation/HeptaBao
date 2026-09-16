#!/usr/bin/env python3
"""Validate the fail-closed OpenBao replacement admission contract."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "planning/OPENBAO_REPLACEMENT_ADMISSION_V1.yaml"
EXPECTED_SCHEMA = "heptabao.openbao-replacement-admission.v1"
ALLOWED = {"OPEN", "ADMITTED"}


def validate(document: dict) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != EXPECTED_SCHEMA:
        errors.append("unexpected admission schema")
    baseline = document.get("baseline") or {}
    if baseline.get("product") != "OpenBao" or baseline.get("version") != "2.6.2":
        errors.append("replacement baseline must remain frozen at OpenBao 2.6.2")
    if baseline.get("scope") != "complete-replacement" or baseline.get("frozen") is not True:
        errors.append("complete-replacement baseline must be frozen")

    gates = document.get("required_gates")
    if not isinstance(gates, list) or not gates:
        errors.append("required_gates must be a non-empty list")
        gates = []

    seen: set[str] = set()
    open_gates: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict):
            errors.append("gate entry must be a mapping")
            continue
        gate_id = gate.get("id")
        if not isinstance(gate_id, str) or not gate_id:
            errors.append("every gate needs a non-empty id")
            continue
        if gate_id in seen:
            errors.append(f"duplicate gate id: {gate_id}")
        seen.add(gate_id)
        status = gate.get("status")
        if status not in ALLOWED:
            errors.append(f"{gate_id}: invalid status {status!r}")
        if status != "ADMITTED":
            open_gates.append(gate_id)
        for field in ("owner", "requirement", "evidence"):
            if not isinstance(gate.get(field), str) or not gate[field].strip():
                errors.append(f"{gate_id}: missing {field}")

    authority = document.get("replacement_authority")
    status = document.get("status")
    all_admitted = bool(gates) and not open_gates and not errors
    if authority is True and not all_admitted:
        errors.append(
            "replacement_authority cannot be true while any required gate is not ADMITTED"
        )
    if authority is True and status != "ADMITTED":
        errors.append("replacement_authority=true requires status=ADMITTED")
    if all_admitted and authority is not True:
        errors.append(
            "all gates are ADMITTED but replacement_authority is not true; perform an explicit authority transition"
        )
    if not all_admitted and status != "NOT_ADMITTED":
        errors.append("open gates require status=NOT_ADMITTED")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT)
    args = parser.parse_args()
    try:
        document = yaml.safe_load(args.manifest.read_text())
    except (OSError, yaml.YAMLError) as error:
        print(f"cannot read admission contract: {error}", file=sys.stderr)
        return 1
    if not isinstance(document, dict):
        print("admission contract must be a mapping", file=sys.stderr)
        return 1
    errors = validate(document)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    gates = document["required_gates"]
    admitted = sum(gate["status"] == "ADMITTED" for gate in gates)
    print(
        f"OpenBao replacement admission: {document['status']} "
        f"({admitted}/{len(gates)} required gates admitted)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
