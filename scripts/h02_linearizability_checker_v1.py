#!/usr/bin/env python3
"""Fail-closed single-register linearizability checker for the H02 OpenRaft fault lab."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

HISTORY_SCHEMA = "heptabao.h02-linearizability-history.v1"
RESULT_SCHEMA = "heptabao.h02-linearizability-result.v1"
EXPECTED_CANDIDATE = "HB-DEP-RAFT-OPENRAFT"
EXPECTED_VERSION = "0.10.0-alpha.33"
EXPECTED_PROFILE = "HB-H02-FAULT-LAB-OPENRAFT-0_10_0_ALPHA_33"
MAX_OPERATIONS = 64
BLOCK_PROMOTION = "BLOCK_PENDING_DURABLE_STORE_OS_DISK_CLOCK_AND_INDEPENDENT_REPRODUCTION"


class HistoryValidationError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def fail(message: str) -> None:
    raise HistoryValidationError(message)


def validate_history(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("history must be a JSON object")
    required = {
        "schema", "model", "candidate_id", "version", "profile_id", "seed", "initial_value",
        "operations", "execution_scope", "durability_class", "qualification",
        "selection_effect", "authority_effect",
    }
    allowed = required | {"metadata"}
    missing, extra = required - value.keys(), value.keys() - allowed
    if missing:
        fail(f"history: missing fields: {', '.join(sorted(missing))}")
    if extra:
        fail(f"history: unexpected fields: {', '.join(sorted(extra))}")
    checks = [
        (value["schema"] == HISTORY_SCHEMA, "schema mismatch"),
        (value["model"] == "single-register-v1", "model mismatch"),
        (value["candidate_id"] == EXPECTED_CANDIDATE, "candidate_id mismatch"),
        (value["version"] == EXPECTED_VERSION, "version mismatch"),
        (value["profile_id"] == EXPECTED_PROFILE, "profile_id mismatch"),
        (value["execution_scope"] == "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY", "execution_scope mismatch"),
        (value["durability_class"] == "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM", "durability_class mismatch"),
        (value["qualification"] is False, "qualification must remain false"),
        (value["selection_effect"] == "NONE", "selection_effect must remain NONE"),
        (value["authority_effect"] == "NONE", "authority_effect must remain NONE"),
    ]
    for condition, message in checks:
        if not condition:
            fail(message)
    if value["initial_value"] is not None and not isinstance(value["initial_value"], str):
        fail("initial_value must be a string or null")
    seed = value["seed"]
    if not isinstance(seed, str) or not seed.startswith("0x"):
        fail("seed must be hexadecimal")
    try:
        int(seed[2:], 16)
    except ValueError:
        fail("seed is not valid hexadecimal")

    operations = value["operations"]
    if not isinstance(operations, list) or not operations:
        fail("operations must be a non-empty array")
    if len(operations) > MAX_OPERATIONS:
        fail(f"operations exceed maximum {MAX_OPERATIONS}")
    ids: set[str] = set()
    required_op = {"id", "client", "kind", "invoke", "complete", "input", "output", "status"}
    for index, operation in enumerate(operations):
        label = f"operations[{index}]"
        if not isinstance(operation, dict):
            fail(f"{label} must be an object")
        if required_op - operation.keys() or operation.keys() - required_op - {"node_id", "error"}:
            fail(f"{label} fields mismatch")
        op_id = operation["id"]
        if not isinstance(op_id, str) or not op_id:
            fail(f"{label}.id must be non-empty")
        if op_id in ids:
            fail(f"duplicate operation id: {op_id}")
        ids.add(op_id)
        if not isinstance(operation["client"], str) or not operation["client"]:
            fail(f"{label}.client must be non-empty")
        if operation["kind"] not in {"write", "read"}:
            fail(f"{label}.kind must be read or write")
        invoke, complete = operation["invoke"], operation["complete"]
        if any(not isinstance(item, int) or isinstance(item, bool) for item in (invoke, complete)):
            fail(f"{label} timestamps must be integers")
        if invoke < 0 or complete < 0 or invoke >= complete:
            fail(f"{label} must satisfy invoke < complete")
        if operation["status"] != "ok":
            fail(f"{label}.status must be ok; failed/unknown operations block checking")
        if operation["input"] is not None and not isinstance(operation["input"], str):
            fail(f"{label}.input must be string or null")
        if operation["output"] is not None and not isinstance(operation["output"], str):
            fail(f"{label}.output must be string or null")
        if operation["kind"] == "write" and operation["input"] is None:
            fail(f"{label}.input is required for writes")
        if operation["kind"] == "read" and operation["input"] is not None:
            fail(f"{label}.input must be null for reads")
    if "metadata" in value and not isinstance(value["metadata"], dict):
        fail("metadata must be an object")
    return value


def check_linearizable(history: dict[str, Any]) -> tuple[bool, list[str], int]:
    operations = history["operations"]
    predecessors = [0] * len(operations)
    for earlier_index, earlier in enumerate(operations):
        for later_index, later in enumerate(operations):
            if earlier_index != later_index and earlier["complete"] < later["invoke"]:
                predecessors[later_index] |= 1 << earlier_index
    explored = 0

    @lru_cache(maxsize=None)
    def search(remaining: int, state: str | None) -> tuple[int, ...] | None:
        nonlocal explored
        explored += 1
        if not remaining:
            return ()
        for index, operation in enumerate(operations):
            bit = 1 << index
            if not remaining & bit or predecessors[index] & remaining:
                continue
            if operation["kind"] == "read":
                if operation["output"] != state:
                    continue
                next_state = state
            else:
                if operation["output"] is not None and operation["output"] != state:
                    continue
                next_state = operation["input"]
            suffix = search(remaining ^ bit, next_state)
            if suffix is not None:
                return (index,) + suffix
        return None

    witness = search((1 << len(operations)) - 1, history["initial_value"])
    return witness is not None, [] if witness is None else [operations[i]["id"] for i in witness], explored


def result(raw: Any, status: str, linearizable: bool | None, reason: str, witness=None, explored=0) -> dict[str, Any]:
    operations = raw.get("operations", []) if isinstance(raw, dict) else []
    return {
        "schema": RESULT_SCHEMA, "status": status, "linearizable": linearizable,
        "history_sha256": canonical_sha256(raw), "operation_count": len(operations) if status != "BLOCKED" else 0,
        "witness_order": witness or [], "explored_states": explored, "reason": reason,
        "checker": {"algorithm": "bounded-real-time-precedence-backtracking", "model": "single-register-v1", "max_operations": 64},
        "qualification": False, "selection_effect": "NONE", "promotion_effect": BLOCK_PROMOTION, "authority_effect": "NONE",
    }


def evaluate(raw: Any) -> dict[str, Any]:
    try:
        history = validate_history(raw)
    except HistoryValidationError as error:
        return result(raw, "BLOCKED", None, str(error))
    linearizable, witness, explored = check_linearizable(history)
    return result(
        history, "EXECUTED_PASS" if linearizable else "EXECUTED_FAIL", linearizable,
        "linearization witness found" if linearizable else "no legal linearization satisfies real-time order and register semantics",
        witness, explored,
    )


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def command_check(args: argparse.Namespace) -> int:
    try:
        raw = load(args.history)
    except (OSError, json.JSONDecodeError) as error:
        raw = {"unreadable_history": str(error)}
        value = result(raw, "BLOCKED", None, f"unable to read history: {error}")
    else:
        value = evaluate(raw)
    write(args.output, value)
    print(f"{value['status']} linearizable={value['linearizable']} reason={value['reason']}")
    return {"EXECUTED_PASS": 0, "EXECUTED_FAIL": 1, "BLOCKED": 2}[value["status"]]


def command_validate(args: argparse.Namespace) -> int:
    value = load(args.history)
    validate_history(value)
    print(f"VALID history_sha256={canonical_sha256(value)} operations={len(value['operations'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("--history", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    check.set_defaults(func=command_check)
    validate = commands.add_parser("validate")
    validate.add_argument("--history", type=Path, required=True)
    validate.set_defaults(func=command_validate)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (HistoryValidationError, OSError, json.JSONDecodeError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
