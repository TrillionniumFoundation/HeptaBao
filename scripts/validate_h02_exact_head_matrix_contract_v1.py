#!/usr/bin/env python3
"""Fail-closed static validation for the H02 exact-head matrix contract."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/h02_exact_head_matrix_v1.py"
RUNNER_TEST = ROOT / "tests/platform/test_h02_exact_head_matrix_v1.py"
SCHEMA = ROOT / "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json"
SPEC = ROOT / "docs/execution/HEPTABAO_H02_EXACT_HEAD_MATRIX_EXECUTION_SPEC_V1.md"
ADDENDUM = ROOT / "docs/plan/HEPTABAO_PLAN_V1_2_1_EXACT_HEAD_EVIDENCE_ADDENDUM.md"
WORKFLOW = ROOT / ".github/workflows/plan-integrity-v4.yml"
HOSTILE = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab.rs"
BLOCKERS = ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml"
MANIFEST = ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml"


class Failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path.relative_to(ROOT)}: expected object")
    return value


def require_tokens(path: Path, tokens: tuple[str, ...]) -> None:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        require(token in text, f"{path.relative_to(ROOT)} missing token: {token}")


def load_runner():
    spec = importlib.util.spec_from_file_location("h02_exact_head_matrix_contract", RUNNER)
    require(spec is not None and spec.loader is not None, "cannot load exact-head runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_schema() -> None:
    schema = load_json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    properties = schema.get("properties", {})
    require(
        properties.get("schema", {}).get("const")
        == "heptabao.h02-exact-head-matrix-summary.v1",
        "matrix summary schema identity drift",
    )
    for field, expected in (
        ("qualification", False),
        ("compatibility_claim", False),
        ("selection_effect", "NONE"),
        ("authority_effect", "NONE"),
    ):
        require(
            properties.get(field, {}).get("const") == expected,
            f"matrix summary {field} is not fail-closed",
        )
    entries = properties.get("entries", {})
    require(entries.get("minItems") == 0, "failure summaries must permit partial entry retention")
    require(entries.get("maxItems") == 24, "schema must cap entries at 24")
    require("runner_errors" in properties, "schema must carry runner-level errors")
    matrix_properties = properties.get("matrix", {}).get("properties", {})
    require("duplicate_entry_ids" in matrix_properties, "schema must represent duplicate IDs")
    entry_properties = entries.get("items", {}).get("properties", {})
    for field in ("process_started", "command_digest", "application_status"):
        require(field in entry_properties, f"entry schema missing {field}")
    require(
        entry_properties.get("entry_id", {}).get("pattern")
        == "^(inmemory|hostile|blocker|durable)-(1\\.88\\.0|1\\.98\\.0)-(5eed20260828cafe|8badf00d12345678|d15ea5e5cafef00d)$",
        "entry schema entry_id matrix pattern drift",
    )
    require(
        entry_properties.get("binary", {}).get("enum")
        == [
            "heptabao-h02-openraft-inmemory-cluster",
            "heptabao-h02-openraft-fault-lab",
            "heptabao-h02-openraft-blocker-closure-lab",
            "heptabao-h02-openraft-durable-store-lab",
        ],
        "entry schema binary matrix drift",
    )
    tuple_rules = entries.get("items", {}).get("allOf", [])
    require(len(tuple_rules) >= 9, "entry schema must bind ID tuple fields")
    tuple_rules_text = json.dumps(tuple_rules, sort_keys=True)
    for token in (
        "heptabao-h02-openraft-inmemory-cluster",
        "heptabao-h02-openraft-fault-lab",
        "heptabao-h02-openraft-blocker-closure-lab",
        "heptabao-h02-openraft-durable-store-lab",
        "0x5eed20260828cafe",
        "0x8badf00d12345678",
        "0xd15ea5e5cafef00d",
    ):
        require(token in tuple_rules_text, f"entry schema tuple binding missing: {token}")

    pass_rule = json.dumps(schema.get("allOf", []), sort_keys=True)
    for token in (
        '"pass": {"const": 24}',
        '"fail": {"const": 0}',
        '"blocked": {"const": 0}',
        '"unknown": {"const": 0}',
        '"unexecuted": {"const": 0}',
        '"clean_tree": {"const": true}',
        '"runner_errors": {"maxItems": 0}',
        '"duplicate_entry_ids": {"maxItems": 0}',
        '"entries": {"maxItems": 24, "minItems": 24}',
    ):
        require(token in pass_rule, f"PASS condition missing: {token}")


def validate_runner() -> None:
    compile(RUNNER.read_text(encoding="utf-8"), str(RUNNER), "exec")
    compile(RUNNER_TEST.read_text(encoding="utf-8"), str(RUNNER_TEST), "exec")
    module = load_runner()
    require(module.TOOLCHAINS == ("1.88.0", "1.98.0"), "runner toolchain set drift")
    require(len(module.SEEDS) == 3, "runner seed set drift")
    require(
        tuple(probe.kind for probe in module.PROBES)
        == ("inmemory", "hostile", "blocker", "durable"),
        "runner probe-kind order drift",
    )
    require(
        tuple(module.PROBES_BY_KIND)
        == ("inmemory", "hostile", "blocker", "durable"),
        "runner canonical probe lookup drift",
    )
    require(
        tuple(probe.binary for probe in module.PROBES)
        == (
            "heptabao-h02-openraft-inmemory-cluster",
            "heptabao-h02-openraft-fault-lab",
            "heptabao-h02-openraft-blocker-closure-lab",
            "heptabao-h02-openraft-durable-store-lab",
        ),
        "runner canonical binary matrix drift",
    )
    require(len(module.expected_entry_ids()) == 24, "runner must define 24 unique entries")
    require_tokens(
        RUNNER,
        (
            "verify_source_binding",
            "declared commit does not match HEAD",
            "output directory must be outside the repository",
            "Process exit status is necessary but not sufficient",
            "Explicit BLOCKED,",
            "terminate_process_group",
            "os.killpg",
            '"command_digest"',
            '"process_started"',
            '"duplicate_entry_ids"',
            '"runner_errors"',
            "repository became dirty during matrix execution",
            "stdout JSONL line",
            "hostile application status",
            "blocker component",
            "durable cases did not pass",
            "matrix-summary.json",
            '"qualification": False',
            '"authority_effect": "NONE"',
            "parse_entry_id",
            "canonical_command",
            "validate_command_tuple",
            "validate_entry_tuple",
            "entry command_digest does not match exact argv",
            "tuple invalid",
        ),
    )
    tests = RUNNER_TEST.read_text(encoding="utf-8")
    for name in (
        "test_explicit_blocked_application_remains_blocked",
        "test_inmemory_unknown_remains_unknown",
        "test_spawn_failure_is_unexecuted",
        "test_timeout_is_blocked_even_with_partial_pass_json",
        "test_duplicate_entry_id_forces_failure",
        "test_entry_tuple_fields_are_bound_to_canonical_matrix",
        "test_command_digest_and_argv_are_bound_to_canonical_tuple",
        "test_runner_error_forces_schema_valid_failure",
        "test_source_binding_rejects_declared_head_mismatch",
        "test_output_inside_repository_is_rejected",
    ):
        require(name in tests, f"exact-head regression test missing: {name}")


def validate_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    for forbidden in (
        re.compile(r"(?mi)^\s*contents\s*:\s*write\s*$"),
        re.compile(r"(?mi)^\s*persist-credentials\s*:\s*true\s*$"),
        re.compile(r"(?mi)^\s*git\s+(?:commit|push|rebase)\b"),
    ):
        require(not forbidden.search(text), "exact-head workflow contains a forbidden mutation")
    require_tokens(
        WORKFLOW,
        (
            "python3 scripts/validate_plan_v1_2_1.py",
            "python3 scripts/validate_h02_exact_head_matrix_contract_v1.py",
            "Execute all 24 exact-head entries and preserve every outcome",
            "scripts/h02_exact_head_matrix_v1.py",
            "matrix-runner.exit",
            "Upload complete exact-head diagnostics before final gate",
            "if: ${{ always() }}",
            "Require schema-valid complete application-level PASS matrix",
            "heptabao_h02_exact_head_matrix_summary_v1.schema.json",
            '"pass": 24',
            '"fail": 0',
            "authority graph remains fail-closed",
        ),
    )
    upload_index = text.index("Upload complete exact-head diagnostics before final gate")
    gate_index = text.index("Require schema-valid complete application-level PASS matrix")
    require(upload_index < gate_index, "diagnostics must upload before the final matrix gate")


def validate_hostile_exit_semantics() -> None:
    require_tokens(
        HOSTILE,
        (
            "fn exit_code_for_status",
            'Some("EXECUTED_PASS") => 0',
            'Some("EXECUTED_FAIL") => 1',
            'Some("BLOCKED") => 2',
            "hostile_application_failure_cannot_exit_successfully",
            "print_parent_result(&result)",
        ),
    )


def validate_normative_links() -> None:
    manifest = load_yaml(MANIFEST)
    paths = {entry.get("path") for entry in manifest.get("documents", [])}
    for path in (
        "docs/plan/HEPTABAO_PLAN_V1_2_1_EXACT_HEAD_EVIDENCE_ADDENDUM.md",
        "docs/execution/HEPTABAO_H02_EXACT_HEAD_MATRIX_EXECUTION_SPEC_V1.md",
        "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json",
    ):
        require(path in paths, f"normative manifest does not index {path}")
    blockers = load_yaml(BLOCKERS)
    by_id = {entry.get("id"): entry for entry in blockers.get("blockers", [])}
    blocker = by_id.get("HB-BLK-REPO-011")
    require(isinstance(blocker, dict), "HB-BLK-REPO-011 is missing")
    criteria = " ".join(str(item) for item in blocker.get("closure_criteria", []))
    evidence = set(blocker.get("evidence", []))
    for token in ("24", "stdout", "stderr", "application", "EXECUTED_FAIL"):
        require(token.lower() in criteria.lower(), f"HB-BLK-REPO-011 lacks criterion: {token}")
    for path in (
        "docs/execution/HEPTABAO_H02_EXACT_HEAD_MATRIX_EXECUTION_SPEC_V1.md",
        "scripts/h02_exact_head_matrix_v1.py",
        "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json",
        "tests/platform/test_h02_exact_head_matrix_v1.py",
    ):
        require(path in evidence, f"HB-BLK-REPO-011 evidence missing: {path}")
    require_tokens(
        SPEC,
        (
            "24 entries",
            "Process result",
            "Application result",
            "Aggregate result",
            "EXECUTED_FAIL",
            "canonical kind",
            "exact argv",
            "authority_effect=NONE",
        ),
    )
    require_tokens(
        ADDENDUM,
        (
            "应用失败、CI 成功",
            "24/24",
            "REMEDIATION_IMPLEMENTED",
            "EXTERNAL_ACTION_REQUIRED",
            "canonical kind/toolchain/seed/binary/argv tuple",
            "authority_effect=NONE",
        ),
    )


def main() -> int:
    try:
        for path in (
            RUNNER,
            RUNNER_TEST,
            SCHEMA,
            SPEC,
            ADDENDUM,
            WORKFLOW,
            HOSTILE,
            BLOCKERS,
            MANIFEST,
        ):
            require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")
        validate_schema()
        validate_runner()
        validate_workflow()
        validate_hostile_exit_semantics()
        validate_normative_links()
    except (Failure, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"H02 exact-head matrix contract validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "H02 exact-head matrix contract validation passed: entries=24; "
        "source-self-binding=true; application-status-preserved=true; "
        "timeout-process-group-termination=true; diagnostics-before-gate=true; "
        "qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
