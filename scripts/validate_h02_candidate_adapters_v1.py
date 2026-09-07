#!/usr/bin/env python3
"""Validate the H02 candidate-adapter plan, fixtures, schemas and semantics."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from argparse import Namespace
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "planning/HEPTABAO_H02_CANDIDATE_ADAPTERS_V1.yaml"
EVIDENCE_SCHEMA_PATH = ROOT / "schemas/heptabao_h02_seeded_behavior_evidence_v1.schema.json"
COMPARISON_SCHEMA_PATH = ROOT / "schemas/heptabao_h02_candidate_comparison_v1.schema.json"
HARNESS_PATH = ROOT / "scripts/h02_candidate_adapter_harness_v1.py"


class Failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def load_harness():
    spec = importlib.util.spec_from_file_location("h02_candidate_adapter_harness_v1", HARNESS_PATH)
    require(spec is not None and spec.loader is not None, "unable to load candidate harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_output(profile: dict, seed: int, status: str = "PASS") -> str:
    rows = [
        {
            "kind": "meta",
            "candidate_id": profile["candidate_id"],
            "version": profile["version"],
            "profile_id": profile["profile_id"],
            "domain": profile["domain"],
            "seed": f"0x{seed:016x}",
        }
    ]
    rows.extend(
        {
            "kind": "case",
            "case_id": case_id,
            "status": status,
            "assertion_count": 1 if status == "PASS" else 0,
            "detail": "validator-synthetic-no-secret",
        }
        for case_id in profile["cases"]
    )
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


def validate() -> None:
    plan = yaml.safe_load(PLAN_PATH.read_text(encoding="utf-8"))
    require(plan["schema"] == "heptabao.h02-candidate-adapters.v1", "unexpected plan schema")
    require(plan["qualification"] is False, "plan cannot self-qualify")
    require(plan["selection_effect"] == "NONE", "plan cannot select a candidate")
    require(plan["authority_effect"] == "NONE", "plan cannot grant authority")
    adapters = plan["adapters"]
    require(len(adapters) == 4, "expected four candidate adapters")
    require(len({row["adapter_id"] for row in adapters}) == 4, "duplicate adapter ID")
    require(sum(row["adapter_scope"] == "FULL_REFERENCE_CASE_SET" for row in adapters) == 3, "expected three full reference-set adapters")
    require(sum(row["adapter_scope"] == "API_SEAM_AND_FAILURE_MODEL_PARTIAL" for row in adapters) == 1, "expected one partial adapter")

    harness = load_harness()
    for adapter in adapters:
        key = adapter["profile_key"]
        require(key in harness.PROFILES, f"missing harness profile {key}")
        profile = harness.PROFILES[key]
        for field in ("profile_id", "candidate_id", "version", "domain", "manifest", "adapter_scope"):
            require(profile[field] == adapter[field], f"{key}: {field} mismatch")
        require(profile["cases"] == adapter["cases"], f"{key}: case mismatch")
        manifest = ROOT / adapter["manifest"]
        source = ROOT / adapter["source"]
        require(manifest.is_file(), f"missing manifest {manifest}")
        require(source.is_file(), f"missing source {source}")
        text = source.read_text(encoding="utf-8")
        require(adapter["candidate_id"] in text, f"{key}: candidate ID absent from source")
        require(adapter["profile_id"] in text, f"{key}: profile ID absent from source")
        for case_id in adapter["cases"]:
            require(case_id in text, f"{key}: source missing case {case_id}")
        lowered = text.lower()
        for marker in ("begin private key", "root_token", "authorization: bearer"):
            require(marker not in lowered, f"{key}: secret marker in source")

    fixture_path = ROOT / "probes/h02/rustls-public-fixtures.rs"
    fixture_text = fixture_path.read_text(encoding="utf-8")
    expected = {
        "ROOT_DER": "a25411462f6a04f4b6787d7d1198cc7a2e78b867100802dfd5dc138fe2d0053a",
        "VALID_CLIENT_DER": "6f64c58577a9946e9d75969f95e9a32df08ed9645dcd37f6a810d323a107f1e3",
        "EXPIRED_CLIENT_DER": "87975f6e8cc8bc56bde21309475835b844f27314820acd02ea90f0baec0c7a20",
    }
    import hashlib
    import re
    for name, digest in expected.items():
        match = re.search(rf"const {name}: &\[u8\] = &\[(.*?)\];", fixture_text, re.S)
        require(match is not None, f"fixture array missing: {name}")
        values = bytes(int(token, 16) for token in re.findall(r"0x([0-9a-f]{2})", match.group(1)))
        require(hashlib.sha256(values).hexdigest() == digest, f"fixture digest mismatch: {name}")
    require("BEGIN PRIVATE KEY" not in fixture_text and "root_token" not in fixture_text.lower(), "fixture source contains a secret marker")

    evidence_schema = json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))
    comparison_schema = json.loads(COMPARISON_SCHEMA_PATH.read_text(encoding="utf-8"))
    evidence_validator = Draft202012Validator(evidence_schema, format_checker=FormatChecker())
    comparison_validator = Draft202012Validator(comparison_schema, format_checker=FormatChecker())

    seed = int("5eed20260828cafe", 16)
    with tempfile.TemporaryDirectory() as temporary:
        tmp = Path(temporary)
        for adapter in adapters:
            key = adapter["profile_key"]
            output = tmp / f"{key}.jsonl"
            replay = tmp / f"{key}.replay.jsonl"
            payload = synthetic_output(harness.PROFILES[key], seed)
            output.write_text(payload, encoding="utf-8")
            replay.write_text(payload, encoding="utf-8")
            evidence = tmp / f"{key}.evidence.json"
            value = harness.collect(
                Namespace(
                    profile=key,
                    adapter_output=str(output),
                    replay_output=str(replay),
                    execution_exit_code=0,
                    seed=f"0x{seed:016x}",
                    toolchain=adapter["toolchains"][-1],
                    target="x86_64-unknown-linux-gnu",
                    source_commit="1" * 40,
                    source_tree="2" * 40,
                    branch="validator",
                    clean_tree=True,
                    environment_id=f"validator-{key}",
                    executor_kind="local-container",
                    runner_id=None,
                    runner_name="validator",
                    root=str(ROOT),
                    output=str(evidence),
                    binding_output=None,
                )
            )
            errors = list(evidence_validator.iter_errors(value))
            require(not errors, f"{key}: candidate evidence schema errors: {[e.message for e in errors]}")
            reference = json.loads(json.dumps(value))
            reference["execution_kind"] = "REFERENCE_MODEL"
            reference["candidate"] = {"bound": False, "candidate_id": None, "version": None, "feature_profile_sha256": None}
            reference["profile_id"] = adapter["reference_profile_id"]
            reference_path = tmp / f"{key}.reference.json"
            reference_path.write_text(json.dumps(reference), encoding="utf-8")
            comparison_path = tmp / f"{key}.comparison.json"
            comparison = harness.compare(
                Namespace(
                    reference=str(reference_path),
                    candidate=str(evidence),
                    adapter_scope=adapter["adapter_scope"],
                    output=str(comparison_path),
                )
            )
            comparison_errors = list(comparison_validator.iter_errors(comparison))
            require(not comparison_errors, f"{key}: comparison schema errors: {[e.message for e in comparison_errors]}")

        invalid = json.loads(evidence.read_text(encoding="utf-8"))
        invalid["authority_effect"] = "GRANT"
        require(bool(list(evidence_validator.iter_errors(invalid))), "authority-bearing candidate evidence was accepted")
        invalid_comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
        invalid_comparison["selection_effect"] = "SELECT"
        require(bool(list(comparison_validator.iter_errors(invalid_comparison))), "selection-bearing comparison was accepted")

    state = plan["current_state"]
    require(state["candidate_adapters_implemented"] == 4, "current state adapter count mismatch")
    require(state["candidate_adapter_executions"] == 0, "source plan cannot claim executions")
    require(state["candidates_selected"] == 0, "source plan cannot claim selections")
    require(state["qualification"] is False and state["authority_effect"] == "NONE", "current state authority violation")


def main() -> int:
    try:
        validate()
    except (Failure, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"H02 candidate adapter plan validation FAILED: {exc}")
        return 1
    print("H02 candidate adapter plan validation passed: adapters=4 fixtures=3 semantic-evidence=4 authority=NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
