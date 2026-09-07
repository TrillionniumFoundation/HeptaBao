#!/usr/bin/env python3
"""Fail-closed semantic validation for the HeptaBao V1.2 execution contract.

This validator proves structure and repository semantics only. It never grants
qualification, compatibility, dependency selection, or operational authority.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_GATES = [f"H{value:02d}" for value in range(28)]
EXPECTED_MATURITY = [
    "PLANNED",
    "SPECIFIED",
    "IMPLEMENTED",
    "LOCALLY_EXECUTED",
    "REMOTELY_EXECUTED",
    "CROSS_PLATFORM_EXECUTED",
    "INDEPENDENTLY_REPRODUCED",
    "REVIEWED",
    "QUALIFIED",
    "CLAIMED",
    "AUTHORIZED",
    "RELEASED",
]
EXPECTED_EXECUTION_OUTCOMES = ["PASS", "FAIL", "BLOCKED", "UNEXECUTED", "UNKNOWN"]
VALID_BLOCKER_STATES = {
    "OPEN",
    "OWNED",
    "REMEDIATION_IMPLEMENTED",
    "EXACT_HEAD_EXECUTED",
    "INDEPENDENTLY_REVIEWED",
    "CLOSED",
    "BLOCKED_UPSTREAM",
    "EXTERNAL_ACTION_REQUIRED",
    "BASE_DRIFT",
    "REVOKED",
    "RESUME_REQUIRED",
}
WORK_PACKAGE_ID = re.compile(r"^H(?:0[0-9]|1[0-9]|2[0-7])-WP[0-9]{2,3}$")
FORBIDDEN_WORKFLOW_PATTERNS = {
    "write content permission": re.compile(r"(?mi)^\s*contents\s*:\s*write\s*$"),
    "persisted checkout credentials": re.compile(
        r"(?mi)^\s*persist-credentials\s*:\s*true\s*$"
    ),
    "direct git mutation": re.compile(r"(?mi)^\s*git\s+(?:commit|push|rebase)\b"),
}


class ValidationFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ValidationFailure(message)


def load_yaml(path: str) -> dict[str, Any]:
    value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected mapping")
    return value


def load_json(path: str) -> dict[str, Any]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected object")
    return value


def schema_validate(document: dict[str, Any], schema_path: str) -> None:
    schema = load_json(schema_path)
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda item: list(item.path))
    if errors:
        first = errors[0]
        location = ".".join(str(item) for item in first.path) or "<root>"
        fail(f"{schema_path}: validation failed at {location}: {first.message}")


def v11_work_package_ids() -> set[str]:
    value = load_yaml("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_1.yaml")
    result: set[str] = set()
    for gate, body in value.get("gates", {}).items():
        if gate not in EXPECTED_GATES or not isinstance(body, dict):
            fail("V1.1 work-package catalog gate drift")
        for raw in body.get("packages", []):
            if not isinstance(raw, str) or ":" not in raw:
                fail(f"V1.1 malformed work-package: {raw!r}")
            identifier = raw.split(":", 1)[0]
            if identifier in result:
                fail(f"V1.1 duplicate work-package ID: {identifier}")
            result.add(identifier)
    return result


def validate_manifest(document: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = document or load_yaml("planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml")
    schema_validate(manifest, "schemas/heptabao_normative_document_manifest_v1.schema.json")
    documents = manifest["documents"]
    ids = [entry["id"] for entry in documents]
    paths = [entry["path"] for entry in documents]
    if len(ids) != len(set(ids)):
        fail("normative manifest contains duplicate document IDs")
    if len(paths) != len(set(paths)):
        fail("normative manifest contains duplicate paths")
    for entry in documents:
        path = ROOT / entry["path"]
        if not path.is_file():
            fail(f"normative manifest path missing: {entry['path']}")
        if entry["digest"] != "RESOLVE_FROM_EXACT_SOURCE":
            fail(f"{entry['id']}: static manifest digest must be resolved at exact-source verification")
        if entry["authority_effect"] != "NONE":
            fail(f"{entry['id']}: document may not grant authority")
    path_to_kind = {entry["path"]: entry["kind"] for entry in documents}
    for path in (
        "planning/HEPTABAO_H00_WORK_PACKAGE_STATUS_V1.yaml",
        "planning/HEPTABAO_H01_WORK_PACKAGE_STATUS_V1.yaml",
        "planning/HEPTABAO_H02_WORK_PACKAGE_STATUS_V1.yaml",
        "planning/HEPTABAO_H02_EXECUTION_QUEUE_V2.yaml",
        "planning/HEPTABAO_H02_EXECUTION_QUEUE_V3.yaml",
    ):
        if path_to_kind.get(path) != "HISTORICAL":
            fail(f"stale state object is not explicitly historical: {path}")
    if manifest["current_plan"] != "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md":
        fail("V1.2 plan is not the current normative plan")
    return manifest


def validate_state_model(document: dict[str, Any] | None = None) -> dict[str, Any]:
    model = document or load_yaml("planning/HEPTABAO_EXECUTION_STATE_MODEL_V1.yaml")
    schema_validate(model, "schemas/heptabao_execution_state_model_v1.schema.json")
    if model["maturity_order"] != EXPECTED_MATURITY:
        fail("execution maturity order drift")
    if model["execution_outcomes"] != EXPECTED_EXECUTION_OUTCOMES:
        fail("execution outcome vocabulary drift")
    expected_edges = list(zip(EXPECTED_MATURITY, EXPECTED_MATURITY[1:]))
    actual_edges = [(entry["from"], entry["to"]) for entry in model["transitions"]]
    if actual_edges != expected_edges:
        fail("execution maturity transitions must be contiguous and ordered")
    return model


def validate_canonical_state(document: dict[str, Any] | None = None) -> dict[str, Any]:
    state = document or load_yaml("planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml")
    schema_validate(state, "schemas/heptabao_canonical_project_state_v1.schema.json")
    binding = state["binding"]
    if binding != {
        "mode": "SELF_RESOLVED_AT_VERIFICATION",
        "repository": "ProfHepta/HeptaBao",
        "ref": "SELF",
        "commit": "SELF",
        "tree": "SELF",
        "clean_tree_required": True,
    }:
        fail("canonical state must use exact-source SELF resolution")
    if state["selected_candidates"]:
        fail("candidate selection must remain empty")
    if state["qualification"] is not False or state["compatibility_claim"] is not False:
        fail("canonical state may not self-qualify or claim compatibility")
    for name, value in state["authority_flags"].items():
        if value is not False:
            fail(f"canonical state authority flag enabled: {name}")
    return state


def validate_work_packages(document: dict[str, Any] | None = None) -> set[str]:
    catalog = document or load_yaml("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_2.yaml")
    if catalog.get("schema") != "heptabao.work-package-catalog.v1_2":
        fail("unexpected V1.2 work-package catalog schema")
    if catalog.get("package_count") != 301:
        fail(f"V1.2 work-package count must be exactly 301, got {catalog.get('package_count')!r}")
    gates = catalog.get("gates")
    if not isinstance(gates, dict) or list(gates) != EXPECTED_GATES:
        fail("V1.2 work-package gates must be exactly ordered H00..H27")
    contract_schema = load_json("schemas/heptabao_work_package_contract_v1.schema.json")
    validator = Draft202012Validator(contract_schema)
    identifiers: set[str] = set()
    actual_count = 0
    for gate, body in gates.items():
        packages = body.get("packages") if isinstance(body, dict) else None
        if not isinstance(packages, list) or not packages:
            fail(f"{gate}: V1.2 package list missing")
        for package in packages:
            actual_count += 1
            errors = sorted(validator.iter_errors(package), key=lambda item: list(item.path))
            if errors:
                location = ".".join(str(item) for item in errors[0].path) or "<root>"
                fail(f"{gate} package contract invalid at {location}: {errors[0].message}")
            identifier = package["id"]
            if not WORK_PACKAGE_ID.fullmatch(identifier) or not identifier.startswith(f"{gate}-"):
                fail(f"{identifier}: gate/ID mismatch")
            if identifier in identifiers:
                fail(f"duplicate V1.2 work-package ID: {identifier}")
            identifiers.add(identifier)
            if package["authority_effect"] != "NONE":
                fail(f"{identifier}: package may not grant authority")
            profile_name = package["contract_profile"]
            profiles = catalog.get("contract_profiles", {})
            profile = profiles.get(profile_name)
            defaults = body.get("defaults")
            if not isinstance(profile, dict) or not isinstance(defaults, dict):
                fail(f"{identifier}: unresolved gate/profile contract")
            if len(profile.get("required_tests", [])) < 3 or len(profile.get("required_artifacts", [])) < 6:
                fail(f"{identifier}: resolved contract lacks tests or artifacts")
            if package["critical"] and profile.get("review_rule") not in {
                "INDEPENDENT_REVIEW_REQUIRED",
                "INDEPENDENT_SPECIALIST_REVIEW_REQUIRED",
            }:
                fail(f"{identifier}: critical package lacks independent review profile")
            if not package["critical"] and profile_name != "STANDARD":
                fail(f"{identifier}: non-critical package uses a critical contract profile")
            if defaults.get("authority_effect") != "NONE" or profile.get("authority_effect") != "NONE":
                fail(f"{identifier}: resolved contract may not grant authority")
            if len(defaults.get("explicit_non_scope", [])) < 3:
                fail(f"{identifier}: gate defaults lack explicit non-scope")
            if len(defaults.get("qualification_requires", [])) < 2:
                fail(f"{identifier}: gate qualification requirements too shallow")
    if actual_count != 301 or actual_count != catalog["package_count"]:
        fail(f"V1.2 actual work-package count drift: {actual_count}")
    previous = v11_work_package_ids()
    if identifiers != previous:
        fail(
            "V1.2 catalog must preserve every existing package ID: "
            f"removed={sorted(previous-identifiers)!r} added={sorted(identifiers-previous)!r}"
        )

    active = load_yaml("planning/HEPTABAO_ACTIVE_WORK_PACKAGE_CONTRACTS_V1.yaml")
    active_ids = [entry.get("id") for entry in active.get("contracts", [])]
    expected_active = sorted(
        identifier for identifier in identifiers if identifier[:3] in {"H00", "H01", "H02", "H03", "H04"}
    )
    if sorted(active_ids) != expected_active or len(active_ids) != len(set(active_ids)):
        fail("active H00-H04 contract coverage is incomplete or duplicated")
    return identifiers


def validate_blockers(document: dict[str, Any] | None = None) -> dict[str, Any]:
    register = document or load_yaml("planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml")
    if register.get("schema") != "heptabao.blocker-register.v1":
        fail("unexpected blocker-register schema")
    blockers = register.get("blockers")
    if not isinstance(blockers, list) or len(blockers) < 12:
        fail("blocker register is too shallow")
    ids: set[str] = set()
    external_count = 0
    repository_count = 0
    for blocker in blockers:
        identifier = blocker.get("id")
        if not isinstance(identifier, str) or identifier in ids:
            fail(f"invalid or duplicate blocker ID: {identifier!r}")
        ids.add(identifier)
        state = blocker.get("state")
        if state not in VALID_BLOCKER_STATES:
            fail(f"{identifier}: invalid blocker state {state!r}")
        cls = blocker.get("class")
        if cls == "REPOSITORY_CONTROLLED":
            repository_count += 1
            if state == "CLOSED" and not blocker.get("evidence"):
                fail(f"{identifier}: repository blocker closed without evidence")
        else:
            external_count += 1
            if state == "CLOSED":
                fail(f"{identifier}: external blocker may not be pre-closed by repository automation")
            if state != "EXTERNAL_ACTION_REQUIRED":
                fail(f"{identifier}: external blocker must remain EXTERNAL_ACTION_REQUIRED")
        if not blocker.get("closure_criteria"):
            fail(f"{identifier}: closure criteria missing")
    if repository_count < 7 or external_count < 7:
        fail("blocker classification coverage is incomplete")
    return register


def validate_workflow_policy(workflow_texts: dict[str, str] | None = None) -> None:
    if workflow_texts is None:
        paths = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
        workflow_texts = {str(path.relative_to(ROOT)): path.read_text(encoding="utf-8") for path in paths}
    if not workflow_texts:
        fail("no workflows found")
    for path, text in workflow_texts.items():
        for label, pattern in FORBIDDEN_WORKFLOW_PATTERNS.items():
            if pattern.search(text):
                fail(f"{path}: forbidden {label}")
    removed = {
        ".github/workflows/apply-h02-candidate-binding-contract.yml",
        ".github/workflows/apply-h02-deterministic-contract-closure.yml",
        ".github/workflows/apply-h02-validit-lock-binding.yml",
        ".github/workflows/materialize-plan-v1-1.yml",
    }
    existing = {path for path in workflow_texts if path in removed}
    if existing:
        fail(f"self-modifying maintenance workflows still present: {sorted(existing)!r}")
    integrity = workflow_texts.get(".github/workflows/plan-integrity-v4.yml", "")
    for token in (
        "permissions:\n  contents: read",
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}",
        "persist-credentials: false",
        "python3 scripts/validate_plan_v1_2.py",
        'TOOLCHAINS: "1.88.0 1.98.0"',
        'cargo +"$toolchain" test --locked --all-targets',
        'cargo +"$toolchain" clippy --locked --all-targets',
    ):
        if token not in integrity:
            fail(f"plan-integrity-v4 workflow missing token: {token}")


def validate_exact_openraft_lock(lock_document: dict[str, Any] | None = None) -> None:
    manifest_path = ROOT / "probes/h02/openraft-tokio/Cargo.toml"
    lock_path = ROOT / "probes/h02/openraft-tokio/Cargo.lock"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("package", {}).get("rust-version") != "1.88":
        fail("OpenRaft candidate effective rust-version must be 1.88")
    override = manifest.get("patch", {}).get("crates-io", {}).get("validit")
    expected_revision = "7016fa5e072a86092928144b3a3040381e6964e9"
    if override != {
        "git": "https://github.com/drmingdrmer/validit.git",
        "rev": expected_revision,
    }:
        fail("OpenRaft validit source override drift")
    lock = lock_document or tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package", [])
    exact = {
        "openraft": "0.10.0-alpha.33",
        "openraft-macros": "0.10.0-alpha.33",
        "openraft-memstore": "0.10.0-alpha.33",
        "openraft-rt": "0.10.0-alpha.33",
        "openraft-rt-tokio": "0.10.0-alpha.33",
        "validit": "0.2.5",
    }
    for name, version in exact.items():
        values = [entry for entry in packages if entry.get("name") == name]
        if len(values) != 1 or values[0].get("version") != version:
            fail(f"exact OpenRaft family drift for {name}: {values!r}")
    validit = next(entry for entry in packages if entry.get("name") == "validit")
    expected_source = (
        "git+https://github.com/drmingdrmer/validit.git?"
        f"rev={expected_revision}#{expected_revision}"
    )
    if validit.get("source") != expected_source:
        fail(f"validit lock source drift: {validit.get('source')!r}")



def validate_candidate_binding_contract() -> None:
    harness = (ROOT / "scripts/h02_candidate_adapter_harness_v1.py").read_text(encoding="utf-8")
    tests = (ROOT / "tests/platform/test_h02_candidate_adapter_harness_v1.py").read_text(encoding="utf-8")
    required = [
        '"source_overrides": {',
        "def _source_override_binding",
        'document.get("patch", {})',
        '"source_overrides": source_overrides',
        '"openraft-rt-tokio"',
        '"futures"',
        '"serde"',
    ]
    for token in required:
        if token not in harness:
            fail(f"candidate binding contract missing token: {token}")
    for token in (
        "test_source_override_is_separate_and_digest_bound",
        "test_source_override_drift_rejected",
        "test_unbound_patch_table_rejected",
    ):
        if token not in tests:
            fail(f"candidate source-override negative test missing: {token}")


def validate_durable_store_contract() -> None:
    store = (
        ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab/store.rs"
    ).read_text(encoding="utf-8")
    executable = (
        ROOT / "probes/h02/openraft-tokio/src/bin/durable_store_lab.rs"
    ).read_text(encoding="utf-8")
    required_store = [
        'const STATE_BUNDLE_MAGIC: [u8; 8] = *b"HBRSB001"',
        "struct PersistentStateBundle",
        'root.join("state-bundle.bin")',
        "let mut candidate = state.clone();",
        "self.persist(&candidate)?;",
        "let mut candidate = bundle.clone();",
        "self.persist_bundle(&candidate)?;",
        "recover_interrupted_replace",
        "failed_log_persist_does_not_publish_candidate_state",
        "failed_snapshot_persist_does_not_publish_snapshot_or_generation",
    ]
    for token in required_store:
        if token not in store:
            fail(f"durable store contract missing token: {token}")
    for forbidden in ('root.join("state-machine.bin")', 'root.join("snapshot.bin")'):
        if forbidden in store:
            fail(f"durable state/snapshot cross-generation file remains: {forbidden}")
    for token in (
        "durable-snapshot-state-atomic-generation-reopen",
        '"snapshot_state_atomic_bundle_publish": true',
        '"state_publish_after_durable_write": true',
        'root.join("state-bundle.bin")',
    ):
        if token not in executable:
            fail(f"durable executable contract missing token: {token}")

def validate_docs() -> None:
    required = {
        "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md": [
            "301", "SELF_RESOLVED_AT_VERIFICATION", "EXTERNAL_ACTION_REQUIRED", "HB-P0-DEV-MEMORY"
        ],
        "docs/storage/HEPTABAO_DURABILITY_AND_CRASH_CONSISTENCY_CONTRACT_V1.md": [
            "persist", "publish", "power-cut", "RPO=0"
        ],
        "docs/governance/HEPTABAO_EVIDENCE_TRUST_ROOT_AND_VERIFICATION_PROTOCOL_V1.md": [
            "SCHEMA_VALID", "CRYPTOGRAPHICALLY_VERIFIED_AND_CURRENT", "Revocation"
        ],
        "docs/compatibility/HEPTABAO_ORACLE_COMPATIBILITY_MATRIX_SPEC_V1.md": [
            "CAPTURED_RAW_RESTRICTED", "DIFFERENTIAL_PASS", "Side-effect"
        ],
    }
    for path, tokens in required.items():
        text = (ROOT / path).read_text(encoding="utf-8")
        for token in tokens:
            if token.lower() not in text.lower():
                fail(f"{path}: required concept missing: {token}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    if "current plan: **v1.2**" not in readme and "current plan: **v1.3**" not in readme:
        fail("README.md: current plan marker is missing")
    deployability = (
        "not yet a deployable secrets server",
        "not a production-deployable secrets server",
    )
    if not any(token in readme for token in deployability):
        fail("README.md: non-production deployability boundary is missing")


def validate_legacy_authority_flags() -> None:
    flags = load_yaml("planning/AUTHORITY_FLAGS_V2.yaml")
    for name, value in flags.get("flags", {}).items():
        expected = name == "implementation_started"
        if value is not expected:
            fail(f"legacy authority flag drift: {name}={value!r}, expected {expected!r}")
    if flags.get("active_grants"):
        fail("active authority grants must remain empty")


def run_all() -> dict[str, Any]:
    manifest = validate_manifest()
    validate_state_model()
    validate_canonical_state()
    packages = validate_work_packages()
    blockers = validate_blockers()
    validate_workflow_policy()
    validate_exact_openraft_lock()
    validate_candidate_binding_contract()
    validate_durable_store_contract()
    validate_docs()
    validate_legacy_authority_flags()
    return {
        "documents": len(manifest["documents"]),
        "work_packages": len(packages),
        "blockers": len(blockers["blockers"]),
        "qualification": False,
        "authority_effect": "NONE",
    }


def main() -> int:
    try:
        result = run_all()
    except (ValidationFailure, OSError, ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError) as error:
        print(f"HeptaBao Plan V1.2 validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "HeptaBao Plan V1.2 validation passed: "
        f"documents={result['documents']} work_packages={result['work_packages']} "
        f"blockers={result['blockers']} qualification=false authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
