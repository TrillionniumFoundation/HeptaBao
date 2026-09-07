#!/usr/bin/env python3
"""Fail-closed semantic validator for HeptaBao Plan V1.3."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "planning/HEPTABAO_PLAN_V1_3_STATUS_V1.yaml"
STATUS_SCHEMA = ROOT / "schemas/heptabao_v1_3_foundation_status_v1.schema.json"
CANONICAL = ROOT / "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1_3.yaml"
MANIFEST = ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3.yaml"
WP_EXTENSION = ROOT / "planning/HEPTABAO_WORK_PACKAGE_EXTENSION_V1_3.yaml"
P0_CONTRACTS = ROOT / "planning/HEPTABAO_P0_WORK_PACKAGE_CONTRACTS_V1.yaml"
P0_TEST_MATRIX = ROOT / "planning/HEPTABAO_P0_TEST_MATRIX_V1.yaml"
THREAT_DELTA = ROOT / "docs/security/HEPTABAO_V1_3_THREAT_MODEL_DELTA.md"
ORACLE = ROOT / "planning/HEPTABAO_H01_ORACLE_EVIDENCE_RECONCILIATION_V1.yaml"
BLOCKERS = ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V1_3.yaml"
INHERITED_BLOCKERS = ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml"
AUTHORITY = ROOT / "planning/AUTHORITY_FLAGS_V2.yaml"
PROTOCOL = ROOT / "crates/heptabao-protocol/src/lib.rs"
AUTHBUS = ROOT / "crates/heptabao-authbus-contracts/src/lib.rs"
P0_LIB = ROOT / "crates/heptabao-p0-server/src/lib.rs"
P0_MAIN = ROOT / "crates/heptabao-p0-server/src/main.rs"
H02_CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/inmemory_cluster/cluster.rs"
H02_CLOCK = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/os_clock.rs"
H02_CLOCK_CLUSTER = ROOT / "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/os_clock_cluster.rs"
WORKFLOWS = ROOT / ".github/workflows"
RUST_SURFACE = ROOT / "scripts/validate_rust_source_surface_v1.py"

EXPECTED_NEW_CRATES = {
    "crates/heptabao-protocol",
    "crates/heptabao-authbus-contracts",
    "crates/heptabao-p0-server",
}
EXPECTED_AUTHBUS_PACKAGES = {
    "H03-WP11", "H07-WP11", "H16-WP11", "H21-WP12", "H25-WP13"
}
EXPECTED_NEW_BLOCKERS = {
    "HB-BLK-REPO-014", "HB-BLK-REPO-015", "HB-BLK-REPO-016", "HB-BLK-REPO-017"
}
EXPECTED_EXTERNAL = {
    "HB-BLK-CTRL-001", "HB-BLK-EXT-001", "HB-BLK-EXT-002", "HB-BLK-EXT-003",
    "HB-BLK-EXT-004", "HB-BLK-EXT-005", "HB-BLK-EXT-006", "HB-BLK-EXT-007",
}


class Failure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Failure(message)


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path}: expected mapping")
    return value


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), f"{path}: expected object")
    return value


def require_tokens(path: Path, tokens: Iterable[str]) -> None:
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        require(token in text, f"{path.relative_to(ROOT)} missing token: {token}")


def validate_status(path: Path = STATUS, schema_path: Path = STATUS_SCHEMA) -> None:
    schema = load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    value = load_yaml(path)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    require(not errors, f"V1.3 status schema errors: {[error.message for error in errors]}")


def validate_workspace(cargo_toml: Path | None = None, cargo_lock: Path | None = None) -> None:
    cargo_toml = cargo_toml or ROOT / "Cargo.toml"
    cargo_lock = cargo_lock or ROOT / "Cargo.lock"
    workspace = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    members = set(workspace.get("workspace", {}).get("members", []))
    require(EXPECTED_NEW_CRATES <= members, "V1.3 workspace crates are missing")
    require(len(members) == 7, f"expected seven workspace crates, observed {len(members)}")
    lock = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    packages = {item.get("name") for item in lock.get("package", [])}
    for package in ("heptabao-protocol", "heptabao-authbus-contracts", "heptabao-p0-server"):
        require(package in packages, f"Cargo.lock does not bind {package}")


def validate_work_packages(path: Path = WP_EXTENSION, p0_path: Path = P0_CONTRACTS) -> None:
    value = load_yaml(path)
    require(value.get("base_package_count") == 301, "V1.2 base package count drift")
    require(value.get("added_package_count") == 5, "Authbus package count drift")
    require(value.get("effective_package_count") == 306, "V1.3 effective package count drift")
    packages = value.get("packages", [])
    require({item.get("id") for item in packages} == EXPECTED_AUTHBUS_PACKAGES, "Authbus package identity drift")
    require(all(item.get("authority_effect") == "NONE" for item in packages), "Authbus package grants authority")
    p0 = load_yaml(p0_path)
    contracts = p0.get("contracts", [])
    require(len(contracts) >= 19, "P0 contract set is incomplete")
    require(all(item.get("implementation_state") == "IMPLEMENTED_LOCAL_UNQUALIFIED" for item in contracts), "P0 contract maturity drift")
    require(p0.get("qualification") is False and p0.get("authority_effect") == "NONE", "P0 contracts grant qualification or authority")


def validate_p0_test_matrix(path: Path = P0_TEST_MATRIX, threat_path: Path = THREAT_DELTA) -> None:
    value = load_yaml(path)
    require(value.get("profile") == "HB-P0-DEV-MEMORY", "P0 test profile drift")
    cases = value.get("cases", {})
    require(isinstance(cases, dict), "P0 test case groups missing")
    flattened = [case for group in cases.values() for case in group]
    require(len(flattened) == 22, f"expected 22 P0 cases, observed {len(flattened)}")
    require(len({case.get("id") for case in flattened}) == 22, "duplicate P0 test case identity")
    require(value.get("execution_requirements", {}).get("h02_matrix", {}).get("entries") == 24, "P0/H02 matrix size drift")
    require(value.get("qualification") is False and value.get("authority_effect") == "NONE", "P0 matrix grants qualification or authority")
    require_tokens(threat_path, (
        "HTTP request smuggling", "Audit bypass before mutation",
        "Authbus assertion replay", "Authentication confused with authorization",
        "Automatic snapshot purges replay source", "Fixed leader assumed after process pause",
    ))


def validate_oracle(path: Path = ORACLE) -> None:
    value = load_yaml(path)
    claim = value.get("claim_source", {})
    observation = value.get("repository_observation", {})
    require(claim.get("claimed_local_vectors") == 4, "Oracle local claim count must be retained")
    require(len(claim.get("claimed_vector_ids", [])) == 4, "Oracle claimed vector identity set is incomplete")
    require(observation.get("repository_verifiable_transferred_vectors") == 0, "unmaterialized Oracle claim was treated as transferred evidence")
    require(observation.get("signed_transfer_records") == 0, "Oracle signed transfer was fabricated")
    require(observation.get("qualified_vectors") == 0, "Oracle qualification was fabricated")
    require(observation.get("known_oracle_branch_fixture_class") == "SYNTHETIC_ONLY", "synthetic Oracle fixture was relabeled")
    require(value.get("qualification") is False and value.get("compatibility_claim") is False, "Oracle reconciliation self-qualified")


def validate_blockers(path: Path = BLOCKERS, inherited_path: Path = INHERITED_BLOCKERS) -> None:
    value = load_yaml(path)
    added = value.get("added_blockers", [])
    require({item.get("id") for item in added} == EXPECTED_NEW_BLOCKERS, "V1.3 blocker identity drift")
    require(all(item.get("state") == "REMEDIATION_IMPLEMENTED_LOCAL" for item in added), "new repository blocker overclaims closure")
    require(value.get("effective_counts") == {"repository_controlled": 17, "external_or_repository_setting": 8, "total": 25}, "V1.3 blocker counts drift")
    require(set(value.get("external_blockers_must_remain_open", [])) == EXPECTED_EXTERNAL, "external blocker set drift")
    inherited = load_yaml(inherited_path)
    external = {item.get("id"): item for item in inherited.get("blockers", []) if item.get("id") in EXPECTED_EXTERNAL}
    require(set(external) == EXPECTED_EXTERNAL, "inherited external blockers are missing")
    for identifier, blocker in external.items():
        require(blocker.get("state") != "CLOSED", f"external blocker was self-closed: {identifier}")


def validate_protocol(path: Path = PROTOCOL) -> None:
    text = path.read_text(encoding="utf-8")
    for token in (
        "MAX_HTTP_HEAD_BYTES: usize = 16 * 1024",
        "MAX_HTTP_BODY_BYTES: usize = 1024 * 1024",
        "MAX_HEADER_COUNT: usize = 64",
        "TransferEncodingForbidden",
        "ContentLengthExceeded",
        "DuplicateHeader",
        "NonCanonicalPercentEncoding",
        "DeadlineExceeded",
        'formatter.write_str("SecretBytes([REDACTED])")',
        "self.0.fill(0)",
    ):
        require(token in text, f"protocol invariant missing: {token}")
    require("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct SecretBytes" not in text, "secret Debug leaks owned bytes")
    require("pub fn parse_http_request" in text and "pub fn classify_operation" in text, "protocol entry points missing")


def validate_authbus(path: Path = AUTHBUS) -> None:
    text = path.read_text(encoding="utf-8")
    for token in (
        "pub struct UnixTimeSeconds",
        "MAX_ASSERTION_TTL_SECONDS: u64 = 30",
        "MAX_CLOCK_SKEW_SECONDS: u64 = 5",
        "heptabao-authbus-request-v1",
        "heptabao-authbus-assertion-v1",
        "signature_verifier.verify",
        "replay_cache.check_and_record",
        "authorization_effect: AuthorizationEffect::None",
        "pub enum AuthorizationEffect {\n    None,\n}",
    ):
        require(token in text, f"Authbus invariant missing: {token}")
    require("MonotonicTick" not in text, "cross-process Authbus assertion uses a process-local monotonic tick")
    require("AuthorizationEffect::Grant" not in text and "AuthorizationEffect::Allow" not in text, "Authbus can grant authorization")


def validate_p0(lib_path: Path = P0_LIB, main_path: Path = P0_MAIN) -> None:
    lib = lib_path.read_text(encoding="utf-8")
    main = main_path.read_text(encoding="utf-8")
    for token in (
        "P0_PRODUCTION_SUPPORTED: bool = false",
        "P0_COMPATIBILITY_CLAIM: bool = false",
        'P0_AUTHORITY_EFFECT: &str = "NONE"',
        "request audit unavailable",
        "rejection audit unavailable",
        "response audit failed after commit",
        "recovery_reference",
        "create_new(true)",
        "symlink_metadata",
    ):
        require(token in lib, f"P0 invariant missing: {token}")
    for token in (
        'env::var("HEPTABAO_P0_DEV_TOKEN")',
        'env::var("HEPTABAO_P0_DEV_UNSEAL_KEY")',
        'env::var("HEPTABAO_P0_AUDIT_PATH")',
        "is_loopback(address.ip())",
        "Host must exactly match the loopback listener address",
        "set_read_timeout",
        "set_write_timeout",
        "production_supported=false authority=NONE",
    ):
        require(token in main, f"P0 binary invariant missing: {token}")
    non_test = lib.split("#[cfg(test)]", 1)[0]
    for literal in ("development-root-token-0001", "development-unseal-key-0001"):
        require(literal not in non_test and literal not in main, f"hard-coded development credential in runtime source: {literal}")


def validate_h02(cluster_path: Path = H02_CLUSTER, clock_path: Path = H02_CLOCK, clock_cluster_path: Path = H02_CLOCK_CLUSTER) -> None:
    cluster = cluster_path.read_text(encoding="utf-8")
    clock = clock_path.read_text(encoding="utf-8")
    child = clock_cluster_path.read_text(encoding="utf-8")
    require("snapshot_policy: SnapshotPolicy::Never" in cluster, "in-memory replay topology can automatically purge required logs")
    require("snapshot_policy: SnapshotPolicy::LogsSinceLast(3)" not in cluster, "automatic snapshot purge was reintroduced")
    for token in ("async fn consensus_leader", "timed out waiting for one post-resume consensus leader", "let leader = self.consensus_leader().await?", ".ensure_linearizable(ReadPolicy::ReadIndex)"):
        require(token in child, f"post-resume leader discovery missing: {token}")
    require("cluster.nodes[&1].raft.current_leader" not in child, "OS/clock case still assumes node 1 leader")
    require("Duration::from_secs(40)" in clock, "post-resume bounded recovery window is missing")


def validate_manifest(path: Path = MANIFEST) -> None:
    value = load_yaml(path)
    require(value.get("inherits") == "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml", "V1.3 manifest inheritance drift")
    documents = value.get("documents", [])
    paths = {item.get("path") for item in documents}
    require(len(documents) >= 18, "V1.3 normative extension is incomplete")
    for relative in paths:
        require(isinstance(relative, str) and (ROOT / relative).is_file(), f"manifest target missing: {relative}")
    require(all(item.get("authority_effect") == "NONE" for item in documents), "normative document grants authority")


def validate_workflow_directory(directory: Path = WORKFLOWS) -> None:
    forbidden = (
        re.compile(r"(?mi)^\s*contents\s*:\s*write\s*$"),
        re.compile(r"(?mi)^\s*persist-credentials\s*:\s*true\s*$"),
        re.compile(r"(?mi)^\s*git\s+(?:commit|push|rebase|merge)\b"),
    )
    for path in sorted(directory.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            require(not pattern.search(text), f"write-capable workflow surface: {path.name}")


def validate_authority(path: Path = AUTHORITY, canonical_path: Path = CANONICAL) -> None:
    authority = load_yaml(path)
    flags = authority.get("flags", {})
    require(isinstance(flags, dict), "authority flags missing")
    for key, enabled in flags.items():
        if key != "implementation_started":
            require(enabled is False, f"authority flag enabled: {key}")
    require(authority.get("active_grants") == [], "active authority grant exists")
    canonical = load_yaml(canonical_path)
    require(canonical.get("qualification") is False and canonical.get("compatibility_claim") is False, "canonical state self-qualified")
    require(canonical.get("selected_candidates") == [], "canonical state selected a candidate")
    require(all(value is False for value in canonical.get("authority_flags", {}).values()), "canonical authority flag enabled")


def validate_rust_surfaces() -> None:
    spec = importlib.util.spec_from_file_location("rust_surface", RUST_SURFACE)
    require(spec is not None and spec.loader is not None, "unable to load Rust surface validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in (PROTOCOL, AUTHBUS, P0_LIB, P0_MAIN):
        module.validate_file(path)


def validate() -> None:
    required = (
        STATUS, STATUS_SCHEMA, CANONICAL, MANIFEST, WP_EXTENSION, P0_CONTRACTS,
        P0_TEST_MATRIX, THREAT_DELTA, ORACLE, BLOCKERS, INHERITED_BLOCKERS, AUTHORITY, PROTOCOL, AUTHBUS,
        P0_LIB, P0_MAIN, H02_CLUSTER, H02_CLOCK, H02_CLOCK_CLUSTER, RUST_SURFACE,
        ROOT / "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_3.md",
        ROOT / "docs/plan/HEPTABAO_PLAN_V1_3_AMENDMENT.md",
        ROOT / "docs/protocol/HEPTABAO_H03_PROTOCOL_CONTRACT_V1.md",
        ROOT / "docs/auth/HEPTABAO_AUTHBUS_INTEGRATION_CONTRACT_V1.md",
        ROOT / "docs/execution/HEPTABAO_P0_DEV_MEMORY_EXECUTION_CONTRACT_V1.md",
    )
    for path in required:
        require(path.is_file(), f"missing V1.3 artifact: {path.relative_to(ROOT)}")
    validate_status()
    validate_workspace()
    validate_work_packages()
    validate_p0_test_matrix()
    validate_oracle()
    validate_blockers()
    validate_protocol()
    validate_authbus()
    validate_p0()
    validate_h02()
    validate_manifest()
    validate_workflow_directory()
    validate_authority()
    validate_rust_surfaces()


def main() -> int:
    try:
        validate()
    except (Failure, OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as error:
        print(f"V1.3 validation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "V1.3 validation passed: effective-work-packages=306; new-crates=3; "
        "repository-remediation=IMPLEMENTED_LOCAL; remote/external closure required; "
        "qualification=false selection=NONE authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
