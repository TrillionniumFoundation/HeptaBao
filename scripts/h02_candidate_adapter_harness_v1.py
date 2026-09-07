#!/usr/bin/env python3
"""Collect and compare H02 candidate-adapter behavior evidence.

The adapter process emits JSON Lines. This collector binds the output to an exact
candidate/version/manifest/toolchain/target/source and produces the existing
seeded-behavior evidence shape with qualification and authority fixed off.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import tomllib
from pathlib import Path
from typing import Any

PLAN_ID = "HEPTABAO-PLAN-2026-08-28"
REVISION = "1.1"
HARNESS_VERSION = "1.0.0"
SCHEMA = "heptabao.h02-seeded-behavior-evidence.v1"
COMPARISON_SCHEMA = "heptabao.h02-candidate-comparison.v1"
MASK64 = (1 << 64) - 1

PROFILES: dict[str, dict[str, Any]] = {
    "tokio": {
        "profile_id": "HB-H02-BEHAVIOR-RUNTIME-TOKIO-1_53_1",
        "candidate_id": "HB-DEP-ASYNC-TOKIO",
        "version": "1.53.1",
        "domain": "RUNTIME",
        "manifest": "probes/h02/tokio-minimal/Cargo.toml",
        "candidate_package": "tokio",
        "support_dependencies": [],
        "adapter_scope": "FULL_REFERENCE_CASE_SET",
        "cases": [
            "runtime-cancel-before-start",
            "runtime-cancel-during-wait",
            "runtime-equal-deadline-seed-replay",
            "runtime-task-panic-isolation",
            "runtime-bounded-blocking-saturation",
            "runtime-zero-task-resource-leak",
        ],
    },
    "rustls-ring": {
        "profile_id": "HB-H02-BEHAVIOR-TLS-RUSTLS-RING-0_23_43",
        "candidate_id": "HB-DEP-TLS-RUSTLS",
        "version": "0.23.43",
        "domain": "TLS",
        "manifest": "probes/h02/rustls-ring/Cargo.toml",
        "candidate_package": "rustls",
        "support_dependencies": ["zeroize"],
        "adapter_scope": "FULL_REFERENCE_CASE_SET",
        "cases": [
            "tls-version-policy-fail-closed",
            "tls-mutual-auth-identity-and-expiry",
            "tls-malformed-ticket-length-no-panic",
            "tls-atomic-stage-activate-revoke",
            "tls-handshake-time-and-byte-bounds",
            "tls-trace-secret-residue-zero",
        ],
    },
    "rustls-aws-lc": {
        "profile_id": "HB-H02-BEHAVIOR-TLS-RUSTLS-AWS_LC-0_23_43",
        "candidate_id": "HB-DEP-TLS-RUSTLS",
        "version": "0.23.43",
        "domain": "TLS",
        "manifest": "probes/h02/rustls-aws-lc/Cargo.toml",
        "candidate_package": "rustls",
        "support_dependencies": ["jobserver", "zeroize"],
        "adapter_scope": "FULL_REFERENCE_CASE_SET",
        "cases": [
            "tls-version-policy-fail-closed",
            "tls-mutual-auth-identity-and-expiry",
            "tls-malformed-ticket-length-no-panic",
            "tls-atomic-stage-activate-revoke",
            "tls-handshake-time-and-byte-bounds",
            "tls-trace-secret-residue-zero",
        ],
    },
    "openraft": {
        "profile_id": "HB-H02-BEHAVIOR-RAFT-OPENRAFT-0_10_0_ALPHA_33",
        "candidate_id": "HB-DEP-RAFT-OPENRAFT",
        "version": "0.10.0-alpha.33",
        "domain": "RAFT",
        "manifest": "probes/h02/openraft-tokio/Cargo.toml",
        "candidate_package": "openraft",
        "support_dependencies": [
            "futures",
            "openraft-macros",
            "openraft-memstore",
            "openraft-rt",
            "openraft-rt-tokio",
            "serde",
            "serde_json",
            "tokio",
        ],
        "source_overrides": {
            "validit": {
                "git": "https://github.com/drmingdrmer/validit.git",
                "rev": "7016fa5e072a86092928144b3a3040381e6964e9",
            }
        },
        "adapter_scope": "API_SEAM_AND_FAILURE_MODEL_PARTIAL",
        "cases": [
            "raft-deterministic-apply-and-restart",
            "raft-committed-snapshot-conflict-rejected",
            "raft-joint-membership-single-writer",
            "raft-process-pause-plus-partition",
            "raft-quorum-loss-fail-closed",
            "raft-incomplete-run-replay-diagnostics",
        ],
    },
}


class Failure(RuntimeError):
    pass


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_seed(raw: str) -> int:
    value = int(raw, 0)
    if value < 0 or value > MASK64:
        raise Failure("seed must be unsigned 64-bit")
    return value


def parse_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise Failure(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise Failure(f"{path}:{number}: row must be an object")
        rows.append(row)
    if not rows:
        raise Failure("adapter output is empty")
    return rows


def _direct_dependency_binding(path: Path, package: str, spec: Any) -> dict[str, Any]:
    if isinstance(spec, str):
        version = spec
        default_features = True
        features: list[str] = []
    elif isinstance(spec, dict):
        allowed_keys = {"version", "default-features", "features"}
        unexpected_keys = sorted(set(spec) - allowed_keys)
        if unexpected_keys:
            raise Failure(
                f"{path}: dependency {package!r} has unapproved keys: {unexpected_keys!r}"
            )
        version = str(spec.get("version", ""))
        default_features = bool(spec.get("default-features", True))
        raw_features = spec.get("features", [])
        if not isinstance(raw_features, list):
            raise Failure(f"{path}: dependency {package!r} features must be a list")
        features = sorted(str(item) for item in raw_features)
        if len(features) != len(set(features)):
            raise Failure(f"{path}: dependency {package!r} has duplicate features")
    else:
        raise Failure(
            f"{path}: dependency {package!r} must be a version string or inline table"
        )
    if not version.startswith("=") or len(version) <= 1:
        raise Failure(f"{path}: dependency {package!r} must use an exact =version pin")
    return {
        "package": package,
        "version": version,
        "default_features": default_features,
        "features": features,
    }


def _source_override_binding(path: Path, package: str, spec: Any) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise Failure(f"{path}: source override {package!r} must be an inline table")
    allowed_keys = {"git", "rev"}
    unexpected_keys = sorted(set(spec) - allowed_keys)
    if unexpected_keys:
        raise Failure(
            f"{path}: source override {package!r} has unapproved keys: {unexpected_keys!r}"
        )
    git = str(spec.get("git", ""))
    rev = str(spec.get("rev", ""))
    if not git.startswith("https://") or git.endswith("/"):
        raise Failure(f"{path}: source override {package!r} must use an exact HTTPS Git URL")
    if len(rev) != 40 or any(character not in "0123456789abcdef" for character in rev):
        raise Failure(f"{path}: source override {package!r} must use a full lowercase commit SHA")
    return {"package": package, "git": git, "rev": rev}


def manifest_binding(
    root: Path,
    profile: dict[str, Any],
    toolchain: str,
    target: str,
) -> dict[str, Any]:
    path = root / profile["manifest"]
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    dependencies = document.get("dependencies", {})
    if not isinstance(dependencies, dict) or not dependencies:
        raise Failure(f"{path}: direct dependency table is missing or empty")
    for table_name in ("dev-dependencies", "build-dependencies"):
        table = document.get(table_name, {})
        if table:
            raise Failure(f"{path}: unbound {table_name} table is forbidden")
    if document.get("target"):
        raise Failure(f"{path}: unbound target-specific dependency tables are forbidden")

    candidate_package = str(profile["candidate_package"])
    support_dependencies = sorted(
        str(item) for item in profile.get("support_dependencies", [])
    )
    if candidate_package in support_dependencies:
        raise Failure(f"{path}: candidate dependency cannot also be a support dependency")
    if len(support_dependencies) != len(set(support_dependencies)):
        raise Failure(f"{path}: duplicate support dependency declaration")

    expected_overrides_raw = profile.get("source_overrides", {})
    if not isinstance(expected_overrides_raw, dict):
        raise Failure(f"{path}: expected source override profile must be a mapping")
    expected_overrides = {
        str(package): _source_override_binding(path, str(package), spec)
        for package, spec in sorted(expected_overrides_raw.items())
    }
    patch_tables = document.get("patch", {})
    if not isinstance(patch_tables, dict):
        raise Failure(f"{path}: patch tables must be a mapping")
    if expected_overrides:
        if set(patch_tables) != {"crates-io"}:
            raise Failure(
                f"{path}: source override registry drift: {sorted(patch_tables)!r}"
            )
        crates_io = patch_tables.get("crates-io", {})
        if not isinstance(crates_io, dict):
            raise Failure(f"{path}: patch.crates-io must be a mapping")
        if set(crates_io) != set(expected_overrides):
            missing = sorted(set(expected_overrides) - set(crates_io))
            unexpected = sorted(set(crates_io) - set(expected_overrides))
            raise Failure(
                f"{path}: source override drift: missing={missing!r} unexpected={unexpected!r}"
            )
        source_overrides = {
            str(package): _source_override_binding(path, str(package), spec)
            for package, spec in sorted(crates_io.items())
        }
        for package, expected in expected_overrides.items():
            if source_overrides[package] != expected:
                raise Failure(
                    f"{path}: source override {package!r} drift: "
                    f"{source_overrides[package]!r} != {expected!r}"
                )
    else:
        if patch_tables:
            raise Failure(f"{path}: unbound patch tables are forbidden")
        source_overrides = {}

    expected_packages = {candidate_package, *support_dependencies}
    actual_packages = set(dependencies)
    if actual_packages != expected_packages:
        missing = sorted(expected_packages - actual_packages)
        unexpected = sorted(actual_packages - expected_packages)
        raise Failure(
            f"{path}: direct dependency drift: missing={missing!r} "
            f"unexpected={unexpected!r}"
        )

    dependency_profile = {
        package: _direct_dependency_binding(path, package, dependencies[package])
        for package in sorted(actual_packages)
    }
    candidate = dependency_profile[candidate_package]
    if candidate["version"] != f"={profile['version']}":
        raise Failure(f"{path}: candidate version drift: {candidate['version']!r}")

    binding = {
        "profile_id": profile["profile_id"],
        "candidate_id": profile["candidate_id"],
        "package": candidate_package,
        "version": profile["version"],
        "manifest_path": profile["manifest"],
        "manifest_sha256": file_sha256(path),
        "default_features": candidate["default_features"],
        "features": candidate["features"],
        "support_dependencies": support_dependencies,
        "direct_dependencies": dependency_profile,
        "source_overrides": source_overrides,
        "toolchain": toolchain,
        "target": target,
    }
    binding["feature_profile_sha256"] = sha256(binding)
    return binding


def _blocked_rows(profile: dict[str, Any], reason: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    meta = {
        "kind": "meta",
        "candidate_id": profile["candidate_id"],
        "version": profile["version"],
        "profile_id": profile["profile_id"],
        "domain": profile["domain"],
        "seed": None,
    }
    cases = [
        {
            "kind": "case",
            "case_id": case_id,
            "status": "BLOCKED",
            "assertion_count": 0,
            "detail": reason,
        }
        for case_id in profile["cases"]
    ]
    return meta, cases


def validate_rows(rows: list[dict[str, Any]], profile: dict[str, Any], seed: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    meta_rows = [row for row in rows if row.get("kind") == "meta"]
    case_rows = [row for row in rows if row.get("kind") == "case"]
    if len(meta_rows) != 1:
        raise Failure("adapter output must contain exactly one meta row")
    meta = meta_rows[0]
    expected_meta = {
        "candidate_id": profile["candidate_id"],
        "version": profile["version"],
        "profile_id": profile["profile_id"],
        "domain": profile["domain"],
        "seed": f"0x{seed:016x}",
    }
    for key, expected in expected_meta.items():
        if meta.get(key) != expected:
            raise Failure(f"adapter meta {key} mismatch: {meta.get(key)!r} != {expected!r}")
    expected_cases = list(profile["cases"])
    actual_cases = [row.get("case_id") for row in case_rows]
    if actual_cases != expected_cases:
        raise Failure(f"case order/identity mismatch: {actual_cases!r}")
    for row in case_rows:
        if row.get("status") not in {"PASS", "FAIL", "BLOCKED", "UNEXECUTED", "UNKNOWN"}:
            raise Failure(f"invalid case status: {row.get('status')!r}")
        assertions = row.get("assertion_count")
        if not isinstance(assertions, int) or assertions < 0:
            raise Failure("assertion_count must be a non-negative integer")
        detail = row.get("detail")
        if not isinstance(detail, str) or len(detail) > 4096:
            raise Failure("detail must be a bounded string")
        lowered = detail.lower()
        for marker in ("begin private key", "root_token", "authorization: bearer", "aws_secret_access_key"):
            if marker in lowered:
                raise Failure(f"secret marker in adapter detail: {marker}")
    return meta, case_rows


def collect(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).resolve()
    profile = PROFILES[args.profile]
    seed = parse_seed(args.seed)
    binding = manifest_binding(root, profile, args.toolchain, args.target)
    if args.execution_exit_code != 0:
        meta, cases = _blocked_rows(profile, f"adapter-process-exit-{args.execution_exit_code}")
        meta["seed"] = f"0x{seed:016x}"
    else:
        rows = parse_jsonl(Path(args.adapter_output))
        meta, cases = validate_rows(rows, profile, seed)
        if args.replay_output:
            replay = parse_jsonl(Path(args.replay_output))
            replay_meta, replay_cases = validate_rows(replay, profile, seed)
            if canon([replay_meta, replay_cases]) != canon([meta, cases]):
                raise Failure("candidate adapter replay output differs")

    trace: list[dict[str, Any]] = []
    evidence_cases: list[dict[str, Any]] = []
    for index, row in enumerate(cases):
        trace_start = len(trace)
        event = {
            "index": index,
            "domain": profile["domain"],
            "case_id": row["case_id"],
            "status": row["status"],
            "assertion_count": row["assertion_count"],
            "detail": row["detail"],
        }
        trace.append(event)
        evidence_cases.append(
            {
                "case_id": row["case_id"],
                "status": row["status"],
                "assertion_count": row["assertion_count"],
                "trace_start": trace_start,
                "trace_end": len(trace),
                "details_sha256": sha256({"detail": row["detail"]}),
            }
        )

    counts = {name: sum(1 for row in cases if row["status"] == name) for name in ["PASS", "FAIL", "BLOCKED", "UNEXECUTED", "UNKNOWN"]}
    if counts["FAIL"]:
        status = "EXECUTED_FAIL"
    elif counts["BLOCKED"]:
        status = "BLOCKED"
    elif counts["UNEXECUTED"]:
        status = "UNEXECUTED"
    elif counts["UNKNOWN"]:
        status = "UNKNOWN"
    else:
        status = "EXECUTED_PASS"

    final_state = {
        "candidate_id": profile["candidate_id"],
        "version": profile["version"],
        "profile_id": profile["profile_id"],
        "adapter_scope": profile["adapter_scope"],
        "feature_profile_sha256": binding["feature_profile_sha256"],
        "seed": seed,
        "case_statuses": {row["case_id"]: row["status"] for row in cases},
    }
    value = {
        "schema": SCHEMA,
        "plan_id": PLAN_ID,
        "revision": REVISION,
        "harness_version": HARNESS_VERSION,
        "execution_kind": "CANDIDATE_ADAPTER",
        "profile_id": profile["profile_id"],
        "domain": profile["domain"],
        "source": {
            "repository": "ProfHepta/HeptaBao",
            "commit_sha": args.source_commit,
            "tree_sha": args.source_tree,
            "branch": args.branch,
            "clean_tree": bool(args.clean_tree),
        },
        "environment": {
            "environment_id": args.environment_id,
            "executor_kind": args.executor_kind,
            "runner_id": args.runner_id,
            "runner_name": args.runner_name,
            "os": platform.system(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "attested": False,
        },
        "seed": {"decimal": seed, "hex": f"0x{seed:016x}"},
        "candidate": {
            "bound": True,
            "candidate_id": profile["candidate_id"],
            "version": profile["version"],
            "feature_profile_sha256": binding["feature_profile_sha256"],
        },
        "cases": evidence_cases,
        "trace_sha256": sha256(trace),
        "final_state_sha256": sha256(final_state),
        "summary": {
            "total": len(cases),
            "passed": counts["PASS"],
            "failed": counts["FAIL"],
            "blocked": counts["BLOCKED"],
            "unexecuted": counts["UNEXECUTED"],
            "unknown": counts["UNKNOWN"],
        },
        "status": status,
        "replay_command": f"cargo run --locked --manifest-path {profile['manifest']} -- --seed 0x{seed:016x}",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.binding_output:
        Path(args.binding_output).write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def compare(args: argparse.Namespace) -> dict[str, Any]:
    reference = json.loads(Path(args.reference).read_text(encoding="utf-8"))
    candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
    if reference.get("execution_kind") != "REFERENCE_MODEL":
        raise Failure("reference input is not REFERENCE_MODEL evidence")
    if candidate.get("execution_kind") != "CANDIDATE_ADAPTER":
        raise Failure("candidate input is not CANDIDATE_ADAPTER evidence")
    for field in ("domain", "seed"):
        if reference.get(field) != candidate.get(field):
            raise Failure(f"reference/candidate {field} mismatch")
    ref_cases = {row["case_id"]: row for row in reference["cases"]}
    cand_cases = {row["case_id"]: row for row in candidate["cases"]}
    if list(ref_cases) != list(cand_cases):
        raise Failure("reference/candidate case identity or order mismatch")
    pairs = []
    for case_id in ref_cases:
        r_status = ref_cases[case_id]["status"]
        c_status = cand_cases[case_id]["status"]
        if r_status != "PASS":
            classification = "REFERENCE_NOT_PASS"
        elif c_status == "PASS":
            classification = "INVARIANT_MATCH"
        elif c_status == "FAIL":
            classification = "DEVIATION_OR_DEFECT"
        else:
            classification = "INCOMPLETE"
        pairs.append({
            "case_id": case_id,
            "reference_status": r_status,
            "candidate_status": c_status,
            "classification": classification,
        })
    all_match = all(row["classification"] == "INVARIANT_MATCH" for row in pairs)
    adapter_scope = args.adapter_scope
    if all_match and adapter_scope == "FULL_REFERENCE_CASE_SET":
        result = "INVARIANT_EQUIVALENT_UNREVIEWED"
    elif all_match:
        result = "PARTIAL_ADAPTER_SCOPE_BLOCKS_PROMOTION"
    elif any(row["classification"] == "DEVIATION_OR_DEFECT" for row in pairs):
        result = "DEVIATION_OR_DEFECT_REVIEW_REQUIRED"
    else:
        result = "INCOMPLETE_BLOCKED"
    value = {
        "schema": COMPARISON_SCHEMA,
        "plan_id": PLAN_ID,
        "revision": REVISION,
        "reference_evidence_sha256": file_sha256(Path(args.reference)),
        "candidate_evidence_sha256": file_sha256(Path(args.candidate)),
        "candidate_id": candidate["candidate"]["candidate_id"],
        "version": candidate["candidate"]["version"],
        "profile_id": candidate["profile_id"],
        "domain": candidate["domain"],
        "seed": candidate["seed"],
        "adapter_scope": adapter_scope,
        "case_pairs": pairs,
        "result": result,
        "review_status": "PENDING",
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }
    Path(args.output).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    collect_p = sub.add_parser("collect")
    collect_p.add_argument("--profile", choices=sorted(PROFILES), required=True)
    collect_p.add_argument("--adapter-output", required=True)
    collect_p.add_argument("--replay-output")
    collect_p.add_argument("--execution-exit-code", type=int, default=0)
    collect_p.add_argument("--seed", required=True)
    collect_p.add_argument("--toolchain", required=True)
    collect_p.add_argument("--target", required=True)
    collect_p.add_argument("--source-commit", required=True)
    collect_p.add_argument("--source-tree", required=True)
    collect_p.add_argument("--branch", required=True)
    collect_p.add_argument("--clean-tree", action="store_true")
    collect_p.add_argument("--environment-id", required=True)
    collect_p.add_argument("--executor-kind", choices=["local-container", "github-hosted", "self-hosted", "offline-lab"], required=True)
    collect_p.add_argument("--runner-id")
    collect_p.add_argument("--runner-name")
    collect_p.add_argument("--root", default=".")
    collect_p.add_argument("--output", required=True)
    collect_p.add_argument("--binding-output")

    compare_p = sub.add_parser("compare")
    compare_p.add_argument("--reference", required=True)
    compare_p.add_argument("--candidate", required=True)
    compare_p.add_argument("--adapter-scope", choices=["FULL_REFERENCE_CASE_SET", "API_SEAM_AND_FAILURE_MODEL_PARTIAL"], required=True)
    compare_p.add_argument("--output", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        value = collect(args) if args.command == "collect" else compare(args)
    except (Failure, OSError, ValueError, KeyError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"H02 candidate adapter evidence FAILED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": value.get("status", value.get("result")), "authority_effect": value["authority_effect"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
