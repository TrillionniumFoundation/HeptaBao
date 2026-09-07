#!/usr/bin/env python3
"""Validate H02 candidate probes and reduce executed outputs to fail-closed evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

try:
    from yaml12_loader import safe_load_yaml12
except ImportError:  # standalone probe checkout
    import yaml
    safe_load_yaml12 = yaml.safe_load

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml"
SCHEMA = ROOT / "schemas/heptabao_dependency_probe_evidence_v1.schema.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
UNSAFE = re.compile(r"\bunsafe\b")
FFI = re.compile(r'extern\s*"C"|#\s*\[\s*link\b|\blink_name\b|\bglobal_asm!?')
NATIVE_TOOLS = {"bindgen", "cc", "cmake", "pkg-config", "vcpkg", "nasm-rs", "aws-lc-sys", "ring"}
EXPECTED = {
    "HB-H02-PROBE-TOKIO-MINIMAL-SERVER": ("HB-DEP-ASYNC-TOKIO", "tokio", "1.53.1", "202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed", "75fef53d0a8590c2d1dbb63672aa7b7d1ef51155"),
    "HB-H02-PROBE-RUSTLS-RING": ("HB-DEP-TLS-RUSTLS", "rustls", "0.23.43", "0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06", "fcf61cdbba30913cfd5b40aefa83989c6233812d"),
    "HB-H02-PROBE-RUSTLS-AWS-LC": ("HB-DEP-TLS-RUSTLS", "rustls", "0.23.43", "0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06", "fcf61cdbba30913cfd5b40aefa83989c6233812d"),
    "HB-H02-PROBE-OPENRAFT-TOKIO": ("HB-DEP-RAFT-OPENRAFT", "openraft", "0.10.0-alpha.33", "ba6e911fb3c97faeecb8324b803a37d77a7387d02ee7019fc2a9777569e7f7b8", "2be3f99a23c0ec734aefc18d1c8e756b35567c35"),
}

class ProbeError(RuntimeError):
    pass

def fail(message: str) -> None:
    raise ProbeError(message)

def load_yaml(path: Path) -> dict[str, Any]:
    value = safe_load_yaml12(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path}: expected mapping")
    return value

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def digest_ref(path: Path, root: Path) -> dict[str, Any] | None:
    if not path.is_file() or path.stat().st_size == 0:
        return None
    try:
        name = path.relative_to(root).as_posix()
    except ValueError:
        name = str(path)
    return {"path": name, "sha256": sha_file(path), "byte_length": path.stat().st_size}

def profiles(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = matrix.get("profiles")
    if not isinstance(items, list):
        fail("profiles must be a list")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("profile_id"), str):
            fail("invalid profile")
        if item["profile_id"] in result:
            fail(f"duplicate profile {item['profile_id']}")
        result[item["profile_id"]] = item
    return result

def normalized_profile(item: dict[str, Any]) -> dict[str, Any]:
    keys = ["profile_id", "candidate_id", "capability", "package", "version", "probe_manifest", "default_features", "declared_rust_version", "probe_toolchains", "targets", "expected_registry_checksum_sha256", "expected_release_commit_sha", "required_cases"]
    value = {key: item[key] for key in keys}
    value["features"] = sorted(item["features"])
    value["forbidden_feature_expansion"] = sorted(item["forbidden_feature_expansion"])
    return value

def profile_digest(item: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(normalized_profile(item))).hexdigest()

def validate_manifest(item: dict[str, Any], root: Path) -> None:
    manifest_path = root / item["probe_manifest"]
    source_path = root / item["probe_source"]
    if not manifest_path.is_file() or not source_path.is_file():
        fail(f"{item['profile_id']}: missing probe file")
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    if "workspace" not in manifest or manifest.get("package", {}).get("publish") is not False:
        fail(f"{item['profile_id']}: probe must be isolated and publish=false")
    dep = manifest.get("dependencies", {}).get(item["package"])
    if not isinstance(dep, dict) or dep.get("version") != f"={item['version']}":
        fail(f"{item['profile_id']}: exact dependency pin missing")
    if dep.get("default-features") is not item["default_features"]:
        fail(f"{item['profile_id']}: default feature drift")
    features = dep.get("features", [])
    if sorted(features) != sorted(item["features"]):
        fail(f"{item['profile_id']}: feature drift")
    if set(features) & set(item["forbidden_feature_expansion"]):
        fail(f"{item['profile_id']}: forbidden feature enabled")

def validate_matrix(path: Path = MATRIX, root: Path = ROOT) -> int:
    matrix = load_yaml(path)
    if matrix.get("schema") != "heptabao.h02-candidate-probe-matrix.v1" or matrix.get("status") != "SPECIFIED_UNEXECUTED":
        fail("unexpected probe matrix state")
    if matrix.get("qualification") is not False or matrix.get("selection_effect") != "NONE" or matrix.get("authority_effect") != "NONE":
        fail("probe matrix attempted qualification or authority")
    found = profiles(matrix)
    if set(found) != set(EXPECTED):
        fail("probe set drift")
    for profile_id, item in found.items():
        candidate, package, version, checksum, commit = EXPECTED[profile_id]
        expected = {"candidate_id": candidate, "package": package, "version": version, "expected_registry_checksum_sha256": checksum, "expected_release_commit_sha": commit}
        for key, value in expected.items():
            if item.get(key) != value:
                fail(f"{profile_id}: {key} drift")
        if not SHA256.fullmatch(checksum) or not SHA40.fullmatch(commit):
            fail(f"{profile_id}: invalid source binding")
        if item.get("state") != "SPECIFIED_UNEXECUTED" or item.get("evidence_refs") != []:
            fail(f"{profile_id}: false execution claim")
        validate_manifest(item, root)
    return len(found)

def summarize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    packages = metadata.get("packages", [])
    if not isinstance(packages, list):
        fail("metadata packages missing")
    builds: list[str] = []
    links: list[str] = []
    native: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        identity = f"{package.get('name','')}@{package.get('version','')}"
        targets = package.get("targets", [])
        if any("custom-build" in target.get("kind", []) for target in targets if isinstance(target, dict)):
            builds.append(identity)
        if package.get("links"):
            links.append(identity)
        if package.get("name") in NATIVE_TOOLS:
            native.append(identity)
    normal = build = 0
    for node in metadata.get("resolve", {}).get("nodes", []):
        for dep in node.get("deps", []):
            kinds = dep.get("dep_kinds", []) or [{"kind": None}]
            for kind in kinds:
                if kind.get("kind") == "build": build += 1
                elif kind.get("kind") in (None, "normal"): normal += 1
    return {"package_count": len(packages), "normal_edge_count": normal, "build_edge_count": build, "build_script_packages": sorted(builds), "native_link_packages": sorted(links), "native_tool_packages": sorted(native)}

def scan_source_tree(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        fail(f"not a source directory: {root}")
    scanned = unsafe_files = unsafe_count = ffi_files = ffi_count = 0
    build_scripts: list[str] = []
    suffixes = {".rs", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".s", ".S"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or (path.name != "build.rs" and path.suffix not in suffixes):
            continue
        scanned += 1
        if path.name == "build.rs": build_scripts.append(path.relative_to(root).as_posix())
        text = path.read_text(encoding="utf-8", errors="replace")
        u = len(UNSAFE.findall(text)); f = len(FFI.findall(text))
        if u: unsafe_files += 1; unsafe_count += u
        if f: ffi_files += 1; ffi_count += f
    return {"schema":"heptabao.h02-source-scan.v1","classification":"HEURISTIC_UNREVIEWED","scanned_files":scanned,"heuristic_unsafe_files":unsafe_files,"heuristic_unsafe_occurrences":unsafe_count,"heuristic_ffi_files":ffi_files,"heuristic_ffi_occurrences":ffi_count,"build_scripts":build_scripts,"qualification":False,"selection_effect":"NONE","authority_effect":"NONE"}

def case_results(path: Path | None, required: list[str]) -> list[dict[str, Any]]:
    if path is None:
        return [{"case_id": item, "status": "UNEXECUTED", "evidence_ref": None} for item in required]
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list): fail("case results must be a list")
    by_id = {item["case_id"]: item for item in value if isinstance(item, dict)}
    if set(by_id) != set(required): fail("case result set mismatch")
    return [by_id[item] for item in required]

def collect(args: argparse.Namespace) -> dict[str, Any]:
    item = profiles(load_yaml(Path(args.matrix))).get(args.profile_id)
    if item is None: fail(f"unknown profile {args.profile_id}")
    root = Path(args.artifact_root).resolve(); metadata_path = root / args.metadata
    if metadata_path.is_file() and metadata_path.stat().st_size:
        try: metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            if args.metadata_status == "PASS": raise
            metadata = {"packages": [], "resolve": {"nodes": []}}
    else:
        if args.metadata_status == "PASS": fail("metadata PASS without artifact")
        metadata = {"packages": [], "resolve": {"nodes": []}}
    graph = summarize_metadata(metadata)
    scan = scan_source_tree(Path(args.source_root)) if args.source_root and Path(args.source_root).is_dir() else {"schema":"heptabao.h02-source-scan.v1","classification":"HEURISTIC_UNREVIEWED","scanned_files":0,"heuristic_unsafe_files":0,"heuristic_unsafe_occurrences":0,"heuristic_ffi_files":0,"heuristic_ffi_occurrences":0,"build_scripts":[],"qualification":False,"selection_effect":"NONE","authority_effect":"NONE"}
    (root / "source-scan.json").write_text(json.dumps(scan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    graph.update({key: scan[key] for key in ("heuristic_unsafe_files","heuristic_unsafe_occurrences","heuristic_ffi_files","heuristic_ffi_occurrences")})
    artifacts = {name: digest_ref(root / filename, root) for name, filename in {"cargo_lock":args.cargo_lock,"cargo_metadata":args.metadata,"dependency_tree":args.dependency_tree,"feature_tree":args.feature_tree,"build_log":args.build_log,"test_log":args.test_log,"source_scan":"source-scan.json"}.items()}
    cases = case_results(Path(args.case_results) if args.case_results else None, item["required_cases"])
    statuses = [args.lock_status,args.metadata_status,args.build_status,args.test_status] + [case["status"] for case in cases]
    failed = sum(value == "FAIL" for value in statuses)
    unknown = sum(value in {"BLOCKED","UNEXECUTED","UNKNOWN"} for value in statuses)
    status = "EXECUTED_PASS" if failed == unknown == 0 else "EXECUTED_FAIL" if failed else "BLOCKED"
    value = {
        "schema":"heptabao.dependency-probe-evidence.v1","plan_id":"HEPTABAO-PLAN-2026-08-28","revision":"1.1","evidence_id":args.evidence_id,"profile_id":item["profile_id"],"candidate_id":item["candidate_id"],"capability":item["capability"],"package":item["package"],"version":item["version"],"execution_kind":args.execution_kind,"status":status,"captured_at_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        "source":{"repository":"ProfHepta/HeptaBao","branch":args.branch,"commit_sha":args.commit_sha,"tree_sha":args.tree_sha,"clean_tree":args.clean_tree},
        "environment":{"environment_id":args.environment_id,"os":args.os or platform.system().lower(),"arch":args.arch or platform.machine(),"target":args.target,"toolchain":args.toolchain,"rustc":args.rustc,"cargo":args.cargo,"python":platform.python_version(),"runner_name":args.runner_name,"runner_id":int(args.runner_id) if args.runner_id else None,"job_id":int(args.job_id) if args.job_id else None,"container_or_image_digest":args.image_digest},
        "profile":{"manifest_path":item["probe_manifest"],"default_features":item["default_features"],"features":sorted(item["features"]),"profile_digest_sha256":profile_digest(item),"expected_registry_checksum_sha256":item["expected_registry_checksum_sha256"],"expected_release_commit_sha":item["expected_release_commit_sha"]},
        "artifacts":artifacts,"graph_summary":graph,
        "result":{"lock_status":args.lock_status,"metadata_status":args.metadata_status,"build_status":args.build_status,"test_status":args.test_status,"package_checksum_match":args.package_checksum_match,"package_vcs_commit_match":args.package_vcs_commit_match,"failed_steps":failed,"unknown_steps":unknown,"required_cases":cases},
        "review_status":{"license":"PENDING","security_advisories":"PENDING","unsafe_and_ffi":"PENDING","msrv":"PENDING","platform":"PENDING","specialist":"PENDING" if item["capability"] in {"TLS","RAFT"} else "NOT_REQUIRED","independent_reproduction_count":0},
        "qualification":False,"selection_effect":"NONE","authority_effect":"NONE"
    }
    errors = list(Draft202012Validator(json.loads(Path(args.schema).read_text()), format_checker=FormatChecker()).iter_errors(value))
    if errors: fail("generated evidence violates schema: " + "; ".join(error.message for error in errors))
    return value

def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__); sub = result.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-matrix"); validate.add_argument("--matrix", default=str(MATRIX)); validate.add_argument("--root", default=str(ROOT))
    scan = sub.add_parser("scan-source"); scan.add_argument("source_root"); scan.add_argument("--output")
    collect_p = sub.add_parser("collect")
    for name, default in (("matrix",str(MATRIX)),("schema",str(SCHEMA)),("cargo-lock","Cargo.lock"),("metadata","cargo-metadata.json"),("dependency-tree","dependency-tree.txt"),("feature-tree","feature-tree.txt"),("build-log","build.log"),("test-log","test.log")):
        collect_p.add_argument(f"--{name}", default=default)
    for name in ("profile-id","evidence-id","artifact-root","execution-kind","environment-id","branch","commit-sha","tree-sha","target","toolchain","output"):
        collect_p.add_argument(f"--{name}", required=True)
    collect_p.add_argument("--source-root"); collect_p.add_argument("--case-results"); collect_p.add_argument("--clean-tree", action=argparse.BooleanOptionalAction, default=False)
    for name in ("os","arch","rustc","cargo","runner-name","runner-id","job-id","image-digest"): collect_p.add_argument(f"--{name}")
    for name in ("lock-status","metadata-status","build-status","test-status"): collect_p.add_argument(f"--{name}", required=True, choices=["PASS","FAIL","BLOCKED","UNEXECUTED","UNKNOWN"])
    collect_p.add_argument("--package-checksum-match", action=argparse.BooleanOptionalAction, default=None); collect_p.add_argument("--package-vcs-commit-match", action=argparse.BooleanOptionalAction, default=None)
    return result

def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate-matrix": print(f"H02 probe matrix passed: profiles={validate_matrix(Path(args.matrix), Path(args.root))} selection=0 authority=NONE")
        elif args.command == "scan-source":
            value = scan_source_tree(Path(args.source_root)); text = json.dumps(value, indent=2, sort_keys=True) + "\n"
            Path(args.output).write_text(text) if args.output else print(text, end="")
        else:
            value = collect(args); Path(args.output).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n"); print(f"H02 probe evidence written: {args.output} status={value['status']} qualification=false authority=NONE")
    except (OSError, ValueError, json.JSONDecodeError, ProbeError) as error:
        print(f"H02 dependency probe FAILED: {error}", file=sys.stderr); return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
