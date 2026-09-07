#!/usr/bin/env python3
"""Normalize V2.1 workspace truth after bounded module recovery.

This script never promotes authority. It aligns only repository-controlled package,
documentation, plan and blocker facts with the actual checked-out source tree.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

REQUIRED_HEADINGS = [
    "## Purpose and non-goals",
    "## Public API and ownership",
    "## State and data model",
    "## Invariants and authorization",
    "## Failure, retry and reconciliation",
    "## Concurrency and ordering",
    "## Security and privacy",
    "## Persistence and compatibility",
    "## Observability",
    "## Operations",
    "## Tests and executable evidence",
    "## Evolution and open boundaries",
]

DOMAINS = {
    "heptabao-aead-barrier": "production-oriented authenticated-encryption barrier",
    "heptabao-access-file": "persistent access policy and token verifier",
    "heptabao-audit-file": "authenticated append-only local audit provider",
    "heptabao-compatibility-runner": "deterministic differential compatibility runner",
    "heptabao-format-migration": "restart-safe persistent-format migration executor",
    "heptabao-http-adapter": "strict HTTP/1.1 request adapter",
    "heptabao-network-server": "bounded network service composition",
    "heptabao-plugin-host": "digest-approved bounded plugin process host",
    "heptabao-raft-replica": "persistent Raft safety-core replica",
    "heptabao-single-node-runtime": "concrete single-node AEAD audit durable runtime",
    "heptabao-tls-server": "TLS 1.3 transport boundary",
}

BLOCKERS = [
    {
        "id": "HB-V2-REP-011", "severity": "CRITICAL",
        "title": "production network and operator service boundary",
        "crates": ["heptabao-http-adapter", "heptabao-tls-server", "heptabao-network-server"],
        "evidence": ["crates/heptabao-http-adapter/src/lib.rs", "crates/heptabao-tls-server/src/lib.rs", "crates/heptabao-network-server/src/lib.rs"],
        "criteria": ["strict HTTP and TLS 1.3 boundaries are implemented", "network admission and shutdown are bounded", "exact-head and prospective-main-merge tests pass", "production deployment qualification remains external"],
    },
    {
        "id": "HB-V2-REP-012", "severity": "CRITICAL",
        "title": "persistent authentication and authorization provider",
        "crates": ["heptabao-access-file"],
        "evidence": ["crates/heptabao-access-file/src/lib.rs"],
        "criteria": ["persistent token and policy state fail closed", "expiry and revocation are enforced", "KMS custody and enterprise identity methods remain separately qualified"],
    },
    {
        "id": "HB-V2-REP-013", "severity": "CRITICAL",
        "title": "persistent HA and Raft safety core",
        "crates": ["heptabao-raft-replica"],
        "evidence": ["crates/heptabao-raft-replica/src/lib.rs"],
        "criteria": ["term vote log commit apply and snapshot state are persistent", "quorum and stale-leader cases fail closed", "multi-process network and destructive qualification remain separate"],
    },
    {
        "id": "HB-V2-REP-014", "severity": "HIGH",
        "title": "restart-safe product format migration",
        "crates": ["heptabao-format-migration"],
        "evidence": ["crates/heptabao-format-migration/src/lib.rs"],
        "criteria": ["source preservation writer fencing journaled stages and recovery are implemented", "real historical fixture and rolling-upgrade qualification remain separate"],
    },
    {
        "id": "HB-V2-REP-015", "severity": "CRITICAL",
        "title": "bounded plugin host and dynamic-secrets execution boundary",
        "crates": ["heptabao-plugin-host"],
        "evidence": ["crates/heptabao-plugin-host/src/lib.rs"],
        "criteria": ["digest approval no-shell execution output bounds and timeout are implemented", "OS sandbox and real dynamic-engine qualification remain separate"],
    },
    {
        "id": "HB-V2-REP-016", "severity": "HIGH",
        "title": "deterministic complete differential compatibility execution",
        "crates": ["heptabao-compatibility-runner"],
        "evidence": ["crates/heptabao-compatibility-runner/src/lib.rs"],
        "criteria": ["candidate and Oracle observations include status headers body state and effects", "coverage and mismatch handling fail closed", "real OpenBao corpus and independent admission remain external"],
    },
    {
        "id": "HB-V2-REP-017", "severity": "CRITICAL",
        "title": "concrete AEAD audit and single-node production composition",
        "crates": ["heptabao-aead-barrier", "heptabao-audit-file", "heptabao-single-node-runtime"],
        "evidence": ["crates/heptabao-aead-barrier/src/lib.rs", "crates/heptabao-audit-file/src/lib.rs", "crates/heptabao-single-node-runtime/src/lib.rs"],
        "criteria": ["authenticated encryption and audit chain are concrete", "single-node runtime composes both with durable service", "HSM custody and destructive I/O qualification remain external"],
    },
]


def load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: mapping required")
    return value


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True), encoding="utf-8")


def claims_closed(value: dict[str, Any]) -> None:
    claims = value.setdefault("claims", {})
    if not isinstance(claims, dict):
        raise SystemExit("claims must be a mapping")
    claims.update({
        "qualification": False,
        "compatibility_claim": False,
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    })


def walk_counts(value: Any, count: int) -> None:
    if isinstance(value, dict):
        for key, child in list(value.items()):
            if isinstance(child, int) and str(key).lower() in {
                "package_count", "workspace_package_count", "workspace_count", "module_count",
                "current_package_count", "current_workspace_count",
            }:
                value[key] = count
            else:
                walk_counts(child, count)
    elif isinstance(value, list):
        for child in value:
            walk_counts(child, count)


def block(text: str, marker: str, body: str) -> str:
    begin = f"<!-- {marker}_BEGIN -->"
    end = f"<!-- {marker}_END -->"
    rendered = f"{begin}\n{body.rstrip()}\n{end}"
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.S)
    if pattern.search(text):
        return pattern.sub(rendered, text, count=1)
    return text.rstrip() + "\n\n" + rendered + "\n"


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: normalize_v21_workspace.py REPOSITORY")
    repo = Path(sys.argv[1]).resolve()
    crates = sorted(path.name for path in (repo / "crates").iterdir() if path.is_dir() and (path / "Cargo.toml").is_file())
    count = len(crates)
    if count < 42:
        raise SystemExit(f"workspace regressed to {count} packages")

    plan_file = repo / "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md"
    match = re.search(r"HEPTABAO-PLAN-\d{4}-\d{2}-\d{2}-V2\.1", plan_file.read_text(encoding="utf-8"))
    plan_id = match.group(0) if match else "HEPTABAO-PLAN-2026-09-07-V2.1"

    state_path = repo / "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml"
    matrix_path = repo / "planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml"
    blocker_path = repo / "planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml"

    state = load(state_path)
    state["plan_id"] = plan_id
    walk_counts(state, count)
    claims_closed(state)
    save(state_path, state)

    matrix = load(matrix_path)
    matrix["plan_id"] = plan_id
    old_modules = matrix.get("modules", [])
    if not isinstance(old_modules, list):
        raise SystemExit("modules must be a list")
    by_name = {entry.get("crate"): entry for entry in old_modules if isinstance(entry, dict) and entry.get("crate")}
    modules = []
    for crate in crates:
        entry = dict(by_name.get(crate, {}))
        entry["crate"] = crate
        entry.setdefault("domain", DOMAINS.get(crate, crate.removeprefix("heptabao-").replace("-", " ")))
        entry.setdefault("state", "IMPLEMENTED_REVIEW_REQUIRED")
        entry.setdefault("documentation_standard", "V3" if crate in DOMAINS else "V2")
        entry["source"] = f"crates/{crate}/src/lib.rs"
        entry["guide"] = f"docs/modules/{crate}.md"
        modules.append(entry)
    matrix["modules"] = modules
    matrix["planned_modules"] = []
    claims_closed(matrix)
    save(matrix_path, matrix)

    blocker = load(blocker_path)
    blocker["plan_id"] = plan_id
    records = blocker.setdefault("repository_blockers", [])
    if not isinstance(records, list):
        raise SystemExit("repository_blockers must be a list")
    by_id = {entry.get("id"): entry for entry in records if isinstance(entry, dict) and entry.get("id")}
    for specification in BLOCKERS:
        present = all(crate in crates for crate in specification["crates"])
        record = dict(by_id.get(specification["id"], {}))
        record.update({
            "id": specification["id"],
            "class": "REPOSITORY_CONTROLLED",
            "severity": specification["severity"],
            "title": specification["title"],
            "state": "IMPLEMENTED_REVIEW_REQUIRED" if present else "SOURCE_REQUIRED",
            "evidence": specification["evidence"],
            "closure_criteria": specification["criteria"],
        })
        if specification["id"] in by_id:
            records[records.index(by_id[specification["id"]])] = record
        else:
            records.append(record)
    claims_closed(blocker)
    save(blocker_path, blocker)

    missing_guides = []
    invalid_guides = []
    for crate in crates:
        guide = repo / f"docs/modules/{crate}.md"
        if not guide.is_file():
            missing_guides.append(crate)
            continue
        if crate in DOMAINS:
            text = guide.read_text(encoding="utf-8")
            if any(text.count(heading) != 1 for heading in REQUIRED_HEADINGS):
                invalid_guides.append(crate)
            if "docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md" not in text:
                invalid_guides.append(crate)
    if missing_guides or invalid_guides:
        raise SystemExit(f"module-guide failure: missing={missing_guides} invalid={sorted(set(invalid_guides))}")

    readme = repo / "README.md"
    readme.write_text(block(readme.read_text(encoding="utf-8"), "HEPTABAO_V2_1_CURRENT_SCOPE", f"## Current V2.1 workspace truth\n\nThe active candidate contains exactly **{count} workspace packages**. Cargo membership, lockfile, capability matrix and module index must contain the same package set. This is implementation accounting only and grants no qualification or operational authority."), encoding="utf-8")

    current = repo / "docs/CURRENT_DOCUMENTATION.md"
    current.write_text(block(current.read_text(encoding="utf-8"), "HEPTABAO_V2_1_CURRENT_SCOPE", f"## V2.1 current workspace\n\nCurrent workspace count: **{count} workspace packages**. The capability matrix and per-package guides are the current source-accounting portals."), encoding="utf-8")

    index = repo / "docs/modules/README.md"
    original = index.read_text(encoding="utf-8")
    rows = ["| Package | Responsibility | Guide |", "|---|---|---|"]
    for crate in crates:
        rows.append(f"| `{crate}` | {DOMAINS.get(crate, 'module-specific contract and implementation')} | [{crate}.md]({crate}.md) |")
    body = f"## V2.1 current package index\n\nThe current source contains **{count} workspace packages**. The historical 40-package V2 scope remains historical evidence only.\n\n" + "\n".join(rows)
    index.write_text(block(original, "HEPTABAO_V2_1_CURRENT_SCOPE", body), encoding="utf-8")

    save(repo / "planning/HEPTABAO_V2_1_WORKSPACE_NORMALIZATION_STATUS.yaml", {
        "schema": "heptabao.v2.1.workspace-normalization.v1",
        "plan_id": plan_id,
        "workspace_packages": count,
        "recovered_modules": [crate for crate in crates if crate in DOMAINS],
        "state": "IMPLEMENTED_PENDING_EXACT_HEAD_AND_PROSPECTIVE_MAIN_MERGE_VALIDATION",
        "claims": {
            "qualification": False,
            "compatibility_claim": False,
            "production_authority": False,
            "migration_authority": False,
            "release_authority": False,
            "authority_effect": "NONE",
        },
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
