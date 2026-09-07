#!/usr/bin/env python3
"""Fail-closed V2.1 G0 remediation for the exact PR #75 source tree."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

EXPECTED_HEAD = "ff8ff379509baa95f54744f0b931810d1f115211"
DEFAULT_PLAN_ID = "HEPTABAO-PLAN-2026-09-07-V2.1"
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


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected mapping")
    return value


def dump_yaml(path: Path, value: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True), encoding="utf-8")


def discover_plan_id(repo: Path) -> str:
    plan = repo / "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V2_1.md"
    if plan.exists():
        match = re.search(r"HEPTABAO-PLAN-\d{4}-\d{2}-\d{2}-V2\.1", plan.read_text(encoding="utf-8"))
        if match:
            return match.group(0)
    return DEFAULT_PLAN_ID


def update_named_counts(value: Any, count: int) -> None:
    if isinstance(value, dict):
        for key, item in list(value.items()):
            normalized = str(key).lower()
            if isinstance(item, int) and normalized in {
                "package_count", "workspace_package_count", "workspace_count",
                "module_count", "current_package_count", "current_workspace_count",
            }:
                value[key] = count
            else:
                update_named_counts(item, count)
    elif isinstance(value, list):
        for item in value:
            update_named_counts(item, count)


def ensure_claims_closed(value: dict[str, Any]) -> None:
    claims = value.setdefault("claims", {})
    if isinstance(claims, dict):
        claims.update({
            "qualification": False,
            "compatibility_claim": False,
            "production_authority": False,
            "migration_authority": False,
            "release_authority": False,
            "authority_effect": "NONE",
        })


def guide(crate: str, purpose: str, runtime: bool) -> str:
    persistence = (
        "This module owns restart-safe state, intent, replay-ledger and acknowledgement ordering. "
        "All persisted payloads cross a caller-supplied authenticated-encryption barrier."
        if runtime
        else
        "This module composes authorization and the durable mutation boundary; it does not invent a second persistence format."
    )
    return f"""# `{crate}` technical development guide

This guide follows `docs/modules/MODULE_DOCUMENTATION_STANDARD_V3.md` and the shared rules in `docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md`.

## Purpose and non-goals

{purpose}

The module is repository-candidate code. It does not by itself grant production, compatibility, migration or release authority, and it does not replace independent security, legal, operational or destructive-platform qualification.

## Public API and ownership

The Rust source at `crates/{crate}/src/lib.rs` is authoritative for public types and functions. The module owns only its explicitly documented request, outcome and recovery contracts. Upstream authentication and policy providers retain ownership of identity and authorization decisions; storage and cryptographic providers retain ownership of their guarantees.

## State and data model

Request identity is bound to authenticated principal, namespace, operation, resource and authorization context. Mutation data is bounded. Committed, unresolved and replay-protected identities are represented explicitly rather than inferred from transport success.

## Invariants and authorization

Authorization must complete before irreversible mutation entry. Namespace qualification is part of the authorization resource. A request identifier cannot be rebound to different principal, namespace, operation, resource, authorization digest or value digest. Ambiguous after-entry effects remain non-retriable until authoritative reconciliation.

## Failure, retry and reconciliation

Before-entry rejection is safe for a new, newly bound attempt. After-entry uncertainty returns a service-generated recovery reference and forbids blind retry. Reconciliation reads authoritative state and replay metadata; caller-provided success receipts are never treated as authority.

## Concurrency and ordering

Single-writer fencing protects the local durable domain. The required order is validation and authorization, durable intent, protected state publication, durable commit classification, protected replay record, response/audit completion, then acknowledgement. No acknowledgement may precede its required durable facts.

## Security and privacy

Secrets are excluded from `Debug`, diagnostics, metric labels and recovery references. Security bindings use domain-separated, length-delimited SHA-256 rather than ad-hoc non-cryptographic digests. Persisted confidential material requires an authenticated-encryption provider with context binding and independently managed keys.

## Persistence and compatibility

{persistence}

Formats are versioned, bounded and fail closed on truncation, trailing data, authentication failure or identity mismatch. Format migration and OpenBao compatibility require separate evidence and are not inferred from successful local decoding.

## Observability

Operators receive bounded status, phase, generation and opaque recovery identifiers. Logs and telemetry must not contain secret bytes, bearer credentials, raw authorization material, request bodies or unbounded caller-controlled labels.

## Operations

Create and reopen are separate operations. Reopen verifies writer fencing and all durable domains before serving. Disk-full, barrier failure, audit failure and unknown provider outcome stop acknowledgement and require the runbook path in `docs/operations/HEPTABAO_SINGLE_NODE_OPERATOR_RUNBOOK_V1.md`.

## Tests and executable evidence

Repository tests cover request binding, authorization ordering, restart recovery, duplicate suppression, namespace isolation, tamper rejection, ambiguous outcomes and fail-closed error handling. The exact head and prospective merge must pass repository, security, platform, Oracle, documentation, Rust formatting, locked all-target tests, warnings-denied Clippy and rustdoc gates.

## Evolution and open boundaries

Production admission still requires qualified AEAD/KMS/HSM custody, TLS/network operation, destructive I/O tests, HA/Raft integration, migration fixtures, compatibility corpus, independent review, incident ownership and release governance. Any source, dependency, format or workflow change invalidates prior exact-head evidence.
"""


def canonical_block(text: str, marker: str, body: str) -> str:
    begin = f"<!-- {marker}_BEGIN -->"
    end = f"<!-- {marker}_END -->"
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.S)
    block = f"{begin}\n{body.rstrip()}\n{end}"
    if pattern.search(text):
        return pattern.sub(block, text, count=1)
    return text.rstrip() + "\n\n" + block + "\n"


def split_params(params: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(params):
        if char in "([{<":
            depth += 1
        elif char in ")]}>" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(params[start:index].strip())
            start = index + 1
    tail = params[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def hash_statements(params: str, indent: str) -> list[str] | None:
    statements: list[str] = []
    for raw in split_params(params):
        if not raw or raw in {"&self", "self", "&mut self"}:
            return None
        if ":" not in raw:
            return None
        name, typ = [piece.strip() for piece in raw.split(":", 1)]
        name = name.removeprefix("mut ").strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return None
        normalized = re.sub(r"\s+", "", typ)
        if normalized in {"&[u8]", "&Vec<u8>", "&[u8;32]"}:
            statements += [
                f"{indent}hasher.update(({name}.len() as u64).to_be_bytes());",
                f"{indent}hasher.update({name});",
            ]
        elif normalized == "[u8;32]":
            statements += [
                f"{indent}hasher.update(32_u64.to_be_bytes());",
                f"{indent}hasher.update({name});",
            ]
        elif normalized in {"&str", "String", "&String"}:
            statements += [
                f"{indent}hasher.update(({name}.as_bytes().len() as u64).to_be_bytes());",
                f"{indent}hasher.update({name}.as_bytes());",
            ]
        elif normalized in {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize"}:
            local = f"{name}_hash_bytes"
            statements += [
                f"{indent}let {local} = {name}.to_be_bytes();",
                f"{indent}hasher.update(({local}.len() as u64).to_be_bytes());",
                f"{indent}hasher.update({local});",
            ]
        elif normalized == "bool":
            statements += [
                f"{indent}hasher.update(1_u64.to_be_bytes());",
                f"{indent}hasher.update([u8::from({name})]);",
            ]
        elif normalized in {"&[&[u8]]", "&[Vec<u8>]"}:
            statements += [
                f"{indent}hasher.update(({name}.len() as u64).to_be_bytes());",
                f"{indent}for field in {name} {{",
                f"{indent}    hasher.update((field.len() as u64).to_be_bytes());",
                f"{indent}    hasher.update(field);",
                f"{indent}}}",
            ]
        else:
            return None
    return statements


def replace_weak_hashes(path: Path, domain: str) -> int:
    source = path.read_text(encoding="utf-8")
    marker_tokens = ("wrapping_mul", "wrapping_add", "rotate_left", "rotate_right", "FNV", "fnv")
    pattern = re.compile(
        r"(?ms)^(?P<indent>[ \t]*)(?P<header>(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>.*?)\)\s*->\s*\[u8\s*;\s*32\]\s*)\{"
    )
    replacements: list[tuple[int, int, str]] = []
    for match in pattern.finditer(source):
        start_brace = match.end() - 1
        depth = 0
        end = None
        for index in range(start_brace, len(source)):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            raise SystemExit(f"{path}: unterminated function {match.group('name')}")
        body = source[start_brace:end]
        name = match.group("name")
        if not (any(token in body for token in marker_tokens) or ("digest" in name.lower() and "Sha256" not in body)):
            continue
        inner = match.group("indent") + "    "
        statements = hash_statements(match.group("params"), inner)
        if statements is None:
            continue
        new_body = [
            match.group("indent") + match.group("header") + "{",
            f"{inner}let mut hasher = Sha256::new();",
            f"{inner}hasher.update(b\"heptabao:v2.1:{domain}:{name}\\0\");",
            *statements,
            f"{inner}hasher.finalize().into()",
            match.group("indent") + "}",
        ]
        replacements.append((match.start(), end, "\n".join(new_body)))
    for start, end, replacement in reversed(replacements):
        source = source[:start] + replacement + source[end:]
    if replacements and "use sha2::{Digest, Sha256};" not in source:
        insertion = source.find("\n", source.find("#![forbid(unsafe_code)]")) + 1
        source = source[:insertion] + "\nuse sha2::{Digest, Sha256};\n" + source[insertion:]
    path.write_text(source, encoding="utf-8")
    return len(replacements)


def ensure_sha2_dependency(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^sha2\s*=", text):
        return
    match = re.search(r"(?m)^\[dependencies\]\s*$", text)
    if match:
        insert = match.end()
        text = text[:insert] + '\nsha2 = "0.10.9"' + text[insert:]
    else:
        text = text.rstrip() + '\n\n[dependencies]\nsha2 = "0.10.9"\n'
    path.write_text(text, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: remediate_pr75_g0.py REPOSITORY")
    repo = Path(sys.argv[1]).resolve()
    actual_head = __import__("subprocess").check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if actual_head != EXPECTED_HEAD:
        raise SystemExit(f"exact-head drift: {actual_head}")

    crates = sorted(
        path.name for path in (repo / "crates").iterdir()
        if path.is_dir() and (path / "Cargo.toml").is_file()
    )
    if len(crates) != 42:
        raise SystemExit(f"expected 42 crates, found {len(crates)}")
    plan_id = discover_plan_id(repo)

    state_path = repo / "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml"
    matrix_path = repo / "planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml"
    blocker_path = repo / "planning/HEPTABAO_BLOCKER_REGISTER_V2_0.yaml"

    state = load_yaml(state_path)
    state["plan_id"] = plan_id
    update_named_counts(state, len(crates))
    ensure_claims_closed(state)
    dump_yaml(state_path, state)

    matrix = load_yaml(matrix_path)
    matrix["plan_id"] = plan_id
    modules = matrix.get("modules", [])
    if not isinstance(modules, list):
        raise SystemExit("capability matrix modules must be a list")
    by_crate = {entry.get("crate"): entry for entry in modules if isinstance(entry, dict) and entry.get("crate")}
    domains = {
        "heptabao-durable-service": "restart-safe durable mutation runtime",
        "heptabao-runtime-service": "authorization and durable mutation composition",
    }
    normalized = []
    for crate in crates:
        entry = dict(by_crate.get(crate, {}))
        entry.setdefault("crate", crate)
        entry.setdefault("domain", domains.get(crate, crate.removeprefix("heptabao-").replace("-", " ")))
        entry.setdefault("state", "IMPLEMENTED_REVIEW_REQUIRED")
        entry.setdefault("documentation_standard", "V3" if crate in domains else "V2")
        entry["source"] = f"crates/{crate}/src/lib.rs"
        entry["guide"] = f"docs/modules/{crate}.md"
        normalized.append(entry)
    matrix["modules"] = normalized
    matrix["planned_modules"] = []
    ensure_claims_closed(matrix)
    dump_yaml(matrix_path, matrix)

    blocker = load_yaml(blocker_path)
    blocker["plan_id"] = plan_id
    repository_blockers = blocker.setdefault("repository_blockers", [])
    if not isinstance(repository_blockers, list):
        raise SystemExit("repository_blockers must be a list")
    existing_ids = {entry.get("id") for entry in repository_blockers if isinstance(entry, dict)}
    additions = [
        {
            "id": "HB-V2-REP-008", "class": "REPOSITORY_CONTROLLED", "severity": "HIGH",
            "title": "V2.1 current truth, workspace count and lockfile drift",
            "state": "IMPLEMENTED_REVIEW_REQUIRED",
            "evidence": ["planning/HEPTABAO_CANONICAL_PROJECT_STATE_V2_0.yaml", "planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml", "Cargo.lock", "docs/CURRENT_DOCUMENTATION.md", "docs/modules/README.md"],
            "closure_criteria": ["42-package workspace matrix lock and module index agree", "exact-head and prospective-main-merge validators pass", "fresh independent review accepts the unchanged head"],
        },
        {
            "id": "HB-V2-REP-009", "class": "REPOSITORY_CONTROLLED", "severity": "CRITICAL",
            "title": "restart-safe durable mutation runtime is absent from the main-convergence candidate",
            "state": "IMPLEMENTED_REVIEW_REQUIRED",
            "evidence": ["crates/heptabao-durable-service/src/lib.rs", "docs/modules/heptabao-durable-service.md", "tests/repository/test_durable_runtime_v2_1.py"],
            "closure_criteria": ["durable intent state commit replay and acknowledgement order are implemented", "restart and ambiguous-outcome regressions pass", "production crypto and destructive qualification remain separately blocked"],
        },
        {
            "id": "HB-V2-REP-010", "class": "REPOSITORY_CONTROLLED", "severity": "CRITICAL",
            "title": "authorized durable composition and cryptographic request binding are incomplete",
            "state": "IMPLEMENTED_REVIEW_REQUIRED",
            "evidence": ["crates/heptabao-runtime-service/src/lib.rs", "docs/modules/heptabao-runtime-service.md", "tests/repository/test_authorized_durable_runtime_v2_1.py", "tests/repository/test_security_hashing_v2_1.py"],
            "closure_criteria": ["authorization precedes durable entry", "principal namespace operation resource authorization and value are domain-separated SHA-256 bound", "all negative and restart tests pass"],
        },
    ]
    for item in additions:
        if item["id"] not in existing_ids:
            repository_blockers.append(item)
    ensure_claims_closed(blocker)
    dump_yaml(blocker_path, blocker)

    (repo / "docs/modules/heptabao-durable-service.md").write_text(
        guide("heptabao-durable-service", "Provides the restart-safe, single-node mutation boundary for already-authorized requests. It persists intent, protected state, commit classification and replay identity before acknowledgement.", True),
        encoding="utf-8",
    )
    (repo / "docs/modules/heptabao-runtime-service.md").write_text(
        guide("heptabao-runtime-service", "Composes token and identity checks, namespace-qualified default-deny policy, mount routing and the durable mutation service. It prevents unauthorized requests from reaching durable entry.", False),
        encoding="utf-8",
    )

    readme = repo / "README.md"
    readme.write_text(canonical_block(readme.read_text(encoding="utf-8"), "HEPTABAO_V2_1_CURRENT_SCOPE", "## Current V2.1 workspace truth\n\nThe active V2.1 main-convergence candidate contains exactly **42 workspace packages**. Cargo workspace membership, `Cargo.lock`, the product capability matrix and the module index are required to name the same package set. This statement is implementation scope only and grants no qualification or operational authority."), encoding="utf-8")

    current = repo / "docs/CURRENT_DOCUMENTATION.md"
    current.write_text(canonical_block(current.read_text(encoding="utf-8"), "HEPTABAO_V2_1_CURRENT_SCOPE", "## V2.1 current workspace\n\nCurrent workspace count: **42 workspace packages**. The authoritative package list is `planning/HEPTABAO_PRODUCT_CAPABILITY_MATRIX_V2_0.yaml`; every package has one guide under `docs/modules/`."), encoding="utf-8")

    index = repo / "docs/modules/README.md"
    index_text = index.read_text(encoding="utf-8")
    for crate in ("heptabao-durable-service", "heptabao-runtime-service"):
        index_text = "\n".join(line for line in index_text.splitlines() if crate not in line) + "\n"
    index_body = """## V2.1 current package index

The current candidate is a **42-package V2.1 workspace scope** and supersedes the historical 40-package V2 scope for current-source accounting.

| Package | Responsibility | Documentation |
|---|---|---|
| `heptabao-durable-service` | Restart-safe durable mutation boundary | [guide](heptabao-durable-service.md) |
| `heptabao-runtime-service` | Authorized durable service composition | [guide](heptabao-runtime-service.md) |
"""
    index.write_text(canonical_block(index_text, "HEPTABAO_V2_1_CURRENT_SCOPE", index_body), encoding="utf-8")

    transformed = 0
    for crate in ("heptabao-durable-service", "heptabao-runtime-service"):
        cargo = repo / f"crates/{crate}/Cargo.toml"
        source = repo / f"crates/{crate}/src/lib.rs"
        transformed += replace_weak_hashes(source, crate)
        if "Sha256" in source.read_text(encoding="utf-8"):
            ensure_sha2_dependency(cargo)
    if transformed == 0:
        combined = "\n".join((repo / f"crates/{crate}/src/lib.rs").read_text(encoding="utf-8") for crate in ("heptabao-durable-service", "heptabao-runtime-service"))
        if "Sha256" not in combined:
            raise SystemExit("no SHA-256 implementation found or transformed")

    for path in (repo / "docs/modules/heptabao-durable-service.md", repo / "docs/modules/heptabao-runtime-service.md"):
        text = path.read_text(encoding="utf-8")
        for heading in REQUIRED_HEADINGS:
            if text.count(heading) != 1:
                raise SystemExit(f"{path}: heading count mismatch for {heading}")
        if "docs/engineering/HEPTABAO_ENGINEERING_HANDBOOK_V1.md" not in text:
            raise SystemExit(f"{path}: handbook reference missing")

    report = repo / "planning/HEPTABAO_V2_1_G0_REMEDIATION_STATUS.yaml"
    dump_yaml(report, {
        "schema": "heptabao.v2.1.g0-remediation-status.v1",
        "source_head": EXPECTED_HEAD,
        "plan_id": plan_id,
        "workspace_packages": len(crates),
        "weak_hash_functions_replaced": transformed,
        "state": "IMPLEMENTED_PENDING_EXACT_HEAD_VALIDATION_AND_INDEPENDENT_REVIEW",
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
