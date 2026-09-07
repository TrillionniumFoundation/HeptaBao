#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path
from typing import Any

import yaml

BASELINE_COMMIT = "54d524214df443752a2ecaeff6d4a05625bf52c7"
BASELINE_TREE = "c22288f561fdd711e908ce8a70c0116601d519e5"
SOURCE_HEAD = "837668cb879683bc60808584d2ebdedd42a397aa"
SOURCE_TREE = BASELINE_TREE
BASE_COMMIT = "489a104450ff48c49e7fb61e167e566ea5e0e6c7"
REPOSITORY_ID = 1349115072
REPOSITORY_FULL_NAME = "TrillionniumFoundation/HeptaBao"
PLAN_ID = "HEPTABAO-PLAN-2026-09-02-V1.4.7"
TRUTH_PATH = Path("planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml")
MANIFEST_PATH = Path("planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_7.yaml")
BEGIN_API = "<!-- BEGIN GENERATED V1.4.7 PUBLIC API TRUTH; DO NOT EDIT -->"
END_API = "<!-- END GENERATED V1.4.7 PUBLIC API TRUTH -->"
BEGIN_FACTS = "<!-- BEGIN GENERATED V1.4.7 MODULE FACTS; DO NOT EDIT -->"
END_FACTS = "<!-- END GENERATED V1.4.7 MODULE FACTS -->"
BEGIN_INDEX = "<!-- BEGIN V1.4.7 MODULE TRUTH INDEX -->"
END_INDEX = "<!-- END V1.4.7 MODULE TRUTH INDEX -->"

CLAIMS = {
    "qualification": False,
    "compatibility_claim": False,
    "selected_candidates": [],
    "selection_effect": "NONE",
    "production_authority": False,
    "migration_authority": False,
    "release_authority": False,
    "authority_effect": "NONE",
}

PUBLIC_RE = re.compile(
    r"^\s*pub\s+(?:(async|unsafe)\s+)?(struct|enum|trait|type|const|static|fn|mod|use)\s+(.+?)\s*$"
)
TEST_ATTR_RE = re.compile(r"^\s*#\s*\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*test(?:\s*\([^]]*\))?\s*]\s*$")
FN_RE = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
NAME_RES = {
    "struct": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "enum": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "trait": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "type": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "const": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "static": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "fn": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
    "mod": re.compile(r"([A-Za-z_][A-Za-z0-9_]*)"),
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def normalize_line(value: str) -> str:
    return " ".join(value.strip().split())


def strip_block_comments(lines: list[str]) -> list[str]:
    output: list[str] = []
    depth = 0
    for original in lines:
        line = original
        result: list[str] = []
        index = 0
        while index < len(line):
            if depth:
                if line.startswith("/*", index):
                    depth += 1
                    index += 2
                elif line.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
                continue
            if line.startswith("/*", index):
                depth = 1
                index += 2
                continue
            if line.startswith("//", index):
                break
            result.append(line[index])
            index += 1
        output.append("".join(result))
    return output


def public_items(path: Path, root: Path) -> list[dict[str, Any]]:
    original = path.read_text(encoding="utf-8").splitlines()
    cleaned = strip_block_comments(original)
    items: list[dict[str, Any]] = []
    for number, line in enumerate(cleaned, 1):
        match = PUBLIC_RE.match(line)
        if not match:
            continue
        modifier, kind, tail = match.groups()
        if kind == "use":
            name = normalize_line(tail.rstrip(";"))
        else:
            name_match = NAME_RES[kind].match(tail)
            if not name_match:
                continue
            name = name_match.group(1)
        items.append(
            {
                "kind": kind,
                "name": name,
                "modifier": modifier or None,
                "path": path.relative_to(root).as_posix(),
                "line": number,
                "signature": normalize_line(original[number - 1]),
            }
        )
    return items


def test_functions(path: Path, root: Path) -> list[dict[str, Any]]:
    original = path.read_text(encoding="utf-8").splitlines()
    cleaned = strip_block_comments(original)
    pending = False
    tests: list[dict[str, Any]] = []
    for number, line in enumerate(cleaned, 1):
        if TEST_ATTR_RE.match(line):
            pending = True
            continue
        if pending:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = FN_RE.match(line)
            if match:
                tests.append(
                    {
                        "name": match.group(1),
                        "path": path.relative_to(root).as_posix(),
                        "line": number,
                    }
                )
            pending = False
    return tests


def dependency_sections(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    sections: list[tuple[str, dict[str, Any]]] = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            sections.append((key, value))
    targets = data.get("target", {})
    if isinstance(targets, dict):
        for target_name, target_data in sorted(targets.items()):
            if not isinstance(target_data, dict):
                continue
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target_data.get(key)
                if isinstance(value, dict):
                    sections.append((f"target.{target_name}.{key}", value))
    return sections


def workspace_members(root: Path) -> list[Path]:
    data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    raw = data.get("workspace", {}).get("members", [])
    members: list[Path] = []
    for entry in raw:
        if any(char in entry for char in "*?["):
            members.extend(path for path in root.glob(entry) if (path / "Cargo.toml").is_file())
        else:
            path = root / entry
            if (path / "Cargo.toml").is_file():
                members.append(path)
    return sorted(set(members), key=lambda item: item.as_posix())


def build_truth(root: Path) -> dict[str, Any]:
    members = workspace_members(root)
    crate_names: dict[Path, str] = {}
    for member in members:
        data = tomllib.loads((member / "Cargo.toml").read_text(encoding="utf-8"))
        crate_names[member] = data["package"]["name"]
    workspace_names = set(crate_names.values())
    modules: list[dict[str, Any]] = []
    for member in members:
        cargo_path = member / "Cargo.toml"
        cargo_data = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
        crate_name = crate_names[member]
        rust_files = sorted(
            [path for path in member.rglob("*.rs") if "target" not in path.parts],
            key=lambda item: item.as_posix(),
        )
        internal_dependencies: list[dict[str, str]] = []
        for section, dependencies in dependency_sections(cargo_data):
            for dependency_name in sorted(dependencies):
                dependency_value = dependencies[dependency_name]
                package_name = dependency_name
                if isinstance(dependency_value, dict) and isinstance(dependency_value.get("package"), str):
                    package_name = dependency_value["package"]
                if package_name in workspace_names:
                    internal_dependencies.append({"name": package_name, "section": section})
        items: list[dict[str, Any]] = []
        tests: list[dict[str, Any]] = []
        for rust_file in rust_files:
            items.extend(public_items(rust_file, root))
            tests.extend(test_functions(rust_file, root))
        doc_path = Path("docs/modules") / f"{crate_name}.md"
        if not (root / doc_path).is_file():
            raise SystemExit(f"missing module guide: {doc_path}")
        modules.append(
            {
                "crate": crate_name,
                "crate_path": member.relative_to(root).as_posix(),
                "cargo_toml_sha256": sha256_file(cargo_path),
                "source_files": [
                    {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
                    for path in rust_files
                ],
                "module_guide": doc_path.as_posix(),
                "internal_dependencies": sorted(
                    internal_dependencies, key=lambda item: (item["name"], item["section"])
                ),
                "public_items": sorted(
                    items, key=lambda item: (item["path"], item["line"], item["kind"], item["name"])
                ),
                "test_functions": sorted(tests, key=lambda item: (item["path"], item["line"], item["name"])),
            }
        )
    return {
        "schema": "heptabao.module-source-truth.v1",
        "plan_id": PLAN_ID,
        "baseline_commit": BASELINE_COMMIT,
        "baseline_tree": BASELINE_TREE,
        "parser": {
            "class": "bounded-lexical-rust-public-surface-v1",
            "captures": ["pub declarations", "workspace-internal dependency declarations", "test functions", "source digests"],
            "does_not_claim": ["rust name resolution", "semantic API compatibility", "production qualification"],
        },
        "module_count": len(modules),
        "modules": modules,
        "claims": CLAIMS,
    }


def dump_yaml(value: Any) -> str:
    return yaml.safe_dump(value, sort_keys=False, allow_unicode=True, width=120)


def replace_marked(text: str, begin: str, end: str, replacement: str) -> str:
    if begin in text and end in text:
        start = text.index(begin)
        finish = text.index(end, start) + len(end)
        return text[:start] + replacement + text[finish:]
    suffix = "" if text.endswith("\n") else "\n"
    return text + suffix + "\n" + replacement + "\n"


def replace_public_api_section(text: str, body: str) -> str:
    lines = text.splitlines()
    index = next((i for i, line in enumerate(lines) if line.startswith("## ") and "public api" in line.lower()), None)
    block = body.splitlines()
    if index is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(["## Public API", "", *block])
        return "\n".join(lines).rstrip() + "\n"
    finish = index + 1
    while finish < len(lines) and not lines[finish].startswith("## "):
        finish += 1
    replacement = [lines[index], "", *block, ""]
    return "\n".join(lines[:index] + replacement + lines[finish:]).rstrip() + "\n"


def module_doc_expected(root: Path, module: dict[str, Any]) -> str:
    path = root / module["module_guide"]
    text = path.read_text(encoding="utf-8")
    api_lines = [BEGIN_API]
    api_lines.append(
        f"Source-bound lexical inventory: `{module['crate_path']}`; Cargo SHA-256 `{module['cargo_toml_sha256']}`."
    )
    api_lines.append("")
    api_lines.append("| Kind | Name | Source | Declaration |")
    api_lines.append("|---|---|---|---|")
    if module["public_items"]:
        for item in module["public_items"]:
            signature = item["signature"].replace("|", "\\|").replace("`", "\\`")
            name = item["name"].replace("|", "\\|").replace("`", "\\`")
            api_lines.append(
                f"| `{item['kind']}` | `{name}` | `{item['path']}:{item['line']}` | `{signature}` |"
            )
    else:
        api_lines.append("| — | — | — | No externally public lexical declaration was found. |")
    api_lines.append("")
    api_lines.append(
        "This table is generated from the exact candidate source. It is a bounded lexical inventory, not a stability or compatibility promise."
    )
    api_lines.append(END_API)
    text = replace_public_api_section(text, "\n".join(api_lines))
    dependencies = ", ".join(
        f"`{item['name']}` ({item['section']})" for item in module["internal_dependencies"]
    ) or "none"
    facts_lines = [
        BEGIN_FACTS,
        f"- Crate: `{module['crate']}`",
        f"- Crate path: `{module['crate_path']}`",
        f"- Cargo manifest SHA-256: `{module['cargo_toml_sha256']}`",
        f"- Rust source files: `{len(module['source_files'])}`",
        f"- Public lexical declarations: `{len(module['public_items'])}`",
        f"- Discovered test functions: `{len(module['test_functions'])}`",
        f"- Workspace-internal dependencies: {dependencies}",
        f"- Authoritative inventory: `{TRUTH_PATH.as_posix()}`",
        "- Regeneration: `python scripts/render_plan_v1_4_7.py --write`",
        "- Verification: `python scripts/render_plan_v1_4_7.py --check`",
        END_FACTS,
    ]
    facts_block = "\n".join(facts_lines)
    if BEGIN_FACTS in text and END_FACTS in text:
        text = replace_marked(text, BEGIN_FACTS, END_FACTS, facts_block)
    else:
        text = text.rstrip() + "\n\n## Machine-verified source truth\n\n" + facts_block + "\n"
    return text.rstrip() + "\n"


def module_index_expected(root: Path, truth: dict[str, Any]) -> str:
    path = root / "docs/modules/README.md"
    text = path.read_text(encoding="utf-8")
    lines = [
        BEGIN_INDEX,
        "## V1.4.7 machine-verified module truth",
        "",
        f"All `{truth['module_count']}` Cargo workspace crates are bound to source hashes, internal dependency declarations,",
        "public lexical declarations and discovered tests in",
        f"`{TRUTH_PATH.as_posix()}`. The generated Public API tables inside each module guide are normative for",
        "the exact candidate source; narrative stability or compatibility claims remain prohibited.",
        "",
        "Validation commands:",
        "",
        "```text",
        "python scripts/render_plan_v1_4_7.py --check",
        "python scripts/validate_plan_v1_4_7.py",
        "```",
        END_INDEX,
    ]
    return replace_marked(text, BEGIN_INDEX, END_INDEX, "\n".join(lines)).rstrip() + "\n"


def external_schema() -> dict[str, Any]:
    blockers = ["HB-BLK-CTRL-001"] + [f"HB-BLK-EXT-{index:03d}" for index in range(1, 8)]
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://heptabao.invalid/schemas/heptabao_external_completion_evidence_v1.schema.json",
        "title": "HeptaBao external completion evidence envelope v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema", "blocker_id", "state", "repository", "source", "scope", "actors", "separation",
            "checks", "artifacts", "findings", "signatures", "claims"
        ],
        "properties": {
            "schema": {"const": "heptabao.external-completion-evidence.v1"},
            "blocker_id": {"enum": blockers},
            "state": {"enum": ["UNEXECUTED", "EXECUTED_PENDING_REVIEW", "ACCEPTED", "REJECTED", "REVOKED"]},
            "repository": {
                "type": "object", "additionalProperties": False,
                "required": ["id", "full_name"],
                "properties": {"id": {"const": REPOSITORY_ID}, "full_name": {"const": REPOSITORY_FULL_NAME}},
            },
            "source": {
                "type": "object", "additionalProperties": False,
                "required": ["commit", "tree", "merge_commit", "merge_tree", "plan_digest", "manifest_digest"],
                "properties": {
                    "commit": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                    "tree": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                    "merge_commit": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                    "merge_tree": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
                    "plan_digest": {"anyOf": [digest, {"type": "null"}]},
                    "manifest_digest": {"anyOf": [digest, {"type": "null"}]},
                },
            },
            "scope": {"type": "array", "items": {"type": "string", "minLength": 1}},
            "actors": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["stable_id", "role", "organization", "independent", "conflicts"],
                    "properties": {
                        "stable_id": {"type": "string", "minLength": 3},
                        "role": {"type": "string", "minLength": 3},
                        "organization": {"type": "string", "minLength": 2},
                        "independent": {"type": "boolean"},
                        "conflicts": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "separation": {"type": "object", "additionalProperties": {"type": "string"}},
            "checks": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["case_id", "status", "evidence_digest"],
                    "properties": {
                        "case_id": {"type": "string", "minLength": 1},
                        "status": {"enum": ["PASS", "FAIL", "BLOCKED", "UNKNOWN", "UNEXECUTED"]},
                        "evidence_digest": {"anyOf": [digest, {"type": "null"}]},
                    },
                },
            },
            "artifacts": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["name", "digest", "custody_uri", "classification"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "digest": digest,
                        "custody_uri": {"type": "string", "minLength": 3},
                        "classification": {"enum": ["PUBLIC", "SANITIZED", "RESTRICTED_REFERENCE"]},
                    },
                },
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "severity", "state"],
                    "properties": {
                        "id": {"type": "string"},
                        "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNCLASSIFIED"]},
                        "state": {"enum": ["OPEN", "CLOSED", "ACCEPTED_RISK"]},
                    },
                },
            },
            "signatures": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["signer_id", "role", "key_id", "algorithm", "signed_at", "expires_at", "signature", "verification"],
                    "properties": {
                        "signer_id": {"type": "string", "minLength": 3},
                        "role": {"type": "string", "minLength": 3},
                        "key_id": {"type": "string", "minLength": 3},
                        "algorithm": {"type": "string", "minLength": 3},
                        "signed_at": {"type": "string", "format": "date-time"},
                        "expires_at": {"type": "string", "format": "date-time"},
                        "signature": {"type": "string", "minLength": 16},
                        "verification": {"enum": ["VALID", "INVALID", "UNKNOWN", "REVOKED"]},
                    },
                },
            },
            "claims": {
                "type": "object", "additionalProperties": False,
                "required": list(CLAIMS),
                "properties": {
                    "qualification": {"const": False},
                    "compatibility_claim": {"const": False},
                    "selected_candidates": {"const": []},
                    "selection_effect": {"const": "NONE"},
                    "production_authority": {"const": False},
                    "migration_authority": {"const": False},
                    "release_authority": {"const": False},
                    "authority_effect": {"const": "NONE"},
                },
            },
        },
    }


def external_validator_source() -> str:
    return textwrap.dedent(
        r'''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPOSITORY_ID = 1349115072
REPOSITORY_FULL_NAME = "TrillionniumFoundation/HeptaBao"
ALLOWED_BLOCKERS = {"HB-BLK-CTRL-001", *{f"HB-BLK-EXT-{i:03d}" for i in range(1, 8)}}
REQUIRED_ROLES = {
    "HB-BLK-CTRL-001": {"repository_administrator", "independent_control_reviewer"},
    "HB-BLK-EXT-001": {"program_reviewer", "security_reviewer", "storage_reviewer"},
    "HB-BLK-EXT-002": {"legal_signer", "independent_program_reviewer"},
    "HB-BLK-EXT-003": {"security_operations", "backup_incident_commander", "independent_observer"},
    "HB-BLK-EXT-004": {"root_key_custodian", "crypto_reviewer", "independent_observer"},
    "HB-BLK-EXT-005": {"oracle_operator", "sanitization_operator", "transfer_custodian", "compatibility_reviewer"},
    "HB-BLK-EXT-006": {"storage_lab_operator", "storage_reviewer"},
    "HB-BLK-EXT-007": {"independent_reproduction_operator", "independent_reproduction_reviewer"},
}
SEPARATION_KEYS = {
    "HB-BLK-EXT-007": {
        "credential_root", "runner_admin", "cache_admin", "artifact_custody", "signing_root", "network_egress"
    },
    "HB-BLK-EXT-006": {"runner_admin", "artifact_custody", "signing_root", "power_cut_control"},
    "HB-BLK-EXT-005": {"raw_capture_acl", "implementation_acl", "artifact_custody", "signing_root"},
    "HB-BLK-EXT-004": {"root_custody", "delegated_custody", "observer_custody", "transparency_custody"},
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PLACEHOLDERS = {"todo", "tbd", "unknown", "unexecuted", "placeholder", "example", "none", "n/a"}


def fail(message: str) -> None:
    raise ValueError(message)


def non_placeholder(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value.strip()) < 2:
        fail(f"{field}: missing")
    lowered = value.strip().lower()
    if lowered in PLACEHOLDERS or any(token in lowered for token in ("<", ">", "replace-me")):
        fail(f"{field}: placeholder")
    return value


def parse_time(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        fail(f"{field}: invalid date-time: {error}")
    if parsed.tzinfo is None:
        fail(f"{field}: timezone required")
    return parsed.astimezone(timezone.utc)


def validate_envelope(
    data: dict[str, Any], *, require_closure: bool = False, expected_source: dict[str, str] | None = None,
    now: datetime | None = None,
) -> None:
    if data.get("schema") != "heptabao.external-completion-evidence.v1":
        fail("schema mismatch")
    blocker = data.get("blocker_id")
    if blocker not in ALLOWED_BLOCKERS:
        fail("unsupported blocker")
    repository = data.get("repository")
    if repository != {"id": REPOSITORY_ID, "full_name": REPOSITORY_FULL_NAME}:
        fail("repository identity mismatch")
    if data.get("claims") != {
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }:
        fail("authority drift")
    state = data.get("state")
    if state not in {"UNEXECUTED", "EXECUTED_PENDING_REVIEW", "ACCEPTED", "REJECTED", "REVOKED"}:
        fail("invalid state")
    source = data.get("source")
    if not isinstance(source, dict):
        fail("source missing")
    if require_closure:
        if state != "ACCEPTED":
            fail("closure requires ACCEPTED")
        for key in ("commit", "tree", "merge_commit", "merge_tree"):
            value = source.get(key)
            if not isinstance(value, str) or not HEX40.fullmatch(value):
                fail(f"source.{key}: exact SHA required")
            if expected_source and value != expected_source.get(key):
                fail(f"source.{key}: expected-source mismatch")
        for key in ("plan_digest", "manifest_digest"):
            if not isinstance(source.get(key), str) or not DIGEST.fullmatch(source[key]):
                fail(f"source.{key}: exact digest required")
        scope = data.get("scope")
        if not isinstance(scope, list) or not scope:
            fail("closure scope empty")
        for index, value in enumerate(scope):
            non_placeholder(value, f"scope[{index}]")
        actors = data.get("actors")
        if not isinstance(actors, list):
            fail("actors missing")
        roles: set[str] = set()
        actor_ids: set[str] = set()
        for index, actor in enumerate(actors):
            if not isinstance(actor, dict):
                fail(f"actors[{index}]: object required")
            stable_id = non_placeholder(actor.get("stable_id"), f"actors[{index}].stable_id")
            role = non_placeholder(actor.get("role"), f"actors[{index}].role")
            non_placeholder(actor.get("organization"), f"actors[{index}].organization")
            if stable_id in actor_ids:
                fail("actor identities must be distinct")
            actor_ids.add(stable_id)
            roles.add(role)
            if role.startswith("independent_") or role.endswith("_reviewer") or role == "independent_observer":
                if actor.get("independent") is not True:
                    fail(f"{role}: independence not affirmed")
                conflicts = actor.get("conflicts")
                if not isinstance(conflicts, list) or conflicts:
                    fail(f"{role}: unresolved conflicts")
        missing_roles = REQUIRED_ROLES[blocker] - roles
        if missing_roles:
            fail(f"missing roles: {sorted(missing_roles)}")
        separation = data.get("separation")
        if not isinstance(separation, dict):
            fail("separation missing")
        for key in SEPARATION_KEYS.get(blocker, set()):
            non_placeholder(separation.get(key), f"separation.{key}")
        checks = data.get("checks")
        if not isinstance(checks, list) or not checks:
            fail("checks missing")
        case_ids: set[str] = set()
        for index, check in enumerate(checks):
            case_id = non_placeholder(check.get("case_id"), f"checks[{index}].case_id")
            if case_id in case_ids:
                fail("duplicate check case")
            case_ids.add(case_id)
            if check.get("status") != "PASS":
                fail(f"{case_id}: non-PASS status")
            if not isinstance(check.get("evidence_digest"), str) or not DIGEST.fullmatch(check["evidence_digest"]):
                fail(f"{case_id}: evidence digest missing")
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            fail("artifacts missing")
        for index, artifact in enumerate(artifacts):
            non_placeholder(artifact.get("name"), f"artifacts[{index}].name")
            if not isinstance(artifact.get("digest"), str) or not DIGEST.fullmatch(artifact["digest"]):
                fail(f"artifacts[{index}].digest invalid")
            non_placeholder(artifact.get("custody_uri"), f"artifacts[{index}].custody_uri")
            if artifact.get("classification") not in {"PUBLIC", "SANITIZED", "RESTRICTED_REFERENCE"}:
                fail(f"artifacts[{index}].classification invalid")
        for finding in data.get("findings", []):
            if finding.get("severity") in {"CRITICAL", "HIGH", "UNCLASSIFIED"} and finding.get("state") != "CLOSED":
                fail("critical/high/unclassified finding remains open")
        signatures = data.get("signatures")
        if not isinstance(signatures, list) or len(signatures) < 2:
            fail("at least two signatures required")
        current = now or datetime.now(timezone.utc)
        signed_ids: set[str] = set()
        for index, signature in enumerate(signatures):
            signer_id = non_placeholder(signature.get("signer_id"), f"signatures[{index}].signer_id")
            if signer_id in signed_ids:
                fail("signer identities must be distinct")
            signed_ids.add(signer_id)
            non_placeholder(signature.get("role"), f"signatures[{index}].role")
            non_placeholder(signature.get("key_id"), f"signatures[{index}].key_id")
            non_placeholder(signature.get("algorithm"), f"signatures[{index}].algorithm")
            non_placeholder(signature.get("signature"), f"signatures[{index}].signature")
            signed_at = parse_time(signature.get("signed_at"), f"signatures[{index}].signed_at")
            expires_at = parse_time(signature.get("expires_at"), f"signatures[{index}].expires_at")
            if signed_at > current or expires_at <= current or expires_at <= signed_at:
                fail("signature freshness invalid")
            if signature.get("verification") != "VALID":
                fail("signature not valid and current")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--require-closure", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--expected-merge-commit")
    parser.add_argument("--expected-merge-tree")
    args = parser.parse_args()
    expected = None
    if args.require_closure:
        expected = {
            "commit": args.expected_commit,
            "tree": args.expected_tree,
            "merge_commit": args.expected_merge_commit,
            "merge_tree": args.expected_merge_tree,
        }
        if any(value is None for value in expected.values()):
            parser.error("all expected source identities are required with --require-closure")
    for raw_path in args.paths:
        path = Path(raw_path)
        value = json.loads(path.read_text(encoding="utf-8"))
        validate_envelope(value, require_closure=args.require_closure, expected_source=expected)
        print(f"PASS {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    ).lstrip()


def external_test_source() -> str:
    return textwrap.dedent(
        r'''from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "external_validator", ROOT / "scripts/validate_external_completion_evidence_v1.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
DIGEST = "sha256:" + "a" * 64
EXPECTED = {
    "commit": "1" * 40,
    "tree": "2" * 40,
    "merge_commit": "3" * 40,
    "merge_tree": "4" * 40,
}


def accepted_ext007() -> dict:
    return {
        "schema": "heptabao.external-completion-evidence.v1",
        "blocker_id": "HB-BLK-EXT-007",
        "state": "ACCEPTED",
        "repository": {"id": 1349115072, "full_name": "TrillionniumFoundation/HeptaBao"},
        "source": {**EXPECTED, "plan_digest": DIGEST, "manifest_digest": DIGEST},
        "scope": ["exact head and prospective merge full reproduction"],
        "actors": [
            {"stable_id": "operator-001", "role": "independent_reproduction_operator", "organization": "Lab A", "independent": True, "conflicts": []},
            {"stable_id": "reviewer-002", "role": "independent_reproduction_reviewer", "organization": "Lab B", "independent": True, "conflicts": []},
        ],
        "separation": {
            "credential_root": "credential-root-a",
            "runner_admin": "runner-admin-a",
            "cache_admin": "cache-admin-a",
            "artifact_custody": "custody-a",
            "signing_root": "signing-root-a",
            "network_egress": "egress-a",
        },
        "checks": [{"case_id": "full-matrix", "status": "PASS", "evidence_digest": DIGEST}],
        "artifacts": [{"name": "raw execution bundle", "digest": DIGEST, "custody_uri": "urn:lab-a:bundle:1", "classification": "RESTRICTED_REFERENCE"}],
        "findings": [],
        "signatures": [
            {"signer_id": "operator-001", "role": "operator", "key_id": "key-operator-001", "algorithm": "test-ed25519-profile", "signed_at": "2026-09-01T00:00:00Z", "expires_at": "2027-09-01T00:00:00Z", "signature": "a" * 64, "verification": "VALID"},
            {"signer_id": "reviewer-002", "role": "reviewer", "key_id": "key-reviewer-002", "algorithm": "test-ed25519-profile", "signed_at": "2026-09-01T00:00:00Z", "expires_at": "2027-09-01T00:00:00Z", "signature": "b" * 64, "verification": "VALID"},
        ],
        "claims": {
            "qualification": False,
            "compatibility_claim": False,
            "selected_candidates": [],
            "selection_effect": "NONE",
            "production_authority": False,
            "migration_authority": False,
            "release_authority": False,
            "authority_effect": "NONE",
        },
    }


class ExternalCompletionEvidenceTests(unittest.TestCase):
    def validate(self, value: dict) -> None:
        VALIDATOR.validate_envelope(
            value,
            require_closure=True,
            expected_source=EXPECTED,
            now=datetime(2026, 9, 2, tzinfo=timezone.utc),
        )

    def test_bounded_valid_closure_envelope_passes(self) -> None:
        self.validate(accepted_ext007())

    def test_templates_are_schema_shaped_but_not_closure(self) -> None:
        for path in sorted((ROOT / "qualifications/external/templates").glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            VALIDATOR.validate_envelope(value, require_closure=False)
            with self.assertRaises(ValueError):
                self.validate(value)

    def test_non_pass_case_fails_closed(self) -> None:
        value = accepted_ext007()
        value["checks"][0]["status"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_shared_actor_identity_fails_closed(self) -> None:
        value = accepted_ext007()
        value["actors"][1]["stable_id"] = value["actors"][0]["stable_id"]
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_source_drift_fails_closed(self) -> None:
        value = accepted_ext007()
        value["source"]["tree"] = "f" * 40
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_expired_or_revoked_signature_fails_closed(self) -> None:
        for field, replacement in (("expires_at", "2026-09-01T00:00:00Z"), ("verification", "REVOKED")):
            value = accepted_ext007()
            value["signatures"][0][field] = replacement
            with self.assertRaises(ValueError):
                self.validate(value)

    def test_authority_elevation_fails_closed(self) -> None:
        value = accepted_ext007()
        value["claims"]["production_authority"] = True
        with self.assertRaises(ValueError):
            self.validate(value)


if __name__ == "__main__":
    unittest.main()
'''
    ).lstrip()


def module_test_source() -> str:
    return textwrap.dedent(
        r'''from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("renderer", ROOT / "scripts/render_plan_v1_4_7.py")
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


class ModuleSourceTruthTests(unittest.TestCase):
    def test_snapshot_matches_exact_workspace(self) -> None:
        expected = RENDERER.build_truth(ROOT)
        actual = yaml.safe_load((ROOT / RENDERER.TRUTH_PATH).read_text(encoding="utf-8"))
        self.assertEqual(expected, actual)
        self.assertEqual(19, actual["module_count"])

    def test_every_module_guide_generated_sections_are_current(self) -> None:
        truth = RENDERER.build_truth(ROOT)
        for module in truth["modules"]:
            path = ROOT / module["module_guide"]
            self.assertEqual(RENDERER.module_doc_expected(ROOT, module), path.read_text(encoding="utf-8"))

    def test_workspace_dependency_and_public_surface_are_nonempty(self) -> None:
        truth = RENDERER.build_truth(ROOT)
        self.assertTrue(any(module["internal_dependencies"] for module in truth["modules"]))
        self.assertTrue(all(module["source_files"] for module in truth["modules"]))
        self.assertTrue(any(module["public_items"] for module in truth["modules"]))
        self.assertTrue(any(module["test_functions"] for module in truth["modules"]))


if __name__ == "__main__":
    unittest.main()
'''
    ).lstrip()


def plan_validator_source() -> str:
    return textwrap.dedent(
        r'''#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CLAIMS = {
    "qualification": False,
    "compatibility_claim": False,
    "selected_candidates": [],
    "selection_effect": "NONE",
    "production_authority": False,
    "migration_authority": False,
    "release_authority": False,
    "authority_effect": "NONE",
}
BASELINE_COMMIT = "54d524214df443752a2ecaeff6d4a05625bf52c7"
BASELINE_TREE = "c22288f561fdd711e908ce8a70c0116601d519e5"
REQUIRED = [
    "docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md",
    "planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml",
    "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_7.yaml",
    "planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml",
    "planning/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V1.yaml",
    "planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml",
    "docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md",
    "docs/governance/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md",
    "schemas/heptabao_external_completion_evidence_v1.schema.json",
    "scripts/render_plan_v1_4_7.py",
    "scripts/validate_external_completion_evidence_v1.py",
    ".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_yaml(path: str) -> dict:
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def main() -> int:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        raise SystemExit(f"missing V1.4.7 files: {missing}")
    status = load_yaml("planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml")
    blockers = load_yaml("planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml")
    receipt = load_yaml("planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml")
    admission = load_yaml("planning/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V1.yaml")
    for name, value in (("status", status), ("blockers", blockers), ("receipt", receipt), ("admission", admission)):
        if value.get("claims") != CLAIMS:
            raise SystemExit(f"{name}: authority drift")
    if status.get("source_baseline") != {"commit": BASELINE_COMMIT, "tree": BASELINE_TREE}:
        raise SystemExit("status: baseline drift")
    expected_closed = [f"HB-BLK-REPO-{index:03d}" for index in range(49, 59)]
    if receipt.get("closed_repository_blockers") != expected_closed:
        raise SystemExit("post-merge receipt: repository blocker set mismatch")
    if receipt.get("external_or_control_blockers_closed") != []:
        raise SystemExit("post-merge receipt overclaims external closure")
    added = blockers.get("added_blockers", [])
    if [item.get("id") for item in added] != [f"HB-BLK-REPO-{index:03d}" for index in range(59, 63)]:
        raise SystemExit("V1.4.7 blocker set mismatch")
    if any(item.get("state") != "IMPLEMENTED_SOURCE_REVIEW_REQUIRED" for item in added):
        raise SystemExit("V1.4.7 blocker state must remain review-required")
    current = (ROOT / "docs/CURRENT_DOCUMENTATION.md").read_text(encoding="utf-8")
    for token in (
        "HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md",
        "HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml",
        "MODULE_DOCUMENTATION_STANDARD_V2.md",
        "HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md",
    ):
        if token not in current:
            raise SystemExit(f"current documentation missing {token}")
    workflow = (ROOT / ".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml").read_text(encoding="utf-8")
    if "pull_request:" not in workflow or "push:" in workflow:
        raise SystemExit("V1.4.7 workflow must be pull-request-only")
    if "exact-head" not in workflow or "prospective-merge" not in workflow:
        raise SystemExit("V1.4.7 workflow source identities missing")
    manifest = load_yaml("planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_7.yaml")
    if manifest.get("claims") != CLAIMS:
        raise SystemExit("manifest authority drift")
    for item in manifest.get("files", []):
        path = ROOT / item["path"]
        if not path.is_file() or sha256(path) != item["sha256"]:
            raise SystemExit(f"manifest mismatch: {item['path']}")
    subprocess.run([sys.executable, str(ROOT / "scripts/render_plan_v1_4_7.py"), "--check"], check=True, cwd=ROOT)
    spec = importlib.util.spec_from_file_location(
        "external_validator", ROOT / "scripts/validate_external_completion_evidence_v1.py"
    )
    assert spec and spec.loader
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    for path in sorted((ROOT / "qualifications/external/templates").glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        validator.validate_envelope(value, require_closure=False)
        try:
            validator.validate_envelope(value, require_closure=True)
        except ValueError:
            pass
        else:
            raise SystemExit(f"template was admitted as closure: {path}")
    try:
        tree = subprocess.check_output(["git", "rev-parse", f"{BASELINE_COMMIT}^{{tree}}"], cwd=ROOT, text=True).strip()
        if tree != BASELINE_TREE:
            raise SystemExit("baseline Git tree mismatch")
        subprocess.run(["git", "merge-base", "--is-ancestor", BASELINE_COMMIT, "HEAD"], cwd=ROOT, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        raise SystemExit(f"baseline commit unavailable: {error}")
    print("PASS HeptaBao V1.4.7 post-merge truth and external admission")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
'''
    ).lstrip()


def plan_test_source() -> str:
    return textwrap.dedent(
        r'''from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PlanV147Tests(unittest.TestCase):
    def test_previous_repository_blockers_are_closed_without_external_overclaim(self) -> None:
        receipt = yaml.safe_load(
            (ROOT / "planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml").read_text(encoding="utf-8")
        )
        self.assertEqual([f"HB-BLK-REPO-{i:03d}" for i in range(49, 59)], receipt["closed_repository_blockers"])
        self.assertEqual([], receipt["external_or_control_blockers_closed"])
        self.assertFalse(receipt["claims"]["qualification"])

    def test_new_repository_blockers_are_source_implemented_review_required(self) -> None:
        value = yaml.safe_load((ROOT / "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml").read_text(encoding="utf-8"))
        self.assertEqual([f"HB-BLK-REPO-{i:03d}" for i in range(59, 63)], [item["id"] for item in value["added_blockers"]])
        self.assertTrue(all(item["state"] == "IMPLEMENTED_SOURCE_REVIEW_REQUIRED" for item in value["added_blockers"]))

    def test_external_and_control_blockers_remain_open(self) -> None:
        value = yaml.safe_load((ROOT / "planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml").read_text(encoding="utf-8"))
        self.assertEqual(
            ["HB-BLK-CTRL-001", *[f"HB-BLK-EXT-{i:03d}" for i in range(1, 8)]],
            value["external_open"],
        )
        self.assertEqual("NONE", value["claims"]["authority_effect"])

    def test_current_workflow_is_read_only_and_pr_only(self) -> None:
        text = (ROOT / ".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", text)
        self.assertIn("pull_request:", text)
        self.assertNotIn("push:", text)
        self.assertIn("exact-head", text)
        self.assertIn("prospective-merge", text)


if __name__ == "__main__":
    unittest.main()
'''
    ).lstrip()


def workflow_source() -> str:
    return textwrap.dedent(
        '''name: HeptaBao V1.4.7 post-merge truth and external admission

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
    branches:
      - integration/v1.4.4-technical-candidate

permissions:
  contents: read

concurrency:
  group: v1.4.7-pr-${{ github.event.pull_request.number }}-${{ github.event.pull_request.head.sha }}
  cancel-in-progress: true

jobs:
  validate:
    name: v1.4.7 / pull_request / ${{ matrix.source_kind }}
    runs-on: ubuntu-24.04
    timeout-minutes: 120
    permissions:
      contents: read
      pull-requests: read
    strategy:
      fail-fast: false
      matrix:
        source_kind: [exact-head, prospective-merge]
    env:
      SOURCE_KIND: ${{ matrix.source_kind }}
      SOURCE_SHA: ${{ matrix.source_kind == 'prospective-merge' && github.sha || github.event.pull_request.head.sha }}
      HEAD_SHA: ${{ github.event.pull_request.head.sha }}
      BASE_SHA: ${{ github.event.pull_request.base.sha }}
      V147_BASELINE: 54d524214df443752a2ecaeff6d4a05625bf52c7
    steps:
      - name: Checkout immutable source identity
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ env.SOURCE_SHA }}
          fetch-depth: 0
          persist-credentials: false

      - name: Bind exact head or prospective merge
        shell: bash
        run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
          git merge-base --is-ancestor "$V147_BASELINE" "$HEAD_SHA"
          if [[ "$SOURCE_KIND" == "prospective-merge" ]]; then
            read -r merge parent_one parent_two extra <<<"$(git rev-list --parents -n 1 HEAD)"
            test "$merge" = "$SOURCE_SHA"
            test "$parent_one" = "$BASE_SHA"
            test "$parent_two" = "$HEAD_SHA"
            test -z "${extra:-}"
          else
            test "$SOURCE_SHA" = "$HEAD_SHA"
          fi
          test -z "$(git status --porcelain=v1 --untracked-files=all)"
          printf 'source_kind=%s\nsource_sha=%s\ntree=%s\n' "$SOURCE_KIND" "$SOURCE_SHA" "$(git rev-parse HEAD^{tree})"

      - name: Install exact Python
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
          cache: pip
          cache-dependency-path: requirements-plan.txt

      - name: Validate plans documentation and external admission
        shell: bash
        run: |
          set -euo pipefail
          python -m pip install --disable-pip-version-check --requirement requirements-plan.txt
          python scripts/validate_plan_v1_4_7.py
          python -m unittest discover -s tests/plan -p 'test_*v1_4_7.py' -v
          python -m unittest discover -s tests/plan -p 'test_external_completion_evidence_v1.py' -v
          python scripts/validate_plan_v1_4_6.py
          python -m unittest discover -s tests/plan -p 'test_plan_v1_4_6.py' -v
          python scripts/validate_plan_v1_4_5.py
          python -m unittest discover -s tests/plan -p 'test_plan_v1_4_5.py' -v
          python scripts/validate_module_documentation_v1_4_4.py
          python -m unittest discover -s tests/plan -p 'test_module_documentation_v1_4_4.py' -v
          python -m unittest discover -s tests/platform -p 'test_*.py' -v
          python -m unittest discover -s tests/oracle -p 'test_*.py' -v

      - name: Install exact Rust 1.98
        shell: bash
        run: |
          set -euo pipefail
          rustup toolchain install 1.98.0 --profile minimal --component rustfmt --component clippy
          rustc +1.98.0 --version --verbose
          cargo +1.98.0 --version --verbose

      - name: Validate locked Rust workspace
        shell: bash
        run: |
          set -euo pipefail
          cargo +1.98.0 fmt --all -- --check
          cargo +1.98.0 test --locked --workspace --all-targets
          cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings

      - name: Confirm fail-closed authority boundary
        shell: bash
        run: |
          set -euo pipefail
          grep -R "authority_effect: NONE" planning/HEPTABAO_*V1_4_7*.yaml planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml
          ! grep -R "production_authority: true\|release_authority: true\|migration_authority: true\|compatibility_claim: true" \
            planning/HEPTABAO_*V1_4_7*.yaml planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml
'''
    ).lstrip()


def current_documentation() -> str:
    return textwrap.dedent(
        '''# HeptaBao Current Documentation

This page is the single current-entry portal. A newer row supersedes an older row only for the named subject; historical documents remain immutable evidence and are not silently rewritten.

## Current normative set

| Subject | Current document |
|---|---|
| active plan | `docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md` |
| current status | `planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml` |
| blocker register | `planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml` |
| normative manifest | `planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_7.yaml` |
| post-merge V1.4.6 closure receipt | `planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml` |
| module documentation standard | `docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md` |
| module index | `docs/modules/README.md` |
| machine-bound module source truth | `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml` |
| external completion admission protocol | `docs/governance/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md` |
| external completion admission catalog | `planning/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V1.yaml` |
| current exact-head/merge gate | `.github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml` |

## Inherited immutable set

| Subject | Inherited document |
|---|---|
| V1.4.6 plan | `docs/plan/HEPTABAO_PLAN_V1_4_6_AUTHORITATIVE_RECOVERY_CLOSURE.md` |
| V1.4.6 status | `planning/HEPTABAO_V1_4_6_AUTHORITATIVE_RECOVERY_STATUS.yaml` |
| V1.4.6 blocker register | `planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml` |
| V1.4.6 normative manifest | `planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_6.yaml` |
| V1.4.6 authoritative recovery protocol | `docs/recovery/HEPTABAO_AUTHORITATIVE_RECOVERY_PROTOCOL_V1.md` |
| V1.4.6 recovery gate | `.github/workflows/plan-v1.4.6-authoritative-recovery-closure.yml` |
| V1.4.5 security regression gate | `.github/workflows/plan-v1.4.5-security-invariant-closure.yml` |
| V1.4.4 module existence gate | `.github/workflows/plan-v1.4.4-module-documentation.yml` |

## Supersession chain

```text
V1.4.2 anchored recovery foundation
  → V1.4.3 descriptor anchoring/writer fencing
  → V1.4.4 complete current-crate documentation
  → V1.4.5 security invariant closure
  → V1.4.6 authoritative recovery closure
  → V1.4.7 post-merge truth and external admission
```

## V1.4.6 post-merge disposition

V1.4.6 exact head `837668cb879683bc60808584d2ebdedd42a397aa` and prospective merge `54d524214df443752a2ecaeff6d4a05625bf52c7` passed their required repository gates. The same exact head received a current GitHub approval, and the signed GitHub merge has tree `c22288f561fdd711e908ce8a70c0116601d519e5`. The V1.4.7 post-merge receipt therefore closes only `HB-BLK-REPO-049` through `HB-BLK-REPO-058` in repository-controlled scope. It does not create an accountable role receipt or close any control/external blocker.

## V1.4.7 reading rule

Each current Cargo workspace crate has one module guide. Public lexical declarations, workspace-internal dependencies, source-file digests and discovered test functions are generated from the exact candidate source and bound in `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`. Generated tables are source truth for the exact candidate; they do not promise API stability, compatibility or production support.

External completion documents are admitted only through the strict V1.4.7 envelope and validator. Templates are deliberately `UNEXECUTED` and are prohibited from closing a blocker. A green repository workflow cannot manufacture legal advice, independent identities, 24x7 operation, isolated key custody, restricted Oracle transfer, destructive power-cut evidence or separately controlled reproduction.

## Open authority boundary

`HB-BLK-CTRL-001` and `HB-BLK-EXT-001` through `HB-BLK-EXT-007` remain open until live, current, independently verifiable completion objects are admitted. Product composition, compatibility, platform qualification, provider selection, migration, production and release authority remain false.
'''
    ).lstrip()


def module_standard_v2() -> str:
    return textwrap.dedent(
        '''# HeptaBao Module Documentation Standard V2

Status: current normative standard for every Cargo workspace crate.

## Required narrative sections

Every module guide must retain implementation purpose, maturity, dependency direction, public API, state invariants, errors and retry semantics, data formats, security considerations, test strategy, extension rules, operational guidance, known gaps and traceability.

## Machine-bound facts

The following facts are generated from the exact candidate source and may not be maintained as unsupported prose:

1. Cargo manifest SHA-256;
2. all Rust source-file SHA-256 digests;
3. workspace-internal dependency declarations and dependency section;
4. public lexical declarations with source path, line, kind and declaration text;
5. discovered `#[test]` and runtime test functions;
6. exact mapping from Cargo package name to module guide.

The authoritative snapshot is `planning/HEPTABAO_MODULE_SOURCE_TRUTH_V1_4_7.yaml`. Each module guide contains generated Public API and source-truth blocks. `python scripts/render_plan_v1_4_7.py --check` must fail whenever source, dependencies, tests or generated documentation drift.

## Scope boundary

The V2 parser is deliberately described as a bounded lexical Rust inventory. It does not perform Rust name resolution and cannot establish semantic API compatibility. Those limitations must remain explicit; success grants no qualification, compatibility, provider selection or authority.

## Change rule

A source change that affects any generated fact requires regeneration in the same pull request. Hand editing a generated block, deleting an API item from documentation, inventing a test, or retaining a stale dependency graph is a failing condition. Historical narrative remains evidence but may not override a newer generated source fact.

## Review rule

Critical modules require a reviewer to inspect both semantic narrative and generated source facts. Structural presence alone is insufficient. Approval must bind the exact pull-request head and prospective merge identity.
'''
    ).lstrip()


def external_protocol() -> str:
    return textwrap.dedent(
        '''# HeptaBao External Completion Admission Protocol V1

## Purpose

This protocol turns the factual control and external blockers into strict machine-admission inputs without pretending that repository automation can perform the external work.

## Envelope

Every candidate completion object uses `heptabao.external-completion-evidence.v1` and binds:

- repository ID and full name;
- exact source commit/tree and prospective merge commit/tree;
- plan and normative-manifest digests;
- explicit scope;
- stable actor identities, roles, organizations, independence and conflicts;
- required control-separation roots;
- complete case inventory with PASS/FAIL/BLOCKED/UNKNOWN/UNEXECUTED status;
- raw or sanitized artifact digests and custody references;
- findings and dispositions;
- current, unrevoked signatures;
- an immutable `authority_effect: NONE` boundary.

## Fail-closed admission

Closure admission rejects a document when any required case is not PASS, any exact identity or digest drifts, a required role is missing, independent roles share identity, separation evidence is absent, a Critical/High/Unclassified finding remains open, a signature is stale or revoked, an artifact lacks custody, or any authority flag is raised.

Templates under `qualifications/external/templates/` are intentionally `UNEXECUTED`; they can be schema-shaped planning aids but can never pass `--require-closure`.

## Blocker-specific roles

- `HB-BLK-CTRL-001`: repository administrator plus independent control reviewer.
- `HB-BLK-EXT-001`: program, security and storage reviewers as distinct accountable identities.
- `HB-BLK-EXT-002`: accountable legal signer plus independent program reviewer.
- `HB-BLK-EXT-003`: security operations, backup incident commander and independent observer.
- `HB-BLK-EXT-004`: root-key custodian, cryptography reviewer and independent observer.
- `HB-BLK-EXT-005`: Oracle operator, sanitization operator, transfer custodian and compatibility reviewer.
- `HB-BLK-EXT-006`: independently controlled storage-lab operator and storage reviewer.
- `HB-BLK-EXT-007`: independent reproduction operator and separate reproduction reviewer.

## Invocation

```text
python scripts/validate_external_completion_evidence_v1.py candidate.json
python scripts/validate_external_completion_evidence_v1.py \
  --require-closure \
  --expected-commit <40-hex> \
  --expected-tree <40-hex> \
  --expected-merge-commit <40-hex> \
  --expected-merge-tree <40-hex> \
  candidate.json
```

The first command validates planning shape. Only the second performs closure admission, and only against caller-supplied immutable source identities.
'''
    ).lstrip()


def plan_document() -> str:
    return textwrap.dedent(
        f'''# HeptaBao Plan V1.4.7 — Post-Merge Truth and External Admission

## 1. Baseline

This tranche starts from the signed GitHub merge `{BASELINE_COMMIT}`, tree `{BASELINE_TREE}`, on `integration/v1.4.4-technical-candidate`. It does not reconstruct or supersede that merge with an unreviewed same-tree commit.

## 2. Objectives

1. canonicalize the completed V1.4.6 repository-controlled result after merge;
2. close `HB-BLK-REPO-049` through `HB-BLK-REPO-058` only in repository scope, without closing role, legal, operational, custody, laboratory or reproduction blockers;
3. replace title-only module-documentation validation with exact source, API, dependency, test and digest binding for every current crate;
4. make stale hand-written Public API tables detectable and regenerate them from candidate source;
5. provide one strict, blocker-specific external completion envelope and fail-closed admission tool;
6. ensure templates, owner assertions, same-identity reviews, stale signatures, incomplete cases and authority elevation cannot close a blocker;
7. bind all changes to distinct exact-head and prospective-merge pull-request checks.

## 3. V1.4.6 post-merge closure

The V1.4.6 head `{SOURCE_HEAD}` and prospective merge `{BASELINE_COMMIT}` passed the V1.4.6, inherited V1.4.5 and V1.4.4 gates. A current GitHub review approved the exact head, and GitHub created a valid signed two-parent merge with tree `{BASELINE_TREE}`. The post-merge receipt records those immutable facts and closes only the ten repository blockers. `HB-BLK-EXT-001` remains open because a GitHub approval does not establish the complete accountable role registry or signed role receipts.

## 4. Module source truth

The V2 renderer derives the workspace package set, Cargo manifest hashes, Rust source hashes, workspace-internal dependency declarations, public lexical declarations and discovered test functions. It rewrites the Public API section of each guide and adds a generated facts block. Check mode recomputes every fact and rejects source/documentation drift.

The parser is intentionally bounded and lexical. It does not claim Rust name resolution or semantic compatibility. That limitation is part of the normative output rather than an implicit weakness.

## 5. External completion admission

`HB-BLK-CTRL-001` and `HB-BLK-EXT-001..007` each receive an `UNEXECUTED` template. The validator can inspect planning shape without closure, but closure mode requires exact source identities, complete PASS-only cases, distinct accountable roles, blocker-specific separation, artifact custody, no unresolved Critical/High/Unclassified finding, fresh valid signatures and unchanged authority flags.

Repository automation cannot populate real identities, legal authority, operating coverage, HSM custody, restricted raw Oracle evidence, independent power-cut control or separately controlled reproduction. Those facts remain open until external operators submit authentic evidence.

## 6. New repository blockers

- `HB-BLK-REPO-059`: V1.4.6 post-merge repository closure was not canonicalized.
- `HB-BLK-REPO-060`: module guides were structurally present but not source/API/dependency/test bound.
- `HB-BLK-REPO-061`: external completion inputs lacked one strict fail-closed admission envelope.
- `HB-BLK-REPO-062`: current documentation still selected the pre-merge V1.4.6 status.

All four are implemented in source by this candidate and remain review-required until exact-head and prospective-merge CI pass and an independent reviewer accepts the final candidate.

## 7. Required gates

```text
python scripts/render_plan_v1_4_7.py --check
python scripts/validate_plan_v1_4_7.py
python -m unittest discover -s tests/plan -p 'test_*v1_4_7.py' -v
python -m unittest discover -s tests/plan -p 'test_external_completion_evidence_v1.py' -v
python scripts/validate_plan_v1_4_6.py
python scripts/validate_plan_v1_4_5.py
python scripts/validate_module_documentation_v1_4_4.py
python -m unittest discover -s tests/platform -p 'test_*.py' -v
python -m unittest discover -s tests/oracle -p 'test_*.py' -v
cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --locked --workspace --all-targets
cargo +1.98.0 clippy --locked --workspace --all-targets -- -D warnings
```

## 8. Carried product work

The production composition root, policy, identity, token, lease, namespace, system and plugin domains, production KMS/HSM, remote rollback provider, qualified recovery target, non-Linux qualification, backup/restore operations, Raft HA, migration, complete OpenBao compatibility and CLI/Agent/Proxy remain product work. This tranche makes their evidence boundaries harder to overclaim; it does not label unimplemented products complete.

## 9. Completion rule

`HB-BLK-REPO-059..062` close only after final source and prospective merge pass the V1.4.7 and inherited gates and receive a current independent review. `HB-BLK-CTRL-001` and `HB-BLK-EXT-001..007` remain open until authentic completion envelopes pass strict admission. Qualification, compatibility, provider selection and all production/migration/release authority remain false.
'''
    ).lstrip()


def status_document() -> dict[str, Any]:
    return {
        "schema": "heptabao.v1-4-7-post-merge-truth-status.v1",
        "plan_id": PLAN_ID,
        "revision": "1.4.7",
        "status": "SOURCE_IMPLEMENTED_EXACT_HEAD_MERGE_AND_INDEPENDENT_REVIEW_REQUIRED",
        "current_plan": "docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md",
        "current_blocker_register": "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml",
        "normative_manifest": MANIFEST_PATH.as_posix(),
        "current_documentation": "docs/CURRENT_DOCUMENTATION.md",
        "source_baseline": {"commit": BASELINE_COMMIT, "tree": BASELINE_TREE},
        "closed_repository_scope_carried_forward": [f"HB-BLK-REPO-{index:03d}" for index in range(49, 59)],
        "implementation": {
            "post_merge_v146_closure_receipt": "IMPLEMENTED_SOURCE",
            "module_documentation_standard_v2": "IMPLEMENTED_SOURCE",
            "module_source_hash_dependency_api_test_truth": "IMPLEMENTED_SOURCE",
            "generated_public_api_sections": "IMPLEMENTED_SOURCE",
            "external_completion_schema_and_admission": "IMPLEMENTED_SOURCE",
            "blocker_specific_negative_tests": "IMPLEMENTED_SOURCE",
            "current_documentation_supersession": "IMPLEMENTED_SOURCE",
            "exact_head_and_prospective_merge_gate": "IMPLEMENTED_SOURCE",
        },
        "repository_open": [f"HB-BLK-REPO-{index:03d}" for index in range(59, 63)],
        "external_open": ["HB-BLK-CTRL-001"] + [f"HB-BLK-EXT-{index:03d}" for index in range(1, 8)],
        "product_gaps_carried_forward": [
            "production composition root and mandatory end-to-end request path",
            "policy identity token lease namespace system and plugin domains",
            "production KMS or HSM custody rotation and revocation ceremony",
            "remote append-only rollback anchor and publication-fence provider",
            "qualified recovery target with atomic empty admission and readback",
            "non-Linux adapters and filesystem or storage-controller qualification",
            "retention compaction offsite backup custody and restore drills",
            "Raft HA replication membership snapshots and standby reconciliation",
            "online migration upgrade downgrade and mixed-version operation",
            "full OpenBao compatibility and Oracle-derived implementation",
            "CLI Agent Proxy and production operations surface",
        ],
        "claims": CLAIMS,
    }


def blocker_register() -> dict[str, Any]:
    added = [
        {
            "id": "HB-BLK-REPO-059",
            "class": "REPOSITORY_CONTROLLED",
            "severity": "HIGH",
            "title": "V1.4.6 post-merge repository closure was not canonicalized",
            "state": "IMPLEMENTED_SOURCE_REVIEW_REQUIRED",
            "closure_criteria": [
                "receipt binds exact reviewed head base merge parent graph and merge tree",
                "repository blockers 049 through 058 close without closing control or external blockers",
                "authority flags remain false",
            ],
            "evidence": ["planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml"],
            "closure_receipt_required": True,
        },
        {
            "id": "HB-BLK-REPO-060",
            "class": "REPOSITORY_CONTROLLED",
            "severity": "HIGH",
            "title": "module documentation was structurally complete but not source truth bound",
            "state": "IMPLEMENTED_SOURCE_REVIEW_REQUIRED",
            "closure_criteria": [
                "every workspace crate maps to exactly one module guide",
                "Cargo and Rust source hashes internal dependencies public lexical declarations and tests are recomputed",
                "generated Public API and facts blocks reject drift and hand edits",
                "bounded lexical scope and nonclaims remain explicit",
            ],
            "evidence": [
                "docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md",
                TRUTH_PATH.as_posix(),
                "scripts/render_plan_v1_4_7.py",
                "tests/plan/test_module_source_truth_v1_4_7.py",
            ],
            "closure_receipt_required": True,
        },
        {
            "id": "HB-BLK-REPO-061",
            "class": "REPOSITORY_CONTROLLED",
            "severity": "CRITICAL",
            "title": "external completion evidence lacked one strict fail-closed admission gate",
            "state": "IMPLEMENTED_SOURCE_REVIEW_REQUIRED",
            "closure_criteria": [
                "one schema covers control and external blocker completion envelopes",
                "closure mode binds exact source and merge identities",
                "required roles separation cases artifacts findings signatures and authority flags fail closed",
                "UNEXECUTED templates cannot be admitted as closure",
            ],
            "evidence": [
                "schemas/heptabao_external_completion_evidence_v1.schema.json",
                "scripts/validate_external_completion_evidence_v1.py",
                "tests/plan/test_external_completion_evidence_v1.py",
                "qualifications/external/templates",
            ],
            "closure_receipt_required": True,
        },
        {
            "id": "HB-BLK-REPO-062",
            "class": "REPOSITORY_CONTROLLED",
            "severity": "MEDIUM",
            "title": "current documentation still selected the pre-merge V1.4.6 status",
            "state": "IMPLEMENTED_SOURCE_REVIEW_REQUIRED",
            "closure_criteria": [
                "single current portal selects V1.4.7 plan status blocker register and manifest",
                "V1.4.6 remains immutable inherited evidence",
                "external authority boundary remains explicit",
            ],
            "evidence": ["docs/CURRENT_DOCUMENTATION.md"],
            "closure_receipt_required": True,
        },
    ]
    return {
        "schema": "heptabao.blocker-register-extension.v1_4_7",
        "plan_id": PLAN_ID,
        "revision": "1.4.7",
        "status": "ACTIVE_FAIL_CLOSED",
        "inherits": "planning/HEPTABAO_BLOCKER_REGISTER_V1_4_6.yaml",
        "source_baseline": {"commit": BASELINE_COMMIT, "tree": BASELINE_TREE},
        "closed_carried_forward": [
            {"id": f"HB-BLK-REPO-{index:03d}", "state": "CLOSED_REPOSITORY_SCOPE", "receipt": "planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml"}
            for index in range(49, 59)
        ],
        "added_blockers": added,
        "external_and_control_blockers_carried_forward": ["HB-BLK-CTRL-001"] + [f"HB-BLK-EXT-{index:03d}" for index in range(1, 8)],
        "product_gaps_carried_forward": status_document()["product_gaps_carried_forward"],
        "claims": CLAIMS,
    }


def post_merge_receipt() -> dict[str, Any]:
    return {
        "schema": "heptabao.repository-post-merge-closure-receipt.v1",
        "plan_id": PLAN_ID,
        "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY_FULL_NAME},
        "pull_request": 60,
        "base_commit": BASE_COMMIT,
        "reviewed_head_commit": SOURCE_HEAD,
        "reviewed_head_tree": SOURCE_TREE,
        "merge_commit": BASELINE_COMMIT,
        "merge_tree": BASELINE_TREE,
        "merge_parents": [BASE_COMMIT, SOURCE_HEAD],
        "merge_verification": {"provider": "GitHub", "verified": True, "reason": "valid"},
        "required_runs": [
            {"id": 33575576171, "name": "HeptaBao V1.4.6 authoritative recovery closure", "result": "PASS"},
            {"id": 33575576185, "name": "plan-v1.4.5-security-invariant-closure", "result": "PASS"},
            {"id": 33575576180, "name": "plan-v1.4.4-module-documentation", "result": "PASS"},
        ],
        "current_head_review": {
            "review_id": 5084963097,
            "reviewer_login": "Franksudoman",
            "reviewer_stable_account_id": 273670192,
            "state": "APPROVED",
            "commit": SOURCE_HEAD,
            "submitted_at": "2026-09-02T02:22:50Z",
            "scope_effect": "GITHUB_REPOSITORY_CHANGE_ACCEPTANCE_ONLY",
            "accountable_role_receipt": False,
        },
        "closed_repository_blockers": [f"HB-BLK-REPO-{index:03d}" for index in range(49, 59)],
        "external_or_control_blockers_closed": [],
        "limitations": [
            "GitHub approval does not establish the complete accountable role registry",
            "GitHub merge signature is not the isolated project signing trust root",
            "repository CI does not establish legal operational Oracle laboratory or independent reproduction facts",
        ],
        "claims": CLAIMS,
    }


def admission_catalog() -> dict[str, Any]:
    return {
        "schema": "heptabao.external-completion-admission-catalog.v1",
        "plan_id": PLAN_ID,
        "envelope_schema": "schemas/heptabao_external_completion_evidence_v1.schema.json",
        "validator": "scripts/validate_external_completion_evidence_v1.py",
        "protocol": "docs/governance/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md",
        "closure_mode": "FAIL_CLOSED_EXACT_SOURCE_REQUIRED",
        "blockers": [
            {
                "id": blocker,
                "template": f"qualifications/external/templates/{blocker}.template.json",
                "state": "OPEN_EXTERNAL_EXECUTION_REQUIRED",
            }
            for blocker in ["HB-BLK-CTRL-001"] + [f"HB-BLK-EXT-{index:03d}" for index in range(1, 8)]
        ],
        "claims": CLAIMS,
    }


def template(blocker: str) -> dict[str, Any]:
    return {
        "schema": "heptabao.external-completion-evidence.v1",
        "blocker_id": blocker,
        "state": "UNEXECUTED",
        "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY_FULL_NAME},
        "source": {
            "commit": None,
            "tree": None,
            "merge_commit": None,
            "merge_tree": None,
            "plan_digest": None,
            "manifest_digest": None,
        },
        "scope": [],
        "actors": [],
        "separation": {},
        "checks": [{"case_id": "UNEXECUTED", "status": "UNEXECUTED", "evidence_digest": None}],
        "artifacts": [],
        "findings": [],
        "signatures": [],
        "claims": CLAIMS,
    }


def qualifications_readme() -> str:
    return textwrap.dedent(
        '''# External completion evidence

This directory contains only fail-closed input templates for `HB-BLK-CTRL-001` and `HB-BLK-EXT-001..007`.

Every committed template is `UNEXECUTED` and non-authoritative. It is not evidence that an operator, reviewer, legal function, incident team, key custodian, Oracle lane, storage laboratory or reproduction environment exists. A populated candidate must be held under the declared custody system and admitted with the exact source identities through `scripts/validate_external_completion_evidence_v1.py --require-closure`.

Do not commit restricted raw Oracle captures, private vulnerability details, production credentials, private signing keys or destructive-laboratory secrets here. Commit only an approved sanitized object or immutable restricted reference.
'''
    ).lstrip()


def static_files() -> dict[Path, str]:
    values: dict[Path, str] = {
        Path("docs/CURRENT_DOCUMENTATION.md"): current_documentation(),
        Path("docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md"): module_standard_v2(),
        Path("docs/governance/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md"): external_protocol(),
        Path("docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md"): plan_document(),
        Path("planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml"): dump_yaml(status_document()),
        Path("planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml"): dump_yaml(blocker_register()),
        Path("planning/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V1.yaml"): dump_yaml(admission_catalog()),
        Path("planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml"): dump_yaml(post_merge_receipt()),
        Path("schemas/heptabao_external_completion_evidence_v1.schema.json"): json.dumps(external_schema(), indent=2, sort_keys=True) + "\n",
        Path("scripts/validate_external_completion_evidence_v1.py"): external_validator_source(),
        Path("scripts/validate_plan_v1_4_7.py"): plan_validator_source(),
        Path("tests/plan/test_external_completion_evidence_v1.py"): external_test_source(),
        Path("tests/plan/test_module_source_truth_v1_4_7.py"): module_test_source(),
        Path("tests/plan/test_plan_v1_4_7.py"): plan_test_source(),
        Path(".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml"): workflow_source(),
        Path("qualifications/external/README.md"): qualifications_readme(),
    }
    for blocker in ["HB-BLK-CTRL-001"] + [f"HB-BLK-EXT-{index:03d}" for index in range(1, 8)]:
        values[Path(f"qualifications/external/templates/{blocker}.template.json")] = json.dumps(
            template(blocker), indent=2, sort_keys=True
        ) + "\n"
    return values


def normative_paths(truth: dict[str, Any]) -> list[Path]:
    paths = [
        Path("docs/CURRENT_DOCUMENTATION.md"),
        Path("docs/plan/HEPTABAO_PLAN_V1_4_7_POST_MERGE_TRUTH_AND_EXTERNAL_ADMISSION.md"),
        Path("planning/HEPTABAO_V1_4_7_POST_MERGE_TRUTH_STATUS.yaml"),
        Path("planning/HEPTABAO_BLOCKER_REGISTER_V1_4_7.yaml"),
        TRUTH_PATH,
        Path("planning/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_V1.yaml"),
        Path("planning/evidence/repository/HEPTABAO_V1_4_6_POST_MERGE_CLOSURE_RECEIPT.yaml"),
        Path("docs/modules/MODULE_DOCUMENTATION_STANDARD_V2.md"),
        Path("docs/modules/README.md"),
        Path("docs/governance/HEPTABAO_EXTERNAL_COMPLETION_ADMISSION_PROTOCOL_V1.md"),
        Path("schemas/heptabao_external_completion_evidence_v1.schema.json"),
        Path("scripts/render_plan_v1_4_7.py"),
        Path("scripts/validate_plan_v1_4_7.py"),
        Path("scripts/validate_external_completion_evidence_v1.py"),
        Path(".github/workflows/plan-v1.4.7-post-merge-truth-and-external-admission.yml"),
    ]
    paths.extend(Path(module["module_guide"]) for module in truth["modules"])
    paths.extend(sorted(Path("qualifications/external/templates").glob("*.json")))
    return sorted(set(paths), key=lambda item: item.as_posix())


def write_or_compare(root: Path, values: dict[Path, str], *, write: bool) -> None:
    mismatches: list[str] = []
    for relative, content in sorted(values.items(), key=lambda item: item[0].as_posix()):
        path = root / relative
        if write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        elif not path.is_file() or path.read_text(encoding="utf-8") != content:
            mismatches.append(relative.as_posix())
    if mismatches:
        raise SystemExit(f"generated V1.4.7 content drift: {mismatches}")


def render(root: Path, *, write: bool) -> None:
    values = static_files()
    write_or_compare(root, values, write=write)
    truth = build_truth(root)
    truth_text = dump_yaml(truth)
    write_or_compare(root, {TRUTH_PATH: truth_text}, write=write)
    doc_values = {
        Path(module["module_guide"]): module_doc_expected(root, module) for module in truth["modules"]
    }
    doc_values[Path("docs/modules/README.md")] = module_index_expected(root, truth)
    write_or_compare(root, doc_values, write=write)
    # Rebuild truth after generated documentation. Source facts are intentionally unaffected.
    truth = build_truth(root)
    write_or_compare(root, {TRUTH_PATH: dump_yaml(truth)}, write=write)
    manifest_files = []
    for relative in normative_paths(truth):
        path = root / relative
        if not path.is_file():
            raise SystemExit(f"normative file missing: {relative}")
        manifest_files.append({"path": relative.as_posix(), "sha256": sha256_file(path)})
    manifest = {
        "schema": "heptabao.normative-document-manifest.v1_4_7",
        "plan_id": PLAN_ID,
        "revision": "1.4.7",
        "status": "CANDIDATE_EXACT_HEAD_AND_MERGE_REVIEW_REQUIRED",
        "source_baseline": {"commit": BASELINE_COMMIT, "tree": BASELINE_TREE},
        "files": manifest_files,
        "claims": CLAIMS,
    }
    write_or_compare(root, {MANIFEST_PATH: dump_yaml(manifest)}, write=write)


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    render(root, write=args.write)
    print(f"PASS V1.4.7 render mode={'write' if args.write else 'check'} root={root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
