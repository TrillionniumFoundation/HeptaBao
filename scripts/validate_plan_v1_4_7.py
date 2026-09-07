#!/usr/bin/env python3
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
