#!/usr/bin/env python3
"""Fail closed on credential, executable-input and artifact-export paths.

This combines the frozen V1 structural checks with V2 closed expression and
artifact-action schemas.  It is still candidate-controlled evidence, not an
independent admission authority, immutable runner proof or transitive sandbox.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import validate_workflow_trust_v1 as _v1  # noqa: E402
import workflow_trust_v2 as _v2  # noqa: E402
from validate_workflow_trust_v1 import *  # noqa: F401,F403,E402

MAX_TEMPLATE_BYTES = _v2.MAX_TEMPLATE_BYTES
CHECKOUT_ACTION = _v2.CHECKOUT_ACTION
SETUP_PYTHON_ACTION = _v2.SETUP_PYTHON_ACTION
UPLOAD_ARTIFACT_ACTION = _v2.UPLOAD_ARTIFACT_ACTION
DOWNLOAD_ARTIFACT_ACTION = _v2.DOWNLOAD_ARTIFACT_ACTION
APPROVED_UPLOAD_PATHS = _v2.APPROVED_UPLOAD_PATHS
APPROVED_DOWNLOAD_OPTIONS = _v2.APPROVED_DOWNLOAD_OPTIONS
check_upload_path = _v2.check_upload_path


def validate_text(text: str, filename: str = "workflow.yml") -> None:
    _v1.validate_text(text, filename)
    _v2.validate_extra(text, filename)


def validate_directory(directory: Path) -> dict[str, object]:
    if directory.is_symlink() or not directory.is_dir():
        raise PolicyError("workflow directory missing or symlinked")
    paths = sorted(path for path in directory.iterdir() if path.suffix.lower() in {".yml", ".yaml"})
    if not paths or len(paths) > MAX_WORKFLOWS:
        raise PolicyError("empty or excessive workflow set")
    checked: list[str] = []
    failures: list[dict[str, str]] = []
    for path in paths:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_WORKFLOW_BYTES:
                raise PolicyError("nonregular or oversized workflow")
            validate_text(path.read_text(encoding="utf-8"), path.name)
            checked.append(path.name)
        except (PolicyError, OSError, UnicodeError, RecursionError) as error:
            failures.append({"path": path.name, "error": str(error)})
    return {
        "schema": "heptabao.workflow-trust-check.v2",
        "checked": checked,
        "failures": failures,
        "result": "FAIL" if failures else "PASS",
        "authority_effect": "NONE",
        "production_authority": False,
        "independent_admission": False,
        "runner_image_immutability": "NOT_ESTABLISHED_BY_LABEL_ALLOWLIST",
        "credential_model": (
            "read-only token use by pinned actions and one exact historical observer; "
            "external/event/repository-variable expressions are excluded from executable env; "
            "not credential-free"
        ),
        "artifact_export_model": "EXACT_PER_INVOCATION_PATH_AND_ACTION_INPUT_SCHEMA",
        "transitive_script_sandbox": False,
        "runtime_symlink_state": "NOT_ESTABLISHED_BY_STATIC_POLICY",
        "requires_live_runner_environment_and_independent_policy_controls": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / ".github/workflows",
    )
    args = parser.parse_args()
    try:
        result = validate_directory(args.directory)
    except (PolicyError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(bool(result["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
