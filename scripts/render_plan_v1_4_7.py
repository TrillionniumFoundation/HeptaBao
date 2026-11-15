#!/usr/bin/env python3
"""Render V1.4.7 using the frozen generator with corrected shell escaping.

The original generator is kept byte-for-byte for a reviewable, narrow repair.
No workflow, test, authority claim or generated input is read back as its own
expected value. Check mode remains read-only and compares complete output bytes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import ModuleType
from typing import Any

BASELINE_PATH = Path(__file__).with_name("_render_plan_v1_4_7_baseline.py")
BASELINE_SHA256 = "274de8d4a99a85954244f0ce84fe6dda06ff05841afda0ee3a62af4bdebebd7b"


def _load_frozen_renderer() -> ModuleType:
    # Verify and execute the SAME snapshot. A file loader may reopen the path or
    # accept an mtime/size-valid .pyc whose code was not covered by this digest.
    source = BASELINE_PATH.read_bytes()
    if hashlib.sha256(source).hexdigest() != BASELINE_SHA256:
        raise ValueError("frozen V1.4.7 generator integrity mismatch")
    module = ModuleType("heptabao_v147_frozen_renderer")
    module.__file__ = str(BASELINE_PATH)
    module.__package__ = ""
    code = compile(source, str(BASELINE_PATH), "exec", dont_inherit=True)
    exec(code, module.__dict__)
    return module


BASELINE = _load_frozen_renderer()
_ORIGINAL_WORKFLOW = BASELINE.workflow_source
_ORIGINAL_PATHS = BASELINE.normative_paths
_ORIGINAL_STATIC_FILES = BASELINE.static_files


def workflow_source() -> str:
    source = _ORIGINAL_WORKFLOW()
    replacements = (
        ("printf 'source_kind=%s\nsource_sha=%s\ntree=%s\n'",
         r"printf 'source_kind=%s\nsource_sha=%s\ntree=%s\n'"),
        ('compatibility_claim: true"             planning/',
         'compatibility_claim: true" ' + "\\" + "\n" + "            planning/"),
    )
    for before, after in replacements:
        if source.count(before) != 1:
            raise ValueError("frozen workflow escape anchor mismatch")
        source = source.replace(before, after, 1)
    return source


def static_files() -> dict[Path, str]:
    # V1.4.7 is retained as historical exact-source evidence. Current entry
    # pages are owned by the active V2 repository truth and are never rewritten
    # or read back as expected output by this historical renderer.
    return _ORIGINAL_STATIC_FILES()


def normative_paths(truth: dict[str, Any]) -> list[Path]:
    additions = {
        Path("tests/plan/test_current_entry_v1_4_7.py"),
        Path("scripts/_render_plan_v1_4_7_baseline.py"),
        Path("tests/plan/test_workflow_render_v1_4_7.py"),
    }
    return sorted(set(_ORIGINAL_PATHS(truth)) | additions, key=lambda path: path.as_posix())


BASELINE.workflow_source = workflow_source
BASELINE.normative_paths = normative_paths
BASELINE.static_files = static_files


def __getattr__(name: str) -> Any:
    # Preserve the generator's public inspection API used by existing tests.
    return getattr(BASELINE, name)


if __name__ == "__main__":
    raise SystemExit(BASELINE.main())
