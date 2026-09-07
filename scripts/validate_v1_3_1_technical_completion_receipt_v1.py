#!/usr/bin/env python3
"""Public V1.3.1 technical-receipt validator with provider lifecycle adaptation.

GitHub's live jobs API reports future steps as ``pending`` while the current
matrix job is still executing.  The stable HeptaBao receipt vocabulary uses
``queued`` for the same non-executed state.  The core validator remains the
frozen V1 implementation; this entrypoint adapts only that provider spelling
and leaves every required-gate PASS check and raw API digest binding intact.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_CORE_PATH = Path(__file__).with_name(
    "validate_v1_3_1_technical_completion_receipt_v1_core.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "heptabao_v1_3_1_technical_receipt_core", _CORE_PATH
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load V1.3.1 technical receipt validator core")
_CORE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CORE)

_ORIGINAL_STEP_OUTCOME = _CORE._step_outcome
_PROVIDER_STEP_STATUSES = set(_CORE.STEP_STATUSES) | {"pending"}


def _step_outcome(status: Any, conclusion: Any) -> str:
    """Map provider ``pending`` to canonical non-passing ``queued``."""

    canonical_status = "queued" if status == "pending" else status
    return _ORIGINAL_STEP_OUTCOME(canonical_status, conclusion)


_CORE.STEP_STATUSES = _PROVIDER_STEP_STATUSES
_CORE.PROVIDER_STEP_STATUSES = _PROVIDER_STEP_STATUSES
_CORE._step_outcome = _step_outcome

for _name in dir(_CORE):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_CORE, _name)

# Preserve the adapted symbols after the compatibility export above.
STEP_STATUSES = _PROVIDER_STEP_STATUSES
PROVIDER_STEP_STATUSES = _PROVIDER_STEP_STATUSES
globals()["_step_outcome"] = _step_outcome


if __name__ == "__main__":
    raise SystemExit(_CORE.main())
