"""Helpers for explicitly quarantining superseded plan-era assertions.

V1.x tests remain useful when replayed against their frozen source snapshot.  The
active V2.5 candidate has deliberately changed manifests, generated documents,
and guard implementations; assertions tied to those exact bytes are therefore
marked historical-only instead of being weakened or reported as current passes.
"""
from __future__ import annotations

import unittest


HISTORICAL_V1_REASON = (
    "historical V1.x snapshot; replay in the pinned V1.x checkout, "
    "not against the active V2.5 candidate"
)


def historical_only(test):
    """Skip an assertion whose input/output is intentionally frozen to V1.x."""
    return unittest.skip(HISTORICAL_V1_REASON)(test)
