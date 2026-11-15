"""Strict JSON parsing shared by repository plan validators."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


def unique_json_pairs(
    pairs: list[tuple[str, Any]], failure_type: type[RuntimeError]
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise failure_type(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def loads_strict_json(
    text: str,
    failure_type: type[RuntimeError],
    object_pairs_hook: Callable[[list[tuple[str, Any]]], dict[str, Any]],
) -> Any:
    return json.loads(
        text,
        object_pairs_hook=object_pairs_hook,
        parse_constant=lambda value: (_ for _ in ()).throw(
            failure_type(f"non-standard JSON constant: {value}")
        ),
    )
