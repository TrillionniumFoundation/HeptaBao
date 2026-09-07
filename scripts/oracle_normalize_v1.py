#!/usr/bin/env python3
"""Deterministically sanitize one JSON Oracle response.

The normalizer preserves unknown fields, applies only versioned path rules,
converts registered secret-bearing values into typed digest/length placeholders,
and rejects suspicious secret fields not covered by a rule.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

POLICY_SCHEMA: Final = "heptabao.oracle-normalization-policy.v1"
OUTPUT_SCHEMA: Final = "heptabao.oracle-normalized-fixture.v1"
REMOVE = object()


class NormalizationError(RuntimeError):
    """The input or policy cannot be sanitized safely."""


def canonical_bytes(value: Any) -> bytes:
    """Encode a JSON value with deterministic separators and key ordering."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def escape_pointer_segment(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def unescape_pointer_segment(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def pointer(segments: tuple[str, ...]) -> str:
    if not segments:
        return ""
    return "/" + "/".join(escape_pointer_segment(segment) for segment in segments)


def parse_pointer(value: str) -> tuple[str, ...]:
    if value == "":
        return ()
    if not value.startswith("/"):
        raise NormalizationError(f"rule path is not a JSON Pointer: {value!r}")
    return tuple(unescape_pointer_segment(segment) for segment in value[1:].split("/"))


def shape(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise NormalizationError(f"non-JSON value type: {type(value).__name__}")


def secret_bytes(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return canonical_bytes(value)


def is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def is_secret_placeholder(value: Any, schema_key: str) -> bool:
    if not isinstance(value, dict) or set(value) != {schema_key}:
        return False
    body = value[schema_key]
    if not isinstance(body, dict):
        return False
    required = {"kind", "sha256", "byte_length", "value_shape"}
    return required.issubset(body)


@dataclass(frozen=True)
class Rule:
    raw_path: str
    segments: tuple[str, ...]
    operation: str
    reason: str
    security_relevance: str
    approved_roles: tuple[str, ...]
    replacement: Any = None
    secret_kind: str | None = None

    @property
    def specificity(self) -> int:
        return sum(segment != "*" for segment in self.segments)

    def matches(self, actual: tuple[str, ...]) -> bool:
        if len(actual) != len(self.segments):
            return False
        return all(expected == "*" or expected == observed for expected, observed in zip(self.segments, actual, strict=True))


class Normalizer:
    def __init__(self, policy: dict[str, Any], policy_bytes: bytes) -> None:
        if policy.get("schema") != POLICY_SCHEMA:
            raise NormalizationError("unsupported normalization policy schema")
        if policy.get("policy_id") != "HB-ORACLE-NORMALIZATION-V1":
            raise NormalizationError("unexpected normalization policy ID")

        defaults = policy.get("defaults")
        if not isinstance(defaults, dict):
            raise NormalizationError("policy defaults are missing")
        expected_defaults = {
            "unknown_fields": "PRESERVE",
            "unknown_arrays": "PRESERVE_ORDER",
            "unmatched_secret_key": "REJECT",
            "authority_effect": "NONE",
        }
        for key, expected in expected_defaults.items():
            if defaults.get(key) != expected:
                raise NormalizationError(f"unsafe default {key}: expected {expected!r}")

        placeholder = policy.get("secret_placeholder")
        if not isinstance(placeholder, dict):
            raise NormalizationError("secret placeholder configuration is missing")
        self.placeholder_key = placeholder.get("schema_key")
        if self.placeholder_key != "$heptabao_secret_placeholder_v1":
            raise NormalizationError("unexpected secret placeholder schema key")
        if placeholder.get("retain_raw_value") is not False:
            raise NormalizationError("secret placeholder must not retain raw values")
        if placeholder.get("digest_algorithm") != "sha256":
            raise NormalizationError("only SHA-256 secret placeholders are supported")

        suspicious = policy.get("suspicious_exact_key_names")
        if not isinstance(suspicious, list) or not suspicious:
            raise NormalizationError("suspicious key registry is empty")
        self.suspicious_keys = {str(item).casefold() for item in suspicious}

        raw_rules = policy.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise NormalizationError("normalization rule set is empty")
        rules: list[Rule] = []
        seen_paths: set[str] = set()
        for item in raw_rules:
            if not isinstance(item, dict):
                raise NormalizationError("normalization rule is not a mapping")
            raw_path = item.get("path")
            operation = item.get("operation")
            reason = item.get("reason")
            relevance = item.get("security_relevance")
            approved_roles = item.get("approved_roles")
            if not isinstance(raw_path, str) or raw_path in seen_paths:
                raise NormalizationError(f"duplicate or invalid rule path: {raw_path!r}")
            if operation not in {"replace", "secret_placeholder", "sort_scalar_array", "remove"}:
                raise NormalizationError(f"unsupported operation at {raw_path}: {operation!r}")
            if not isinstance(reason, str) or not reason.strip():
                raise NormalizationError(f"missing rule reason at {raw_path}")
            if not isinstance(relevance, str) or not relevance:
                raise NormalizationError(f"missing security relevance at {raw_path}")
            if not isinstance(approved_roles, list) or not {"compatibility", "security"}.issubset(approved_roles):
                raise NormalizationError(f"rule lacks compatibility/security approval at {raw_path}")
            if operation == "remove" and relevance != "NON_SECURITY":
                raise NormalizationError(f"security-relevant remove rule is forbidden at {raw_path}")
            if operation == "secret_placeholder" and not isinstance(item.get("secret_kind"), str):
                raise NormalizationError(f"secret rule lacks secret_kind at {raw_path}")
            if operation == "replace" and "replacement" not in item:
                raise NormalizationError(f"replace rule lacks replacement at {raw_path}")
            seen_paths.add(raw_path)
            rules.append(
                Rule(
                    raw_path=raw_path,
                    segments=parse_pointer(raw_path),
                    operation=operation,
                    reason=reason,
                    security_relevance=relevance,
                    approved_roles=tuple(str(role) for role in approved_roles),
                    replacement=item.get("replacement"),
                    secret_kind=item.get("secret_kind"),
                )
            )
        self.rules = tuple(rules)
        self.policy_id = str(policy["policy_id"])
        self.policy_version = str(policy.get("version", "unknown"))
        self.policy_sha256 = sha256_hex(policy_bytes)
        self.changes: list[dict[str, str]] = []

    def select_rule(self, path: tuple[str, ...]) -> Rule | None:
        matches = [rule for rule in self.rules if rule.matches(path)]
        if not matches:
            return None
        highest = max(rule.specificity for rule in matches)
        winners = [rule for rule in matches if rule.specificity == highest]
        if len(winners) != 1:
            names = ", ".join(rule.raw_path for rule in winners)
            raise NormalizationError(f"ambiguous normalization rules for {pointer(path)}: {names}")
        return winners[0]

    def apply_rule(self, rule: Rule, value: Any, path: tuple[str, ...]) -> Any:
        location = pointer(path)
        if rule.operation == "replace":
            result = rule.replacement
        elif rule.operation == "secret_placeholder":
            raw = secret_bytes(value)
            result = {
                self.placeholder_key: {
                    "kind": rule.secret_kind,
                    "sha256": sha256_hex(raw),
                    "byte_length": len(raw),
                    "value_shape": shape(value),
                }
            }
        elif rule.operation == "sort_scalar_array":
            if not isinstance(value, list) or not all(is_scalar(item) for item in value):
                raise NormalizationError(f"sort_scalar_array requires a scalar array at {location}")
            result = sorted(value, key=canonical_bytes)
        elif rule.operation == "remove":
            result = REMOVE
        else:
            raise NormalizationError(f"unreachable operation at {location}: {rule.operation}")
        self.changes.append({"path": location, "operation": rule.operation, "reason": rule.reason})
        return result

    def normalize_node(self, value: Any, path: tuple[str, ...] = ()) -> Any:
        rule = self.select_rule(path)
        if rule is not None:
            return self.apply_rule(rule, value, path)

        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for key, child in value.items():
                if not isinstance(key, str):
                    raise NormalizationError(f"non-string JSON object key at {pointer(path)}")
                normalized = self.normalize_node(child, (*path, key))
                if normalized is not REMOVE:
                    result[key] = normalized
            return result
        if isinstance(value, list):
            result_list: list[Any] = []
            for index, child in enumerate(value):
                normalized = self.normalize_node(child, (*path, str(index)))
                if normalized is not REMOVE:
                    result_list.append(normalized)
            return result_list
        if isinstance(value, float) and not math.isfinite(value):
            raise NormalizationError(f"non-finite number at {pointer(path)}")
        if is_scalar(value):
            return value
        raise NormalizationError(f"unsupported JSON value at {pointer(path)}: {type(value).__name__}")

    def validate_no_unmatched_secrets(self, value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            if is_secret_placeholder(value, self.placeholder_key):
                return
            for key, child in value.items():
                child_path = (*path, key)
                if key.casefold() in self.suspicious_keys and child is not None and not is_secret_placeholder(child, self.placeholder_key):
                    raise NormalizationError(
                        f"unmatched suspicious secret field at {pointer(child_path)}; add an approved exact/wildcard rule"
                    )
                self.validate_no_unmatched_secrets(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self.validate_no_unmatched_secrets(child, (*path, str(index)))

    def normalize(self, value: Any, input_bytes: bytes) -> dict[str, Any]:
        normalized = self.normalize_node(value)
        if normalized is REMOVE:
            raise NormalizationError("root removal is forbidden")
        self.validate_no_unmatched_secrets(normalized)
        normalized_bytes = canonical_bytes(normalized)
        return {
            "schema": OUTPUT_SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "input_sha256": sha256_hex(input_bytes),
            "normalized_sha256": sha256_hex(normalized_bytes),
            "changes": self.changes,
            "document": normalized,
            "authority_effect": "NONE",
        }


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError as error:
        raise NormalizationError(f"invalid JSON input: {error}") from error


def load_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise NormalizationError(f"invalid YAML policy: {error}") from error
    if not isinstance(value, dict):
        raise NormalizationError("normalization policy is not a mapping")
    return value, raw


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_bytes(encoded)
    os.replace(temporary, path)


def normalize_file(input_path: Path, policy_path: Path) -> dict[str, Any]:
    document, input_bytes = load_json(input_path)
    policy, policy_bytes = load_policy(policy_path)
    return Normalizer(policy, policy_bytes).normalize(document, input_bytes)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="restricted or synthetic JSON input")
    parser.add_argument("--policy", required=True, type=Path, help="versioned normalization policy YAML")
    parser.add_argument("--output", required=True, type=Path, help="sanitized JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = normalize_file(args.input, args.policy)
        atomic_write_json(args.output, result)
    except (OSError, NormalizationError) as error:
        print(f"Oracle normalization FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "Oracle normalization passed: "
        f"policy={result['policy_id']} changes={len(result['changes'])} "
        f"output_sha256={result['normalized_sha256']} authority=NONE"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
