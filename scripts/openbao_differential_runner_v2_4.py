#!/usr/bin/env python3
"""Bounded, secret-redacting OpenBao/HeptaBao differential capture runner."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MAX_PROFILE_BYTES = 2 * 1024 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SURFACES = 1024
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "LIST"}
DENIED_PROFILE_HEADERS = {"authorization", "x-vault-token", "x-openbao-token"}
SENSITIVE_KEY_TOKENS = (
    "token", "secret", "password", "private", "recovery_key", "unseal_key",
    "client_key", "access_key", "credential", "ciphertext", "otp", "code",
)


class CaptureError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path, maximum: int = MAX_PROFILE_BYTES) -> Any:
    data = path.read_bytes()
    if not data or len(data) > maximum:
        raise CaptureError(f"invalid JSON artifact size: {path}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CaptureError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CaptureError(f"invalid JSON: {path}: {exc}") from exc


def _extract_surface_ids(document: Any) -> set[str]:
    candidates: list[Any]
    if isinstance(document, dict) and isinstance(document.get("surfaces"), list):
        candidates = document["surfaces"]
    elif isinstance(document, list):
        candidates = document
    else:
        candidates = []
        if isinstance(document, dict):
            for value in document.values():
                if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                    if any("surface_id" in item or "id" in item for item in value):
                        candidates.extend(value)
    surface_ids: set[str] = set()
    for item in candidates:
        if not isinstance(item, dict):
            continue
        value = item.get("surface_id", item.get("id"))
        if isinstance(value, str) and value:
            if value in surface_ids:
                raise CaptureError(f"duplicate denominator surface: {value}")
            surface_ids.add(value)
    if not surface_ids or len(surface_ids) > MAX_SURFACES:
        raise CaptureError("denominator surface inventory is empty or out of bounds")
    return surface_ids


def _checked_surface_id(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise CaptureError("invalid surface identifier")
    if not all(ch.isalnum() or ch in "-_.:" for ch in value):
        raise CaptureError(f"invalid surface identifier: {value}")
    return value


def _checked_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/v1/") or len(value) > 2048:
        raise CaptureError("request path must be a bounded /v1/ path")
    decoded = urllib.parse.unquote(value)
    if ".." in decoded.split("/") or "\x00" in decoded:
        raise CaptureError("request path contains traversal or NUL")
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def _redact(value: Any, key: str | None = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        encoded = _canonical_json_bytes(value)
        return {"redacted_sha256": _sha256(encoded), "redacted_bytes": len(encoded)}
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _replace_pointer(document: Any, pointer: str, replacement: Any) -> None:
    if pointer == "":
        raise CaptureError("root JSON pointer normalization is forbidden")
    if not pointer.startswith("/"):
        raise CaptureError(f"invalid JSON pointer: {pointer}")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        if isinstance(current, dict):
            if part not in current:
                return
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return
        else:
            return
    leaf = parts[-1]
    if isinstance(current, dict) and leaf in current:
        current[leaf] = replacement
    elif isinstance(current, list):
        try:
            current[int(leaf)] = replacement
        except (ValueError, IndexError):
            return


@dataclass(frozen=True)
class RequestSpec:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes | None
    selected_response_headers: tuple[str, ...]
    normalize_json_pointers: tuple[str, ...]


@dataclass(frozen=True)
class SurfaceSpec:
    surface_id: str
    request: RequestSpec


@dataclass(frozen=True)
class CaptureProfile:
    surfaces: tuple[SurfaceSpec, ...]
    profile_sha256: str
    denominator_sha256: str


def load_profile(profile_path: Path, denominator_path: Path) -> CaptureProfile:
    profile_bytes = profile_path.read_bytes()
    denominator_bytes = denominator_path.read_bytes()
    profile = _load_json(profile_path)
    denominator = _load_json(denominator_path)
    required = _extract_surface_ids(denominator)
    items = profile.get("surfaces") if isinstance(profile, dict) else None
    if not isinstance(items, list) or not items or len(items) > MAX_SURFACES:
        raise CaptureError("capture profile surfaces are missing or out of bounds")
    surfaces: list[SurfaceSpec] = []
    observed: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise CaptureError("surface profile entry must be an object")
        surface_id = _checked_surface_id(item.get("surface_id", item.get("id")))
        if surface_id in observed:
            raise CaptureError(f"duplicate profile surface: {surface_id}")
        observed.add(surface_id)
        request = item.get("request")
        if not isinstance(request, dict):
            raise CaptureError(f"surface {surface_id} has no request")
        method = str(request.get("method", "")).upper()
        if method not in ALLOWED_METHODS:
            raise CaptureError(f"surface {surface_id} uses denied method")
        path = _checked_path(request.get("path"))
        raw_headers = request.get("headers", {})
        if not isinstance(raw_headers, dict) or len(raw_headers) > 64:
            raise CaptureError("request headers are invalid")
        headers: dict[str, str] = {}
        for name, value in raw_headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise CaptureError("request header must be string:string")
            lowered = name.lower()
            if lowered in DENIED_PROFILE_HEADERS or "\r" in value or "\n" in value:
                raise CaptureError(f"profile contains denied header: {name}")
            headers[name] = value
        body_value = request.get("body")
        body = None if body_value is None else _canonical_json_bytes(body_value)
        if body is not None and len(body) > MAX_REQUEST_BYTES:
            raise CaptureError("request body exceeds bound")
        selected = item.get("selected_response_headers", [])
        if not isinstance(selected, list) or len(selected) > 64 or not all(isinstance(v, str) for v in selected):
            raise CaptureError("selected response headers are invalid")
        pointers = item.get("normalize_json_pointers", [])
        if not isinstance(pointers, list) or len(pointers) > 256 or not all(isinstance(v, str) for v in pointers):
            raise CaptureError("normalization pointers are invalid")
        surfaces.append(SurfaceSpec(surface_id, RequestSpec(
            method, path, headers, body,
            tuple(value.lower() for value in selected), tuple(pointers),
        )))
    if observed != required:
        missing = sorted(required - observed)
        extra = sorted(observed - required)
        raise CaptureError(f"profile denominator mismatch missing={missing} extra={extra}")
    return CaptureProfile(tuple(surfaces), _sha256(profile_bytes), _sha256(denominator_bytes))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise CaptureError(f"redirect denied: {code} {newurl}")


def _ssl_context(ca_file: Path | None, client_cert: Path | None, client_key: Path | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    if (client_cert is None) != (client_key is None):
        raise CaptureError("client certificate and key must be supplied together")
    if client_cert is not None:
        context.load_cert_chain(str(client_cert), str(client_key))
    return context


def _capture_one(
    base_url: str,
    spec: SurfaceSpec,
    token: str,
    timeout: float,
    context: ssl.SSLContext,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", spec.request.path.lstrip("/"))
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise CaptureError("capture endpoint must be HTTPS")
    headers = dict(spec.request.headers)
    headers["X-Vault-Token"] = token
    headers["Accept"] = "application/json"
    if spec.request.body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url=url,
        data=spec.request.body,
        headers=headers,
        method=spec.request.method,
    )
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
        raise CaptureError(f"surface {spec.surface_id} transport failed: {exc}") from exc
    status = int(response.status)
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise CaptureError(f"surface {spec.surface_id} response exceeds bound")
    selected_headers = {
        name: response.headers.get(name, "")
        for name in spec.request.selected_response_headers
    }
    body_kind = "bytes"
    normalized_body: Any = {"sha256": _sha256(body), "bytes": len(body)}
    if body:
        try:
            parsed_body = json.loads(body, object_pairs_hook=lambda pairs: _unique_response_object(pairs))
        except (json.JSONDecodeError, UnicodeDecodeError, CaptureError):
            pass
        else:
            body_kind = "json"
            parsed_body = _redact(parsed_body)
            for pointer in spec.request.normalize_json_pointers:
                _replace_pointer(parsed_body, pointer, "<normalized>")
            normalized_body = parsed_body
    canonical = {
        "status": status,
        "headers": selected_headers,
        "body_kind": body_kind,
        "body": normalized_body,
    }
    return {
        "surface_id": spec.surface_id,
        "status": status,
        "body_kind": body_kind,
        "response_bytes": len(body),
        "canonical_sha256": _sha256(_canonical_json_bytes(canonical)),
    }


def _unique_response_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureError(f"duplicate response JSON member: {key}")
        result[key] = value
    return result


def capture(
    profile: CaptureProfile,
    base_url: str,
    mode: str,
    producer: str,
    source_ref: str,
    token: str,
    timeout: float,
    context: ssl.SSLContext,
) -> dict[str, Any]:
    if mode not in {"candidate", "oracle"}:
        raise CaptureError("capture mode must be candidate or oracle")
    if mode == "oracle" and producer == "repository-controlled":
        raise CaptureError("oracle producer must be independently controlled")
    if not token or len(token) > 16 * 1024 or any(ch.isspace() for ch in token):
        raise CaptureError("capture token is invalid")
    observations = [
        _capture_one(base_url, surface, token, timeout, context)
        for surface in profile.surfaces
    ]
    artifact = {
        "schema": "heptabao-openbao-differential-v2.4",
        "mode": mode,
        "producer": producer,
        "source_ref": source_ref,
        "profile_sha256": profile.profile_sha256,
        "denominator_sha256": profile.denominator_sha256,
        "surface_count": len(observations),
        "observations": observations,
    }
    artifact["artifact_sha256"] = _sha256(_canonical_json_bytes(artifact))
    return artifact


def _validate_capture_artifact(artifact: dict[str, Any], expected_mode: str) -> dict[str, dict[str, Any]]:
    if not isinstance(artifact, dict) or artifact.get("mode") != expected_mode:
        raise CaptureError(f"capture artifact mode is not {expected_mode}")
    supplied_hash = artifact.get("artifact_sha256")
    if not isinstance(supplied_hash, str) or len(supplied_hash) != 64:
        raise CaptureError("capture artifact digest is invalid")
    unsigned = dict(artifact)
    unsigned.pop("artifact_sha256", None)
    if _sha256(_canonical_json_bytes(unsigned)) != supplied_hash:
        raise CaptureError("capture artifact digest mismatch")
    rows = artifact.get("observations")
    count = artifact.get("surface_count")
    if not isinstance(rows, list) or not isinstance(count, int) or count != len(rows):
        raise CaptureError("capture artifact observation count mismatch")
    if count <= 0 or count > MAX_SURFACES:
        raise CaptureError("capture artifact observation count is out of bounds")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise CaptureError("capture artifact observation is invalid")
        surface_id = _checked_surface_id(row.get("surface_id"))
        if surface_id in result:
            raise CaptureError(f"duplicate artifact surface: {surface_id}")
        status = row.get("status")
        response_bytes = row.get("response_bytes")
        canonical = row.get("canonical_sha256")
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise CaptureError(f"invalid status for surface {surface_id}")
        if not isinstance(response_bytes, int) or not 0 <= response_bytes <= MAX_RESPONSE_BYTES:
            raise CaptureError(f"invalid response size for surface {surface_id}")
        if (
            not isinstance(canonical, str)
            or len(canonical) != 64
            or any(character not in "0123456789abcdef" for character in canonical)
        ):
            raise CaptureError(f"invalid canonical digest for surface {surface_id}")
        result[surface_id] = row
    return result


def compare_artifacts(candidate: dict[str, Any], oracle: dict[str, Any]) -> dict[str, Any]:
    candidate_rows = _validate_capture_artifact(candidate, "candidate")
    oracle_rows = _validate_capture_artifact(oracle, "oracle")
    if oracle.get("producer") == "repository-controlled":
        raise CaptureError("oracle artifact is not independently produced")
    for field in ("profile_sha256", "denominator_sha256", "surface_count"):
        if candidate.get(field) != oracle.get(field):
            raise CaptureError(f"artifact binding mismatch: {field}")
    if candidate_rows.keys() != oracle_rows.keys():
        raise CaptureError("candidate/oracle surface sets differ")
    mismatches = [
        surface_id
        for surface_id in candidate_rows
        if candidate_rows[surface_id].get("canonical_sha256")
        != oracle_rows[surface_id].get("canonical_sha256")
    ]
    return {
        "schema": "heptabao-openbao-differential-comparison-v2.4",
        "surface_count": len(candidate_rows),
        "matching_surfaces": len(candidate_rows) - len(mismatches),
        "mismatches": mismatches,
        "compatible": not mismatches,
        "candidate_artifact_sha256": candidate.get("artifact_sha256"),
        "oracle_artifact_sha256": oracle.get("artifact_sha256"),
    }


def _write_json(path: Path, value: Any) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(encoded, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-profile")
    validate.add_argument("--profile", type=Path, required=True)
    validate.add_argument("--denominator", type=Path, required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--profile", type=Path, required=True)
    capture_parser.add_argument("--denominator", type=Path, required=True)
    capture_parser.add_argument("--base-url", required=True)
    capture_parser.add_argument("--mode", choices=("candidate", "oracle"), required=True)
    capture_parser.add_argument("--producer", required=True)
    capture_parser.add_argument("--source-ref", required=True)
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--ca-file", type=Path)
    capture_parser.add_argument("--client-cert", type=Path)
    capture_parser.add_argument("--client-key", type=Path)
    capture_parser.add_argument("--timeout", type=float, default=15.0)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--candidate", type=Path, required=True)
    compare_parser.add_argument("--oracle", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-profile":
            profile = load_profile(args.profile, args.denominator)
            print(json.dumps({"surface_count": len(profile.surfaces), "profile_sha256": profile.profile_sha256, "denominator_sha256": profile.denominator_sha256}, sort_keys=True))
            return 0
        if args.command == "capture":
            profile = load_profile(args.profile, args.denominator)
            token = os.environ.get("HEPTABAO_CAPTURE_TOKEN", "")
            artifact = capture(profile, args.base_url, args.mode, args.producer, args.source_ref, token, args.timeout, _ssl_context(args.ca_file, args.client_cert, args.client_key))
            _write_json(args.output, artifact)
            return 0
        candidate = _load_json(args.candidate)
        oracle = _load_json(args.oracle)
        comparison = compare_artifacts(candidate, oracle)
        _write_json(args.output, comparison)
        return 0 if comparison["compatible"] else 2
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
