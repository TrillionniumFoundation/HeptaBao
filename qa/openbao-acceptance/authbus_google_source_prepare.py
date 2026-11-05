#!/usr/bin/env python3
"""Validate an owned Google API key and stage an isolated AuthBus source bundle.

This tool reads one existing owner-only environment file. It sends exactly two
metadata GETs to the official Google endpoint (without a key, then with the
selected key in an HTTPS header). It never generates content, refreshes OAuth,
contacts J3160, changes a source file, or writes any Bao/agent configuration.

A positive receipt means key-authenticated models metadata is available. It
does not establish inference availability, billing entitlement, source-account
identity, complete AuthBus migration, or production cutover.

The private candidate stays on the source machine in a newly created mode 0700
directory. Public output contains only metadata and non-secret hashes. Never
copy the private candidate or environment file into a tool/chat transcript.

Official contracts checked 2026-10-17:
  https://ai.google.dev/api/models#method:-models.list
  https://ai.google.dev/api#authentication
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from typing import Any


HOST = "generativelanguage.googleapis.com"
TARGET = "/v1beta/models?pageSize=1000"
MAX_RESPONSE = 1024 * 1024
SOURCE_KEYS = ("GOOGLE_API_KEY", "GEMINI_API_KEY")


class SourceError(Exception):
    """A fixed diagnostic code, never including untrusted/source text."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_source(p: Path) -> tuple[dict[str, str], dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise SourceError("source_open_failed") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise SourceError("source_must_be_owned_private_regular_file")
        if before.st_size > 65536:
            raise SourceError("source_exceeds_bound")
        data = os.read(fd, 65537)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if len(data) > 65536 or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise SourceError("source_changed_during_read")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceError("source_not_utf8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        key, separator, raw = stripped.partition("=")
        key = key.strip()
        if key not in SOURCE_KEYS:
            continue
        if not separator or key in values:
            raise SourceError("duplicate_or_invalid_source_assignment")
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            raw = raw[1:-1]
        # No shell parsing, expansion, command substitution, or ambiguous
        # escaped values. The known Google API-key alphabet needs none.
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,512}", raw):
            raise SourceError("unsupported_source_value_shape")
        values[key] = raw
    meta = {
        "path": str(p), "uid": before.st_uid, "mode": oct(stat.S_IMODE(before.st_mode)),
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "mtime_ns": before.st_mtime_ns, "present_fields": sorted(values),
    }
    return values, meta


def models_probe(key: str | None) -> dict[str, Any]:
    context = ssl.create_default_context()
    conn = http.client.HTTPSConnection(HOST, 443, timeout=10, context=context)
    headers = {"Accept": "application/json", "User-Agent": "HeptaBao-AuthBus-source-validation/1"}
    if key is not None:
        headers["x-goog-api-key"] = key
    try:
        conn.request("GET", TARGET, headers=headers)
        response = conn.getresponse()
        body = response.read(MAX_RESPONSE + 1)
        result: dict[str, Any] = {"http_status": response.status, "tls_verified": True, "body_within_bound": len(body) <= MAX_RESPONSE}
        if response.status == 200 and len(body) <= MAX_RESPONSE:
            try:
                parsed = json.loads(body)
                models = parsed.get("models") if isinstance(parsed, dict) else None
                result["models_array"] = isinstance(models, list)
                result["model_count_this_page"] = len(models) if isinstance(models, list) else 0
                result["has_next_page"] = bool(parsed.get("nextPageToken")) if isinstance(parsed, dict) else False
            except (ValueError, TypeError):
                result["models_array"] = False
        return result
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"transport_error_class": type(exc).__name__, "http_status": None, "tls_verified": False}
    finally:
        conn.close()


def exclusive_json(path: Path, value: Any) -> None:
    payload = canonical(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        # Preserve a private partial result for an operator; do not overwrite
        # or silently delete custody artifacts.
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--env-file", type=Path, required=True)
    p.add_argument("--env-key", choices=SOURCE_KEYS, default="GOOGLE_API_KEY")
    p.add_argument("--work-dir", type=Path, required=True, help="New absolute directory, must not already exist")
    p.add_argument("--provider", required=True, help="Canonical provider confirmed by the installed OpenClaw SDK")
    p.add_argument("--profile-id", required=True, help="New non-secret profile label")
    p.add_argument("--expected-source-sha256", default=None)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    receipt: dict[str, Any] = {
        "schema": "authbus-independent-source-v1", "ok": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_kind": "existing_owned_google_api_key", "contacts_j3160": False,
        "oauth_refreshed": False, "inference_called": False, "production_cutover": False,
        "verification_scope": "authenticated_models_metadata_only",
        "destination_written": False, "private_candidate_written": False,
    }
    created = False
    try:
        if not args.work_dir.is_absolute() or args.work_dir.is_symlink():
            raise SourceError("work_dir_must_be_new_absolute_path")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", args.provider):
            raise SourceError("invalid_provider_identifier")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._@-]{0,239}", args.profile_id):
            raise SourceError("invalid_profile_identifier")
        if not args.env_file.is_absolute():
            raise SourceError("source_path_must_be_absolute")
        if args.expected_source_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", args.expected_source_sha256):
            raise SourceError("invalid_expected_source_digest")
        args.work_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        created = True
        if stat.S_IMODE(args.work_dir.stat().st_mode) != 0o700:
            raise SourceError("work_dir_permissions_invalid")
        values, source_meta = read_source(args.env_file)
        receipt["source"] = source_meta
        if args.expected_source_sha256 is not None and source_meta["sha256"] != args.expected_source_sha256:
            raise SourceError("source_fingerprint_changed")
        if args.env_key not in values:
            raise SourceError("selected_source_field_missing")
        receipt["selected_field"] = args.env_key
        receipt["alias_values_equal"] = hmac.compare_digest(values[SOURCE_KEYS[0]], values[SOURCE_KEYS[1]]) if all(k in values for k in SOURCE_KEYS) else None
        negative = models_probe(None)
        receipt["unauthenticated_control"] = negative
        # A successful public metadata endpoint cannot establish key validity.
        if negative.get("http_status") not in (400, 401, 403):
            raise SourceError("unauthenticated_control_did_not_deny")
        positive = models_probe(values[args.env_key])
        receipt["authenticated_probe"] = positive
        if positive.get("http_status") != 200 or not positive.get("models_array") or not positive.get("body_within_bound"):
            raise SourceError("selected_key_not_verified")
        credential = {"type": "api_key", "provider": args.provider, "key": values[args.env_key]}
        credential_sha = digest(credential)
        identity = {field: credential.get(field) for field in ("provider", "type", "email", "accountId", "projectId")}
        identity_sha = digest(identity)
        profile_key = "sha256-" + credential_sha
        entry = {"profileId": args.profile_id, "key": profile_key, "digest": credential_sha,
                 "provider": args.provider, "type": "api_key"}
        profile = {"schemaVersion": 1, "profileId": args.profile_id, "credential": credential,
                   "digest": credential_sha, "identity": identity_sha}
        candidate = {
            "schema": "authbus-private-bootstrap-candidate-v1", "created_at": receipt["created_at"],
            "source": source_meta, "selected_field": args.env_key,
            "mount": "openclaw-auth",
            "profile": {"path": "profiles/" + profile_key, "data": profile, "cas": 0},
            "manifest": {"path": "manifest", "data": {"schemaVersion": 1, "generation": 1, "profiles": [entry]}, "cas": 0},
            "order_policy": {"path": "order-policy", "data": {"schemaVersion": 1, "generation": 1, "providers": {}}, "cas": 0},
            "scheduler_assignments": {"path": "scheduler-assignments", "data": {"schemaVersion": 1, "generation": 1, "scopes": [], "assignments": [], "refreshLeases": []}, "cas": 0},
            "verification": {"unauthenticated_control": negative, "authenticated_probe": positive},
            "constraints": {"leader": False, "publishNew": False, "manageOrder": False, "schedulerMode": "shadow"},
        }
        private_path = args.work_dir / "candidate.private.json"
        exclusive_json(private_path, candidate)
        receipt.update(ok=True, private_candidate_written=True, private_candidate_path=str(private_path),
                       private_candidate_mode="0o600", credential_digest=credential_sha,
                       identity_digest=identity_sha, profile_id=args.profile_id, provider=args.provider,
                       profile_key=profile_key, profile_count=1, manifest_generation=1)
    except (SourceError, OSError) as exc:
        receipt["error"] = str(exc) if isinstance(exc, SourceError) else type(exc).__name__
    except Exception as exc:
        receipt["error"] = "unexpected_" + type(exc).__name__
    if created:
        try:
            exclusive_json(args.work_dir / "public-receipt.json", receipt)
        except OSError as exc:
            receipt["receipt_persistence_error"] = type(exc).__name__
            receipt["ok"] = False
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
