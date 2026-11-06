#!/usr/bin/env python3
"""SOURCE ONLY: bounded raw response observation for the frozen HTTP12/ACL23 gate.

This module does not launch a fixture, read credentials, create a Client, or grant
Runtime authority. A narrow private copy of the pinned Client.request records
one response while preserving the original validation, opener, response context,
JSON decoding and error classification. It never substitutes the client's opener
or mutates its timeout. The fixture must bind the exact source and Client owner.
"""
from __future__ import annotations

import hashlib
import math
import http.client
import urllib.error
import urllib.request

from heptabao.transport import (BaoError, MAX_BODY, Client, Response, canonical,
                               decode_json, _transport_diagnostic)
from heptabao.consistency import (Metadata, InvalidConsistency, response_index,
                                 retry_after)

PUBLIC_ACL_IDS = frozenset((
    "delete-none", "delete-update", "delete-update-sudo", "delete-delete",
    "delete-delete-sudo", "collection-bare-get-none", "collection-bare-get-read",
    "collection-bare-get-list", "collection-list-query-none",
    "collection-list-query-read", "collection-list-query-list",
    "collection-list-method-none", "collection-list-method-read",
    "collection-list-method-list", "existing-post-none", "existing-post-update",
    "existing-post-update-sudo", "fresh-post-create", "fresh-post-update-sudo",
    "fresh-post-create-update-sudo", "config-post-none", "config-post-update",
    "config-post-update-sudo",
))
PUBLIC_ACL_REQUESTS = {
    "delete-none": [
        "DELETE",
        "/v1/auth/jwt-acl/role/delete-none"
    ],
    "delete-update": [
        "DELETE",
        "/v1/auth/jwt-acl/role/delete-update"
    ],
    "delete-update-sudo": [
        "DELETE",
        "/v1/auth/jwt-acl/role/delete-update-sudo"
    ],
    "delete-delete": [
        "DELETE",
        "/v1/auth/jwt-acl/role/delete-delete"
    ],
    "delete-delete-sudo": [
        "DELETE",
        "/v1/auth/jwt-acl/role/delete-delete-sudo"
    ],
    "collection-bare-get-none": [
        "GET",
        "/v1/auth/jwt-acl/role"
    ],
    "collection-bare-get-read": [
        "GET",
        "/v1/auth/jwt-acl/role"
    ],
    "collection-bare-get-list": [
        "GET",
        "/v1/auth/jwt-acl/role"
    ],
    "collection-list-query-none": [
        "GET",
        "/v1/auth/jwt-acl/role?list=true"
    ],
    "collection-list-query-read": [
        "GET",
        "/v1/auth/jwt-acl/role?list=true"
    ],
    "collection-list-query-list": [
        "GET",
        "/v1/auth/jwt-acl/role?list=true"
    ],
    "collection-list-method-none": [
        "LIST",
        "/v1/auth/jwt-acl/role"
    ],
    "collection-list-method-read": [
        "LIST",
        "/v1/auth/jwt-acl/role"
    ],
    "collection-list-method-list": [
        "LIST",
        "/v1/auth/jwt-acl/role"
    ],
    "existing-post-none": [
        "POST",
        "/v1/auth/jwt-acl/role/existing-none"
    ],
    "existing-post-update": [
        "POST",
        "/v1/auth/jwt-acl/role/existing-update"
    ],
    "existing-post-update-sudo": [
        "POST",
        "/v1/auth/jwt-acl/role/existing-update-sudo"
    ],
    "fresh-post-create": [
        "POST",
        "/v1/auth/jwt-acl/role/fresh-create"
    ],
    "fresh-post-update-sudo": [
        "POST",
        "/v1/auth/jwt-acl/role/fresh-update-sudo"
    ],
    "fresh-post-create-update-sudo": [
        "POST",
        "/v1/auth/jwt-acl/role/fresh-create-update-sudo"
    ],
    "config-post-none": [
        "POST",
        "/v1/auth/jwt-acl/config"
    ],
    "config-post-update": [
        "POST",
        "/v1/auth/jwt-acl/config"
    ],
    "config-post-update-sudo": [
        "POST",
        "/v1/auth/jwt-acl/config"
    ]
}

PUBLIC_PKI_ERROR_IDS = frozenset((
    "pki.lease_expire_lookup", "pki.revoked_lease_absent",
))



def _observed_request(self, method: str, path: str, payload=None, *, token: str | None = None,
            wrap_ttl: str | None = None, content_type: str = "application/json",
            consistency_index: str | None = None, inconsistent=None,
            _record, _timeout) -> Response:
    try:
        metadata = Metadata(consistency_index, inconsistent)
    except InvalidConsistency as error:
        raise BaoError(str(error)) from None
    if method not in ("GET", "HEAD", "LIST", "POST", "PUT", "PATCH", "DELETE", "SCAN"):
        raise BaoError("invalid_request_method")
    if not path.startswith("/v1/") or len(path) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in path):
        raise BaoError("invalid_request_path")
    if token is not None and (not isinstance(token, str) or len(token) > 8192
                              or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise BaoError("invalid_token_input")
    if content_type not in ("application/json", "application/merge-patch+json"):
        raise BaoError("unsupported_content_type")
    headers = {"X-Vault-Token": self._token if token is None else token, "Accept": "application/json"}
    if wrap_ttl is not None:
        if (not isinstance(wrap_ttl, str) or not 1 <= len(wrap_ttl) <= 64
                or any(ord(c) < 33 or ord(c) > 126 for c in wrap_ttl)):
            raise BaoError("invalid_wrapping_ttl_header")
        headers["X-Vault-Wrap-TTL"] = wrap_ttl
    if self.namespace:
        headers["X-Vault-Namespace"] = self.namespace
    raw = None if payload is None else canonical(payload)
    if raw is not None:
        if len(raw) > MAX_BODY:
            raise BaoError("request_size_limit")
        headers["Content-Type"] = content_type
    request = urllib.request.Request(self.address + path, data=raw, headers=headers, method=method)
    if metadata.headers():
        request.heptabao_consistency = metadata
    phase = "open_response"
    _record["open_calls"] = 1
    try:
        try:
            response = self._opener.open(request, timeout=_timeout)
        except urllib.error.HTTPError as error:
            response = error
        phase = "response_context"
        with response:
            _record["context_entered"] = True
            phase = "response_metadata"
            status = response.code
            if type(status) is not int or not 100 <= status <= 599:
                raise BaoError("raw_status_shape")
            _record["status"] = status
            if 300 <= status < 400:
                raise BaoError("redirect_rejected")
            index, index_valid = response_index(response.headers)
            retry_seconds = retry_after(response.headers)
            phase = "read_response"
            _record["read_calls"] = 1
            body = response.read(MAX_BODY + 1)
            _record["body_bytes"] = len(body)
            _record["body_within_cap"] = len(body) <= MAX_BODY
            if _record["public_body"] and len(body) <= MAX_BODY:
                _record["body_sha256"] = hashlib.sha256(body).hexdigest()
            if len(body) > MAX_BODY:
                raise BaoError("response_size_limit")
            phase = "close_response"
        _record["context_closed"] = True
        phase = "process_response"
        decoded = decode_json(body) if body else {}
        if not isinstance(decoded, dict):
            raise BaoError("response_object_required")
        return Response(status, decoded, index, index_valid, retry_seconds)
    except BaoError:
        raise
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException) as error:
        # Never retry a write automatically. Even a timeout can follow a commit.
        raise BaoError("transport_outcome_unknown" if method not in ("GET", "LIST", "HEAD")
                       else "transport_read_failed",
                       _diagnostic=_transport_diagnostic(error, phase)) from None



class RawStatusCalls:
    """Request-local public projection; no process, TLS or credential ownership."""

    def __init__(self, client, remaining):
        if type(client) is not Client or not callable(remaining) or client.timeout != 15:
            raise BaoError("original_client_http_15s_and_owner_clock_required")
        self.client = client
        self.remaining = remaining
        self.active = False
        self.records = []

    def seconds_left(self):
        left = self.remaining()
        if type(left) not in (float, int) or not math.isfinite(left) or left <= 0:
            raise BaoError("original_fixture_deadline_expired")
        return left

    def call(self, case_id, method, path, payload=None, *, token=None,
             path_template=None, public_body=False, **kwargs):
        if self.active:
            raise BaoError("nested_http_observation")
        if public_body and case_id not in PUBLIC_ACL_IDS | PUBLIC_PKI_ERROR_IDS:
            raise BaoError("private_response_not_publicly_hashable")
        if public_body and case_id in PUBLIC_ACL_IDS:
            if PUBLIC_ACL_REQUESTS[case_id] != [method, path]:
                raise BaoError("public_acl_exact_request_required")
        if public_body and case_id in PUBLIC_PKI_ERROR_IDS:
            if (method, path) != ("POST", "/v1/sys/leases/lookup"):
                raise BaoError("public_pki_exact_request_required")
        if not isinstance(case_id, str) or not 1 <= len(case_id) <= 96:
            raise BaoError("fixed_case_id_required")
        timeout = min(15, self.seconds_left())
        record = {
            "case_id": case_id, "method": method,
            "path_template": path_template or path,
            "public_body": public_body, "status": None,
            "open_calls": 0, "read_calls": 0, "body_bytes": None,
            "body_within_cap": False, "body_sha256": None,
            "context_entered": False, "context_closed": False,
            "complete": False, "failure_code": None,
            "normalized_status": False, "retried": False,
        }
        try:
            self.active = True
            response = _observed_request(
                self.client, method, path, payload, token=token,
                _record=record, _timeout=timeout, **kwargs,
            )
            if (record["open_calls"] != 1 or record["read_calls"] != 1
                    or not record["context_closed"] or not record["body_within_cap"]
                    or record["status"] != response.status):
                raise BaoError("original_response_not_fully_observed")
            self.seconds_left()
            record["complete"] = True
            return response
        except BaoError as error:
            record["failure_code"] = error.code
            raise
        finally:
            # No opener/timeout mutation, new response owner, replay, raw body,
            # credential, request header or exception text enters this record.
            self.active = False
            self.records.append(record)


def run_original_pki12(suite, calls):
    """Invoke the original pki_cases unchanged; exact two400 expectations stay."""

    original_call = suite.call

    def observe(case, method, path, payload=None, *, token=None, wrap_ttl=None,
                path_template=None):
        if method not in ("GET", "LIST", "HEAD") and not suite.allow_writes:
            raise BaoError("test_write_opt_in_required")
        suite.requests[case] = {
            "method": method,
            "path_template": path_template or path.replace(suite.run_id, "{run_id}"),
        }
        record_start = len(calls.records)
        try:
            return calls.call(
                case, method, path, payload, token=token, wrap_ttl=wrap_ttl,
                path_template=suite.requests[case]["path_template"],
                public_body=case in PUBLIC_PKI_ERROR_IDS,
            )
        except BaoError as error:
            new_records = [row for row in calls.records[record_start:]
                           if row.get("case_id") == case]
            current_status = (new_records[0]["status"]
                              if len(new_records) == 1 else None)
            suite.results[case] = {
                "result": "failed", "reason": error.code,
                "http_status": current_status,
                "semantics": {},
            }
            raise

    try:
        suite.call = observe
        suite.pki_cases()
    finally:
        suite.call = original_call

def pki_public_result(suite, calls, cleanup, stop_reason=None):
    """Pure projection; original_suite checks and raw statuses are never changed."""
    names = (
        "mount", "root", "role", "role_read", "issue", "lease_lookup",
        "lease_expire_issue", "lease_expire_lookup", "cert_lookup",
        "lease_revoke", "revoked_lease_absent", "crl_json",
    )
    cases = {}
    for name in names:
        case_id = "pki." + name
        result = suite.results.get(case_id)
        if result is None:
            result = {"result": "not_run", "reason": stop_reason or "not_executed",
                      "http_status": None, "semantics": {}}
        wire = [row for row in calls.records if row["case_id"] == case_id]
        cases[case_id] = {"original_result": result, "wire": wire}
    passed = (
        cleanup.get("result") == "passed"
        and all(row["original_result"].get("result") == "passed"
                and len(row["wire"]) == 1 and row["wire"][0]["complete"]
                and row["wire"][0]["status"] == row["original_result"]["http_status"]
                for row in cases.values())
    )
    return {"denominator": 12, "cases": cases, "original_cleanup": cleanup,
            "pki12_passed": passed, "raw_status_normalization": False,
            "independent_fixture_qualification": False}
