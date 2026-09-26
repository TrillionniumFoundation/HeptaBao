#!/usr/bin/env python3
"""Compare the bounded HeptaBao OpenAPI endpoint with pinned OpenBao 2.6.2.

This profile proves a real authenticated runtime entry, a syntactically bounded
OpenAPI 3.0.2 document, fail-closed non-root visibility, token revocation and
restart stability. It intentionally does not claim browser UI coverage or exact
OpenBao schema/path parity.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile

from bao_http import BaoError, Client, SafeArgumentParser, private_write
from official_openbao_launcher import (
    BINARY_SHA256,
    file_digest,
    start_oracle,
    stop_oracle,
)

ROOT = Path(__file__).resolve().parents[2]
STANDARD_OPERATIONS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}
PATH_ITEM_FIELDS = STANDARD_OPERATIONS | {
    "$ref",
    "summary",
    "description",
    "servers",
    "parameters",
}


def load_smoke():
    spec = importlib.util.spec_from_file_location(
        "openapi_live_smoke",
        ROOT / "qa/single-node/smoke.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_document(document, *, candidate):
    if not isinstance(document, dict) or document.get("openapi") != "3.0.2":
        raise BaoError("openapi_live_invalid_version")
    info = document.get("info")
    paths = document.get("paths")
    if not isinstance(info, dict) or not isinstance(info.get("title"), str):
        raise BaoError("openapi_live_invalid_info")
    if not isinstance(paths, dict) or not paths:
        raise BaoError("openapi_live_missing_paths")
    for path, item in paths.items():
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or not isinstance(item, dict)
            or any(key not in PATH_ITEM_FIELDS and not key.startswith("x-") for key in item)
        ):
            raise BaoError("openapi_live_invalid_path_item")
        for method, operation in item.items():
            if method not in STANDARD_OPERATIONS:
                continue
            if not isinstance(operation, dict):
                raise BaoError("openapi_live_invalid_operation")
            responses = operation.get("responses")
            if not isinstance(responses, dict) or not responses:
                raise BaoError("openapi_live_missing_responses")
    if candidate:
        if document.get("x-heptabao-bounded") is not True:
            raise BaoError("openapi_live_candidate_not_bounded")
        lowered = "\n".join(paths).lower()
        for unsupported in (
            "/auth/cert",
            "/auth/radius",
            "/auth/kerberos",
            "/rabbitmq/",
            "/openldap/",
        ):
            if unsupported in lowered:
                raise BaoError("openapi_live_candidate_advertises_unsupported_surface")
    return paths


def run(binary, output):
    checks = []

    def check(name, condition):
        if not condition:
            raise BaoError("openapi_live_" + name)
        checks.append(name)

    if not all(
        Path(os.environ.get(name, "/missing")).is_file()
        for name in ("HB_ORACLE_BINARY", "HB_ORACLE_ARCHIVE")
    ):
        raise FileNotFoundError("pinned oracle prerequisite missing")

    smoke = load_smoke()
    with tempfile.TemporaryDirectory(prefix="heptabao-openapi-live-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        oracle = instance = None
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                oracle_port = listener.getsockname()[1]
            oracle = start_oracle(oracle_port)
            oracle_client = Client(
                oracle["address"],
                oracle["ca_file"],
                Path(oracle["token_file"]).read_text().strip(),
            )

            instance = smoke.Instance(binary.resolve(), root / "candidate")
            instance.start()
            status, initialized = instance.call(
                "POST",
                "sys/init",
                {"secret_shares": 1, "secret_threshold": 1},
            )
            check("candidate_init", status == 200)
            instance.token = initialized["root_token"]
            unseal_key = initialized["keys_base64"][0]
            check(
                "candidate_unseal",
                instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200,
            )
            candidate = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                instance.token,
            )

            oracle_response = oracle_client.request(
                "GET", "/v1/sys/internal/specs/openapi"
            )
            candidate_response = candidate.request(
                "GET", "/v1/sys/internal/specs/openapi"
            )
            check(
                "root_openapi_entries",
                oracle_response.status == 200 and candidate_response.status == 200,
            )
            oracle_paths = validate_document(oracle_response.body, candidate=False)
            candidate_paths = validate_document(candidate_response.body, candidate=True)
            for common in ("/sys/health", "/sys/internal/specs/openapi"):
                check(
                    "common_path_" + common.replace("/", "_").strip("_"),
                    common in oracle_paths and common in candidate_paths,
                )
            check(
                "candidate_has_only_standard_openapi_operation_keys",
                all(
                    key in PATH_ITEM_FIELDS or key.startswith("x-")
                    for item in candidate_paths.values()
                    for key in item
                ),
            )

            oracle_generic = oracle_client.request(
                "POST",
                "/v1/sys/internal/specs/openapi",
                {"generic_mount_paths": True},
            )
            candidate_generic = candidate.request(
                "POST",
                "/v1/sys/internal/specs/openapi",
                {"generic_mount_paths": True},
            )
            check(
                "generic_mount_request_supported_on_both",
                oracle_generic.status == 200 and candidate_generic.status == 200,
            )
            validate_document(oracle_generic.body, candidate=False)
            generic_paths = validate_document(candidate_generic.body, candidate=True)
            check(
                "candidate_generic_mount_paths_are_explicit",
                candidate_generic.body.get("x-heptabao-generic-mount-paths") is True
                and "/{kv_mount_path}/data/{path}" in generic_paths
                and "/auth/{userpass_mount_path}/login/{username}" in generic_paths,
            )

            invalid = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                "synthetic-invalid-token",
            ).request("GET", "/v1/sys/internal/specs/openapi")
            check("invalid_token_denied", invalid.status == 403)

            policy = (
                'path "sys/internal/specs/openapi" '
                '{ capabilities = ["read"] }'
            )
            check(
                "restricted_policy",
                candidate.request(
                    "PUT",
                    "/v1/sys/policies/acl/openapi-live-reader",
                    {"policy": policy},
                ).status
                == 204,
            )
            issued = candidate.request(
                "POST",
                "/v1/auth/token/create",
                {
                    "policies": ["openapi-live-reader"],
                    "no_default_policy": True,
                },
            )
            restricted_token = issued.body.get("auth", {}).get("client_token")
            check(
                "restricted_token_created",
                issued.status == 200
                and isinstance(restricted_token, str)
                and bool(restricted_token),
            )
            restricted_client = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                restricted_token,
            )
            restricted = restricted_client.request(
                "GET", "/v1/sys/internal/specs/openapi"
            )
            restricted_paths = validate_document(restricted.body, candidate=True)
            check(
                "non_root_visibility_fails_closed",
                restricted.status == 200
                and restricted.body.get("x-heptabao-policy-filtering")
                == "fail_closed_non_root_subset"
                and "/sys/health" in restricted_paths
                and "/sys/internal/specs/openapi" in restricted_paths
                and "/auth/token/create" not in restricted_paths
                and "/identity/entity" not in restricted_paths,
            )
            check(
                "restricted_token_revoke",
                candidate.request(
                    "POST",
                    "/v1/auth/token/revoke",
                    {"token": restricted_token},
                ).status
                in (200, 204),
            )
            check(
                "revoked_token_denied",
                restricted_client.request(
                    "GET", "/v1/sys/internal/specs/openapi"
                ).status
                == 403,
            )

            expected_root = candidate_response.body
            instance.stop()
            instance.start()
            check(
                "restart_unseal",
                instance.call(
                    "POST", "sys/unseal", {"key": unseal_key}
                )[0]
                == 200,
            )
            candidate = Client(
                instance.address,
                str(instance.root / "ca.crt"),
                instance.token,
            )
            reopened = candidate.request(
                "GET", "/v1/sys/internal/specs/openapi"
            )
            check(
                "openapi_restart_stable",
                reopened.status == 200 and reopened.body == expected_root,
            )

            report = {
                "schema": "heptabao.openapi-live.v1",
                "status": "passed_scoped_openapi_runtime",
                "checks": checks,
                "count": len(checks),
                "candidate_binary_sha256": file_digest(binary),
                "oracle_binary_sha256": BINARY_SHA256,
                "official_openbao_version": oracle_client.health()["version"],
                "openapi_version": "3.0.2",
                "candidate_path_count": len(candidate_paths),
                "oracle_path_count": len(oracle_paths),
                "runtime_entry_implemented": True,
                "root_schema_restart_stable": True,
                "non_root_overadvertising_prevented": True,
                "exact_policy_filtered_schema_implemented": False,
                "browser_ui_implemented": False,
                "full_openbao_compatibility": False,
                "production_authority": False,
                "independent_qualification": False,
            }
            private_write(output, report, replace=False)
            return report
        finally:
            if instance is not None:
                instance.stop()
            if oracle is not None:
                stop_oracle(oracle)
                shutil.rmtree(oracle["root"], ignore_errors=True)


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output):
        raise BaoError("output_already_exists")
    report = run(args.binary.resolve(), args.output.absolute())
    print(
        json.dumps(
            {
                "status": report["status"],
                "count": report["count"],
                "candidate_path_count": report["candidate_path_count"],
                "oracle_path_count": report["oracle_path_count"],
                "full_openbao_compatibility": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError:
        print(
            json.dumps(
                {
                    "status": "blocked_prerequisite",
                    "full_openbao_compatibility": False,
                }
            )
        )
        raise SystemExit(77) from None
    except Exception as error:
        reason = (
            error.code
            if isinstance(error, BaoError)
            else "openapi_live_failed"
        )
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason": reason,
                    "full_openbao_compatibility": False,
                }
            )
        )
        raise SystemExit(2) from None
