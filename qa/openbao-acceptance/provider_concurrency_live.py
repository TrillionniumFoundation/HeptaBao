#!/usr/bin/env python3
"""Prove a slow enrolled provider does not serialize unrelated durable work.

A synthetic HTTPS JWKS endpoint is deliberately held after the candidate has
entered the remote read. While that provider request is still in flight, this
profile performs a real KV write and read through the candidate TLS listener,
then releases the provider and verifies both the login and post-crash KV state.

The fixture uses no external credentials and does not grant production,
compatibility, or independent qualification authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

from external_tls_fixtures import JsonIssuer
from remote_jwks_live import signing_key, token

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance


def isolated_call(instance, method, path, body=None, *, token_value=None):
    context = ssl.create_default_context(cafile=str(instance.root / "ca.crt"))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    headers = {
        "Content-Type": "application/json",
        "X-Vault-Token": instance.token if token_value is None else token_value,
    }
    request = urllib.request.Request(
        instance.address + "/v1/" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers=headers,
        method=method,
    )
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise RuntimeError("unbounded_candidate_response")
        return response.status, json.loads(raw) if raw else {}


def run(binary: Path, root: Path, report: dict) -> None:
    instance = Instance(binary, root / "candidate")
    issuer = JsonIssuer(instance.root / "tls.crt", instance.root / "tls.key")
    login_result: dict[str, object] = {}
    worker = None

    def check(name: str, condition: bool) -> None:
        report["checks"].append({"case": name, "passed": condition is True})
        if condition is not True:
            raise RuntimeError(name)

    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    # Native JWT configuration owns its explicit TLS trust snapshot. Do not
    # depend on the legacy process-enrolled endpoint registry for native calls.
    config["outbound_endpoints"] = []
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)

    private, jwk = signing_key("RS256", "provider-concurrency")
    issuer.documents["/keys"] = {"keys": [jwk]}

    try:
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        unseal_key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200)
        check("jwt_mount", instance.call("POST", "sys/auth/federated", {"type": "jwt"})[0] == 204)
        check(
            "untrusted_jwks_configuration_rejected",
            instance.call(
                "POST",
                "auth/federated/config",
                {"bound_issuer": issuer.origin, "jwks_url": issuer.origin + "/keys",
                 "jwt_supported_algs": ["RS256"]},
            )[0] == 400,
        )
        check(
            "jwks_config",
            instance.call(
                "POST",
                "auth/federated/config",
                {
                    "bound_issuer": issuer.origin,
                    "jwks_url": issuer.origin + "/keys",
                    "jwks_ca_pem": (instance.root / "ca.crt").read_text(),
                    "jwt_supported_algs": ["RS256"],
                },
            )[0] == 204,
        )
        check(
            "jwt_role",
            instance.call(
                "POST",
                "auth/federated/role/test",
                {
                    "role_type": "jwt",
                    "user_claim": "sub",
                    "bound_audiences": ["heptabao-test"],
                    "token_policies": ["default"],
                },
            )[0] == 204,
        )

        assertion = token(private, jwk, issuer.origin)
        issuer.block_next("/keys")

        def login_worker() -> None:
            try:
                login_result["response"] = isolated_call(
                    instance,
                    "POST",
                    "auth/federated/login",
                    {"role": "test", "jwt": assertion},
                    token_value="",
                )
            except Exception as error:
                login_result["error"] = type(error).__name__

        worker = threading.Thread(target=login_worker, name="provider-concurrency-login")
        worker.start()
        check("provider_request_entered", issuer.block_entered.wait(timeout=3))
        check("provider_request_is_held", worker.is_alive() and not issuer.block_release.is_set())

        marker = "provider-concurrency-" + secrets.token_hex(32)
        started = time.monotonic()
        write_status, _ = isolated_call(
            instance,
            "POST",
            "secret/data/provider-concurrency",
            {"data": {"value": marker}},
        )
        report["kv_write_ms"] = round((time.monotonic() - started) * 1000, 3)
        check(
            "durable_kv_write_completed_while_provider_blocked",
            write_status == 200 and worker.is_alive() and not issuer.block_release.is_set(),
        )

        started = time.monotonic()
        read_status, read = isolated_call(instance, "GET", "secret/data/provider-concurrency")
        report["kv_read_ms"] = round((time.monotonic() - started) * 1000, 3)
        check(
            "kv_read_observed_committed_value_while_provider_blocked",
            read_status == 200
            and read.get("data", {}).get("data", {}).get("value") == marker
            and worker.is_alive()
            and not issuer.block_release.is_set(),
        )

        issuer.release_block()
        worker.join(timeout=6)
        check("provider_request_completed_after_release", not worker.is_alive())
        login = login_result.get("response")
        check(
            "remote_login_completed_after_release",
            isinstance(login, tuple)
            and len(login) == 2
            and login[0] == 200
            and bool(login[1].get("auth", {}).get("client_token")),
        )

        instance.stop()
        instance.start()
        check("restart_unseal", instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200)
        read_status, read = instance.call("GET", "secret/data/provider-concurrency")
        check(
            "concurrent_kv_commit_survives_restart",
            read_status == 200 and read.get("data", {}).get("data", {}).get("value") == marker,
        )
    finally:
        issuer.release_block()
        if worker is not None:
            worker.join(timeout=1)
        instance.stop()
        issuer.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        parser.error("output must be new")
    root = Path(tempfile.mkdtemp(prefix="heptabao-provider-concurrency-"))
    root.chmod(0o700)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    report = {
        "schema": "heptabao.provider-concurrency-live.v1",
        "candidate_binary_sha256": digest,
        "checks": [],
        "production_authority": False,
        "independent_qualification": False,
    }
    try:
        run(binary, root, report)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["safe_error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        shutil.rmtree(root)
    report["check_count"] = len(report["checks"])
    report["binary_unchanged"] = hashlib.sha256(binary.read_bytes()).hexdigest() == digest
    if not report["binary_unchanged"]:
        report["status"] = "failed"

    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({
        "status": report["status"],
        "check_count": report["check_count"],
        "binary_unchanged": report["binary_unchanged"],
        "kv_write_ms": report.get("kv_write_ms"),
        "kv_read_ms": report.get("kv_read_ms"),
        "failure": report.get("safe_error"),
    }))
    return 0 if report["status"] == "passed" and report["binary_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
