#!/usr/bin/env python3
"""Real HTTPS/JWKS gates exercise JWT config and wrapped-login publication.

The event order proves an unrelated request finished while JWKS remained held.
This candidate-only concurrency fixture does not measure performance, expose
internal locks, or qualify the separate API-owned JWT transport profile.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import threading
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT
from external_tls_fixtures import JsonIssuer
from online_evidence import admit_output, source_identity
from remote_jwks_live import Instance, signing_key, token

GATE_SECONDS = 1.5  # Below the existing enrolled outbound request timeout (3s).
PHASES = frozenset({"config_success", "config_noop", "wrapped_success",
                    "role_changed", "config_changed", "actor_revoked"})
EVENTS = ["jwks_entered", "concurrent_completed", "gate_released", "request_completed"]
COUNTERS = ("state_bytes", "generation", "retained_operations", "journal_bytes")


class Failure(Exception):
    """Only fixed scenario labels may cross the report boundary."""


class Work:
    def __init__(self, operation):
        self.done = threading.Event()
        self.value = None
        self.error = None

        def run():
            try:
                self.value = operation()
            except Exception as error:
                self.error = type(error).__name__
            finally:
                self.done.set()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def result(self):
        if self.error is not None:
            raise Failure("request_worker_failed")
        return self.value


def gate(issuer, phase, request, concurrent, observations, *, budget=GATE_SECONDS):
    """Never release the gate to make a blocked concurrent operation pass."""
    issuer.block_next("/keys")
    external = Work(request)
    other = None
    row = {"phase": phase, "events": [], "held_before_release": False,
           "concurrent_completed_before_release": False,
           "request_pending_before_release": False, "within_enrolled_deadline": False}
    observations.append(row)
    try:
        if not issuer.block_entered.wait(1.5):
            raise Failure("jwks_gate_not_entered")
        row["events"].append("jwks_entered")
        entered = time.monotonic()
        other = Work(concurrent)
        if not other.done.wait(budget):
            raise Failure("concurrent_request_blocked_by_jwks")
        concurrent_result = other.result()
        row["held_before_release"] = not issuer.block_release.is_set()
        row["concurrent_completed_before_release"] = True
        row["request_pending_before_release"] = not external.done.is_set()
        row["within_enrolled_deadline"] = time.monotonic() - entered < budget
        row["events"].append("concurrent_completed")
        if not all(row[name] is True for name in row if name not in ("phase", "events")):
            raise Failure("jwks_gate_did_not_prove_order")
        issuer.release_block()
        row["events"].append("gate_released")
        if not external.done.wait(10):
            raise Failure("jwks_request_not_finished")
        response = external.result()
        row["events"].append("request_completed")
        return response, concurrent_result
    finally:
        issuer.release_block()
        for worker in (external, other):
            if worker is not None:
                worker.thread.join(timeout=11)
                if worker.thread.is_alive():
                    raise Failure("request_worker_cleanup_failed")


def valid_observations(rows):
    expected = {"phase", "events", "held_before_release", "concurrent_completed_before_release",
                "request_pending_before_release", "within_enrolled_deadline"}
    return (isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
            and len(rows) == len(PHASES) and {row.get("phase") for row in rows} == PHASES
            and all(set(row) == expected and row["events"] == EVENTS
                    and all(row[field] is True for field in expected - {"phase", "events"})
                    for row in rows))


def complete_checks(checks):
    names = []
    for row in checks:
        if (not isinstance(row, dict) or set(row) != {"case", "passed"}
                or row["passed"] is not True or not isinstance(row["case"], str)
                or re.fullmatch(r"[a-z0-9_]{1,120}", row["case"]) is None):
            return False
        names.append(row["case"])
    return bool(names) and names[-1] == "complete" and len(names) == len(set(names))


def refused(status, body, expected):
    return (type(status) is int and status == expected and isinstance(body, dict)
            and not any(body.get(key) for key in ("auth", "wrap_info", "data")))


def safe_failure(error, checks):
    failed = next((row["case"] for row in reversed(checks) if row["passed"] is False), None)
    if failed is not None:
        return failed
    if isinstance(error, Failure) and re.fullmatch(r"[a-z0-9_]{1,120}", str(error)):
        return str(error)
    return "fixture_" + type(error).__name__


def run(binary, root, checks, observations):
    instance = issuer = None

    def check(name, condition):
        checks.append({"case": name, "passed": condition is True})
        if condition is not True:
            raise Failure(name)

    try:
        instance = Instance(binary, root / "candidate")
        issuer = JsonIssuer(instance.root / "tls.crt", instance.root / "tls.key")
        cfg_path = instance.root / "server.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["lifecycle_interval_seconds"] = 0
        cfg["outbound_endpoints"] = [{"origin": issuer.origin,
            "address": f"127.0.0.1:{issuer.port}", "server_name": "localhost",
            "ca_pem": (instance.root / "ca.crt").read_text()}]
        cfg_path.write_text(json.dumps(cfg))
        cfg_path.chmod(0o600)
        private, jwk = signing_key("ES256", "synthetic-gated-key")
        issuer.documents["/keys"] = {"keys": [jwk]}
        params = {"bound_issuer": issuer.origin, "jwks_url": issuer.origin + "/keys",
                  "audiences": ["heptabao-test"], "jwt_supported_algs": ["ES256", "RS256"]}
        path = "auth/gated/config"
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialized", status == 200)
        instance.token = initialized["root_token"]
        check("unsealed", instance.call("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] == 200)
        check("mounted", instance.call("POST", "sys/auth/gated", {"type": "jwt"})[0] == 204)

        def counters():
            status, response = instance.call("GET", "sys/internal/storage/capacity")
            data = response.get("data", {})
            if status != 200 or any(type(data.get(name)) is not int for name in COUNTERS):
                raise Failure("durable_counters_unavailable")
            return {name: data[name] for name in COUNTERS}

        def config_read():
            status, response = instance.call("GET", path)
            if status != 200 or not isinstance(response.get("data"), dict):
                raise Failure("configuration_read_failed")
            return response["data"]

        def write(phase):
            value = secrets.token_hex(20)
            status, response = instance.call("POST", "secret/data/jwt-gate-" + phase,
                                             {"data": {"value": value}, "options": {"cas": 0}})
            if status != 200 or response.get("data", {}).get("version") != 1:
                raise Failure("concurrent_kv_write_failed")
            return value

        def visible(phase, value):
            status, body = instance.call("GET", "secret/data/jwt-gate-" + phase)
            check(phase + "_write_preserved", status == 200 and body.get("data", {}).get("data") == {"value": value})

        response, value = gate(issuer, "config_success", lambda: instance.call("POST", path, params),
                               lambda: write("config_success"), observations)
        check("config_success_status", response[0] == 204)
        visible("config_success", value)
        check("configured_jwks_source", config_read().get("jwks_url") == issuer.origin + "/keys")
        check("role_created", instance.call("POST", "auth/gated/role/app", {
            "role_type": "jwt", "user_claim": "sub", "bound_audiences": ["heptabao-test"],
            "token_policies": ["default"], "token_ttl": 600, "token_max_ttl": 1200})[0] == 204)

        def noop_concurrent():
            value = write("config_noop")
            return value, counters()

        response, (value, before) = gate(issuer, "config_noop", lambda: instance.call("POST", path, params),
                                         noop_concurrent, observations)
        check("config_noop_status", response[0] == 204)
        check("config_noop_no_durable_append", counters() == before)
        visible("config_noop", value)

        def wrapped():
            return instance.call("POST", "auth/gated/login", {"role": "app", "jwt": token(private, jwk, issuer.origin)},
                                 token="", extra_headers={"X-Vault-Wrap-TTL": "60s"})

        response, value = gate(issuer, "wrapped_success", wrapped, lambda: write("wrapped_success"), observations)
        status, body = response
        check("wrapped_success_no_bearer", status == 200 and not body.get("auth")
              and bool(body.get("wrap_info", {}).get("token")))
        visible("wrapped_success", value)
        wrapper = body["wrap_info"]["token"]
        check("wrapper_creation_path", body["wrap_info"].get("creation_path") == "auth/gated/login")
        status, body = instance.call("POST", "sys/wrapping/unwrap", {}, token=wrapper)
        check("unwrap_issued_service_token", status == 200 and bool(body.get("auth", {}).get("client_token")))
        issued = body["auth"]["client_token"]
        check("issued_token_usable", instance.call("GET", "auth/token/lookup-self", token=issued)[0] == 200)
        check("wrapper_single_use", instance.call("POST", "sys/wrapping/unwrap", {}, token=wrapper)[0] == 400)

        # A rejected observation contains genuinely different public keys, so
        # unchanged durable counters also rule out a separately published cache.
        private, jwk = signing_key("ES256", "synthetic-rotated-gated-key")
        issuer.documents["/keys"] = {"keys": [jwk]}

        def role_change():
            value = write("role_changed")
            if instance.call("POST", "auth/gated/role/app", {"token_ttl": 601})[0] != 204:
                raise Failure("concurrent_role_update_failed")
            return value, counters()

        response, (value, before) = gate(issuer, "role_changed", wrapped, role_change, observations)
        check("role_change_rejects_without_token_or_wrapper", refused(*response, 409))
        check("role_change_no_token_keycache_or_wrapper_publication", counters() == before)
        visible("role_changed", value)

        def config_change():
            value = write("config_changed")
            static = {name: value for name, value in params.items() if name != "jwks_url"}
            static["jwks"] = {"keys": [jwk]}
            if instance.call("POST", path, static)[0] != 204:
                raise Failure("concurrent_static_config_update_failed")
            return value, counters(), config_read()

        response, (value, before, changed) = gate(issuer, "config_changed", wrapped, config_change, observations)
        check("config_change_rejects_without_token_or_wrapper", refused(*response, 409))
        check("config_change_no_token_keycache_or_wrapper_publication", counters() == before)
        check("concurrent_configuration_preserved", config_read() == changed)
        visible("config_changed", value)
        check("remote_configuration_restored", instance.call("POST", path, params)[0] == 204)

        status, body = instance.call("POST", "auth/token/create-orphan", {
            "policies": ["root"], "no_default_policy": True, "ttl": 600})
        check("separate_root_actor_created", status == 200 and bool(body.get("auth", {}).get("client_token")))
        actor, accessor = body["auth"]["client_token"], body["auth"]["accessor"]
        current_config = config_read()
        proposed = dict(params, jwt_supported_algs=["ES256"])
        _, revoked_observation_key = signing_key("ES256", "synthetic-revoked-observation")
        issuer.documents["/keys"] = {"keys": [revoked_observation_key]}

        def revoke_actor():
            value = write("actor_revoked")
            if instance.call("POST", "auth/token/revoke-accessor", {"accessor": accessor})[0] != 204:
                raise Failure("concurrent_actor_revoke_failed")
            return value, counters()

        response, (value, before) = gate(issuer, "actor_revoked",
            lambda: instance.call("POST", path, proposed, token=actor), revoke_actor, observations)
        check("revoked_actor_config_rejected", refused(*response, 403))
        check("revoked_actor_no_configuration_publication", counters() == before and config_read() == current_config)
        visible("actor_revoked", value)
        check("revoked_actor_unusable", instance.call("GET", "auth/token/lookup-self", token=actor)[0] == 403)
        check("all_event_orders_proved", valid_observations(observations))
        check("complete", True)
    finally:
        if issuer is not None:
            issuer.release_block()
        if instance is not None:
            instance.stop()
        if issuer is not None:
            issuer.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    binary, output = args.binary.resolve(strict=True), args.output.absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, binary)
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="heptabao-jwt-split-phase-"))
    root.chmod(0o700)
    checks, observations, failure = [], [], None
    try:
        run(binary, root, checks, observations)
    except Exception as error:
        # Never stringify HTTP/provider exceptions or expose JWTs and bearers.
        failure = safe_failure(error, checks)
    finally:
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary)
    runner_unchanged = runner_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if not unchanged or not runner_unchanged:
        failure = "source_binary_or_runner_changed"
    if not complete_checks(checks) or not valid_observations(observations):
        failure = failure or "incomplete_or_invalid_observations"
    report = {"schema": "heptabao.jwt-split-phase-live.v1", **before,
        "build_source_commit": args.build_source_commit,
        "build_source_binding_basis": "caller-supplied commit; exact binary hash recorded; no independent attestation",
        "status": "passed" if failure is None else "failed", "failure": failure,
        "checks": checks, "observations": observations,
        "source_and_binary_unchanged": unchanged, "runner_sha256": runner_hash,
        "runner_unchanged": runner_unchanged, "synthetic_only": True,
        "transport": "real_https_with_process_enrolled_jwks", "gate_hold_budget_seconds": GATE_SECONDS,
        "internal_lock_instrumentation": False, "http_deadline_test": False,
        "performance_measurement": False, "full_openbao_compatibility": False,
        "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "checks": len(checks), "failure": failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
