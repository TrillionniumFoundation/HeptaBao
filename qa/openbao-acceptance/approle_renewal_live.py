#!/usr/bin/env python3
"""Compare AppRole renewal lifetime/issuer semantics with pinned OpenBao 2.6.2.

Fresh local HTTPS instances use identical role fields and synthetic SecretIDs.
The trace includes three renewal routes, wrapped success/failure, SIGKILL and
reopen, current ordinary bounds, frozen explicit caps and token-API children.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import socket
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, successful_comparison
from official_openbao_launcher import ARTIFACT_SHA256, BINARY_SHA256, restart_oracle, start_oracle, stop_oracle, verify_inputs
from online_evidence import admit_output, source_identity
from radius_renewal_live import renewal_token_shape, wrapped_renewal_shape

MOUNT = "approle-renewal"
BASE_ROLE = {"token_ttl": 120, "token_max_ttl": 300, "token_period": 0,
             "token_explicit_max_ttl": 0, "secret_id_num_uses": 0, "token_policies": ["approle-issuer"]}
EXPECTED_COUNT = 153


def ttl_matches(value, *, exact=None, maximum=None):
    return type(value) is int and value > 0 and (value == exact if exact is not None else maximum is not None and value <= maximum)


def complete_side(rows):
    return (len(rows) == EXPECTED_COUNT and len({row.get("case") for row in rows}) == EXPECTED_COUNT
            and all(row.get("passed") is True for row in rows)
            and rows[-1].get("case") == "approle_renewal.orphan_after_unmount.ttl")


def run_scenarios(client, restart, results=None, *, wait=time.sleep):
    results = [] if results is None else results

    def check(name, condition, **observation):
        case = "approle_renewal." + name
        results.append({"case": case, **observation, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(case)

    def call(name, method, path, payload=None, *, token=None, expected=204, wrap_ttl=None):
        response = client.request(method, "/v1/" + path, payload, token=token, wrap_ttl=wrap_ttl)
        check(name, response.status == expected, status=response.status)
        return response.body

    def issue(name, **options):
        settings = {**BASE_ROLE, **options}
        path = "auth/" + MOUNT + "/role/" + name
        call(name + ".role", "POST", path, settings)
        role_id = call(name + ".role_id", "GET", path + "/role-id", expected=200)["data"]["role_id"]
        secret = call(name + ".secret_id", "POST", path + "/secret-id", {}, expected=200)["data"]["secret_id"]
        body = call(name + ".login", "POST", "auth/" + MOUNT + "/login", {"role_id": role_id, "secret_id": secret}, token="", expected=200)
        auth = body.get("auth", {})
        check(name + ".credentials", all(isinstance(auth.get(key), str) and auth[key] for key in ("client_token", "accessor")))
        return {"path": path, "settings": settings, "token": auth["client_token"],
                "accessor": auth["accessor"], "secret": secret, "login_ttl": auth.get("lease_duration")}

    def tune(name, issued, **options):
        call(name, "POST", issued["path"], {**issued["settings"], **options})

    def renew(name, issued, *, operation="renew-self", payload=None, exact=None, maximum=None, policies=None):
        body = {} if payload is None else dict(payload)
        actor = issued["token"] if operation == "renew-self" else None
        if operation == "renew":
            body["token"] = issued["token"]
        elif operation == "renew-accessor":
            body["accessor"] = issued["accessor"]
        response = call(name + ".renew", "POST", "auth/token/" + operation, body, token=actor, expected=200)
        auth = response.get("auth", {})
        check(name + ".shape", renewal_token_shape(auth, issued["token"], via_accessor=operation == "renew-accessor")
              and auth.get("renewable") is True and auth.get("token_policies") == (policies or ["approle-issuer", "default"]))
        check(name + ".ttl", ttl_matches(auth.get("lease_duration"), exact=exact, maximum=maximum))

    def lookup(name, issued):
        body = call(name, "GET", "auth/token/lookup-self", token=issued["token"], expected=200)
        ttl = body.get("data", {}).get("ttl")
        check(name + ".ttl", type(ttl) is int and ttl > 0)
        return ttl

    call("mount", "POST", "sys/auth/" + MOUNT, {"type": "approle"})
    call("issuer_policy", "POST", "sys/policies/acl/approle-issuer", {
        "policy": 'path "auth/token/create*" { capabilities = ["update", "sudo"] }'})
    finite = issue("finite")
    call("destroy_issued_secret_id", "POST", finite["path"] + "/secret-id/destroy", {"secret_id": finite["secret"]})
    children = {}
    for name, orphan in (("child", False), ("orphan", True)):
        body = call(name + ".create", "POST", "auth/token/create", {
            "policies": ["default"], "ttl": 60, "explicit_max_ttl": 90, "no_parent": orphan}, token=finite["token"], expected=200)
        auth = body.get("auth", {})
        check(name + ".credentials", all(isinstance(auth.get(key), str) and auth[key] for key in ("client_token", "accessor")))
        children[name] = {"token": auth["client_token"], "accessor": auth["accessor"]}
    tune("raise_ordinary_maximum", finite, token_max_ttl=600)
    for operation in ("renew-self", "renew", "renew-accessor"):
        renew("raised_maximum." + operation, finite, operation=operation, payload={"increment": 500}, exact=500)
    renew("omitted_increment", finite, exact=120)
    renew("zero_increment", finite, payload={"increment": 0}, exact=120)
    wrapped = call("wrapped_renewal", "POST", "auth/token/renew", {"token": finite["token"], "increment": 120}, expected=200, wrap_ttl="60s")
    check("wrapped_renewal.opaque", wrapped_renewal_shape(wrapped, finite["token"]))
    wrapper = wrapped["wrap_info"]["token"]
    unwrapped = call("unwrap", "POST", "sys/wrapping/unwrap", {"token": wrapper}, expected=200)
    check("unwrap.target", renewal_token_shape(unwrapped.get("auth"), finite["token"], via_accessor=False))
    call("unwrap.single_use", "POST", "sys/wrapping/unwrap", {"token": wrapper}, expected=400)
    wait(3)
    tune("shrink_ordinary_maximum", finite, token_ttl=1, token_max_ttl=1)
    before = lookup("past_maximum.before", finite)
    failed = call("past_maximum.wrapped_rejection", "POST", "auth/token/renew-self", {"increment": 120},
                  token=finite["token"], expected=500, wrap_ttl="60s")
    check("past_maximum.no_response_credentials", not failed.get("wrap_info") and failed.get("auth") is None)
    after = lookup("past_maximum.after", finite)
    check("past_maximum.no_extension", after <= before)
    tune("restore_finite_role", finite, token_max_ttl=600)
    restart()
    call("reopened_health", "GET", "sys/health", expected=200)
    for operation in ("renew-self", "renew", "renew-accessor"):
        renew("reopened." + operation, finite, operation=operation, exact=120)
    call("delete_finite_role", "DELETE", finite["path"])
    call("deleted_role_rejection", "POST", "auth/token/renew-self", {}, token=finite["token"], expected=500)
    for name, child in children.items():
        renew(name + ".deleted_role", child, payload={"increment": 60}, exact=60, policies=["default"])

    for name, initial, current, exact, maximum in (
        ("explicit-added", 0, 20, 120, None),
        ("explicit-lowered", 200, 20, 120, None),
        ("explicit-raised", 20, 600, None, 20),
        ("explicit-removed", 20, 0, None, 20),
    ):
        issued = issue(name, token_explicit_max_ttl=initial)
        tune(name + ".tune", issued, token_explicit_max_ttl=current)
        renew(name, issued, payload={"increment": 120}, exact=exact, maximum=maximum)
    issued = issue("finite-to-periodic", token_ttl=10, token_max_ttl=15)
    tune("finite-to-periodic.tune", issued, token_period=30, token_max_ttl=300)
    renew("finite-to-periodic", issued, payload={"increment": 1}, exact=30)
    issued = issue("periodic-to-finite", token_period=30)
    tune("periodic-to-finite.tune", issued, token_period=0, token_max_ttl=600)
    renew("periodic-to-finite", issued, payload={"increment": 500}, exact=500)
    issued = issue("periodic-role-cap", token_ttl=5, token_max_ttl=10, token_period=30)
    check("periodic-role-cap.login_ttl", issued["login_ttl"] == 10)
    renew("periodic-role-cap", issued, payload={"increment": 1}, exact=10)
    call("periodic-mount-cap.tune", "POST", "sys/auth/" + MOUNT + "/tune", {"default_lease_ttl": 5, "max_lease_ttl": 7})
    renew("periodic-mount-cap", issued, payload={"increment": 1}, exact=7)
    # Restore before issuing independent explicit-cap scenarios. The final
    # mount disable below still verifies the original children's ownership.
    call("restore_mount_maximum", "POST", "sys/auth/" + MOUNT + "/tune", {"default_lease_ttl": 120, "max_lease_ttl": 600})
    issued = issue("periodic-explicit-added", token_period=30)
    tune("periodic-explicit-added.tune", issued, token_explicit_max_ttl=5)
    renew("periodic-explicit-added", issued, payload={"increment": 1}, exact=30)
    issued = issue("periodic-explicit-raised", token_period=30, token_explicit_max_ttl=20)
    tune("periodic-explicit-raised.tune", issued, token_explicit_max_ttl=60)
    renew("periodic-explicit-raised", issued, payload={"increment": 1}, maximum=20)
    call("disable_mount", "DELETE", "sys/auth/" + MOUNT)
    call("child_revoked", "GET", "auth/token/lookup-self", token=children["child"]["token"], expected=403)
    lookup("orphan_survives_unmount", children["orphan"])
    renew("orphan_after_unmount", children["orphan"], payload={"increment": 60}, exact=60, policies=["default"])
    return results


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary")
    parser.add_argument("--output", required=True)
    parser.add_argument("--oracle-only", action="store_true")
    args = parser.parse_args()
    if not args.oracle_only and not args.binary:
        parser.error("candidate binary required")
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    binary = verify_inputs() if args.oracle_only else Path(args.binary).resolve(strict=True)
    before = source_identity(ROOT, binary)
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-approle-renewal-"))
    private_root.chmod(0o700)
    instance = oracle = None
    report = {"schema": "heptabao.approle-renewal-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "candidate_observed": not args.oracle_only,
              "oracle_binary_sha256": BINARY_SHA256, "oracle_artifact_sha256": ARTIFACT_SHA256,
              "candidate_binary_sha256": None if args.oracle_only else before["binary_sha256"],
              "independent_qualification": False, "compatibility_claim": False, "production_authority": False,
              "expected_cases_per_side": EXPECTED_COUNT, "cases": {}, "side_failures": {}}
    try:
        for side in (["oracle"] if args.oracle_only else ["oracle", "candidate"]):
            rows = report["cases"][side] = []
            if side == "oracle":
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                oracle = start_oracle(port)
                client = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())

                def restart():
                    oracle["process"].kill()
                    oracle["process"].wait(timeout=5)
                    stop_oracle(oracle)
                    restart_oracle(oracle)
            else:
                spec = importlib.util.spec_from_file_location("approle_smoke", ROOT / "qa/single-node/smoke.py")
                smoke = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(smoke)
                instance = smoke.Instance(binary, private_root / "candidate")
                path = instance.root / "server.json"
                config = json.loads(path.read_text())
                config["lifecycle_interval_seconds"] = 0
                private_write(path, config)
                instance.start()
                status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
                if status != 200:
                    raise ScenarioFailure("approle_renewal.candidate_init")
                instance.token = initialized["root_token"]
                key = initialized["keys_base64"][0]
                if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                    raise ScenarioFailure("approle_renewal.candidate_unseal")
                client = Client(instance.address, str(instance.root / "ca.crt"), instance.token)

                def restart():
                    instance.stop()
                    instance.start()
                    if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                        raise ScenarioFailure("approle_renewal.candidate_restart_unseal")

            try:
                run_scenarios(client, restart, rows)
            except ScenarioFailure as error:
                report["side_failures"][side] = str(error)
            except Exception as error:
                report["side_failures"][side] = "unexpected_" + type(error).__name__
        complete = all(complete_side(rows) for rows in report["cases"].values()) and not report["side_failures"]
        report["cases_match"] = not args.oracle_only and successful_comparison(report["cases"], report["side_failures"])
        report["status"] = ("oracle_passed" if args.oracle_only else "passed") if complete and (args.oracle_only or report["cases_match"]) else "failed"
    except Exception as error:
        report["status"] = "failed"
        report["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        shutil.rmtree(private_root)
        after = source_identity(ROOT, binary)
        report["source_identity"] = before
        report["source_and_binary_unchanged"] = before == after
        if before != after:
            report["status"] = "failed"
            report["safe_failure_code"] = "source_or_binary_changed_during_execution"
        if admit_output(output) != admitted:
            raise ValueError("report_parent_changed")
        private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "counts": {side: len(rows) for side, rows in report["cases"].items()},
                      "side_failures": report["side_failures"]}))
    return 0 if report["status"] in ("passed", "oracle_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
