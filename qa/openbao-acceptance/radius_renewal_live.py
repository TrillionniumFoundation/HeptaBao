#!/usr/bin/env python3
"""Compare RADIUS token renewal with pinned OpenBao 2.6.2 over HTTPS and UDP.

Both sides use fresh local stores and synthetic PAP credentials. Configuration
is explicitly adapted: HeptaBao uses a process-enrolled URL/secret; OpenBao
uses host/port/secret API fields. This is not RADIUS configuration API parity.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

from bao_http import BaoError, Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash, successful_comparison
from online_evidence import source_identity
from official_openbao_launcher import BINARY_SHA256, start_oracle, stop_oracle, restart_oracle

SECRET = b"synthetic-radius-renewal-shared-secret"
USERNAME = b"alice"
PASSWORD = b"synthetic-radius-renewal-password"
ADAPTATION = {
    "candidate": "url API field; endpoint, UDP address and shared secret enrolled in server configuration",
    "oracle": "host, port and secret API fields",
    "request_message_authenticator": "mandatory and validated for candidate; absent in official 2.6.2 PAP requests",
    "response": "both sides receive signed Response-Authenticator and Message-Authenticator",
    "configuration_api_parity": False,
}


def md5(*parts):
    digest = hashlib.md5()
    for part in parts:
        digest.update(part)
    return digest.digest()


def message_authenticator(packet):
    return hmac.new(SECRET, packet, hashlib.md5).digest()


def pap_packet_response(packet: bytes, *, require_ma: bool, allow: bool):
    """Validate one synthetic request; return signed reply plus booleans only."""
    if len(packet) < 20 or len(packet) > 4096 or packet[0] != 1:
        raise ValueError("invalid_request")
    if struct.unpack("!H", packet[2:4])[0] != len(packet):
        raise ValueError("invalid_length")
    values = {}
    signed = bytearray(packet)
    offset = 20
    while offset < len(packet):
        if len(packet) - offset < 2:
            raise ValueError("invalid_attribute")
        kind, length = packet[offset:offset + 2]
        if length < 2 or length > len(packet) - offset:
            raise ValueError("invalid_attribute")
        if kind in (1, 2, 80):
            if kind in values:
                raise ValueError("duplicate_attribute")
            values[kind] = packet[offset + 2:offset + length]
        if kind == 80:
            if length != 18:
                raise ValueError("invalid_authenticator")
            signed[offset + 2:offset + length] = b"\0" * 16
        offset += length
    present = 80 in values
    if (require_ma and not present) or (present and not hmac.compare_digest(values[80], message_authenticator(signed))):
        raise ValueError("invalid_authenticator")
    encrypted = values.get(2, b"")
    if not encrypted or len(encrypted) > 128 or len(encrypted) % 16:
        raise ValueError("invalid_password_shape")
    clear = bytearray()
    previous = packet[4:20]
    for offset in range(0, len(encrypted), 16):
        block = encrypted[offset:offset + 16]
        clear.extend(a ^ b for a, b in zip(block, md5(SECRET, previous)))
        previous = block
    credentials_valid = (values.get(1) == USERNAME and hmac.compare_digest(bytes(clear).rstrip(b"\0"), PASSWORD))
    clear[:] = b"\0" * len(clear)
    accepted = credentials_valid and allow
    response = bytearray([2 if accepted else 3, packet[1], 0, 38])
    response.extend(packet[4:20])
    response.extend([80, 18])
    response.extend(b"\0" * 16)
    response[22:] = message_authenticator(response)
    response[4:20] = md5(response[:4], packet[4:20], response[20:], SECRET)
    return bytes(response), {"credentials_valid": credentials_valid, "message_authenticator_present": present, "accepted": accepted}


class RadiusResponder:
    def __init__(self, *, require_ma):
        self.require_ma = require_ma
        self.allow = True
        self.requests = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                packet, source = self.socket.recvfrom(4096)
                response, observation = pap_packet_response(packet, require_ma=self.require_ma, allow=self.allow)
                with self.lock:
                    self.requests.append(observation)
                self.socket.sendto(response, source)
            except TimeoutError:
                continue
            except ValueError:
                continue
            except OSError:
                break

    def count(self):
        with self.lock:
            return len(self.requests)

    def observed(self, start, *, accepted):
        with self.lock:
            rows = self.requests[start:]
            return bool(rows) and all(row == {"credentials_valid": True,
                "message_authenticator_present": self.require_ma, "accepted": accepted} for row in rows)

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise ScenarioFailure("radius_renewal.responder_shutdown")


def configuration(side, responder, policies):
    common = {"token_policies": policies, "token_ttl": 60, "token_max_ttl": 600}
    if side == "candidate":
        return dict(common, url=f"radius://127.0.0.1:{responder.port}")
    return dict(common, host="127.0.0.1", port=responder.port, secret=SECRET.decode(), dial_timeout=2, read_timeout=2)


def renewal_token_shape(auth, target, *, via_accessor):
    if not isinstance(auth, dict):
        return False
    returned = auth.get("client_token")
    return returned in (None, "") if via_accessor else isinstance(returned, str) and returned == target


def wrapped_renewal_shape(body, target):
    info = body.get("wrap_info")
    return (body.get("auth") is None and body.get("data") is None and not body.get("client_token")
            and isinstance(info, dict) and isinstance(info.get("token"), str)
            and bool(info["token"]) and info["token"] != target)


def run_scenarios(client, responder, configure, restart, results=None):
    results = [] if results is None else results

    def check(case, passed, **observed):
        row = {"case": "radius_renewal." + case, **observed, "passed": bool(passed)}
        results.append(row)
        if not passed:
            raise ScenarioFailure(row["case"])

    def call(case, method, path, payload=None, *, token=None, expected=200, provider=None, wrap_ttl=None):
        before = responder.count()
        response = client.request(method, "/v1/" + path, payload, token=token, wrap_ttl=wrap_ttl)
        observed = {"status": response.status}
        passed = response.status == expected
        if provider is not None:
            observed["provider_checked"] = responder.observed(before, accepted=provider)
            passed &= observed["provider_checked"]
        check(case, passed, **observed)
        return response.body

    def config(case, policies):
        call(case, "POST", "auth/radius/config", configure(policies), expected=204)

    def login(case):
        body = call(case, "POST", "auth/radius/login", {"username": USERNAME.decode(), "password": PASSWORD.decode()}, provider=True)
        auth = body.get("auth", {})
        valid = isinstance(auth.get("client_token"), str) and bool(auth["client_token"]) and isinstance(auth.get("accessor"), str) and bool(auth["accessor"])
        check(case + ".credentials_present", valid)
        return auth["client_token"], auth["accessor"]

    def lookup_ttl(case, token):
        body = call(case, "GET", "auth/token/lookup-self", token=token)
        ttl = body.get("data", {}).get("ttl")
        check(case + ".ttl_shape", type(ttl) is int and ttl > 0)
        return ttl

    call("mount", "POST", "sys/auth/radius", {"type": "radius"}, expected=204)
    config("configure", ["default"])
    token, accessor = login("login")
    routes = [("self", "auth/token/renew-self", {}, token),
              ("token", "auth/token/renew", {"token": token}, None),
              ("accessor", "auth/token/renew-accessor", {"accessor": accessor}, None)]
    for name, route, payload, caller in routes:
        responder.allow = True
        body = call(name + ".accepted", "POST", route, dict(payload, increment=120), token=caller, provider=True)
        auth = body.get("auth", {})
        check(name + ".renewed_lease", auth.get("renewable") is True and type(auth.get("lease_duration")) is int and auth["lease_duration"] > 0)
        check(name + ".token_response_shape", renewal_token_shape(auth, token, via_accessor=name == "accessor"))
        before = lookup_ttl(name + ".before_reject", token)
        responder.allow = False
        call(name + ".provider_rejected", "POST", route, dict(payload, increment=300), token=caller, expected=400, provider=False)
        after = lookup_ttl(name + ".after_reject", token)
        check(name + ".rejection_did_not_extend_ttl", after <= before)

    responder.allow = True
    wrapped = call("wrap.accepted", "POST", "auth/token/renew-self", {"increment": 120}, token=token, provider=True, wrap_ttl="60s")
    check("wrap.auth_and_bearer_hidden", wrapped_renewal_shape(wrapped, token))
    wrapping_token = wrapped["wrap_info"]["token"]
    unwrapped = call("wrap.unwrap", "POST", "sys/wrapping/unwrap", {"token": wrapping_token})
    check("wrap.original_target_auth_restored", renewal_token_shape(unwrapped.get("auth"), token, via_accessor=False))
    call("wrap.single_use", "POST", "sys/wrapping/unwrap", {"token": wrapping_token}, expected=400)
    before = lookup_ttl("wrap.before_reject", token)
    responder.allow = False
    denied = call("wrap.provider_rejected", "POST", "auth/token/renew-self", {"increment": 300}, token=token, expected=400, provider=False, wrap_ttl="60s")
    check("wrap.rejection_has_no_wrapper_or_auth", not denied.get("wrap_info") and denied.get("auth") is None)
    after = lookup_ttl("wrap.after_reject", token)
    check("wrap.rejection_did_not_extend_ttl", after <= before)

    responder.allow = True
    call("policy_create", "PUT", "sys/policies/acl/radius-changed", {"policy": 'path "cubbyhole/*" { capabilities = ["read"] }'}, expected=204)
    config("policy_change", ["default", "radius-changed"])
    call("changed_policy_rejected", "POST", "auth/token/renew-self", {"increment": 300}, token=token, expected=500, provider=True)
    config("policy_restore", ["default"])
    call("restored_policy_renews", "POST", "auth/token/renew-self", {"increment": 120}, token=token, provider=True)

    revoked, _ = login("revocation_login")
    call("revoke", "POST", "auth/token/revoke", {"token": revoked}, expected=204)
    before = responder.count()
    call("revoked_token_rejected", "POST", "auth/token/renew-self", {"increment": 120}, token=revoked, expected=403)
    check("revoked_token_does_not_contact_provider", responder.count() == before)

    restart()
    check("same_store_restart", True)
    responder.allow = False
    call("restart_provider_rejected", "POST", "auth/token/renew-self", {"increment": 300}, token=token, expected=400, provider=False)
    responder.allow = True
    call("restart_provider_accepted", "POST", "auth/token/renew-self", {"increment": 120}, token=token, provider=True)
    return results



def run_finite_lifetime_scenarios(client, provider, configure, update_limits, restart, results):
    """Finite service lifetime only; no period/explicit configuration adaptation."""
    mount = 'radius' + "-finite-lifetime"
    def check(name, passed, **observed):
        case = 'radius' + "_renewal.finite." + name
        results.append({"case": case, **observed, "passed": bool(passed)})
        if not passed:
            raise ScenarioFailure(case)
    def call(name, method, path, payload=None, *, token=None, expected=200, contact=False):
        cursor = provider.count()
        response = client.request(method, "/v1/" + path, payload, token=token)
        safe = {"status": response.status}
        passed = response.status == expected
        if contact:
            safe["provider_checked"] = provider.observed(cursor, accepted=True)
            passed &= safe["provider_checked"]
        check(name, passed, **safe)
        return response.body
    call("mount", "POST", "sys/auth/" + mount, {"type": 'radius'}, expected=204)
    configure(mount, 60, 120)
    check("initial_config", True)
    issued = call("login", "POST", "auth/" + mount + '/login',
                  {"username": USERNAME.decode(), "password": PASSWORD.decode()}, token="", contact=True)["auth"]
    raw, accessor = issued["client_token"], issued["accessor"]
    check("initial_ttl60", issued.get("lease_duration") == 60)
    data = call("lookup_initial", "GET", "auth/token/lookup-self", token=raw)["data"]
    check("ordinary_max_is_not_explicit", data.get("explicit_max_ttl") == 0)
    update_limits(mount, 120, 600)
    check("raised_current_max", True)
    routes = [("self", "auth/token/renew-self", {}, raw),
              ("token", "auth/token/renew", {"token": raw}, None),
              ("accessor", "auth/token/renew-accessor", {"accessor": accessor}, None)]
    for name, path, payload, actor in routes:
        renewed = call(name + ".raised_renew", "POST", path, dict(payload, increment=300),
                       token=actor, contact=True)["auth"]
        check(name + ".full300_beyond_issue_max", renewed.get("lease_duration") == 300)
    restart()
    check("same_store_restart", True)
    data = call("lookup_reopened", "GET", "auth/token/lookup-self", token=raw)["data"]
    check("no_explicit_cap_after_reopen", data.get("explicit_max_ttl") == 0)
    for name, payload in [("omitted", {}), ("zero", {"increment": 0})]:
        renewed = call(name + ".renew", "POST", "auth/token/renew-self", payload,
                       token=raw, contact=True)["auth"]
        check(name + ".current_ttl120", renewed.get("lease_duration") == 120)
    time.sleep(2)
    update_limits(mount, 1, 1)
    check("shrink_max_past_issue_age", True)
    for name, path, payload, actor in routes:
        before = call(name + ".before_past_max", "GET", "auth/token/lookup-self", token=raw)["data"]["ttl"]
        call(name + ".past_max500", "POST", path, payload, token=actor, expected=500, contact=True)
        after = call(name + ".lease_still_active", "GET", "auth/token/lookup-self", token=raw)["data"]["ttl"]
        check(name + ".failed_renewal_did_not_extend", type(after) is int and 0 < after <= before)
    check("complete", True)


def run_finite_scenarios(client, responder, configure, restart, results):
    def settings(mount, ttl, maximum):
        config = dict(configure(["default"]), token_ttl=ttl, token_max_ttl=maximum)
        response = client.request("POST", "/v1/auth/" + mount + "/config", config)
        if response.status != 204:
            raise ScenarioFailure("radius_renewal.finite.config_failed")
    run_finite_lifetime_scenarios(client, responder, settings, settings, restart, results)


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve(strict=True)
    output = Path(args.output).resolve()
    parent = output.parent.stat()
    if output.exists() or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        parser.error("private unused output required")
    private_root = Path(tempfile.mkdtemp(prefix="heptabao-radius-renewal-"))
    private_root.chmod(0o700)
    spec = importlib.util.spec_from_file_location("radius_smoke", ROOT / "qa/single-node/smoke.py")
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    source_before = source_identity(ROOT, binary)
    instance = None
    oracle = None
    responders = []
    result = {"schema": "heptabao.radius-renewal-comparison.v1", "synthetic_only": True,
              "target_version": "2.6.2", "full_openbao_compatibility": False,
              "independent_qualification": False, "production_authority": False,
              "configuration_adaptation": ADAPTATION,
              "candidate_binary_sha256": file_hash(binary), "oracle_binary_sha256": BINARY_SHA256,
              "runner_sha256": file_hash(Path(__file__)), "cargo_lock_sha256": file_hash(ROOT / "Cargo.lock"),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_worktree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "started_at_unix": time.time(), "cases": {}, "side_failures": {}}
    try:
        candidate_udp = RadiusResponder(require_ma=True)
        oracle_udp = RadiusResponder(require_ma=False)
        responders.extend([candidate_udp, oracle_udp])
        instance = smoke.Instance(binary, private_root / "candidate")
        cfg = json.loads((instance.root / "server.json").read_text())
        cfg["lifecycle_interval_seconds"] = 0
        cfg["outbound_endpoints"] = [{"origin": f"radius://127.0.0.1:{candidate_udp.port}",
            "address": f"127.0.0.1:{candidate_udp.port}", "server_name": "127.0.0.1",
            "ca_pem": "", "path_prefix": "/", "shared_secret": SECRET.decode()}]
        (instance.root / "server.json").write_text(json.dumps(cfg))
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if status != 200:
            raise ScenarioFailure("radius_renewal.candidate_init")
        instance.token = init["root_token"]
        key = init["keys_base64"][0]
        if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
            raise ScenarioFailure("radius_renewal.candidate_unseal")
        candidate = Client(instance.address, str(instance.root / "ca.crt"), instance.token)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        oracle = start_oracle(port)
        reference = Client(oracle["address"], oracle["ca_file"], private_read(oracle["token_file"], 8192).decode().strip())

        def restart_candidate():
            instance.stop()
            instance.start()
            if instance.call("POST", "sys/unseal", {"key": key})[0] != 200:
                raise ScenarioFailure("radius_renewal.candidate_restart_unseal")

        def restart_reference():
            oracle["process"].kill()
            oracle["process"].wait(timeout=5)
            stop_oracle(oracle)
            restart_oracle(oracle)

        for side, client, responder, restart in [("candidate", candidate, candidate_udp, restart_candidate),
                                                 ("oracle", reference, oracle_udp, restart_reference)]:
            result["cases"][side] = []
            try:
                run_scenarios(client, responder, lambda policies: configuration(side, responder, policies), restart, result["cases"][side])
                run_finite_scenarios(client, responder, lambda policies: configuration(side, responder, policies), restart, result["cases"][side])
            except ScenarioFailure as error:
                result["side_failures"][side] = str(error)
            except Exception as error:
                result["side_failures"][side] = "unexpected_" + type(error).__name__
        result["cases_match"] = result["cases"].get("candidate") == result["cases"].get("oracle")
        complete = all(len(rows) == 90 and len({row["case"] for row in rows}) == 90
                       and rows[-1].get("case") == "radius_renewal.finite.complete"
                       for rows in result["cases"].values()) and len(result["cases"]) == 2
        result["status"] = "passed" if complete and successful_comparison(result["cases"], result["side_failures"]) else "mismatch"
    except ScenarioFailure as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error)
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if oracle is not None:
            stop_oracle(oracle)
            shutil.rmtree(oracle["root"])
        for responder in responders:
            responder.close()
        shutil.rmtree(private_root)
        result["candidate_binary_unchanged"] = file_hash(binary) == result["candidate_binary_sha256"]
        result["source_identity"] = source_before
        result["source_and_binary_unchanged"] = source_before == source_identity(ROOT, binary)
        if not result["source_and_binary_unchanged"]:
            result["status"] = "failed"
            result["safe_failure_code"] = "source_or_binary_changed_during_execution"
        result["finished_at_unix"] = time.time()
        private_write(output, result)
    print(json.dumps({"status": result["status"], "checks_per_side": {side: len(rows) for side, rows in result["cases"].items()},
                      "side_failures": result["side_failures"], "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] == "passed" and result["candidate_binary_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
