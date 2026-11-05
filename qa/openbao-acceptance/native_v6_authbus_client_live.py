#!/usr/bin/env python3
"""Real native-V6 HTTPS, AppRole agent and mTLS re-enrollment canary.

Creates a new loopback-only server, CA and disposable credentials. It never
loads production AuthBus configuration or imports J3160 authority. A pass is
the named client/storage lifecycle evidence, not production cutover evidence.
The new private work directory and all failure evidence are retained.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import owned_process
from cert_auth_live import cert_sha256, issue_leaf

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_authbus_smoke", REPO / "qa/single-node/smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
POLICY = (
    'path "secret/data/authbus-canary/*" { capabilities = ["create", "read", "update", "delete"] }\n'
    'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
    'path "auth/token/renew-self" { capabilities = ["update"] }\n'
    'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
)
SELF_ONLY = "\n".join(POLICY.splitlines()[1:])
ROLE = "auth/authbus-canary/role/consumer"
LOGIN = "auth/authbus-canary/login"
SECRET = "secret/data/authbus-canary/credential"

CONSUMER = r'''
import hashlib,json,sys,time
from heptabao.agent import AgentConfig
from heptabao.private_state import StateDirectory,token_snapshot
from heptabao.transport import Client
try:
 cfg=AgentConfig.load(sys.argv[1]); req=json.load(sys.stdin)
 with StateDirectory(cfg.state_dir) as directory:
  token,state=token_snapshot(directory,time.time(),cfg.binding())
  r=Client(cfg.address,cfg.ca_file,token,cfg.namespace,cfg.timeout).request(req['method'],'/v1/'+req['path'],req.get('body'))
  data=r.body.get('data',{}) if isinstance(r.body,dict) else {}
  value=data.get('data') if isinstance(data,dict) else None
  metadata=data.get('metadata',{}) if isinstance(data,dict) else {}
  out={'status':r.status,'authentications':state['authentications'],'generation':state['generation'],
       'version':metadata.get('version',data.get('version')) if isinstance(data,dict) else None,
       'data_sha256':hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest() if value is not None else None}
  print(json.dumps(out,sort_keys=True))
except Exception:
 print(json.dumps({'error':'private_consumer_failed'}));sys.exit(2)
'''


class CanaryFailure(RuntimeError):
    pass


def private(path, value, *, replace=False):
    data = value if isinstance(value, bytes) else value.encode()
    target = path.with_name(path.name + ".new") if replace else path
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if replace:
        os.replace(target, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def value_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class NativeInstance(smoke.Instance):
    def start(self):
        self.log = open(self.root / "server.log", "ab")
        self.process = owned_process.popen(
            [str(self.binary), "--config", str(self.root / "server.json"), "--fixture-native-v6-service"],
            stdout=self.log, stderr=self.log, label="native-authbus.server", action="KILL", stop_timeout=5,
        )
        try:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise CanaryFailure("native_server_startup_exit")
                try:
                    status, _ = self.call("GET", "sys/health")
                    if status in (200, 501, 503):
                        return
                except urllib.error.URLError as error:
                    if isinstance(error.reason, ssl.SSLCertVerificationError):
                        raise CanaryFailure("server_ca_verification_failed") from None
                except OSError:
                    pass
                time.sleep(0.05)
            raise CanaryFailure("native_server_readiness_timeout")
        except BaseException:
            self.stop()
            raise


def run(args, report):
    root = args.work_dir
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    binary = args.binary.resolve(strict=True)
    report.update(binary_sha256=sha(binary), client_source_sha256=sha(REPO / "clients/python/heptabao/agent.py"),
                  harness_sha256=sha(__file__), checks=[], process_cycles=[], consumer_observations=[])
    confidential = []
    instance = None
    agent = None
    agent_logs = []
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "clients/python")
    config_path = root / "agent.json"

    def check(name, condition, **values):
        report["checks"].append({"case": name, "passed": bool(condition), **values})
        if not condition:
            raise CanaryFailure(name)

    def call(name, method, path, body=None, *, expected=200, token=None, opener=None):
        if opener is None:
            status, result = instance.call(method, path, body, token=token)
        else:
            req = urllib.request.Request(instance.address + "/v1/" + path, method=method,
                data=None if body is None else json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "X-Vault-Token": instance.token if token is None else token})
            try:
                response = opener.open(req, timeout=8)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read(1024 * 1024 + 1)
                check(name + ".bounded", len(data) <= 1024 * 1024)
                status, result = response.status, json.loads(data) if data else {}
        check(name, status == expected, status=status, expected=expected)
        return result

    def once(name, *, expected=0):
        p = subprocess.run([sys.executable, "-m", "heptabao.agent", "--config", str(config_path), "--once"],
                           cwd=root, env=env, capture_output=True, timeout=12)
        check(name, p.returncode == expected, exit_code=p.returncode)
        check(name + ".diagnostics_redacted", all(s.encode() not in p.stdout + p.stderr for s in confidential))

    def state():
        return json.loads((root / "agent/state.json").read_text())

    def sink():
        return (root / "agent/token").read_text().strip()

    def consume(name, method="GET", path=SECRET, body=None, expected=200, digest=None, version=None):
        p = subprocess.run([sys.executable, "-c", CONSUMER, str(config_path)], input=json.dumps({"method": method, "path": path, "body": body}).encode(),
                           cwd=root, env=env, capture_output=True, timeout=12)
        check(name + ".process", p.returncode == 0, exit_code=p.returncode)
        value = json.loads(p.stdout)
        check(name, value.get("status") == expected, status=value.get("status"), expected=expected)
        if digest is not None:
            check(name + ".exact_readback", value.get("data_sha256") == digest)
        if version is not None:
            check(name + ".version", value.get("version") == version, version=value.get("version"))
        report["consumer_observations"].append({"case": name, **value})
        return value

    def stop_agent():
        nonlocal agent
        if agent is not None:
            old = agent
            agent = None
            owned_process.stop(old, action="KILL", timeout=5, expected_codes=(-9,))
            report["process_cycles"].append({"kind": "agent", "pid": old.pid, "stop": "SIGKILL", "exit_code": old.returncode})

    def restart_server(name, key):
        old = instance.process
        instance.stop()
        report["process_cycles"].append({"kind": "server", "pid": old.pid, "stop": "SIGKILL", "exit_code": old.returncode})
        check(name + ".binary_identity", sha(binary) == report["binary_sha256"])
        instance.start()
        call(name + ".sealed", "GET", "sys/health", expected=503)
        call(name + ".unseal", "POST", "sys/unseal", {"key": key}, token="")
        cap = call(name + ".capacity", "GET", "sys/internal/capacity")["data"]
        check(name + ".native_v6_survives", cap.get("native_kv2_reader_format") == 2)

    try:
        instance = NativeInstance(binary, root / "server")
        client_ext = ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
                      "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        good_cert, good_key = issue_leaf(instance.root, "client", "/CN=authbus-client.example.test",
                                       instance.root / "ca.crt", instance.root / "ca.key", client_ext)
        wrong_cert, wrong_key = issue_leaf(instance.root, "wrong-client", "/CN=other-client.example.test",
                                         instance.root / "ca.crt", instance.root / "ca.key", client_ext)
        cfg = json.loads((instance.root / "server.json").read_text())
        cfg.update(tls_client_ca_file=str(instance.root / "ca.crt"), tls_client_auth_optional=True, lifecycle_interval_seconds=0)
        private(instance.root / "server.json", json.dumps(cfg), replace=True)
        report["trust"] = {"source": "new_canary_CA_and_native_local_init", "j3160_contacted": False,
                           "ca_pem_sha256": sha(instance.root / "ca.crt"), "server_cert_der_sha256": cert_sha256(instance.root / "tls.crt"),
                           "client_cert_der_sha256": cert_sha256(good_cert), "tls_server_san": ["DNS:localhost", "IP:127.0.0.1"]}
        instance.start()
        with socket.create_connection(("127.0.0.1", instance.port), timeout=3) as raw:
            with instance.context.wrap_socket(raw, server_hostname="localhost") as tls:
                report["trust"]["negotiated_tls"] = tls.version()
                check("tls.verified_leaf_identity", hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() == report["trust"]["server_cert_der_sha256"])
        rejected = False
        try:
            with socket.create_connection(("127.0.0.1", instance.port), timeout=3) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname="localhost"):
                    pass
        except ssl.SSLCertVerificationError:
            rejected = True
        check("tls.untrusted_server_ca_rejected", rejected)
        initialized = call("server.init", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token="")
        instance.token, key = initialized["root_token"], initialized["keys_base64"][0]
        confidential.extend((instance.token, key))
        private(root / "recovery.private.json", json.dumps({"root_token": instance.token, "unseal_key": key}))
        call("server.unseal", "POST", "sys/unseal", {"key": key}, token="")
        call("setup.kv2_mount", "POST", "sys/mounts/secret", {"type": "kv", "options": {"version": "2"}}, expected=204)
        call("native.activate", "POST", "sys/internal/native-v6/activate", {}, expected=204)
        cap = call("native.capacity", "GET", "sys/internal/capacity")["data"]
        check("native.actual_reader_floor2", cap.get("native_kv2_reader_format") == 2)
        call("native.policy_create", "PUT", "sys/policies/acl/authbus-canary", {"policy": POLICY}, expected=204)
        call("native.approle_mount", "POST", "sys/auth/authbus-canary", {"type": "approle"}, expected=204)
        call("native.role_create", "POST", ROLE, {"token_policies": ["authbus-canary"], "token_ttl": "40s",
            "token_max_ttl": "3m", "secret_id_ttl": "3m", "secret_id_num_uses": 1, "token_type": "service"}, expected=204)
        role_id = call("native.role_id", "GET", ROLE + "/role-id")["data"]["role_id"]
        sid = call("native.secret_id", "POST", ROLE + "/secret-id", {})["data"]["secret_id"]
        confidential.extend((role_id, sid))
        private(root / "role-id", role_id)
        private(root / "secret-id", sid)
        (root / "agent").mkdir(mode=0o700)
        acfg = dict(address=instance.address, ca_file=str(instance.root / "ca.crt"), auth_mount="auth/authbus-canary",
                    role_id_file=str(root / "role-id"), secret_id_file=str(root / "secret-id"), state_dir=str(root / "agent"),
                    timeout=5, interval_seconds=0.2, renew_increment_seconds=40, max_token_ttl_seconds=180,
                    max_authentications=4, max_runtime_seconds=90)
        private(config_path, json.dumps(acfg))
        original_config = config_path.read_bytes()
        private(root / "agent.rollback.json", original_config)
        once("agent.actual_private_file_login")
        first_token, initial = sink(), state()
        confidential.append(first_token)
        check("agent.ready_nonroot_one_authentication", initial["phase"] == "ready" and initial["authentications"] == 1)
        check("agent.private_sink", (root / "agent/token").stat().st_mode & 0o777 == 0o600)
        call("approle.single_use_sid_consumed", "POST", LOGIN, {"role_id": role_id, "secret_id": sid}, expected=400, token="")
        marker = {"credential": "synthetic-" + secrets.token_hex(24)}
        confidential.append(marker["credential"])
        consume("client.kv_create", "POST", body={"options": {"cas": 0}, "data": marker}, version=1)
        consume("client.kv_exact_read", digest=value_sha(marker), version=1)
        consume("client.stale_cas_denied", "POST", body={"options": {"cas": 0}, "data": {"credential": "wrong"}}, expected=400)
        consume("client.kv_unchanged_after_denial", digest=value_sha(marker), version=1)
        consume("client.outside_policy_denied", "POST", path="secret/data/outside-authbus", body={"data": marker}, expected=403)
        marker2 = {"credential": "synthetic-rotated-" + secrets.token_hex(24)}
        confidential.append(marker2["credential"])
        consume("client.kv_cas_update", "POST", body={"options": {"cas": 1}, "data": marker2}, version=2)
        call("policy.drop_kv_access", "PUT", "sys/policies/acl/authbus-canary", {"policy": SELF_ONLY}, expected=204)
        consume("client.live_policy_denied", expected=403)
        call("policy.restore_kv_access", "PUT", "sys/policies/acl/authbus-canary", {"policy": POLICY}, expected=204)
        consume("client.live_policy_restored", digest=value_sha(marker2), version=2)
        logfile = (root / "agent-process.log").open("ab")
        agent_logs.append(logfile)
        agent = owned_process.popen([sys.executable, "-m", "heptabao.agent", "--config", str(config_path)], cwd=root, env=env,
            stdout=logfile, stderr=logfile, label="native-authbus.agent", action="KILL", stop_timeout=5)
        renewal_deadline = time.monotonic() + 45
        renewed = False
        while time.monotonic() < renewal_deadline and agent.poll() is None:
            current = state()
            if current["phase"] == "ready" and current.get("expires_at", 0) > initial["expires_at"]:
                renewed = True
                break
            time.sleep(0.1)
        check("agent.real_automatic_renewal", renewed)
        check("agent.renewal_keeps_bearer_and_auth_count", sink() == first_token and state()["authentications"] == 1)
        stop_agent()
        restart_server("server.first_cold_restart", key)
        consume("client.read_after_server_sigkill", digest=value_sha(marker2), version=2)
        call("approle.sid_consumption_persisted", "POST", LOGIN, {"role_id": role_id, "secret_id": sid}, expected=400, token="")
        # An explicitly wrong staged client configuration must fail; restoring
        # the exact admitted bytes must permit the real agent's resume lookup.
        bad = {**acfg, "ca_file": str(instance.root / "tls.crt")}
        private(config_path, json.dumps(bad), replace=True)
        once("rollback.mismatched_client_binding_rejected", expected=2)
        private(config_path, original_config, replace=True)
        check("rollback.exact_config_restored", config_path.read_bytes() == (root / "agent.rollback.json").read_bytes())
        once("agent.actual_resume_after_sigkill_and_rollback")
        check("agent.restart_reuses_persisted_token", sink() == first_token and state()["authentications"] == 1)

        def cert_opener(cert, keyfile):
            context = ssl.create_default_context(cafile=str(instance.root / "ca.crt"))
            context.load_cert_chain(str(cert), str(keyfile))
            return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        good, wrong = cert_opener(good_cert, good_key), cert_opener(wrong_cert, wrong_key)
        call("cert.native_mount", "POST", "sys/auth/native-cert", {"type": "cert"}, expected=204)
        call("cert.native_role", "POST", "auth/native-cert/certs/client", {"certificate_sha256": cert_sha256(good_cert),
            "allowed_common_names": ["authbus-client.example.test"], "token_policies": ["authbus-canary"],
            "token_ttl": "2m", "token_max_ttl": "3m"}, expected=204)
        call("cert.no_client_certificate_denied", "POST", "auth/native-cert/login", {}, expected=403, token="")
        call("cert.same_ca_wrong_leaf_denied", "POST", "auth/native-cert/login", {}, expected=403, token="", opener=wrong)
        cert_token = call("cert.actual_mtls_login", "POST", "auth/native-cert/login", {}, token="", opener=good)["auth"]["client_token"]
        confidential.append(cert_token)
        cert_data = call("cert.actual_policy_kv", "GET", SECRET, token=cert_token, opener=good)
        check("cert.exact_kv_read", value_sha(cert_data["data"]["data"]) == value_sha(marker2))
        call("cert.renew_same_leaf", "POST", "auth/token/renew-self", {"increment": 60}, token=cert_token, opener=good)
        before_denied = call("cert.lease_before_denied_renewals", "GET", "auth/token/lookup-self", token=cert_token)["data"]
        # Auth::cert_renewal_limits uses bad(...) for an absent TLS peer
        # certificate (HTTP 400); a present but differently pinned leaf uses
        # denied() (HTTP 403). Check the exact errors and absence of Auth data
        # so an unrelated 400 cannot make this negative control pass.
        absent = call("cert.renew_without_leaf_denied", "POST", "auth/token/renew-self", {"increment": 60}, expected=400, token=cert_token)
        check("cert.renew_without_leaf_exact_contract", absent.get("errors") == ["TLS client certificate required for renewal"] and "auth" not in absent)
        different = call("cert.renew_wrong_leaf_denied", "POST", "auth/token/renew-self", {"increment": 60}, expected=403, token=cert_token, opener=wrong)
        check("cert.renew_wrong_leaf_exact_contract", different.get("errors") == ["permission denied"] and "auth" not in different)
        after_denied = call("cert.lease_after_denied_renewals", "GET", "auth/token/lookup-self", token=cert_token)["data"]
        check("cert.denied_renewals_preserve_lease", bool(before_denied.get("expire_time")) and all(before_denied.get(field) == after_denied.get(field) for field in ("expire_time", "expire_time_unix", "last_renewal", "last_renewal_time")))

        call("token.first_revoke", "POST", "auth/token/revoke", {"token": first_token}, expected=204)
        consume("client.revoked_token_denied", expected=403)
        once("agent.revoked_token_resume_invalidates_sink")
        check("agent.revoked_sink_removed", state()["phase"] == "empty" and not (root / "agent/token").exists())
        new_sid = call("native.fresh_reenrollment_secret_id", "POST", ROLE + "/secret-id", {})["data"]["secret_id"]
        confidential.append(new_sid)
        private(root / "secret-id", new_sid, replace=True)
        once("agent.real_fresh_reenrollment")
        second_token = sink()
        confidential.append(second_token)
        check("agent.new_token_new_authentication", second_token != first_token and state()["authentications"] == 2)
        consume("client.new_credential_reads_persisted_kv", digest=value_sha(marker2), version=2)
        call("token.second_revoke", "POST", "auth/token/revoke", {"token": second_token}, expected=204)
        call("cert.token_revoke", "POST", "auth/token/revoke", {"token": cert_token}, expected=204)
        restart_server("server.second_cold_restart", key)
        for label, token in (("first", first_token), ("second", second_token), ("cert", cert_token)):
            call("revoke.persisted_" + label, "GET", SECRET, expected=403, token=token)
        final = call("server.final_kv_read", "GET", SECRET)
        check("server.final_data_survives_credentials_revoke", value_sha(final["data"]["data"]) == value_sha(marker2))
        check("server.final_binary_identity", sha(binary) == report["binary_sha256"])
        private_state = (root / "agent/state.json").read_bytes()
        check("agent.checkpoint_redacts_credential_bytes", all(value.encode() not in private_state for value in confidential))
        log_bytes = (root / "agent-process.log").read_bytes() + (instance.root / "audit.jsonl").read_bytes()
        check("logs.redact_disposable_secrets", all(value.encode() not in log_bytes for value in confidential))
        report["status"] = "passed"
    finally:
        try:
            stop_agent()
        finally:
            for log in agent_logs:
                log.close()
            if instance is not None:
                instance.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute() or args.work_dir.exists():
        parser.error("absolute --binary and new absolute --work-dir required")
    report = {"schema": "heptabao.native-v6-authbus-client-live.v1", "status": "failed", "native_v6_fixture": True,
              "production_credentials_imported": False, "production_cutover": False, "ha_qualification": False,
              "started_unix_ns": time.time_ns()}
    result = 0
    try:
        run(args, report)
    except BaseException as error:
        result = 1
        report["status"] = "failed"
        report["failure"] = str(error) if isinstance(error, CanaryFailure) else type(error).__name__
    report["finished_unix_ns"] = time.time_ns()
    report["check_count"] = len(report.get("checks", []))
    if args.work_dir.is_dir():
        private(args.work_dir / "public-receipt.json", json.dumps(report, sort_keys=True, indent=2))
    print(json.dumps(report, sort_keys=True))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
