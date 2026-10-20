#!/usr/bin/env python3
"""Pinned OpenBao 2.7.1 vs native HeptaBao AppRole default-policy behavior.

Only fresh private loopback TLS fixtures and synthetic credentials. These
observations do not authorize production migration or whole-product replacement.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
MOUNTS = ("approle", "build")
POLICY = "nd-policy"
PROFILES = (
    ("implicit", {}, False, [], ["default"], "service"),
    ("empty", {"token_no_default_policy": True, "token_policies": []}, True, [], [], "service"),
    ("nil", {"token_no_default_policy": True}, True, [], [], "service"),
    ("named", {"token_no_default_policy": True, "token_policies": [POLICY]}, True, [POLICY], [POLICY], "service"),
    ("explicit", {"token_no_default_policy": True, "token_policies": ["default", POLICY]}, True, ["default", POLICY], ["default", POLICY], "service"),
    ("batch", {"token_no_default_policy": True, "token_policies": [POLICY], "token_type": "batch"}, True, [POLICY], [POLICY], "batch"),
    ("batch_empty", {"token_no_default_policy": True, "token_policies": [], "token_type": "batch"}, True, [], [], "batch"),
)
BASE_CASES = ("write", "read", "read.shape", "role_id", "secret_id", "login", "login.shape", "lookup", "lookup.shape")
TAIL_CASES = (
    "omit_write", "omit_read", "omit_read.shape",
    "kv_write", "kv_read", "kv_read.shape", "deny_ungranted",
    "false_write", "false_read", "false_read.shape", "false_login", "false_login.shape",
    "old_renew", "old_renew.shape", "old_self_renew", "old_self_renew.shape",
    "true_write", "old_default_renew", "old_default_renew.shape",
    "bad_flag", "bad_read", "bad_read.shape",
    "string_write", "string_read", "string_read.shape",
    "null_write", "null_read", "null_read.shape",
    "clear_write", "clear_read", "clear_read.shape", "clear_login", "clear_login.shape",
    "clear_renew", "clear_renew.shape", "empty_self_denied",
    "restore_write", "restore_read", "restore_read.shape",
)
RESTART_CASES = (
    "read", "read.shape", "old_lookup", "old_lookup.shape",
    "old_default_lookup", "old_default_lookup.shape", "batch_lookup", "batch_lookup.shape",
    "empty_renew", "empty_renew.shape", "old_self_renew", "old_self_renew.shape",
    "kv_read", "kv_read.shape", "fresh_login", "fresh_login.shape", "revoke_old", "revoked_denied",
)
REQUIRED = frozenset(
    ["kv_mount", "policy", "restarted", "complete"]
    + [mount + "." + suffix for mount in MOUNTS for suffix in ("mount", "tune")]
    + [mount + "." + name + "." + suffix for mount in MOUNTS for name, *_ in PROFILES for suffix in BASE_CASES]
    + [mount + ".tail." + suffix for mount in MOUNTS for suffix in TAIL_CASES]
    + [mount + ".restart." + suffix for mount in MOUNTS for suffix in RESTART_CASES]
)
EXPECTED_ROWS = 248


class Failure(RuntimeError):
    pass


def need(ok, label):
    if ok is not True:
        raise Failure(label)


def stable_file(path, cap, expected=None, budget=None):
    path = Path(path)
    need(path.is_absolute() and not path.is_symlink(), "input_path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and 0 <= before.st_size <= cap, "input_file")
        digest = hashlib.sha256()
        size = 0
        while True:
            if budget is not None:
                budget.remaining()
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            need(size <= cap, "input_size")
            digest.update(block)
        after = os.fstat(descriptor)
        anchor = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        snapshot = tuple(getattr(before, field) for field in fields)
        need(snapshot == tuple(getattr(after, field) for field in fields)
             == tuple(getattr(anchor, field) for field in fields)
             and size == before.st_size, "input_changed")
        value = digest.hexdigest()
        need(expected is None or value == expected, "input_digest")
        return {"sha256": value, "bytes": size, "stat": list(snapshot)}
    finally:
        os.close(descriptor)


def load_module(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    need(specification is not None and specification.loader is not None, "module_spec")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


class Api:
    def __init__(self, address, ca_file, root_token, owner):
        endpoint = urlsplit(address)
        need(endpoint.scheme == "https" and endpoint.hostname == "127.0.0.1"
             and endpoint.path in ("", "/") and endpoint.port is not None
             and 1024 <= endpoint.port <= 65534, "endpoint")
        self.endpoint, self.token, self.owner = endpoint, root_token, owner
        self.context = ssl.create_default_context(cafile=str(ca_file))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def call(self, method, path, body=None, token=None):
        self.owner.remaining()
        connection = http.client.HTTPSConnection(
            self.endpoint.hostname, self.endpoint.port, context=self.context,
            timeout=min(10.0, self.owner.remaining()))
        headers = {"Connection": "close"}
        bearer = self.token if token is None else token
        if bearer:
            headers["X-Vault-Token"] = bearer
        raw = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(body, separators=(",", ":")).encode()
        try:
            connection.request(method, "/v1/" + path, body=raw, headers=headers)
            response = connection.getresponse()
            raw = response.read(65537)
            need(len(raw) <= 65536, "response_limit")
            data = json.loads(raw) if raw else {}
            need(isinstance(data, dict), "response_object")
            return response.status, data
        finally:
            connection.close()


class Trace:
    def __init__(self, api, rows, private):
        self.api, self.rows, self.private = api, rows, private

    def check(self, case, passed, status=None):
        need(case in REQUIRED and not any(row["case"] == case for row in self.rows), "case_definition")
        row = {"case": case, "passed": passed is True}
        if status is not None:
            need(type(status) is int and 100 <= status <= 599, "status_shape")
            row["status"] = status
        self.rows.append(row)
        need(passed is True, case)

    def req(self, case, method, path, body=None, expected=204, token=None):
        status, data = self.api.call(method, path, body, token)
        valid = status == expected
        if expected >= 400:
            valid = valid and not data.get("auth") and not data.get("wrap_info")
        self.check(case, valid, status)
        return data

    def role_read(self, case, mount, name, flag, policies):
        body = self.req(case, "GET", "auth/" + mount + "/role/" + name, expected=200)
        data = body.get("data") or {}
        self.check(case + ".shape", data.get("token_no_default_policy") is flag
                   and data.get("token_policies") == policies)

    def auth_shape(self, case, body, policies, kind, bearer):
        auth = body.get("auth") or {}
        self.check(case + ".shape", isinstance(auth, dict)
                   and auth.get("policies") == policies
                   and auth.get("token_policies") == (policies if policies else None)
                   and ("token_policies" in auth) is bool(policies)
                   and auth.get("token_type") == kind
                   and auth.get("renewable") is (kind == "service")
                   and (not bearer or isinstance(auth.get("client_token"), str)
                        and len(auth["client_token"]) >= 16))
        if isinstance(auth.get("client_token"), str) and auth["client_token"]:
            self.private.append(auth["client_token"])
        return auth

    def login(self, case, mount, credentials, policies, kind="service"):
        body = self.req(case, "POST", "auth/" + mount + "/login", credentials, 200, token="")
        return self.auth_shape(case, body, policies, kind, True)

    def lookup(self, case, auth, policies):
        body = self.req(case, "POST", "auth/token/lookup", {"token": auth["client_token"]}, 200)
        self.check(case + ".shape", (body.get("data") or {}).get("policies") == policies)

    def renew(self, case, auth, policies, self_request=False):
        path = "auth/token/renew-self" if self_request else "auth/token/renew"
        body = {"increment": 180}
        if not self_request:
            body["token"] = auth["client_token"]
        result = self.req(case, "POST", path, body, 200,
                          token=auth["client_token"] if self_request else None)
        self.auth_shape(case, result, policies, "service", False)


def scenario(api, restart, rows, private):
    t = Trace(api, rows, private)
    t.req("kv_mount", "POST", "sys/mounts/ndkv", {"type": "kv", "options": {"version": "2"}})
    policy = ('path "ndkv/data/*" { capabilities = ["create", "update", "read"] } '
              'path "auth/token/renew-self" { capabilities = ["update"] } '
              'path "auth/token/lookup-self" { capabilities = ["read"] }')
    t.req("policy", "PUT", "sys/policies/acl/" + POLICY, {"policy": policy})
    all_held = {}
    for mount in MOUNTS:
        t.req(mount + ".mount", "POST", "sys/auth/" + mount, {"type": "approle"})
        t.req(mount + ".tune", "POST", "sys/auth/" + mount + "/tune",
              {"default_lease_ttl": 120, "max_lease_ttl": 600})
        held = {}
        for name, fields, flag, raw_policies, issued_policies, kind in PROFILES:
            prefix = mount + "." + name
            path = "auth/" + mount + "/role/" + name
            body = {"token_ttl": 120, "token_max_ttl": 600, **fields}
            t.req(prefix + ".write", "POST", path, body)
            t.role_read(prefix + ".read", mount, name, flag, raw_policies)
            rid = t.req(prefix + ".role_id", "GET", path + "/role-id", expected=200)["data"]["role_id"]
            sid = t.req(prefix + ".secret_id", "POST", path + "/secret-id", {}, 200)["data"]["secret_id"]
            need(isinstance(rid, str) and isinstance(sid, str), "credential_shape")
            private.extend((rid, sid))
            credentials = {"role_id": rid, "secret_id": sid}
            auth = t.login(prefix + ".login", mount, credentials, issued_policies, kind)
            t.lookup(prefix + ".lookup", auth, issued_policies)
            held[name] = {"credentials": credentials, "auth": auth}
        prefix = mount + ".tail."
        path = "auth/" + mount + "/role/named"
        old = held["named"]["auth"]
        credentials = held["named"]["credentials"]
        t.req(prefix + "omit_write", "POST", path, {"token_ttl": 120})
        t.role_read(prefix + "omit_read", mount, "named", True, [POLICY])
        kv_path = "ndkv/data/" + mount
        t.req(prefix + "kv_write", "POST", kv_path, {"data": {"value": "fixture-" + mount}}, 200, old["client_token"])
        data = t.req(prefix + "kv_read", "GET", kv_path, expected=200, token=old["client_token"])
        t.check(prefix + "kv_read.shape", data.get("data", {}).get("data", {}).get("value") == "fixture-" + mount)
        t.req(prefix + "deny_ungranted", "GET", "ndkv/metadata/" + mount, expected=403, token=old["client_token"])
        t.req(prefix + "false_write", "POST", path, {"token_no_default_policy": False})
        t.role_read(prefix + "false_read", mount, "named", False, [POLICY])
        old_default = t.login(prefix + "false_login", mount, credentials, ["default", POLICY])
        t.renew(prefix + "old_renew", old, [POLICY])
        t.renew(prefix + "old_self_renew", old, [POLICY], True)
        t.req(prefix + "true_write", "POST", path, {"token_no_default_policy": True})
        t.renew(prefix + "old_default_renew", old_default, ["default", POLICY])
        t.req(prefix + "bad_flag", "POST", path, {"token_no_default_policy": [], "token_policies": ["changed"]}, 400)
        t.role_read(prefix + "bad_read", mount, "named", True, [POLICY])
        t.req(prefix + "string_write", "POST", path, {"token_no_default_policy": "false"})
        t.role_read(prefix + "string_read", mount, "named", False, [POLICY])
        t.req(prefix + "null_write", "POST", path, {"token_no_default_policy": None})
        t.role_read(prefix + "null_read", mount, "named", False, [POLICY])
        t.req(prefix + "clear_write", "POST", path, {"token_no_default_policy": True, "token_policies": None})
        t.role_read(prefix + "clear_read", mount, "named", True, [])
        empty = t.login(prefix + "clear_login", mount, credentials, [])
        t.renew(prefix + "clear_renew", empty, [])
        t.req(prefix + "empty_self_denied", "POST", "auth/token/renew-self", {}, 403, empty["client_token"])
        t.req(prefix + "restore_write", "POST", path, {"token_policies": [POLICY]})
        t.role_read(prefix + "restore_read", mount, "named", True, [POLICY])
        held["old_default"] = {"auth": old_default}
        all_held[mount] = held
    restart()
    t.check("restarted", True)
    for mount in MOUNTS:
        held = all_held[mount]
        prefix = mount + ".restart."
        old = held["named"]["auth"]
        t.role_read(prefix + "read", mount, "named", True, [POLICY])
        t.lookup(prefix + "old_lookup", old, [POLICY])
        t.lookup(prefix + "old_default_lookup", held["old_default"]["auth"], ["default", POLICY])
        t.lookup(prefix + "batch_lookup", held["batch"]["auth"], [POLICY])
        t.renew(prefix + "empty_renew", held["nil"]["auth"], [])
        t.renew(prefix + "old_self_renew", old, [POLICY], True)
        data = t.req(prefix + "kv_read", "GET", "ndkv/data/" + mount, expected=200, token=old["client_token"])
        t.check(prefix + "kv_read.shape", data.get("data", {}).get("data", {}).get("value") == "fixture-" + mount)
        t.login(prefix + "fresh_login", mount, held["named"]["credentials"], [POLICY])
        t.req(prefix + "revoke_old", "POST", "auth/token/revoke", {"token": old["client_token"]})
        t.req(prefix + "revoked_denied", "GET", "ndkv/data/" + mount, expected=403, token=old["client_token"])
    t.check("complete", True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "manifest", "binary", "private-work-root", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("source-commit", "source-tree", "manifest-sha256", "binary-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--official-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    need(sys.platform == "linux", "linux_process_owner_required")
    need(len(REQUIRED) == EXPECTED_ROWS, "required_case_count")
    for path in (args.source_root, args.manifest, args.binary, args.private_work_root, args.output):
        need(path.is_absolute() and not path.is_symlink(), "absolute_unlinked_path")
    need(args.output.parent == args.private_work_root and not os.path.lexists(args.output), "output_scope")
    need((args.source_root / "qa/openbao-acceptance/approle_no_default_271_live.py").resolve(strict=True)
         == Path(__file__).resolve(strict=True), "harness_source_binding")
    for value, length in ((args.source_commit, 40), (args.source_tree, 40),
                          (args.manifest_sha256, 64), (args.binary_sha256, 64)):
        need(re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None, "input_digest_shape")
    args.private_work_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    sys.path.insert(0, str(args.source_root / "qa/openbao-acceptance"))
    sys.path.insert(0, str(args.source_root / "qa/single-node"))
    sys.path.insert(0, str(args.source_root / "clients/python"))
    import owned_process as O
    import smoke as S
    import official_openbao_launcher as F
    from bao_http import private_read, private_write
    V = load_module("_approle135_tree_verify", args.source_root / "qa/openbao-acceptance/native_candidate_host_run.py")
    owner = O.Owner(args.private_work_root, deadline_ns=time.monotonic_ns() + 330_000_000_000,
                    profile="approle_no_default_271")
    report = {
        "schema": "heptabao.openbao271-approle-no-default.v1",
        "source_commit": args.source_commit, "source_tree": args.source_tree,
        "manifest_sha256": args.manifest_sha256, "binary_sha256": args.binary_sha256,
        "official_version": "2.7.1", "candidate_executed": False,
        "candidate_native_fixture": False, "synthetic_only": True,
        "tls_required": True, "tls_verified_endpoints": [], "independent_qualification": False,
        "production_authority": False, "replacement_authority": False,
        "old_heptabao_binary_upgrade_performed": False,
        "expected_rows_per_endpoint": EXPECTED_ROWS, "observations": {}, "failures": {},
    }
    private = []
    try:
        with O.activated(owner):
            manifest_pin = stable_file(args.manifest, 16 * 1024 * 1024, args.manifest_sha256, owner)
            manifest = json.loads(args.manifest.read_text())
            need(manifest.get("commit") == args.source_commit and manifest.get("tree") == args.source_tree,
                 "source_identity")
            source_before = V.verify_tree(args.source_root, manifest)
            binary_before = stable_file(args.binary, 1024 * 1024 * 1024, args.binary_sha256, owner)
            F.verify_inputs(version="2.7.1")
            report["official"] = F.pinned_artifact(version="2.7.1")
            report["harness_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            os.environ["HB_ORACLE_WORK_ROOT"] = str(args.private_work_root)

            class Native(S.Instance):
                def start(self):
                    self.log = open(self.root / "server.log", "ab")
                    self.process = O.popen(
                        [str(self.binary), "--fixture-native-v6-service", "--config", str(self.root / "server.json")],
                        stdout=self.log, stderr=self.log, close_fds=True,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                        label="approle135.native", action="KILL", stop_timeout=5)
                    end = min(time.monotonic() + 10, time.monotonic() + owner.remaining())
                    while time.monotonic() < end:
                        need(self.process.poll() is None, "candidate_early_exit")
                        try:
                            if self.call("GET", "sys/health", token="")[0] in (200, 501, 503):
                                return
                        except Exception:
                            pass
                        time.sleep(0.05)
                    raise Failure("candidate_start_timeout")

            for label in (("official",) if args.official_only else ("official", "candidate")):
                oracle = instance = None
                rows = []
                report["observations"][label] = rows
                try:
                    if label == "official":
                        oracle = F.start_oracle(S.free_loopback_port(), version="2.7.1")
                        token = private_read(Path(oracle["token_file"])).decode().strip()
                        private.extend((token, private_read(Path(oracle["root"]) / "unseal.key").decode().strip()))
                        api = Api(oracle["address"], oracle["ca_file"], token, owner)
                        health_status, health = api.call("GET", "sys/health")
                        need(health_status == 200, "official_health")
                        F.verify_selected_oracle(oracle, health, version="2.7.1")
                        report["tls_verified_endpoints"].append(label)
                        def restart():
                            F.stop_oracle(oracle)
                            F.restart_oracle(oracle)
                    else:
                        instance = Native(args.binary, args.private_work_root / "candidate")
                        instance.start()
                        report["candidate_executed"] = True
                        report["candidate_native_fixture"] = True
                        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
                        need(status == 200, "candidate_init")
                        token, key = initialized["root_token"], initialized["keys_base64"][0]
                        private.extend((token, key))
                        instance.token = token
                        need(instance.call("POST", "sys/unseal", {"key": key})[0] == 200, "candidate_unseal")
                        api = Api(instance.address, instance.root / "ca.crt", token, owner)
                        health_status, health = api.call("GET", "sys/health")
                        need(health_status == 200 and health.get("initialized") is True
                             and health.get("sealed") is False, "candidate_health")
                        report["tls_verified_endpoints"].append(label)
                        def restart():
                            instance.stop()
                            instance.start()
                            need(instance.call("POST", "sys/unseal", {"key": key})[0] == 200,
                                 "candidate_restart_unseal")
                    scenario(api, restart, rows, private)
                except BaseException as error:
                    report["failures"][label] = str(error) if isinstance(error, Failure) else type(error).__name__
                finally:
                    cleanup = []
                    if instance is not None:
                        cleanup.append(instance.stop)
                    if oracle is not None:
                        cleanup.append(lambda: F.stop_oracle(oracle))
                    O.close_all(cleanup)
            source_after = V.verify_tree(args.source_root, manifest)
            report["source_and_binary_unchanged"] = (
                source_before["commit"] == source_after["commit"]
                and source_before["tree"] == source_after["tree"]
                and source_before["verified_files"] == source_after["verified_files"]
                and manifest_pin == stable_file(args.manifest, 16 * 1024 * 1024, args.manifest_sha256, owner)
                and binary_before == stable_file(args.binary, 1024 * 1024 * 1024, args.binary_sha256, owner))
    except BaseException as error:
        report["failures"]["controller"] = str(error) if isinstance(error, Failure) else type(error).__name__
    report["process"] = getattr(owner, "receipt", {"passed_process_method": False})
    observations = report["observations"]
    labels = ("official",) if args.official_only else ("official", "candidate")
    complete = set(observations) == set(labels) and all(
        len(observations[label]) == EXPECTED_ROWS
        and {row["case"] for row in observations[label]} == REQUIRED
        and all(row["passed"] is True for row in observations[label])
        for label in labels)
    report["mismatches"] = []
    if not args.official_only and set(observations) == set(labels):
        left = {row["case"]: row for row in observations["official"]}
        right = {row["case"]: row for row in observations["candidate"]}
        if set(left) != set(right):
            report["mismatches"].append("case_sets")
        report["mismatches"].extend(case for case in sorted(set(left) & set(right))
            if left[case].get("status") != right[case].get("status")
            or left[case]["passed"] != right[case]["passed"])
    report["tls_verified"] = report["tls_verified_endpoints"] == list(labels)
    report["status"] = "passed" if (complete and report["tls_verified"] is True
        and not report["failures"] and not report["mismatches"]
        and report.get("source_and_binary_unchanged") is True
        and report["process"].get("passed_process_method") is True) else "failed"
    encoded = json.dumps(report, sort_keys=True)
    need(not any(value and len(value) >= 16 and value in encoded for value in private), "private_value_in_public_report")
    private_write(args.output, report, replace=False)
    print(json.dumps({"status": report["status"], "candidate_executed": report["candidate_executed"],
        "counts": {label: len(rows) for label, rows in observations.items()},
        "failures": report["failures"], "mismatches": report["mismatches"],
        "passed_process_method": report["process"].get("passed_process_method")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
