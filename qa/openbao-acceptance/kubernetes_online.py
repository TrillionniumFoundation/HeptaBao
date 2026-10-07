#!/usr/bin/env python3
"""Actual HeptaBao -> pinned TLS TokenReview protocol fixture.

This is NOT a real kube-apiserver/etcd/RBAC or Kubernetes distribution acceptance.
The controlled reviewer verifies the request and emits hostile or valid protocol
responses. All credentials are synthetic and secret-bearing roots are removed.
"""
from __future__ import annotations
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance
from bao_http import private_write
from heptabao.transport import SafeArgumentParser
from online_evidence import admit_output, source_identity, publish

REVIEW_PATH = "/apis/authentication.k8s.io/v1/tokenreviews"


class Reviewer:
    """Fixture credentials never enter request diagnostics or persistent logs."""
    def __init__(self, cert: Path, key: Path):
        self.reviewer = secrets.token_urlsafe(32)
        self.presented = secrets.token_urlsafe(32)
        self.mode = "ok"
        self.count = 0
        self.request_valid = True
        self.uid = "test-uid-111"
        self.audience = "heptabao-online"
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                owner.count += 1
                try:
                    lengths = self.headers.get_all("Content-Length", [])
                    n = int(lengths[0]) if len(lengths) == 1 else -1
                    if not 0 < n <= 65536:
                        raise ValueError("bounds")
                    request = json.loads(self.rfile.read(n))
                    expected = {"apiVersion":"authentication.k8s.io/v1", "kind":"TokenReview",
                                "spec":{"token":owner.presented,"audiences":[owner.audience]}}
                    valid = (self.path == REVIEW_PATH and request == expected
                             and self.headers.get_all("Authorization") == ["Bearer " + owner.reviewer]
                             and self.headers.get("Content-Type") == "application/json")
                    owner.request_valid &= valid
                    if not valid:
                        self.send_error(403)
                        return
                    if owner.mode == "redirect":
                        self.send_response(302)
                        self.send_header("Location", "https://untrusted.invalid:443/")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    if owner.mode == "drop":
                        self.connection.close()
                        return
                    response = {"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
                        "status":{"authenticated":True,"audiences":[owner.audience],
                        "user":{"username":"system:serviceaccount:workload:worker", "uid":owner.uid,
                                "groups":["system:masters"]}}}
                    status = response["status"]
                    if owner.mode == "revoked": status["authenticated"] = False
                    if owner.mode == "bool_string": status["authenticated"] = "true"
                    if owner.mode == "wrong_audience": status["audiences"] = ["kubernetes-default"]
                    if owner.mode == "no_audience": status.pop("audiences")
                    if owner.mode == "no_uid": status["user"].pop("uid")
                    if owner.mode == "wrong_namespace": status["user"]["username"] = "system:serviceaccount:foreign:worker"
                    if owner.mode == "wrong_name": status["user"]["username"] = "system:serviceaccount:workload:other"
                    if owner.mode == "non_sa": status["user"]["username"] = "administrator"
                    if owner.mode == "wrong_version": response["apiVersion"] = "authentication.k8s.io/v1beta1"
                    if owner.mode == "error": status["error"] = "synthetic rejection"
                    raw = json.dumps(response).encode()
                    if owner.mode == "duplicate": raw = b'{"kind":"TokenReview","kind":"TokenReview"}'
                    if owner.mode == "oversized": raw = b'{"padding":"' + b'x' * (129 * 1024) + b'"}'
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (ValueError, OSError, ssl.SSLError):
                    self.close_connection = True
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.origin = f"https://localhost:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("reviewer_join_failed")


# Named safety milestones permit additional observations without accepting skipped phases.
REQUIRED_CASES = frozenset({
    'initialize',
    'unseal',
    'nested_mount',
    'config_before_egress',
    'role',
    'reviewer_redacted_in_readback',
    'request_cannot_enable_tls_bypass',
    'request_cannot_use_ambient_credentials',
    'pre_egress_reject_role',
    'pre_egress_reject_extra',
    'pre_egress_reject_jwt',
    'online_review_to_real_token',
    'reviewer_request_binding',
    'uid_metadata',
    'reviewer_groups_never_become_root_policy',
    'token_reads_own_identity',
    'provider_cannot_grant_root',
    'each_login_requires_new_review',
    'config_requires_authorization',
    'root_policy_assignment_rejected',
    'realm_rebinding_requires_remount',
    'reject_revoked',
    'no_error_credential_echo_revoked',
    'reject_bool_string',
    'no_error_credential_echo_bool_string',
    'reject_wrong_audience',
    'no_error_credential_echo_wrong_audience',
    'reject_no_audience',
    'no_error_credential_echo_no_audience',
    'reject_no_uid',
    'no_error_credential_echo_no_uid',
    'reject_wrong_namespace',
    'no_error_credential_echo_wrong_namespace',
    'reject_wrong_name',
    'no_error_credential_echo_wrong_name',
    'reject_non_sa',
    'no_error_credential_echo_non_sa',
    'reject_wrong_version',
    'no_error_credential_echo_wrong_version',
    'reject_error',
    'no_error_credential_echo_error',
    'reject_redirect',
    'no_error_credential_echo_redirect',
    'reject_duplicate',
    'no_error_credential_echo_duplicate',
    'reject_oversized',
    'no_error_credential_echo_oversized',
    'reject_drop',
    'no_error_credential_echo_drop',
    'issued_token_is_not_continuously_reviewed',
    'disable_entity',
    'disabled_identity_denies_new_login',
    'disabled_identity_denies_existing_token',
    'enable_entity',
    'recreated_serviceaccount_uid_gets_different_identity',
    'finite_role',
    'finite_login',
    'finite_first_read',
    'finite_replay_denied',
    'unmount_revokes_issued_tokens',
    'remount',
    'configure_remount',
    'role_remount',
    'remount_accessor_prevents_old_alias_rebind',
    'sealed_after_sigkill',
    'unseal_after_sigkill',
    'durable_token_after_sigkill',
    'role_config_and_identity_survive_sigkill',
    'all_egress_requests_match_review_contract',
    'no_plaintext_credentials_in_state_or_diagnostics',
    'complete',
})



def run(binary: Path, root: Path, checks: list[dict]):
    instance = Instance(binary, root / "candidate")
    reviewer = Reviewer(instance.root / "tls.crt", instance.root / "tls.key")
    def check(name, condition):
        checks.append({"case":name,"passed":condition is True})
        if condition is not True:
            raise RuntimeError(name)
    config_path = instance.root / "server.json"
    config = json.loads(config_path.read_text())
    config["outbound_endpoints"] = []
    config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
    mount = "platform/kubernetes"
    params = {"kubernetes_host":reviewer.origin,"kubernetes_ca_cert":(instance.root / "ca.crt").read_text(),"token_reviewer_jwt":reviewer.reviewer,"disable_local_ca_jwt":True}
    role = {"bound_service_account_names":["worker"],"bound_service_account_namespaces":["workload"],
            "audience":reviewer.audience,"token_policies":["default"],"token_ttl":300}
    def login(**extra):
        return instance.call("POST",f"auth/{mount}/login",{"role":"worker","jwt":reviewer.presented,**extra},token="")
    try:
        instance.start()
        status, init = instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
        check("initialize",status == 200); unseal = init["keys_base64"][0]; instance.token = init["root_token"]
        check("unseal", instance.call("POST","sys/unseal",{"key":unseal})[0] == 200)
        check("nested_mount", instance.call("POST",f"sys/auth/{mount}",{"type":"kubernetes"})[0] == 204)
        check("config_before_egress", instance.call("POST",f"auth/{mount}/config",params)[0] == 204 and reviewer.count == 0)
        check("role", instance.call("POST",f"auth/{mount}/role/worker",role)[0] == 204)
        status, result = instance.call("GET",f"auth/{mount}/config")
        check("reviewer_redacted_in_readback", status == 200 and reviewer.reviewer not in json.dumps(result))
        check("request_cannot_enable_tls_bypass",instance.call("POST",f"auth/{mount}/config",{**params,"tls_skip_verify":True})[0] == 400)
        check("request_cannot_use_ambient_credentials",instance.call("POST",f"auth/{mount}/config",{**params,"disable_local_ca_jwt":False})[0] == 400)
        for addition in [{"role":"absent"},{"extra":"untrusted"},{"jwt":"short"}]:
            count = reviewer.count
            check("pre_egress_reject_"+next(iter(addition)), login(**addition)[0] >= 400 and reviewer.count == count)
        status, logged = login(); auth=logged.get("auth",{})
        check("online_review_to_real_token",status == 200 and bool(auth.get("entity_id")))
        check("reviewer_request_binding",reviewer.request_valid and reviewer.count == 1)
        old_token = auth["client_token"]; entity = auth["entity_id"]
        check("uid_metadata",auth["metadata"]["service_account_uid"] == reviewer.uid)
        check("reviewer_groups_never_become_root_policy","root" not in auth["policies"])
        check("token_reads_own_identity",instance.call("GET","auth/token/lookup-self",token=old_token)[0] == 200)
        check("provider_cannot_grant_root",instance.call("POST","sys/auth/forbidden",{"type":"userpass"},token=old_token)[0] == 403)
        count=reviewer.count
        status, repeated=login()
        check("each_login_requires_new_review",status == 200 and reviewer.count == count + 1 and repeated["auth"]["entity_id"] == entity)
        check("config_requires_authorization",instance.call("POST",f"auth/{mount}/config",params,token=old_token)[0] == 403)
        check("root_policy_assignment_rejected",instance.call("POST",f"auth/{mount}/role/unsafe",{**role,"token_policies":["root"]})[0] == 400)
        check("realm_rebinding_requires_remount",instance.call("POST",f"auth/{mount}/config",{**params,"kubernetes_host":"https://other.invalid:443"})[0] == 409)
        for mode in ["revoked","bool_string","wrong_audience","no_audience","no_uid","wrong_namespace","wrong_name","non_sa","wrong_version","error","redirect","duplicate","oversized","drop"]:
            reviewer.mode=mode; count=reviewer.count
            status, result=login()
            check("reject_"+mode,status >= 400 and "auth" not in result and reviewer.count == count + 1)
            check("no_error_credential_echo_"+mode,reviewer.presented not in json.dumps(result) and reviewer.reviewer not in json.dumps(result))
        reviewer.mode="revoked"
        check("issued_token_is_not_continuously_reviewed",instance.call("GET","auth/token/lookup-self",token=old_token)[0] == 200)
        reviewer.mode="ok"
        check("disable_entity",instance.call("POST","identity/entity/id/"+entity,{"disabled":True})[0] == 204)
        check("disabled_identity_denies_new_login",login()[0] == 403)
        check("disabled_identity_denies_existing_token",instance.call("GET","auth/token/lookup-self",token=old_token)[0] == 403)
        check("enable_entity",instance.call("POST","identity/entity/id/"+entity,{"disabled":False})[0] == 204)
        reviewer.uid="test-uid-222"
        status, result=login();check("recreated_serviceaccount_uid_gets_different_identity",status == 200 and result["auth"]["entity_id"] != entity)
        reviewer.uid="test-uid-111"
        check("finite_role",instance.call("POST",f"auth/{mount}/role/worker",{**role,"token_num_uses":1})[0] == 204)
        status, result=login();check("finite_login",status == 200)
        finite=result["auth"]["client_token"]
        check("finite_first_read",instance.call("GET","auth/token/lookup-self",token=finite)[0] == 200)
        check("finite_replay_denied",instance.call("GET","auth/token/lookup-self",token=finite)[0] == 403)
        check("unmount_revokes_issued_tokens",instance.call("DELETE",f"sys/auth/{mount}")[0] == 204 and instance.call("GET","auth/token/lookup-self",token=old_token)[0] == 403)
        check("remount",instance.call("POST",f"sys/auth/{mount}",{"type":"kubernetes"})[0] == 204)
        check("configure_remount",instance.call("POST",f"auth/{mount}/config",params)[0] == 204)
        check("role_remount",instance.call("POST",f"auth/{mount}/role/worker",role)[0] == 204)
        status, result=login();check("remount_accessor_prevents_old_alias_rebind",status == 200 and result["auth"]["entity_id"] != entity)
        fresh=result["auth"]["client_token"]; fresh_entity=result["auth"]["entity_id"]
        instance.stop();instance.start()
        check("sealed_after_sigkill",instance.call("GET","sys/seal-status")[1]["sealed"] is True)
        check("unseal_after_sigkill",instance.call("POST","sys/unseal",{"key":unseal})[0] == 200)
        check("durable_token_after_sigkill",instance.call("GET","auth/token/lookup-self",token=fresh)[0] == 200)
        status,result=login();check("role_config_and_identity_survive_sigkill",status == 200 and result["auth"]["entity_id"] == fresh_entity)
        check("all_egress_requests_match_review_contract",reviewer.request_valid)
        sensitive=[reviewer.reviewer.encode(),reviewer.presented.encode(),fresh.encode(),finite.encode()]
        paths=list((instance.root/"data").rglob("*"))+[instance.root/"server.log",instance.root/"audit.jsonl"]
        check("no_plaintext_credentials_in_state_or_diagnostics",all(not any(v in p.read_bytes() for v in sensitive) for p in paths if p.is_file()))
        check("complete", True)
    finally:
        instance.stop();reviewer.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args();output=args.output.absolute()
    try:
        parent=admit_output(output)
        binary=args.binary.resolve(strict=True)
        before=source_identity(ROOT,binary)
    except Exception:
        parser.error("new private output and existing source-bound binary required")
    checks=[];failure=None;inherited=[]
    root=Path(tempfile.mkdtemp(prefix="hb-online-"));root.chmod(0o700)
    try:
        run(binary,root,checks)
    except Exception as error:
        # Fixed case or exception class only: never exception text, callback
        # URL, provider response, credential or authorization-code bytes.
        failure=next((c["case"] for c in reversed(checks) if not c["passed"]),"fixture_"+type(error).__name__)
    finally:
        shutil.rmtree(root)
    report={"schema":"heptabao.kubernetes-tokenreview-protocol.v1","checks":checks,"failure":failure,
        "actual_kube_apiserver":False,"browser_ui_automation":False}
    publish(output,parent,report,before,source_identity(ROOT,binary), required_cases=REQUIRED_CASES)
    print(json.dumps({"status":report["status"],"checks":len(checks),"failure":report["failure"]}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())
