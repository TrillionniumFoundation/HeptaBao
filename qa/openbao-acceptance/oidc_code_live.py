#!/usr/bin/env python3
"""HeptaBao code flow against the checksum-pinned official OpenBao OIDC issuer.

Actual non-dev TLS servers, actual issuer login, code grant, S256 PKCE, Basic
client authentication and signed ID-token validation. No browser UI automation,
external identity provider, refresh-token or independent product qualification.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance
from bao_http import Client, private_write
from heptabao.transport import SafeArgumentParser
from online_evidence import admit_output, source_identity, publish
from official_openbao_launcher import start_oracle, stop_oracle


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        return sock.getsockname()[1]


def run(binary: Path, root: Path, checks: list[dict]):
    oracle=None; instance=None
    def check(name, condition):
        checks.append({"case":name,"passed":condition is True})
        if condition is not True:
            raise RuntimeError(name)
    try:
        port=free_port(); oracle=start_oracle(port)
        issuer_admin=Client(oracle["address"],Path(oracle["ca_file"]),Path(oracle["token_file"]).read_text().strip())
        def upstream(method,path,payload=None,token=None):
            return issuer_admin.request(method,"/v1/"+path,payload,token=token)
        password=secrets.token_urlsafe(32)
        check("issuer_userpass_mount",upstream("POST","sys/auth/test-users",{"type":"userpass"}).status == 204)
        check("issuer_enduser_enrolled",upstream("POST","auth/test-users/users/browser-user",{"password":password,"token_policies":["default"]}).status == 204)
        logged=upstream("POST","auth/test-users/login/browser-user",{"password":password})
        check("issuer_real_enduser_login",logged.status == 200 and bool(logged.body.get("auth",{}).get("entity_id")))
        enduser=logged.body["auth"]["client_token"]
        redirect=f"http://127.0.0.1:{free_port()}/oidc/callback"
        # Use a configured real confidential client; never accept a constant
        # synthetic ID-token assertion or signature bypass as an issuer.
        check("issuer_oidc_key",upstream("POST","identity/oidc/key/hepta-key",{"algorithm":"RS256","allowed_client_ids":["*"]}).status == 204)
        check("issuer_confidential_client",upstream("POST","identity/oidc/client/hepta-client",{
            "client_type":"confidential","key":"hepta-key","redirect_uris":[redirect],
            "assignments":["allow_all"],"id_token_ttl":300,"access_token_ttl":300}).status == 204)
        result=upstream("GET","identity/oidc/client/hepta-client")
        check("issuer_client_credentials",result.status == 200 and bool(result.body.get("data",{}).get("client_id")))
        client_id=result.body["data"]["client_id"];client_secret=result.body["data"]["client_secret"]
        check("issuer_provider",upstream("POST","identity/oidc/provider/hepta",{"allowed_client_ids":[client_id]}).status == 204)
        issuer=oracle["address"]+"/v1/identity/oidc/provider/hepta"
        instance=Instance(binary,root/"candidate")
        config_path=instance.root/"server.json";config=json.loads(config_path.read_text())
        config["outbound_endpoints"]=[{"origin":oracle["address"],"address":f"127.0.0.1:{port}",
            "server_name":"127.0.0.1","ca_pem":Path(oracle["ca_file"]).read_text()}]
        config_path.write_text(json.dumps(config));config_path.chmod(0o600)
        instance.start()
        status,initial=instance.call("POST","sys/init",{"secret_shares":1,"secret_threshold":1})
        check("candidate_initialize",status == 200);unseal=initial["keys_base64"][0];instance.token=initial["root_token"]
        check("candidate_unseal",instance.call("POST","sys/unseal",{"key":unseal})[0] == 200)
        mount="browser/external"
        check("candidate_oidc_mount",instance.call("POST",f"sys/auth/{mount}",{"type":"oidc"})[0] == 204)
        params={"oidc_discovery_url":issuer,"oidc_client_id":client_id,"oidc_client_secret":client_secret,"jwt_supported_algs":["RS256"]}
        # OpenBao 2.6.2 supports S256 but does not advertise its metadata
        # property. Without explicit operator enrollment, absence must deny.
        check("missing_pkce_discovery_does_not_enable_implicit_fallback",instance.call("POST",f"auth/{mount}/config",params)[0] == 400)
        params["pkce_s256_enrolled"]=True
        check("candidate_explicit_s256_enrollment",instance.call("POST",f"auth/{mount}/config",params)[0] == 204)
        role={"role_type":"oidc","user_claim":"sub","allowed_redirect_uris":[redirect],"token_policies":["default"],"token_ttl":300}
        check("candidate_role",instance.call("POST",f"auth/{mount}/role/app",role)[0] == 204)
        status,config_read=instance.call("GET",f"auth/{mount}/config")
        check("client_secret_readback_redacted",status == 200 and client_secret not in json.dumps(config_read))
        check("client_rebinding_requires_new_mount",instance.call("POST",f"auth/{mount}/config",{**params,"oidc_client_id":"different-client"})[0] == 409)
        for label,body in [("missing_client_proof",{"role":"app","redirect_uri":redirect}),
            ("unregistered_redirect",{"role":"app","redirect_uri":"http://127.0.0.1:1/oidc/callback","client_nonce":secrets.token_urlsafe(32)}),
            ("unknown_role",{"role":"other","redirect_uri":redirect,"client_nonce":secrets.token_urlsafe(32)})]:
            status,result=instance.call("POST",f"auth/{mount}/oidc/auth_url",body,token="")
            check(label,status >= 400 and "auth_url" not in result.get("data",{}))
        def begin(label):
            proof=secrets.token_urlsafe(32)
            status,result=instance.call("POST",f"auth/{mount}/oidc/auth_url",{"role":"app","redirect_uri":redirect,"client_nonce":proof},token="")
            check(label+"_session_published",status == 200)
            auth_url=result["data"]["auth_url"]
            parsed=urllib.parse.urlsplit(auth_url)
            values=urllib.parse.parse_qs(parsed.query,strict_parsing=True)
            check(label+"_fixed_s256_and_client",values.get("code_challenge_method") == ["S256"] and values.get("client_id") == [client_id]
                and values.get("redirect_uri") == [redirect] and values.get("response_type") == ["code"])
            check(label+"_no_client_proof_or_secret_in_url",proof not in auth_url and client_secret not in auth_url)
            return {k:v[0] for k,v in values.items()},proof
        def authorize(values,label):
            result=upstream("POST","identity/oidc/provider/hepta/authorize",values,token=enduser)
            check(label+"_real_issuer_code",result.status == 200 and isinstance(result.body.get("code"),str))
            return result.body["code"]
        def callback(values,proof,code):
            return instance.call("POST",f"auth/{mount}/oidc/callback",{"state":values["state"],"client_nonce":proof,"code":code},token="")
        values,proof=begin("first");code=authorize(values,"first")
        check("wrong_client_proof_does_not_consume",callback(values,secrets.token_urlsafe(32),code)[0] == 403)
        status,result=callback(values,proof,code)
        check("real_code_exchange_to_signed_id_token_to_candidate_login",status == 200 and bool(result.get("auth",{}).get("entity_id")))
        auth=result["auth"];entity=auth["entity_id"];token=auth["client_token"]
        check("no_root_or_unbounded_renewal", "root" not in auth["policies"] and auth["renewable"] is False and 0 < auth["lease_duration"] <= 300)
        check("new_token_enters_actual_service",instance.call("GET","auth/token/lookup-self",token=token)[0] == 200)
        check("one_use_session_denies_callback_replay",callback(values,proof,code)[0] == 403)
        check("online_identity_has_no_administrative_authority",instance.call("POST",f"auth/{mount}/config",params,token=token)[0] == 403)
        # IdP authentication performed against a changed challenge must fail at
        # the real token endpoint. The client MUST NOT retry after that effect.
        wrong,wrong_proof=begin("wrong_pkce");changed=dict(wrong);changed["code_challenge"]=secrets.token_urlsafe(32)
        wrong_code=authorize(changed,"wrong_pkce")
        status,result=callback(wrong,wrong_proof,wrong_code)
        check("issuer_rejects_wrong_s256_verifier",status >= 400 and "auth" not in result)
        check("failed_exchange_session_not_restored",callback(wrong,wrong_proof,wrong_code)[0] == 403)
        bad_nonce,nonce_proof=begin("wrong_nonce");changed=dict(bad_nonce);changed["nonce"]=secrets.token_urlsafe(32)
        nonce_code=authorize(changed,"wrong_nonce")
        status,result=callback(bad_nonce,nonce_proof,nonce_code)
        check("signature_valid_wrong_nonce_never_issues_token",status == 403 and "auth" not in result)
        check("nonce_failure_is_terminal",callback(bad_nonce,nonce_proof,nonce_code)[0] == 403)
        pending,pending_proof=begin("pending_restart");pending_code=authorize(pending,"pending_restart")
        instance.stop();instance.start()
        check("restart_stays_sealed",instance.call("GET","sys/seal-status")[1]["sealed"] is True)
        check("restart_unseal",instance.call("POST","sys/unseal",{"key":unseal})[0] == 200)
        check("consumed_session_stays_consumed_after_restart",callback(values,proof,code)[0] == 403)
        check("failed_exchange_stays_consumed_after_restart",callback(wrong,wrong_proof,wrong_code)[0] == 403)
        status,result=callback(pending,pending_proof,pending_code)
        check("pending_session_verifier_and_proof_survive_restart",status == 200 and result.get("auth",{}).get("entity_id") == entity)
        check("issuer_subject_reuses_live_identity",result["auth"]["entity_id"] == entity)
        check("existing_token_survives_restart",instance.call("GET","auth/token/lookup-self",token=token)[0] == 200)
        # Drive the actual native client executable through its browser callback
        # receiver. The IdP authorization API supplies the browser redirect query;
        # no browser rendering or consent interaction is claimed by this fixture.
        private=root/"native-client";private.mkdir(mode=0o700)
        native_output=private/"login.json"
        command=[sys.executable,"-m","heptabao.oidc_login","--address",instance.address,
            "--ca-file",str(instance.root/"ca.crt"),"--issuer-origin",oracle["address"],
            "--mount",mount,"--role","app","--listen-port",str(urllib.parse.urlsplit(redirect).port),
            "--callback-timeout","30","--output",str(native_output),"--allow-write","--display-auth-url"]
        environment=dict(os.environ);environment["PYTHONPATH"]=str(ROOT/"clients/python")
        process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment)
        try:
            check("native_client_publishes_authorization_url",bool(select.select([process.stdout],[],[],15)[0]))
            native_url=process.stdout.readline().decode().strip()
            native_values={k:v[0] for k,v in urllib.parse.parse_qs(urllib.parse.urlsplit(native_url).query,strict_parsing=True).items()}
            check("native_client_reserves_private_output_before_login",native_output.is_file() and native_output.stat().st_size == 0 and native_output.stat().st_mode & 0o777 == 0o600)
            native_code=authorize(native_values,"native_client")
            callback_query=urllib.parse.urlencode({"state":native_values["state"],"code":native_code})
            callback_port=urllib.parse.urlsplit(redirect).port
            with socket.create_connection(("127.0.0.1",callback_port),timeout=3) as connection:
                connection.sendall(f"GET /oidc/callback?{callback_query} HTTP/1.1\r\nHost: 127.0.0.1:{callback_port}\r\n\r\n".encode())
                reply=connection.recv(4096)
            stdout,stderr=process.communicate(timeout=20)
            check("native_client_real_callback_and_exchange",reply.startswith(b"HTTP/1.1 200") and process.returncode == 0)
            native_auth=json.loads(native_output.read_text())["auth"]
            check("native_client_receives_bound_identity",native_auth["entity_id"] == entity)
            check("native_client_never_prints_bearer_or_client_secret",native_auth["client_token"].encode() not in stdout+stderr and client_secret.encode() not in stdout+stderr)
            check("native_client_token_is_usable",instance.call("GET","auth/token/lookup-self",token=native_auth["client_token"])[0] == 200)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            if process.stdout:process.stdout.close()
            if process.stderr:process.stderr.close()
        check("disable_entity",instance.call("POST","identity/entity/id/"+entity,{"disabled":True})[0] == 204)
        disabled,disabled_proof=begin("disabled_identity");disabled_code=authorize(disabled,"disabled_identity")
        status,result=callback(disabled,disabled_proof,disabled_code)
        check("disabled_identity_denies_fresh_valid_code",status == 403 and "auth" not in result and result.get("retry_allowed") is False and result.get("oidc_session_consumed") is True)
        check("disabled_identity_denies_existing_token",instance.call("GET","auth/token/lookup-self",token=token)[0] == 403)
        check("enable_entity",instance.call("POST","identity/entity/id/"+entity,{"disabled":False})[0] == 204)
        invalidated,invalidated_proof=begin("role_update");invalidated_code=authorize(invalidated,"role_update")
        check("role_update",instance.call("POST",f"auth/{mount}/role/app",{**role,"token_num_uses":1})[0] == 204)
        check("role_update_invalidates_old_session",callback(invalidated,invalidated_proof,invalidated_code)[0] == 403)
        finite,finite_proof=begin("finite");finite_code=authorize(finite,"finite")
        status,result=callback(finite,finite_proof,finite_code)
        check("finite_token_issued",status == 200);finite_token=result["auth"]["client_token"]
        check("finite_first_use",instance.call("GET","auth/token/lookup-self",token=finite_token)[0] == 200)
        check("finite_second_use_denied",instance.call("GET","auth/token/lookup-self",token=finite_token)[0] == 403)
        check("disable_mount",instance.call("DELETE",f"sys/auth/{mount}")[0] == 204)
        check("disable_mount_revokes_issued_tokens",instance.call("GET","auth/token/lookup-self",token=token)[0] == 403)
        paths=list((instance.root/"data").rglob("*"))+[instance.root/"server.log",instance.root/"audit.jsonl"]
        forbidden=[client_secret.encode(),pending_proof.encode(),proof.encode(),code.encode(),token.encode(),finite_token.encode()]
        check("no_cleartext_oidc_credentials_in_candidate_persistence_and_logs",all(not any(secret in p.read_bytes() for secret in forbidden) for p in paths if p.is_file()))
    finally:
        if instance: instance.stop()
        if oracle:
            stop_oracle(oracle);shutil.rmtree(oracle["root"])


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
    report={"schema":"heptabao.official-oidc-code.v1","checks":checks,"failure":failure,
        "actual_kube_apiserver":False,"browser_ui_automation":False}
    observed=any(c["case"]=="issuer_real_enduser_login" and c["passed"] is True for c in checks)
    report["actual_official_issuer"]=observed
    if observed:
        from official_openbao_launcher import VERSION, ARTIFACT_SHA256, BINARY_SHA256
        report["official_input"]={"version":VERSION,"archive_sha256":ARTIFACT_SHA256,"binary_sha256":BINARY_SHA256}
    publish(output,parent,report,before,source_identity(ROOT,binary),82)
    print(json.dumps({"status":report["status"],"checks":len(checks),"failure":report["failure"]}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())
