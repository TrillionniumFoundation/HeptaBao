#!/usr/bin/env python3
"""Real same-host HA: durable OIDC code state and online TokenReview forwarding.

Official pinned OpenBao is the OIDC issuer. TokenReview is a controlled TLS
protocol fixture, NOT a kube-apiserver. Three processes are not physical hosts.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from bao_http import Client, private_write
from heptabao.transport import SafeArgumentParser
from online_evidence import admit_output, source_identity, publish
from official_openbao_launcher import start_oracle, stop_oracle
from ha_destructive import Cluster, free_port
from kubernetes_online import Reviewer
ROOT=Path(__file__).resolve().parents[2]


def callback_targets(nodes, leader):
    """Exercise Service serialization without saturating the one forward slot.

    A pair of fixed node indices can both be followers after an election. That
    tests deliberate forwarding backpressure (503), not callback single-use.
    Never relax the actual callback expectation of one 200 and one 403.
    """
    ids=[node.node_id for node in nodes]
    if len(nodes)!=3 or any(type(value) is not int or value<=0 for value in ids) or len(set(ids))!=3 or not any(node is leader for node in nodes):
        raise ValueError("invalid_callback_topology")
    return [leader,next(node for node in nodes if node is not leader)]


def run(binary, root, checks, inherited, observations):
    oracle=None;cluster=None;reviewer=None
    def check(name, condition):
        checks.append({"case":name,"passed":condition is True})
        if condition is not True:raise RuntimeError(name)
    try:
        port=free_port();oracle=start_oracle(port)
        client=Client(oracle["address"],Path(oracle["ca_file"]),Path(oracle["token_file"]).read_text().strip())
        def upstream(method,path,body=None,token=None):return client.request(method,"/v1/"+path,body,token=token)
        password=secrets.token_urlsafe(32)
        check("issuer_auth_mount",upstream("POST","sys/auth/test-users",{"type":"userpass"}).status == 204)
        check("issuer_user",upstream("POST","auth/test-users/users/operator",{"password":password}).status == 204)
        logged=upstream("POST","auth/test-users/login/operator",{"password":password})
        check("issuer_login",logged.status == 200);user=logged.body["auth"]["client_token"]
        redirect=f"http://127.0.0.1:{free_port()}/oidc/callback"
        check("issuer_key",upstream("POST","identity/oidc/key/ha",{"algorithm":"RS256","allowed_client_ids":["*"]}).status == 204)
        check("issuer_client",upstream("POST","identity/oidc/client/ha",{"key":"ha","redirect_uris":[redirect],"assignments":["allow_all"],"id_token_ttl":300,"access_token_ttl":300}).status == 204)
        configured=upstream("GET","identity/oidc/client/ha").body["data"]
        check("issuer_provider",upstream("POST","identity/oidc/provider/ha",{"allowed_client_ids":[configured["client_id"]]}).status == 204)
        issuer=oracle["address"]+"/v1/identity/oidc/provider/ha"
        cluster=Cluster(binary,root/"cluster")
        reviewer=Reviewer(cluster.nodes[0].root/"tls.crt",cluster.nodes[0].root/"tls.key")
        endpoints=[]  # Both auth methods use their explicit API CA snapshots.
        for node in cluster.nodes:
            path=node.root/"server.json";config=json.loads(path.read_text());config["outbound_endpoints"]=endpoints
            path.write_text(json.dumps(config));path.chmod(0o600)
        cluster.run();inherited.extend(cluster.scenarios)
        leader=cluster.leader();follower=next(n for n in cluster.nodes if n is not leader)
        def admin(method,path,body=None):return follower.call(method,path,body,token=cluster.root_token)
        check("oidc_mount_via_follower",admin("POST","sys/auth/browser",{"type":"oidc"})[0] == 204)
        check("oidc_config_via_follower",admin("POST","auth/browser/config",{
            "oidc_discovery_url":issuer,"oidc_discovery_ca_pem":Path(oracle["ca_file"]).read_text(),"oidc_client_id":configured["client_id"],"oidc_client_secret":configured["client_secret"],"pkce_s256_enrolled":True})[0] == 204)
        check("oidc_role_via_follower",admin("POST","auth/browser/role/app",{"allowed_redirect_uris":[redirect],"token_policies":["default"]})[0] == 204)
        check("kubernetes_mount_via_follower",admin("POST","sys/auth/workload",{"type":"kubernetes"})[0] == 204)
        check("kubernetes_config_via_follower",admin("POST","auth/workload/config",{"kubernetes_host":reviewer.origin,"kubernetes_ca_cert":(cluster.root/"ca.crt").read_text(),"token_reviewer_jwt":reviewer.reviewer})[0] == 204)
        check("kubernetes_role_via_follower",admin("POST","auth/workload/role/app",{
            "bound_service_account_names":["worker"],"bound_service_account_namespaces":["workload"],"audience":reviewer.audience})[0] == 204)
        def code_flow(node,label):
            proof=secrets.token_urlsafe(32)
            status,result=node.call("POST","auth/browser/oidc/auth_url",{"role":"app","redirect_uri":redirect,"client_nonce":proof})
            check(label+"_session",status == 200)
            values={k:v[0] for k,v in urllib.parse.parse_qs(urllib.parse.urlsplit(result["data"]["auth_url"]).query,strict_parsing=True).items()}
            granted=upstream("POST","identity/oidc/provider/ha/authorize",values,token=user)
            check(label+"_issuer_code",granted.status == 200 and bool(granted.body.get("code")))
            return {"state":values["state"],"client_nonce":proof,"code":granted.body["code"]}
        callback=code_flow(follower,"pre_failover")
        old=leader;old.stop();leader=cluster.leader()
        check("leader_killed_after_session_commit_before_code_exchange",leader is not old)
        follower=next(n for n in cluster.running() if n is not leader)
        status,result=follower.call("POST","auth/browser/oidc/callback",callback)
        check("successor_consumes_replicated_pkce_session",status == 200 and bool(result.get("auth",{}).get("entity_id")))
        token=result["auth"]["client_token"];entity=result["auth"]["entity_id"]
        for n in cluster.running():
            check(f"callback_replay_denied_node_{n.node_id}",n.call("POST","auth/browser/oidc/callback",callback)[0] == 403)
        count=reviewer.count
        status,result=follower.call("POST","auth/workload/login",{"role":"app","jwt":reviewer.presented})
        check("follower_tokenreview_executes_once_on_leader",status == 200 and reviewer.count == count+1 and reviewer.request_valid)
        workload_token=result["auth"]["client_token"]
        second=leader;second.stop();time.sleep(2)
        count=reviewer.count
        check("no_quorum_no_external_tokenreview",follower.call("POST","auth/workload/login",{"role":"app","jwt":reviewer.presented})[0] == 503 and reviewer.count == count)
        check("no_quorum_cannot_publish_oidc_session",follower.call("POST","auth/browser/oidc/auth_url",{"role":"app","redirect_uri":redirect,"client_nonce":secrets.token_urlsafe(32)})[0] == 503)
        check("no_quorum_cannot_accept_local_token",follower.call("GET","auth/token/lookup-self",token=token)[0] == 503)
        cluster.restart(old);leader=cluster.leader();follower=next(n for n in cluster.running() if n is not leader)
        check("spent_session_survives_second_leader_loss",follower.call("POST","auth/browser/oidc/callback",callback)[0] == 403)
        status,result=follower.call("GET","auth/token/lookup-self",token=token)
        check("published_identity_token_survives_second_leader_loss",status == 200 and result.get("data",{}).get("entity_id") == entity)
        check("published_kubernetes_token_survives_second_leader_loss",follower.call("GET","auth/token/lookup-self",token=workload_token)[0] == 200)
        cluster.restart(second);leader=cluster.leader();follower=next(n for n in cluster.running() if n is not leader)
        concurrent=code_flow(follower,"concurrent")
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs=[pool.submit(n.call,"POST","auth/browser/oidc/callback",concurrent) for n in callback_targets(cluster.nodes,leader)]
            results=[job.result(timeout=15) for job in jobs]
        statuses=sorted(status for status,_ in results)
        returned_tokens=sum(bool(body.get("auth",{}).get("client_token")) for _,body in results)
        observations["callback_statuses"]=statuses
        observations["returned_token_count"]=returned_tokens
        observations["targets_include_current_leader"]=True
        check("concurrent_cross_node_callback_releases_exactly_one_token",statuses == [200,403] and returned_tokens == 1 and all("auth" not in body for status,body in results if status!=200))
        check("disable_oidc_mount",admin("DELETE","sys/auth/browser")[0] == 204)
        check("disable_kubernetes_mount",admin("DELETE","sys/auth/workload")[0] == 204)
        for n in cluster.nodes:
            check(f"mount_revocations_apply_node_{n.node_id}",n.call("GET","auth/token/lookup-self",token=token)[0] == 403 and n.call("GET","auth/token/lookup-self",token=workload_token)[0] == 403)
        private_values=[configured["client_secret"].encode(),reviewer.reviewer.encode(),reviewer.presented.encode(),callback["client_nonce"].encode(),callback["code"].encode(),token.encode(),workload_token.encode()]
        files=[]
        for n in cluster.nodes:files += [p for folder in [n.data_dir,n.root/"raft"] for p in folder.rglob("*") if p.is_file()]+[n.root/"audit.jsonl",n.root/"process.log"]
        check("replicated_auth_state_and_logs_are_not_plaintext",all(not any(v in p.read_bytes() for v in private_values) for p in files if p.is_file()))
    finally:
        if cluster:cluster.close()
        if reviewer:reviewer.close()
        if oracle:stop_oracle(oracle);shutil.rmtree(oracle["root"])


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
    checks=[];failure=None;inherited=[];observations={}
    root=Path(tempfile.mkdtemp(prefix="hb-online-"));root.chmod(0o700)
    try:
        run(binary,root,checks,inherited,observations)
    except Exception as error:
        # Fixed case or exception class only: never exception text, callback
        # URL, provider response, credential or authorization-code bytes.
        failure=next((c["case"] for c in reversed(checks) if not c["passed"]),"fixture_"+type(error).__name__)
    finally:
        shutil.rmtree(root)
    report={"schema":"heptabao.online-auth-ha.v1","checks":checks,"failure":failure,
        "actual_kube_apiserver":False,"browser_ui_automation":False}
    observed=any(c["case"]=="issuer_login" and c["passed"] is True for c in checks)
    report["actual_official_issuer"]=observed
    if observed:
        from official_openbao_launcher import VERSION, ARTIFACT_SHA256, BINARY_SHA256
        report["official_input"]={"version":VERSION,"archive_sha256":ARTIFACT_SHA256,"binary_sha256":BINARY_SHA256}
    report["same_host"]=True
    report["concurrency_observations"]=observations
    report["base_ha_scenarios"]=inherited
    # Base HA may gain additional checks. Require its actual fault/recovery
    # milestones instead of rejecting successful runs for a stale case count.
    required_base={"new_leader_after_sigkill","quorum_loss_write_denied",
        "all_three_rejoined_after_quorum_recovery"}
    if not required_base.issubset(inherited) or len(set(inherited))!=len(inherited):
        report["failure"]=report["failure"] or "incomplete_base_ha"
    publish(output,parent,report,before,source_identity(ROOT,binary),34)
    print(json.dumps({"status":report["status"],"checks":len(checks),"failure":report["failure"]}))
    return 0 if report["status"]=="passed" else 1
if __name__=="__main__":raise SystemExit(main())
