#!/usr/bin/env python3
"""Selected SSH OTP/lease behavior against an exact official OpenBao binary.

Verifies the online API only: no sshd, PAM helper, host account or CA is
configured, and no production credential is read or changed.
"""
from pathlib import Path
from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results=[] if results is None else results
    def call(path,body=None,token=None,method="POST",ttl=None):
        return client.request(method,"/v1/"+path,body,token=token,wrap_ttl=ttl)
    def check(name,response,status=200):
        results.append({"case":name,"status":response.status,"passed":response.status==status})
        if response.status!=status:raise ScenarioFailure(name)
        return response.body
    def truth(name,condition):
        results.append({"case":name,"passed":bool(condition)})
        if not condition:raise ScenarioFailure(name)
    mount="ssh-compare"
    role=mount+"/roles/deploy"
    creds=mount+"/creds/deploy"
    verify=mount+"/verify"
    check("ssh.mount",call("sys/mounts/"+mount,{"type":"ssh","config":{"default_lease_ttl":"60s","max_lease_ttl":"120s"}}),204)
    config=check("ssh.tune_read",call("sys/mounts/"+mount+"/tune",method="GET"))["data"]
    truth("ssh.ttl_policy",config.get("default_lease_ttl")==60 and config.get("max_lease_ttl")==120)
    check("ssh.role",call(role,{"key_type":"otp","default_user":"deploy","allowed_users":"deploy,backup","cidr_list":"127.0.0.0/8","exclude_cidr_list":"127.1.0.0/16"}),204)
    info=check("ssh.role_read",call(role,method="GET"))["data"]
    truth("ssh.role_configuration",info.get("key_type")=="otp" and info.get("default_user")=="deploy" and info.get("port")==22)
    roles=check("ssh.role_list",call(mount+"/roles",method="LIST"))["data"]
    truth("ssh.role_name_listed",roles.get("keys")==["deploy"])
    info=check("ssh.role_lookup",call(mount+"/lookup",{"ip":"127.0.0.1"}))["data"]
    truth("ssh.role_match",info.get("roles")==["deploy"])
    check("ssh.excluded_ip",call(creds,{"ip":"127.1.2.3"}),400)
    check("ssh.outside_ip",call(creds,{"ip":"10.0.0.1"}),400)
    check("ssh.forbidden_user",call(creds,{"ip":"127.0.0.1","username":"root"}),400)
    created=check("ssh.issue",call(creds,{"ip":"127.0.0.1"}))
    otp,lease=created["data"]["key"],created["lease_id"]
    truth("ssh.secret_has_bounded_lease",bool(otp) and lease.startswith(creds+"/") and created.get("lease_duration")==60 and created.get("renewable") is False)
    truth("ssh.target_binding",created["data"].get("ip")=="127.0.0.1" and created["data"].get("username")=="deploy")
    meta=check("ssh.lease_lookup",call("sys/leases/lookup",{"lease_id":lease}))["data"]
    truth("ssh.lease_metadata",meta.get("id")==lease and meta.get("renewable") is False and 0<meta.get("ttl",0)<=60)
    keys=check("ssh.lease_list",call("sys/leases/lookup/"+creds,method="LIST"))["data"]["keys"]
    truth("ssh.lease_list_id",keys==[lease.rsplit("/",1)[-1]])
    result=check("ssh.verify",call(verify,{"otp":otp},""))
    truth("ssh.verify_exact_target",result.get("data")=={"ip":"127.0.0.1","username":"deploy","role_name":"deploy"})
    check("ssh.replay_denied",call(verify,{"otp":otp},""),400)
    check("ssh.lease_retained_after_verification",call("sys/leases/lookup",{"lease_id":lease}))
    created=check("ssh.issue_for_revoke",call(creds,{"ip":"127.0.0.1"}))
    check("ssh.revoke",call("sys/leases/revoke",{"lease_id":created["lease_id"],"sync":True}),204)
    check("ssh.revoked_denied",call(verify,{"otp":created["data"]["key"]},""),400)
    check("ssh.revoked_lease_absent",call("sys/leases/lookup",{"lease_id":created["lease_id"]}),400)
    check("ssh.revoke_idempotent",call("sys/leases/revoke",{"lease_id":created["lease_id"],"sync":True}),204)
    check("ssh.second_role",call(mount+"/roles/deploy-other",{"key_type":"otp","default_user":"deploy","cidr_list":"127.0.0.1/32"}),204)
    a=check("ssh.prefix_first",call(creds,{"ip":"127.0.0.1"}))
    b=check("ssh.prefix_other",call(mount+"/creds/deploy-other",{"ip":"127.0.0.1"}))
    check("ssh.prefix_revoke",call("sys/leases/revoke-prefix/"+creds,{"sync":True}),204)
    check("ssh.prefix_revoked",call(verify,{"otp":a["data"]["key"]},""),400)
    check("ssh.prefix_boundary_preserves_other",call(verify,{"otp":b["data"]["key"]},""))
    check("ssh.issuer_policy",call("sys/policies/acl/ssh-issue",{"policy":f'path "{creds}" {{ capabilities = ["update"] }}'}),204)
    issued=check("ssh.issuer_token",call("auth/token/create",{"policies":["default","ssh-issue"]}))["auth"]["client_token"]
    credential=check("ssh.delegated_issue",call(creds,{"ip":"127.0.0.1"},issued))
    check("ssh.issuer_revoked",call("auth/token/revoke",{"token":issued}),204)
    check("ssh.issuer_revocation_invalidates_otp",call(verify,{"otp":credential["data"]["key"]},""),400)
    wrapped=check("ssh.wrapped_issue",call(creds,{"ip":"127.0.0.1"},ttl="60s"))
    truth("ssh.wrapper_no_plaintext",wrapped.get("data") is None and bool(wrapped.get("wrap_info",{}).get("token")))
    unwrapped=check("ssh.unwrap",call("sys/wrapping/unwrap",{},wrapped["wrap_info"]["token"]))
    truth("ssh.unwrapped_contains_lease",bool(unwrapped.get("lease_id")) and unwrapped.get("lease_duration")==60)
    check("ssh.unwrapped_otp_works",call(verify,{"otp":unwrapped["data"]["key"]},""))
    return results


if __name__=="__main__":
    raise SystemExit(core_isolation.main(scenario_runner=run_scenarios,profile="ssh-otp-live",
        scope="selected local SSH OTP role/credential/verification and registered lease lifecycle; no SSH CA/PAM qualification",runner_path=Path(__file__)))
