#!/usr/bin/env python3
"""Selected actual-policy capability introspection against the pinned Oracle.

This does not certify every ACL dialect, parameter or identity integration.
"""
from pathlib import Path
from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results
    def call(path, body=None, token=None, method="POST"):
        return client.request(method, "/v1/"+path, body, token=token)
    def check(name, response, expected=200):
        results.append({"case": name, "status": response.status, "passed": response.status == expected})
        if response.status != expected:
            raise ScenarioFailure(name)
        return response.body
    def truth(name, condition):
        results.append({"case": name, "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure(name)
    r=check("caps.root",call("sys/capabilities-self",{"paths":["secret/a"]}))
    truth("caps.root_alias_and_data",r.get("capabilities")==["root"] and r.get("secret/a")==["root"] and r["data"]["secret/a"]==["root"])
    r=check("caps.legacy_path",call("sys/capabilities-self",{"path":"secret/a"}))
    truth("caps.legacy_result",r.get("capabilities")==["root"])
    check("caps.invalid_token",call("sys/capabilities",{"token":"synthetic-invalid","paths":["a"]}),400)
    check("caps.invalid_accessor",call("sys/capabilities-accessor",{"accessor":"synthetic-invalid","paths":["a"]}),400)
    check("caps.empty_paths",call("sys/capabilities-self",{"paths":[]}),400)
    check("caps.policy",call("sys/policies/acl/cap-query",{"policy":
        'path "secret/*" { capabilities = ["read","update","delete"] }\npath "secret/data/locked" { capabilities = ["read"] }'}),204)
    user=check("caps.user",call("auth/token/create",{"policies":["default","cap-query"]}))["auth"]
    token=user["client_token"]
    paths=["secret/data/locked","secret/data/other","no-match","sys/wrapping/rewrap"]
    r=check("caps.multi",call("sys/capabilities-self",{"paths":paths},token))
    truth("caps.specificity",r["data"][paths[0]]==["read"] and r["data"][paths[1]]==["delete","read","update"])
    truth("caps.deny_and_multi_shape",r["data"]["no-match"]==["deny"] and r["data"]["sys/wrapping/rewrap"]==["deny"] and "capabilities" not in r)
    check("caps.foreign_denied",call("sys/capabilities",{"token":client._token,"paths":["a"]},token),403)
    check("caps.accessor_denied",call("sys/capabilities-accessor",{"accessor":user["accessor"],"paths":["a"]},token),403)
    for endpoint,selector in [("sys/capabilities",{"token":token}),("sys/capabilities-accessor",{"accessor":user["accessor"]})]:
        r=check("caps.admin."+endpoint,call(endpoint,dict(selector,paths=[paths[0]])))
        truth("caps.admin_result."+endpoint,r.get("capabilities")==["read"])
    check("caps.denied_write",call("secret/data/locked",{"data":{"v":"must-not-write"}},token),403)
    check("caps.change_policy",call("sys/policies/acl/cap-query",{"policy":'path "secret/data/locked" { capabilities = ["deny","read"] }'}),204)
    r=check("caps.live_revoke",call("sys/capabilities-self",{"paths":[paths[0]]},token))
    truth("caps.current_policy_used",r.get("capabilities")==["deny"])
    finite=check("caps.finite",call("auth/token/create",{"policies":["default"],"num_uses":1}))["auth"]
    for endpoint,selector in [("sys/capabilities",{"token":finite["client_token"]}),("sys/capabilities-accessor",{"accessor":finite["accessor"]})]:
        r=check("caps.non_consuming."+endpoint,call(endpoint,dict(selector,paths=["auth/token/lookup-self"])))
        truth("caps.non_consuming_result."+endpoint,r.get("capabilities")==["read"])
    check("caps.target_still_has_use",call("auth/token/lookup-self",token=finite["client_token"],method="GET"))
    check("caps.target_spent",call("auth/token/lookup-self",token=finite["client_token"],method="GET"),403)
    # Current entity/internal group policies, not only the token policy names.
    check("caps.mount_auth",call("sys/auth/caps-login",{"type":"approle"}),204)
    check("caps.identity_role",call("auth/caps-login/role/caps-live",{"token_policies":["default"],"secret_id_num_uses":0}),204)
    rid=check("caps.role_id",call("auth/caps-login/role/caps-live/role-id",method="GET"))["data"]["role_id"]
    sid=check("caps.secret_id",call("auth/caps-login/role/caps-live/secret-id",{}))["data"]["secret_id"]
    login=check("caps.login",call("auth/caps-login/login",{"role_id":rid,"secret_id":sid},""))["auth"]
    check("caps.identity_policy",call("sys/policies/acl/caps-live",{"policy":'path "secret/data/live" { capabilities = ["read"] }'}),204)
    check("caps.entity_grant",call("identity/entity/id/"+login["entity_id"],{"policies":["caps-live"]}),204)
    r=check("caps.identity_self",call("sys/capabilities-self",{"paths":["secret/data/live"]},login["client_token"]))
    truth("caps.identity_included",r.get("capabilities")==["read"])
    r=check("caps.identity_accessor",call("sys/capabilities-accessor",{"accessor":login["accessor"],"paths":["secret/data/live"]}))
    truth("caps.identity_accessor_included",r.get("capabilities")==["read"])
    check("caps.entity_revoke",call("identity/entity/id/"+login["entity_id"],{"policies":[]}),204)
    r=check("caps.identity_revoked",call("sys/capabilities-self",{"paths":["secret/data/live"]},login["client_token"]))
    truth("caps.no_cached_identity_grant",r.get("capabilities")==["deny"])
    return results


if __name__ == "__main__":
    raise SystemExit(core_isolation.main(scenario_runner=run_scenarios,profile="capabilities-live",
        scope="selected token/self/accessor capabilities, live Identity and non-consuming target inspection",runner_path=Path(__file__)))
