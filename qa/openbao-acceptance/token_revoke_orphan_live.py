#!/usr/bin/env python3
"""Fresh loopback-only fixture comparison of service-token orphan revocation.

The common harness creates, owns and destroys both test services. Test bearers
remain in memory. Reports contain case labels and status observations only.
"""
from pathlib import Path
from core_isolation import ScenarioFailure, main as compare

_CONTEXT = {}


class Trace:
    def __init__(self, client, rows):
        self.client, self.rows = client, rows

    def check(self, name, condition):
        row = {"case": "orphan270." + name, "passed": bool(condition)}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])

    def call(self, name, method, path, expected, body=None, token=None):
        response = self.client.request(method, "/v1/" + path, body, token=token)
        row = {"case": "orphan270." + name, "status": response.status,
               "passed": response.status == expected}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body

    def create(self, name, parent=None):
        result = self.call(name, "POST", "auth/token/create", 200,
                           {"policies": ["default", "orphan-fixture"], "ttl": "300s"}, parent)
        return result["auth"]["client_token"]

    def live(self, name, token, orphan):
        data = self.call(name, "GET", "auth/token/lookup-self", 200, token=token)["data"]
        self.check(name + "_parent_binding", data.get("orphan") is orphan)


def run_scenarios(client, results=None):
    rows = [] if results is None else results
    t = Trace(client, rows)
    t.call("issuer_policy", "POST", "sys/policies/acl/orphan-fixture", 204,
           {"policy": 'path "auth/token/create" { capabilities=["update"] } '
                      'path "auth/token/revoke-orphan" { capabilities=["update"] }'})
    contexts = []
    for method in ("POST", "PUT"):
        tag = method.lower()
        parent = t.create(tag + "_parent")
        child = t.create(tag + "_child", parent)
        sibling = t.create(tag + "_sibling", parent)
        grandchild = t.create(tag + "_grandchild", child)
        peer = t.create(tag + "_peer")
        t.call(tag + "_sudo_required", method, "auth/token/revoke-orphan", 400, {"token": parent}, parent)
        t.live(tag + "_denied_preserves_parent", parent, False)
        t.live(tag + "_denied_preserves_child_edge", child, False)
        result = t.call(tag + "_orphan", method, "auth/token/revoke-orphan", 204, {"token": parent})
        t.check(tag + "_no_secret_response", not result.get("data") and not result.get("auth"))
        t.call(tag + "_parent_dead", "GET", "auth/token/lookup-self", 403, token=parent)
        t.call(tag + "_absent_target", method, "auth/token/revoke-orphan", 400, {"token": parent})
        for name, value, orphan in (("child", child, True), ("sibling", sibling, True),
                                    ("grandchild", grandchild, False), ("peer", peer, False)):
            t.live(tag + "_" + name, value, orphan)
        contexts.append((tag, parent, child, sibling, grandchild, peer))
    _CONTEXT[id(rows)] = contexts
    return rows


def run_after_restart(client, rows):
    contexts = _CONTEXT.pop(id(rows), None)
    if not contexts:
        raise ScenarioFailure("orphan270.restart_context_missing")
    t = Trace(client, rows)
    for tag, parent, child, sibling, grandchild, peer in contexts:
        tag += "_restart"
        t.call(tag + "_parent_dead", "GET", "auth/token/lookup-self", 403, token=parent)
        for name, value, orphan in (("child", child, True), ("sibling", sibling, True),
                                    ("grandchild", grandchild, False), ("peer", peer, False)):
            t.live(tag + "_" + name, value, orphan)
        descendant = t.create(tag + "_new_descendant", child)
        t.call(tag + "_normal_cascade", "POST", "auth/token/revoke", 204, {"token": child})
        for name, value in (("child", child), ("grandchild", grandchild), ("descendant", descendant)):
            t.call(tag + "_cascade_" + name, "GET", "auth/token/lookup-self", 403, token=value)
        t.live(tag + "_sibling_retained", sibling, True)
        t.live(tag + "_peer_retained", peer, False)
    t.call("root_retained", "GET", "auth/token/lookup-self", 200)
    t.check("complete", True)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                   profile="token-revoke-orphan270", required_oracle_version="2.7.0",
                   scope="service_token_direct_orphans_subtree_revoke_and_native_restart",
                   runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
