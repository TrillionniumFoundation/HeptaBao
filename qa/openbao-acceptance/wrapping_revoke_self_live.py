#!/usr/bin/env python3
"""Exact OpenBao 2.7 opaque wrapping self-discard, including process restart.

New local TLS fixtures only. Tokens stay in process memory, never in reports.
This does not qualify general token semantics, migration or production use.
"""
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure, main as compare

_RESTART_STATE: dict[int, dict] = {}


class Trace:
    def __init__(self, client: Client, rows: list[dict]):
        self.client, self.rows = client, rows

    def truth(self, name, condition):
        row = {"case": "wrapping270." + name, "passed": bool(condition)}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])

    def call(self, name, method, path, expected, body=None, *, token=None, ttl=None):
        response = self.client.request(method, "/v1/" + path, body, token=token, wrap_ttl=ttl)
        row = {"case": "wrapping270." + name, "status": response.status,
               "passed": response.status == expected}
        self.rows.append(row)
        if not row["passed"]:
            raise ScenarioFailure(row["case"])
        return response.body

    def wrap(self, name, value):
        result = self.call(name, "POST", "sys/wrapping/wrap", 200,
                           {"synthetic": value}, ttl="300s")
        self.truth(name + "_hidden", result.get("data") is None and result.get("auth") is None)
        return result["wrap_info"]["token"]


def run_scenarios(client: Client, results: list[dict] | None = None):
    rows = [] if results is None else results
    t = Trace(client, rows)
    revoked = []
    peer = t.wrap("peer", "independent-peer")
    for method in ("POST", "PUT"):
        name = method.lower()
        token = t.wrap(name + "_create", "discard-not-disclose")
        paths = ["auth/token/revoke-self", "sys/wrapping/unwrap", "auth/token/revoke",
                 "auth/token/revoke-accessor", "auth/token/create", "auth/token/renew-self",
                 "sys/wrapping/rewrap", "auth/token/revoke-self/peer"]
        caps = t.call(name + "_capabilities", "POST", "sys/capabilities", 200,
                      {"token": token, "paths": paths})["data"]
        t.truth(name + "_least_authority", all(caps[path] == (["update"] if index < 2 else ["deny"])
                                               for index, path in enumerate(paths)))
        response = t.call(name + "_discard", method, "auth/token/revoke-self", 204, {}, token=token)
        t.truth(name + "_no_response_release", not response.get("data") and not response.get("auth")
                and not response.get("wrap_info"))
        t.call(name + "_lookup_denied", "POST", "sys/wrapping/lookup", 400, {"token": token})
        t.call(name + "_unwrap_denied", "POST", "sys/wrapping/unwrap", 400, {"token": token})
        t.call(name + "_replay_denied", method, "auth/token/revoke-self", 403, {}, token=token)
        t.call(name + "_root_unchanged", "GET", "auth/token/lookup-self", 200)
        revoked.append(token)
    # An otherwise forbidden use cannot turn into a reusable discard capability.
    denied = t.wrap("denied_create", "must-not-release")
    t.call("peer_revoke_forbidden", "POST", "auth/token/revoke", 403, {"token": peer}, token=denied)
    t.call("denied_attempt_consumed", "POST", "sys/wrapping/lookup", 400, {"token": denied})
    t.call("peer_not_revoked", "POST", "sys/wrapping/lookup", 200, {"token": peer})
    pending = t.wrap("pending_before_restart", "discard-after-restart")
    _RESTART_STATE[id(rows)] = {"revoked": revoked, "peer": peer, "pending": pending}
    return rows


def run_after_restart(client: Client, rows: list[dict]):
    state = _RESTART_STATE.pop(id(rows), None)
    if state is None:
        raise ScenarioFailure("wrapping270.restart_context_missing")
    t = Trace(client, rows)
    for index, token in enumerate(state["revoked"]):
        name = "restart_revoked_" + str(index)
        t.call(name + "_lookup", "POST", "sys/wrapping/lookup", 400, {"token": token})
        t.call(name + "_unwrap", "POST", "sys/wrapping/unwrap", 400, {"token": token})
        t.call(name + "_revoke", "POST", "auth/token/revoke-self", 403, {}, token=token)
    t.call("restart_pending_discard", "POST", "auth/token/revoke-self", 204, {}, token=state["pending"])
    t.call("restart_pending_no_release", "POST", "sys/wrapping/unwrap", 400, {"token": state["pending"]})
    peer = t.call("restart_peer_unwrap", "POST", "sys/wrapping/unwrap", 200, {}, token=state["peer"])
    t.truth("restart_peer_exact_payload", peer.get("data") == {"synthetic": "independent-peer"})
    t.call("restart_root_unchanged", "GET", "auth/token/lookup-self", 200)
    t.truth("complete", True)


def main():
    return compare(scenario_runner=run_scenarios, restart_runner=run_after_restart,
                   profile="wrapping-self-revoke270", required_oracle_version="2.7.0",
                   scope="opaque_self_discard_scoped_authority_no_disclosure_and_restart",
                   runner_path=Path(__file__))


if __name__ == "__main__":
    raise SystemExit(main())
