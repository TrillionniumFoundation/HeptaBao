#!/usr/bin/env python3
"""Compare bounded KV enumeration behavior with pinned OpenBao 2.6.2 over TLS.

The same synthetic hierarchy is created independently on two fresh instances.
Only fixed assertions and HTTP status codes enter the receipt, never returned
secret values, tokens, or metadata timestamps.
"""
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation

SEED_KEYS = ("a", "a/b", "a/c/d", "false", "m/x", "m/y/z", "pure/leaf", "true", "z")
LIST_KEYS = ["a", "a/", "false", "m/", "pure/", "true", "z"]
# ScanView visits root leaves first and pushes sorted directories onto a stack.
SCAN_KEYS = ["a", "false", "true", "z", "pure/leaf", "m/x", "m/y/z", "a/b", "a/c/d"]


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(case, method, path, payload=None, expected=200, expected_data=None):
        response = client.request(method, "/v1/" + path, payload)
        observation = {"case": "kv_enumeration." + case, "status": response.status,
                       "passed": response.status == expected}
        if expected_data is not None:
            observation["data_matches"] = response.body.get("data") == expected_data
            observation["passed"] &= observation["data_matches"]
        results.append(observation)
        if not observation["passed"]:
            raise ScenarioFailure(observation["case"])
        return response.body

    def keys(case, method, path, expected_keys, payload=None):
        return call(case, method, path, payload, expected_data={"keys": expected_keys})

    for version in (1, 2):
        name = "v" + str(version)
        mount = "enumeration-" + name
        call(name + ".mount", "POST", "sys/mounts/" + mount,
             {"type": "kv", "options": {"version": str(version)}}, 204)
        for index, key in enumerate(SEED_KEYS):
            path = mount + "/" + ("data/" if version == 2 else "") + key
            data = {"synthetic": "enumeration-only"}
            call(name + ".seed." + str(index), "POST", path,
                 {"data": data} if version == 2 else data, 200 if version == 2 else 204)

        base = mount + "/" + ("metadata/" if version == 2 else "")
        for method, root_keys, subkeys in (("LIST", LIST_KEYS, ["b", "c/"]),
                                           ("SCAN", SCAN_KEYS, ["b", "c/d"])):
            prefix = name + "." + method.lower()
            keys(prefix + ".root", method, base, root_keys)
            keys(prefix + ".root_no_slash", method, base.rstrip("/"), root_keys)
            for index, query in enumerate(("limit=-1", "limit=-42", "limit=0", "limit=",
                                            "limit=-9223372036854775808",
                                            "limit=9223372036854775807", "after=")):
                keys(prefix + ".unlimited." + str(index), method, base + "?" + query, root_keys)

            for case, query, page in (
                    ("page_one", "limit=2", ["a", "a/"]),
                    ("page_two", "after=a%2F&limit=2", ["false", "m/"]),
                    ("after_leaf", "after=a&limit=2", ["a/", "false"]),
                    ("after_missing", "after=b&limit=2", ["false", "m/"]),
                    ("after_false", "after=false", ["m/", "pure/", "true", "z"]),
                    ("after_true", "after=true", ["z"])):
                keys(prefix + "." + case, method, base + "?" + query,
                     page if version == 2 and method == "LIST" else root_keys)

            for index, value in enumerate(("9223372036854775808", "-9223372036854775809",
                                            "bad", "true", "1.5")):
                # KV v1 defines neither field. KV v2 validates the field before
                # dispatch, including for SCAN which ignores valid pagination.
                path = base + "?limit=" + value
                if version == 2:
                    call(prefix + ".invalid_limit." + str(index), method, path, expected=400)
                else:
                    keys(prefix + ".invalid_limit_ignored." + str(index), method, path, root_keys)

            # The official HTTP handler reads query parameters for LIST/SCAN;
            # a JSON body is not used for pagination or field validation.
            for index, payload in enumerate(({"limit": 2, "after": "a/"},
                                              {"limit": "bad", "after": []},
                                              {"limit": {}, "after": True})):
                keys(prefix + ".body_ignored." + str(index), method, base, root_keys, payload)
            keys(prefix + ".body_query_precedence", method, base + "?limit=2",
                 ["a", "a/"] if version == 2 and method == "LIST" else root_keys,
                 {"limit": "bad", "after": "z"})
            for suffix, label in (("a", "prefix"), ("a/", "prefix_slash")):
                keys(prefix + "." + label, method, base + suffix, subkeys)
            for suffix, label in (("missing", "empty"), ("missing/", "empty_slash")):
                call(prefix + "." + label, method, base + suffix,
                     expected=404 if method == "LIST" else 200,
                     expected_data=None if method == "LIST" else {})
            if method == "LIST":
                keys(prefix + ".get_alias", "GET", base + "?list=true&limit=2",
                     ["a", "a/"] if version == 2 else root_keys)
            else:
                keys(prefix + ".get_alias", "GET", base + "?scan=true&after=z&limit=2", root_keys)

        if version == 2:
            metadata = {}
            for index, key in enumerate(SEED_KEYS):
                metadata[key] = call("v2.metadata." + str(index), "GET", base + key)["data"]
            detailed = mount + "/detailed-metadata/"
            root_info = {key: metadata.get(key.rstrip("/"), {}) for key in LIST_KEYS}
            call("v2.detailed.list", "LIST", detailed,
                 expected_data={"keys": LIST_KEYS, "key_info": root_info})
            call("v2.detailed.page", "LIST", detailed + "?after=a&limit=2",
                 expected_data={"keys": ["a/", "false"],
                                "key_info": {key: root_info[key] for key in ("a/", "false")}})
            call("v2.detailed.prefix", "LIST", detailed + "a",
                 expected_data={"keys": ["b", "c/"], "key_info": {"b": metadata["a/b"], "c/": {}}})
            call("v2.detailed.scan", "SCAN", detailed + "?after=z&limit=1",
                 expected_data={"keys": SCAN_KEYS, "key_info": {key: metadata[key] for key in SCAN_KEYS}})
            call("v2.detailed.scan_empty", "SCAN", detailed + "missing", expected_data={})
            call("v2.detailed.list_empty", "LIST", detailed + "missing", expected=404)
    return results


if __name__ == "__main__":
    raise SystemExit(core_isolation.main(
        scenario_runner=run_scenarios, profile="kv-enumeration-live",
        scope="KV v1/v2 LIST and SCAN query pagination, validation, traversal order, empty results and detailed metadata",
        runner_path=Path(__file__)))
