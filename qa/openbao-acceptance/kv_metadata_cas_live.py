#!/usr/bin/env python3
"""Compare KV v2 metadata CAS against pinned official OpenBao 2.6.2 over HTTPS.

Only new local synthetic instances are accepted. The shared comparison harness
pins the official artifact and records hashes; this profile checks metadata CAS,
not full KV compatibility or production qualification.
"""
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation

PREFIX = "metadata-cas/"
WARNING = ('"metadata_cas_required" set to false, but is mandated by backend '
           'config. This value will be ignored.')


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def check(case, condition, **observation):
        results.append({"case": "metadata_cas." + case, **observation,
                        "passed": bool(condition)})
        if not condition:
            raise ScenarioFailure("metadata_cas." + case)

    def call(case, method, path, payload=None, expected=204):
        response = client.request(method, "/v1/" + path, payload,
                                  content_type=("application/merge-patch+json"
                                                if method == "PATCH" else "application/json"))
        check(case, response.status == expected, status=response.status)
        return response.body

    def read(case, key):
        return call(case, "GET", PREFIX + "metadata/" + key, expected=200)["data"]

    def write(case, key, payload, method="POST", expected=204):
        return call(case, method, PREFIX + "metadata/" + key, payload, expected)

    def rejected(case, key, payload, method="POST"):
        before = read(case + ".before", key)
        write(case + ".reject", key, payload, method, 400)
        after = read(case + ".after", key)
        check(case + ".no_effect", after == before)

    call("mount", "POST", "sys/mounts/metadata-cas",
         {"type": "kv", "options": {"version": "2"}})
    cfg = call("config.default", "GET", PREFIX + "config", expected=200)["data"]
    check("config.default_flag", cfg.get("metadata_cas_required") is False)
    call("data.create", "POST", PREFIX + "data/data-first", {"data": {"value": "synthetic"}}, 200)
    data_first = read("data.metadata", "data-first")
    check("data.initial_metadata_version", data_first.get("current_metadata_version") == 0)
    check("data.initial_data_version", data_first.get("current_version") == 1)
    write("data.metadata_cas_zero", "data-first",
          {"metadata_cas": 0, "custom_metadata": {"owner": "first"}})
    check("data.first_metadata_increment", read("data.metadata_after", "data-first").get("current_metadata_version") == 1)

    write("new.nonzero_rejected", "new", {"metadata_cas": 1, "custom_metadata": {"owner": "bad"}}, expected=400)
    call("new.failed_creation_absent", "GET", PREFIX + "metadata/new", expected=404)
    write("new.create", "new", {"metadata_cas": 0, "metadata_cas_required": True,
                                  "custom_metadata": {"owner": "first", "keep": "yes"}})
    created = read("new.read", "new")
    check("new.shape", created.get("current_metadata_version") == 1
          and created.get("metadata_cas_required") is True
          and created.get("current_version") == 0
          and created.get("custom_metadata") == {"owner": "first", "keep": "yes"})
    rejected("missing", "new", {"custom_metadata": {"owner": "bad"}})
    rejected("stale", "new", {"metadata_cas": 0, "custom_metadata": {"owner": "bad"}})
    rejected("future", "new", {"metadata_cas": 2, "custom_metadata": {"owner": "bad"}})
    write("patch.update", "new", {"metadata_cas": 1, "custom_metadata": {"owner": None, "team": "second"}}, "PATCH")
    patched = read("patch.read", "new")
    check("patch.shape", patched.get("current_metadata_version") == 2
          and patched.get("custom_metadata") == {"keep": "yes", "team": "second"}
          and patched.get("current_version") == 0)
    rejected("patch.stale", "new", {"metadata_cas": 1, "custom_metadata": {"team": "bad"}}, "PATCH")
    rejected("patch.invalid", "new", {"metadata_cas": 2, "cas_required": True,
                                        "custom_metadata": {"owner": ["invalid"]}}, "PATCH")
    for method in ("POST", "PATCH"):
        before = read("noop." + method + ".before", "new")
        write("noop." + method + ".empty", "new", {}, method)
        write("noop." + method + ".counter_only", "new", {"metadata_cas": 999}, method)
        check("noop." + method + ".unchanged", read("noop." + method + ".after", "new") == before)
    call("data.independent_write", "POST", PREFIX + "data/new", {"data": {"value": "synthetic"}}, 200)
    independent = read("data.independent_read", "new")
    check("data.independent_versions", independent.get("current_metadata_version") == 2
          and independent.get("current_version") == 1)
    write("put.disable_local", "new", {"metadata_cas": 2, "metadata_cas_required": False}, "PUT")
    write("local.optional_again", "new", {"custom_metadata": {"owner": "unforced"}})
    check("local.version_four", read("local.read", "new").get("current_metadata_version") == 4)

    call("global.enable", "POST", PREFIX + "config", {"metadata_cas_required": True})
    cfg = call("global.read", "GET", PREFIX + "config", expected=200)["data"]
    check("global.enabled", cfg.get("metadata_cas_required") is True)
    write("global.new_missing", "global-new", {"custom_metadata": {"owner": "bad"}}, expected=400)
    call("global.new_absent", "GET", PREFIX + "metadata/global-new", expected=404)
    write("global.new_create", "global-new", {"metadata_cas": 0, "custom_metadata": {"owner": "first"}})
    for method, version in (("POST", 1), ("PATCH", 2)):
        warned = write("warning." + method, "global-new", {"metadata_cas": version, "metadata_cas_required": False}, method, 200)
        check("warning." + method + ".exact", warned.get("warnings") == [WARNING])
        rejected("global.still_required." + method, "global-new", {"custom_metadata": {"owner": "bad"}})
    final = read("global.final_read", "global-new")
    check("global.final_shape", final.get("current_metadata_version") == 3
          and final.get("metadata_cas_required") is False
          and final.get("custom_metadata") == {"owner": "first"})
    return results


if __name__ == "__main__":
    raise SystemExit(core_isolation.main(
        scenario_runner=run_scenarios, profile="kv-metadata-cas-live",
        scope="KV v2 metadata CAS create/write/PATCH, independent counters, no-op, global requirement and warning semantics",
        runner_path=Path(__file__)))
