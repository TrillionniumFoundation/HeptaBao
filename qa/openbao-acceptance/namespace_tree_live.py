#!/usr/bin/env python3
"""Compare a bounded OpenBao 2.6 namespace-tree lifecycle on isolated TLS servers.

This profile covers ordinary namespace creation, read/list, nested hierarchy,
custom-metadata merge patch, delete/recreate identity and direct-child listing.
Per-namespace sealing, namespace locks, force deletion, full ACL inheritance,
migration and production qualification remain separate surfaces/exits.
"""
from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(method, path, body=None, *, merge_patch=False):
        return client.request(
            method,
            "/v1/" + path,
            body,
            content_type="application/merge-patch+json" if merge_patch else "application/json",
        )

    def check(name, response, expected):
        row = {"case": name, "status": response.status, "passed": response.status == expected}
        results.append(row)
        if not row["passed"]:
            raise ScenarioFailure(name)
        return response.body

    def truth(name, value):
        row = {"case": name, "passed": bool(value)}
        results.append(row)
        if not row["passed"]:
            raise ScenarioFailure(name)

    check(
        "namespace.create_parent",
        call("POST", "sys/namespaces/team",
             {"custom_metadata": {"owner": "platform", "tier": "dev"}}),
        204,
    )
    parent = check("namespace.read_parent", call("GET", "sys/namespaces/team"), 200)
    first_id = parent.get("id")
    truth(
        "namespace.parent_shape",
        isinstance(first_id, str)
        and len(first_id) == 5
        and parent.get("path") == "team/"
        and parent.get("custom_metadata") == {"owner": "platform", "tier": "dev"},
    )

    listed = check("namespace.list_root", call("LIST", "sys/namespaces"), 200).get("data", {})
    truth(
        "namespace.list_parent_metadata",
        listed.get("keys") == ["team/"]
        and isinstance(listed.get("key_info"), dict)
        and listed["key_info"].get("team/", {}).get("path") == "team/"
        and listed["key_info"].get("team/", {}).get("custom_metadata")
            == {"owner": "platform", "tier": "dev"}
        and isinstance(listed["key_info"].get("team/", {}).get("id"), str),
    )

    check(
        "namespace.create_child",
        call(
            "POST",
            "sys/namespaces/team/child",
            {"custom_metadata": {
                "owner": "application",
                "keep": "retained",
                "obsolete": "remove-me",
            }},
        ),
        204,
    )
    child = check("namespace.read_child", call("GET", "sys/namespaces/team/child"), 200)
    truth(
        "namespace.child_shape",
        child.get("path") == "team/child/"
        and child.get("custom_metadata", {}).get("owner") == "application"
        and isinstance(child.get("id"), str)
        and len(child["id"]) == 5,
    )
    root_after_child = check(
        "namespace.list_direct_children_only",
        call("LIST", "sys/namespaces"),
        200,
    ).get("data", {})
    truth(
        "namespace.child_not_flattened_into_root_list",
        root_after_child.get("keys") == ["team/"],
    )

    check(
        "namespace.patch_child",
        call(
            "PATCH",
            "sys/namespaces/team/child",
            {"custom_metadata": {"owner": "payments", "obsolete": None}},
            merge_patch=True,
        ),
        204,
    )
    patched = check(
        "namespace.read_patched_child",
        call("GET", "sys/namespaces/team/child"),
        200,
    )
    truth(
        "namespace.merge_patch_semantics",
        patched.get("custom_metadata") == {"owner": "payments", "keep": "retained"},
    )

    check("namespace.delete_child", call("DELETE", "sys/namespaces/team/child"), 204)
    check("namespace.child_absent", call("GET", "sys/namespaces/team/child"), 404)
    check("namespace.delete_parent", call("DELETE", "sys/namespaces/team"), 204)

    check(
        "namespace.recreate_parent",
        call("POST", "sys/namespaces/team",
             {"custom_metadata": {"owner": "replacement"}}),
        204,
    )
    recreated = check(
        "namespace.read_recreated_parent",
        call("GET", "sys/namespaces/team"),
        200,
    )
    truth(
        "namespace.recreate_changes_identity",
        isinstance(recreated.get("id"), str)
        and len(recreated["id"]) == 5
        and recreated["id"] != first_id
        and recreated.get("custom_metadata") == {"owner": "replacement"},
    )
    check("namespace.cleanup_parent", call("DELETE", "sys/namespaces/team"), 204)
    return results


if __name__ == "__main__":
    raise SystemExit(
        core_isolation.main(
            scenario_runner=run_scenarios,
            profile="namespace-tree",
            scope=(
                "ordinary namespace create/read/list/nested/metadata-patch/"
                "delete-recreate identity only; sealing/locks/migration excluded"
            ),
            runner_path=Path(__file__),
        )
    )
