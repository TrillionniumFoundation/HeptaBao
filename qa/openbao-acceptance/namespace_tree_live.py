#!/usr/bin/env python3
"""Compare a bounded OpenBao 2.6 namespace-tree lifecycle on isolated TLS servers.

This profile covers ordinary namespace creation, read/list, nested hierarchy,
custom-metadata merge patch, delete/recreate identity and direct-child listing.
Per-namespace sealing, namespace locks, force deletion, full ACL inheritance,
migration and production qualification remain separate surfaces/exits.
"""
from pathlib import Path
import copy
import time
import uuid

from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(method, path, body=None, *, merge_patch=False, namespace=""):
        scoped = copy.copy(client)
        scoped.namespace = namespace
        return scoped.request(
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

    def metadata(body):
        data = body.get("data")
        if not isinstance(data, dict):
            raise ScenarioFailure("namespace.missing_data_envelope")
        return data

    def valid_identity(data):
        identifier = data.get("id")
        value = data.get("uuid")
        try:
            parsed = uuid.UUID(value) if isinstance(value, str) else None
        except (ValueError, AttributeError):
            return False
        return (isinstance(identifier, str) and 1 <= len(identifier) <= 128
                and identifier.isascii() and identifier.isalnum()
                and parsed is not None and str(parsed) == value
                and data.get("locked") is False and data.get("tainted") is False)

    def deleted(name, path, namespace=""):
        # Only poll observation; never repeat an uncertain effect to obtain a pass.
        deadline = time.monotonic() + 10
        while True:
            response = call("GET", path, namespace=namespace)
            if response.status == 404:
                return check(name, response, 404)
            if response.status != 200 or time.monotonic() >= deadline:
                raise ScenarioFailure(name)
            time.sleep(0.05)

    created = check(
        "namespace.create_parent",
        call("POST", "sys/namespaces/team",
             {"custom_metadata": {"owner": "platform", "tier": "dev"}}),
        200,
    )
    parent = metadata(check("namespace.read_parent", call("GET", "sys/namespaces/team"), 200))
    first_id = parent.get("id")
    first_uuid = parent.get("uuid")
    truth(
        "namespace.parent_shape",
        valid_identity(parent)
        and metadata(created) == parent
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
            "sys/namespaces/child",
            {"custom_metadata": {
                "owner": "application",
                "keep": "retained",
                "obsolete": "remove-me",
            }},
            namespace="team",
        ),
        200,
    )
    child = metadata(check("namespace.read_child", call("GET", "sys/namespaces/child", namespace="team"), 200))
    truth(
        "namespace.child_shape",
        child.get("path") == "team/child/"
        and child.get("custom_metadata", {}).get("owner") == "application"
        and valid_identity(child),
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
            "sys/namespaces/child",
            {"custom_metadata": {"owner": "payments", "obsolete": None}},
            merge_patch=True,
            namespace="team",
        ),
        200,
    )
    patched = metadata(check(
        "namespace.read_patched_child",
        call("GET", "sys/namespaces/child", namespace="team"),
        200,
    ))
    truth(
        "namespace.merge_patch_semantics",
        patched.get("custom_metadata") == {"owner": "payments", "keep": "retained"}
        and patched.get("id") == child.get("id") and patched.get("uuid") == child.get("uuid"),
    )

    check("namespace.nested_suffix_rejected", call("GET", "sys/namespaces/team/child"), 400)
    removed = check("namespace.delete_child", call("DELETE", "sys/namespaces/child", namespace="team"), 200)
    truth("namespace.delete_child_accepted", metadata(removed).get("status") == "in-progress")
    deleted("namespace.child_absent", "sys/namespaces/child", "team")
    repeated = check("namespace.delete_child_terminal", call("DELETE", "sys/namespaces/child", namespace="team"), 200)
    truth("namespace.delete_child_terminal_has_no_work", repeated.get("data") is None)
    check("namespace.delete_parent", call("DELETE", "sys/namespaces/team"), 200)
    deleted("namespace.parent_absent", "sys/namespaces/team")

    check(
        "namespace.recreate_parent",
        call("POST", "sys/namespaces/team",
             {"custom_metadata": {"owner": "replacement"}}),
        200,
    )
    recreated = metadata(check(
        "namespace.read_recreated_parent",
        call("GET", "sys/namespaces/team"),
        200,
    ))
    truth(
        "namespace.recreate_changes_identity",
        valid_identity(recreated)
        and recreated["id"] != first_id
        and recreated["uuid"] != first_uuid
        and recreated.get("custom_metadata") == {"owner": "replacement"},
    )
    check("namespace.cleanup_parent", call("DELETE", "sys/namespaces/team"), 200)
    deleted("namespace.cleanup_confirmed", "sys/namespaces/team")
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
