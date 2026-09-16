#!/usr/bin/env python3
"""Exercise the bounded ``sys/audit`` file-device management profile.

The profile proves the real API binding to the process-owned authenticated
file sink. HTTP, socket and syslog devices remain unsupported and are not
represented as compatibility claims.
"""
from __future__ import annotations

from pathlib import Path

from bao_http import Client
from core_isolation import ScenarioFailure
import core_isolation


def run_scenarios(client: Client, results: list[dict] | None = None) -> list[dict]:
    results = [] if results is None else results

    def call(method: str, path: str, body=None):
        return client.request(method, "/v1/" + path, body)

    def check(name: str, response, status: int):
        result = {"case": name, "status": response.status, "passed": response.status == status}
        results.append(result)
        if not result["passed"]:
            raise ScenarioFailure(name)
        return response.body

    listing = check("audit_file.list", call("GET", "sys/audit"), 200)
    device = listing.get("data", {}).get("file/", {})
    if device.get("type") != "file":
        raise ScenarioFailure("audit_file.list_shape")
    results.append({"case": "audit_file.list_shape", "passed": True})
    file_path = device.get("options", {}).get("file_path")
    if not isinstance(file_path, str) or not file_path:
        raise ScenarioFailure("audit_file.path_present")
    results.append({"case": "audit_file.path_present", "passed": True})

    detail = check("audit_file.read", call("GET", "sys/audit/file"), 200)
    if detail.get("data", {}).get("options", {}).get("file_path") != file_path:
        raise ScenarioFailure("audit_file.read_binding")
    results.append({"case": "audit_file.read_binding", "passed": True})

    check("audit_file.enable_idempotent", call(
        "PUT", "sys/audit/file", {"type": "file", "options": {"file_path": file_path}}
    ), 204)
    check("audit_file.disable_rejected", call("DELETE", "sys/audit/file"), 400)
    return results


def main() -> int:
    return core_isolation.main(
        scenario_runner=run_scenarios,
        profile="audit-file-management",
        scope="sys_audit_list_read_idempotent_enable_and_fail_closed_disable",
        runner_path=Path(__file__),
    )


if __name__ == "__main__":
    raise SystemExit(main())
