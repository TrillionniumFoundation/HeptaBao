#!/usr/bin/env python3
"""Exercise the bounded ``sys/audit`` file-device management profile.

Both real processes have a deployment-configured file device. Standard per-device
GET and duplicate enable must match the exact upstream refusals; list/readback
must preserve the configured device. HeptaBao's separate internal idempotent
binding extension is not presented as OpenBao behavior. Other audit device
profiles remain separate, and this profile grants no compatibility authority.
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

    check("audit_file.detail_read_rejected", call("GET", "sys/audit/file"), 405)
    check("audit_file.duplicate_enable_rejected", call(
        "PUT", "sys/audit/file", {"type": "file", "options": {"file_path": file_path}}
    ), 400)
    check("audit_file.disable_rejected", call("DELETE", "sys/audit/file"), 400)
    after = check("audit_file.readback", call("GET", "sys/audit"), 200)
    if after.get("data", {}).get("file/", {}) != device:
        raise ScenarioFailure("audit_file.read_binding")
    results.append({"case": "audit_file.read_binding", "passed": True})
    return results


def main() -> int:
    return core_isolation.main(
        scenario_runner=run_scenarios,
        profile="audit-file-management",
        scope="deployment_configured_file_list_exact_api_refusals_and_unchanged_readback",
        runner_path=Path(__file__),
    )


if __name__ == "__main__":
    raise SystemExit(main())
