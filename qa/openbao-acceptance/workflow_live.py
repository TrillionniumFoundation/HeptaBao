#!/usr/bin/env python3
"""Exercise the scoped authenticated JSON workflow runtime on a real server.

This is a bounded HeptaBao profile: definitions are literal local API steps,
execution reuses the caller's authenticated namespace context, and output is
limited to explicit response-field mappings.  It does not claim OpenBao CEL or
template compatibility, unauthenticated execution, trace output, or
crash-resumable step execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    binary = Path(args.binary)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    source_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    source_worktree_dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()
    )
    checks: list[dict[str, object]] = []
    root = Path(tempfile.mkdtemp(prefix="heptabao-workflow-"))
    root.chmod(0o700)
    instance = Instance(binary, root / "candidate")

    def check(name: str, passed: bool) -> None:
        checks.append({"case": name, "passed": bool(passed)})
        if not passed:
            raise RuntimeError(name)

    def call(method: str, path: str, body: object | None = None, **kwargs):
        return instance.call(method, path, body, **kwargs)

    try:
        instance.start()
        status, initialized = call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        unseal_key = initialized["keys_base64"][0]
        check("unseal", call("POST", "sys/unseal", {"key": unseal_key})[0] == 200)
        check(
            "mount_local_kv",
            call("POST", "sys/mounts/workflow-kv", {"type": "kv", "options": {"version": "2"}})[0]
            == 204,
        )

        basic = {
            "cas": 0,
            "steps": [
                {
                    "name": "write",
                    "method": "POST",
                    "path": "workflow-kv/data/item",
                    "body": {"data": {"value": "workflow-value", "secret": "not-returned"}},
                },
                {"name": "read", "method": "GET", "path": "workflow-kv/data/item"},
            ],
            "outputs": {"value": {"step": "read", "field": ["data", "data", "value"]}},
        }
        status, created = call("POST", "sys/workflows/manage/operations/basic", basic)
        check("manage_create_cas_zero", status == 200 and created.get("data", {}).get("version") == 1)
        status, listed = call("LIST", "sys/workflows/manage")
        check("manage_list_root", status == 200 and listed.get("data", {}).get("keys") == ["operations/"])
        status, prefixed = call("LIST", "sys/workflows/manage/operations")
        check("manage_list_prefix", status == 200 and prefixed.get("data", {}).get("keys") == ["basic"])
        status, stored = call("GET", "sys/workflows/manage/operations/basic")
        check(
            "manage_get_versioned_definition",
            status == 200 and stored.get("data", {}).get("version") == 1
            and stored.get("data", {}).get("workflow", {}).get("outputs") == basic["outputs"],
        )
        status, executed = call("POST", "sys/workflows/execute/operations/basic", {})
        check(
            "execute_sequential_local_steps",
            status == 200 and executed.get("data") == {"value": "workflow-value"}
            and "secret" not in json.dumps(executed),
        )
        status, conflict = call(
            "POST",
            "sys/workflows/manage/operations/basic",
            {**basic, "cas": 0},
        )
        check("cas_create_only_rejects_overwrite", status == 409 and bool(conflict.get("errors")))
        status, malformed = call(
            "POST",
            "sys/workflows/manage/operations/bad",
            {
                "steps": [{"name": "read", "method": "GET", "path": "https://example.test/x"}],
                "outputs": {},
            },
        )
        check("external_url_rejected", status == 400)
        status, unauthenticated = call(
            "POST",
            "sys/workflows/manage/operations/unauth",
            {**basic, "allow_unauthenticated": True},
        )
        check("allow_unauthenticated_rejected", status == 400)
        status, recursive = call(
            "POST",
            "sys/workflows/manage/operations/recursive",
            {
                "steps": [{"name": "again", "method": "POST", "path": "sys/workflows/execute/operations/basic"}],
                "outputs": {},
            },
        )
        check("recursive_workflow_rejected", status == 400)
        status, anonymous = call("POST", "sys/workflows/execute/operations/basic", {}, token="")
        check("unauthenticated_execution_denied", status == 403)

        stopped = {
            "cas": 0,
            "steps": [
                {"name": "missing", "method": "GET", "path": "workflow-kv/data/absent"},
                {
                    "name": "must-not-run",
                    "method": "POST",
                    "path": "workflow-kv/data/stopped",
                    "body": {"data": {"value": "forbidden"}},
                },
            ],
            "outputs": {},
        }
        check("manage_stop_definition", call("POST", "sys/workflows/manage/operations/stopped", stopped)[0] == 200)
        status, _ = call("POST", "sys/workflows/execute/operations/stopped", {})
        check("stop_on_failed_step", status == 404)
        check("failed_step_has_no_following_effect", call("GET", "workflow-kv/data/stopped")[0] == 404)

        continued = {
            "cas": 0,
            "steps": [
                {
                    "name": "missing",
                    "method": "GET",
                    "path": "workflow-kv/data/absent",
                    "allow_failure": True,
                },
                {
                    "name": "write",
                    "method": "POST",
                    "path": "workflow-kv/data/continued",
                    "body": {"data": {"value": "continued"}},
                },
                {"name": "read", "method": "GET", "path": "workflow-kv/data/continued"},
            ],
            "outputs": {"value": {"step": "read", "field": ["data", "data", "value"]}},
        }
        check("manage_allow_failure_definition", call("POST", "sys/workflows/manage/operations/continued", continued)[0] == 200)
        status, continued_result = call("POST", "sys/workflows/execute/operations/continued", {})
        check("allow_failure_continues", status == 200 and continued_result.get("data") == {"value": "continued"})

        check("namespace_create", call("POST", "sys/namespaces/workflow-ns", {})[0] == 204)
        scoped = {**basic, "cas": 0}
        check(
            "namespace_scoped_management",
            call("POST", "sys/workflows/manage/operations/basic", scoped, namespace="workflow-ns")[0] == 200,
        )
        check(
            "namespace_scoped_isolation",
            call("GET", "sys/workflows/manage/operations/basic")[0] == 200
            and call("GET", "sys/workflows/manage/operations/basic", namespace="workflow-ns")[1]["data"]["version"] == 1,
        )

        instance.stop()
        instance.start()
        check("restart_starts_sealed", call("GET", "sys/health")[0] == 503)
        check("restart_unseal", call("POST", "sys/unseal", {"key": unseal_key})[0] == 200)
        status, after_restart = call("GET", "sys/workflows/manage/operations/basic")
        check("workflow_survives_restart", status == 200 and after_restart["data"]["version"] == 1)
        status, deleted = call("DELETE", "sys/workflows/manage/operations/basic", {"cas": 1})
        check("delete_cas", status == 204 and deleted == {})
        check("delete_readback", call("GET", "sys/workflows/manage/operations/basic")[0] == 404)

        report = {
            "schema": "heptabao.workflow-bounded.v1",
            "status": "passed",
            "checks": checks,
            "bounded_profile": "authenticated namespace-scoped durable JSON workflows with local sequential dispatch and explicit outputs",
            "unauthenticated_execution": False,
            "trace_output": False,
            "crash_resumable_steps": False,
            "compatibility_claim": False,
            "production_authority": False,
            "candidate_binary_sha256": binary_sha256,
            "candidate_binary_source_head": source_head,
            "source_worktree_dirty": source_worktree_dirty,
        }
        output = Path(args.output)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"status": "passed", "check_count": len(checks)}))
        return 0
    except Exception as error:
        report = {
            "schema": "heptabao.workflow-bounded.v1",
            "status": "failed",
            "checks": checks,
            "safe_error": type(error).__name__,
            "compatibility_claim": False,
            "production_authority": False,
        }
        with Path(args.output).open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"status": "failed", "check_count": len(checks)}))
        return 1
    finally:
        instance.stop()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
