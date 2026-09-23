#!/usr/bin/env python3
"""Exercise the bounded workflow/profile API over the real TLS service.

The fixture intentionally uses only the public HTTPS API. It does not provide
an outbound URL, shell, plugin, caller identity or authorization field to the
workflow request, and it never writes a secret marker to the evidence file.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile


def load_smoke():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("workflow_tls_smoke", root / "single-node" / "smoke.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("TLS fixture loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or not output.parent.is_dir():
        parser.error("output must be a new file in an existing private directory")
    mode = output.parent.stat()
    if mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        parser.error("output directory must be private and caller-owned")

    smoke = load_smoke()
    root = Path(tempfile.mkdtemp(prefix="heptabao-workflow-profile-"))
    root.chmod(0o700)
    instance = None
    report = {
        "schema": "heptabao.workflow-profile-live.v1",
        "synthetic_only": True,
        "production_authority": False,
        "independent_qualification": False,
        "cases": [],
    }

    def check(name: str, condition: bool) -> None:
        report["cases"].append({"case": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError(name)

    def request(method: str, path: str, body=None, *, namespace: str = ""):
        return instance.call(method, path, body, namespace=namespace)

    try:
        instance = smoke.Instance(binary, root / "server")
        instance.start()
        status, initialized = request("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("tls_initialize", status == 200)
        instance.token = initialized["root_token"]
        check("tls_unseal", request("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] == 200)

        marker = "workflow-marker-" + secrets.token_hex(24)
        check(
            "input_write",
            request("POST", "secret/data/workflow-input", {"data": {"value": marker}})[0] == 200,
        )
        profile = {
            "revision": 1,
            "steps": [
                {
                    "id": "read_input",
                    "depends_on": [],
                    "operation": "KvRead",
                    "target": "secret/data/workflow-input",
                    "secret_output": False,
                },
                {
                    "id": "write_output",
                    "depends_on": ["read_input"],
                    "operation": "KvWrite",
                    "target": "secret/data/workflow-output",
                    "secret_output": False,
                },
            ],
        }
        status, body = request("POST", "sys/workflows/profiles/safe-copy", profile)
        check("profile_create", status == 204 and not body)
        status, fetched = request("GET", "sys/workflows/profiles/safe-copy")
        check("profile_read", status == 200 and fetched["data"]["revision"] == 1)

        run_body = {"request_id": "request-1", "values": {"write_output": {"data": {"value": marker}}}}
        status, run = request("POST", "sys/workflows/profiles/safe-copy/runs", run_body)
        check("run_succeeds", status == 200 and run["data"]["phase"] == "Succeeded")
        check("run_response_redacted", marker not in json.dumps(run))
        run_id = run["data"]["id"]
        status, duplicate = request("POST", "sys/workflows/profiles/safe-copy/runs", run_body)
        check("duplicate_replay_same_run", status == 200 and duplicate["data"]["id"] == run_id)
        check("duplicate_replay_no_new_version", request("GET", "secret/data/workflow-output")[1]["data"]["metadata"]["version"] == 1)
        status, output_body = request("GET", "secret/data/workflow-output")
        check("output_write_exact", status == 200 and output_body["data"]["data"]["value"] == marker)
        status, run_status = request("GET", f"sys/workflows/runs/{run_id}")
        check("run_status_readback", status == 200 and run_status["data"]["phase"] == "Succeeded")

        check("ssrf_profile_rejected", request("POST", "sys/workflows/profiles/ssrf", {
            "revision": 1,
            "steps": [{"id": "egress", "depends_on": [], "operation": "KvRead", "target": "https://127.0.0.1", "secret_output": False}],
        })[0] == 400)
        check("path_escape_rejected", request("POST", "sys/workflows/profiles/escape", {
            "revision": 1,
            "steps": [{"id": "escape", "depends_on": [], "operation": "KvRead", "target": "secret/data/../../outside", "secret_output": False}],
        })[0] == 400)
        check("unknown_action_rejected", request("POST", "sys/workflows/profiles/shell", {
            "revision": 1,
            "steps": [{"id": "shell", "depends_on": [], "operation": "Shell", "target": "secret/data/x", "secret_output": False}],
        })[0] == 400)
        check("secret_output_rejected", request("POST", "sys/workflows/profiles/echo", {
            "revision": 1,
            "steps": [{"id": "echo", "depends_on": [], "operation": "KvRead", "target": "secret/data/workflow-input", "secret_output": True}],
        })[0] == 400)
        check("caller_identity_rejected", request("POST", "sys/workflows/profiles/identity", {
            "revision": 1,
            "principal": "root",
            "steps": [],
        })[0] == 400)
        check("payload_bound", request("POST", "sys/workflows/profiles/safe-copy/runs", {
            "request_id": "oversized",
            "values": {"write_output": {"data": {"value": "x" * (16 * 1024 + 1)}}},
        })[0] == 413)
        check("cross_namespace_rejected", request("POST", "sys/workflows/profiles/safe-copy/runs", run_body, namespace="other") [0] == 404)
        check("reconcile_is_inspect_only", request("POST", f"sys/workflows/runs/{run_id}/reconcile", {})[1]["reconciliation"]["automatic_retry"] is False)

        instance.stop()
        instance.start()
        check("restart_sealed", request("GET", "sys/health")[0] == 503)
        check("restart_unseal", request("POST", "sys/unseal", {"key": initialized["keys_base64"][0]})[0] == 200)
        status, restarted = request("GET", f"sys/workflows/runs/{run_id}")
        check("restart_run_readback", status == 200 and restarted["data"]["phase"] == "Succeeded")
        check("restart_output_readback", request("GET", "secret/data/workflow-output")[1]["data"]["data"]["value"] == marker)
        report["status"] = "passed"
    except Exception as error:  # pragma: no cover - exercised by fixture failures
        report["status"] = "failed"
        report["failure"] = type(error).__name__
    finally:
        if instance is not None:
            try:
                instance.stop()
            except Exception:
                report["status"] = "failed"
                report["failure"] = "process_cleanup_failed"
        shutil.rmtree(root, ignore_errors=True)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"status": report["status"], "count": len(report["cases"]), "failure": report.get("failure")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
