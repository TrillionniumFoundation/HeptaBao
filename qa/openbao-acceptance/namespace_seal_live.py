#!/usr/bin/env python3
"""Exercise the bounded namespace-seal routing profile on a real server.

The profile binds a namespace's sealed flag to the already authenticated global
barrier state. It proves durable seal/unseal routing, ancestor inheritance and
fail-closed access, but does not claim independent per-namespace key custody,
namespace key rotation or OpenBao's complete namespace workflow API.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
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
    checks: list[dict[str, object]] = []
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
    root = Path(tempfile.mkdtemp(prefix="heptabao-namespace-seal-"))
    root.chmod(0o700)
    instance = Instance(Path(args.binary), root / "candidate")
    unseal_key = ""

    def check(name: str, passed: bool) -> None:
        checks.append({"case": name, "passed": bool(passed)})
        if not passed:
            raise RuntimeError(name)

    try:
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        unseal_key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200)

        check(
            "create_namespace",
            instance.call("POST", "sys/namespaces/team", {})[0] == 200,
        )
        check(
            "create_child_before_parent_seal",
            instance.call("POST", "sys/namespaces/child", {}, namespace="team")[0] == 200,
        )
        check(
            "seal_namespace",
            instance.call("POST", "sys/namespaces/team/seal", {})[0] == 204,
        )
        status, info = instance.call("GET", "sys/namespaces/team/seal-status")
        check("sealed_state_readback", status == 200 and info.get("sealed") is True)
        status, seal_status = instance.call("GET", "sys/namespaces/team/seal-status")
        check("seal_status", status == 200 and seal_status.get("sealed") is True)
        check(
            "sealed_child_fails_closed",
            instance.call("GET", "secret/data/item", namespace="team")[0] == 503,
        )
        check(
            "sealed_descendant_inherits_parent_fence",
            instance.call("GET", "secret/data/item", namespace="team/child")[0] == 503,
        )
        check(
            "unauthorized_seal_control_denied",
            instance.call("POST", "sys/namespaces/team/unseal", {}, token="invalid")[0] == 403,
        )
        check(
            "parent_unseal",
            instance.call("POST", "sys/namespaces/team/unseal", {})[0] == 204,
        )
        check(
            "unsealed_child_reachable",
            instance.call("GET", "secret/data/item", namespace="team")[0] == 404,
        )
        check(
            "reseal",
            instance.call("POST", "sys/namespaces/team/seal", {})[0] == 204,
        )
        instance.stop()
        instance.start()
        check("restart_starts_globally_sealed", instance.call("GET", "sys/health")[0] == 503)
        check(
            "global_unseal_preserves_namespace_seal",
            instance.call("POST", "sys/unseal", {"key": unseal_key})[0] == 200,
        )
        status, seal_status = instance.call("GET", "sys/namespaces/team/seal-status")
        check("namespace_seal_survives_restart", status == 200 and seal_status.get("sealed") is True)
        check(
            "post_restart_fence",
            instance.call("GET", "secret/data/item", namespace="team")[0] == 503,
        )
        check(
            "post_restart_parent_unseal",
            instance.call("POST", "sys/namespaces/team/unseal", {})[0] == 204,
        )
        report = {
            "schema": "heptabao.namespace-seal-bounded.v1",
            "status": "passed",
            "checks": checks,
            "bounded_profile": "durable namespace seal flag; ancestor request fence; parent-controlled unseal; global barrier custody",
            "global_barrier_bound": True,
            "independent_namespace_key_hierarchy": False,
            "full_openbao_namespace_seal_compatibility": False,
            "independent_qualification": False,
            "candidate_binary_sha256": binary_sha256,
            "candidate_binary_source_head": source_head,
            "source_worktree_dirty": source_worktree_dirty,
            "execution_platform": platform.system() + " " + platform.machine(),
        }
        output = Path(args.output)
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"status": "passed", "check_count": len(checks)}))
        return 0
    except Exception as error:
        output = Path(args.output)
        report = {
            "schema": "heptabao.namespace-seal-bounded.v1",
            "status": "failed",
            "checks": checks,
            "safe_error": type(error).__name__,
        }
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"status": "failed", "check_count": len(checks)}))
        return 1
    finally:
        instance.stop()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
