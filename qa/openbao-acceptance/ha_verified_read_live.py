#!/usr/bin/env python3
"""Observe read consistency across real three-process HA authority changes.

Repeated reads exercise the workload eligible for verified-read reuse. This
fixture observes HTTPS results, not internal cache hits or performance. Faults
use the existing bounded opaque loopback links and fixture-owned processes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT
from ha_destructive import FixtureError
from ha_network_partition import PartitionCluster, inactive_health
from online_evidence import admit_output, source_identity

KEY = "secret/data/ha-verified-read/value"
WARM_READS = 8
REQUIRED_PHASES = frozenset({
    "warm_initial_complete", "updated_value_visible", "isolated_warm_reads_denied",
    "majority_new_value_visible", "partition_healed", "all_quorum_reads_denied",
    "quorum_restored", "sealed_reads_denied", "unsealed_latest_visible",
    "restart_latest_visible", "complete",
})


def exact_value(status, body, value, version):
    data = body.get("data") if isinstance(body, dict) else None
    metadata = data.get("metadata") if isinstance(data, dict) else None
    return (type(status) is int and status == 200 and isinstance(metadata, dict)
            and type(metadata.get("version")) is int and metadata["version"] == version
            and data.get("data") == {"value": value})


def read_denied(status, body):
    return (type(status) is int and status == 503 and isinstance(body, dict)
            and not any(body.get(key) for key in ("data", "auth", "wrap_info")))


def read_exact(node, token, value, version, *, recover=False):
    """Never hide a successful stale read by waiting for a later good one."""
    deadline = time.monotonic() + 30
    while True:
        status, body = node.call("GET", KEY, token=token, timeout=10)
        if exact_value(status, body, value, version):
            return
        if (type(status) is not int or status not in (429, 503)
                or not recover or time.monotonic() >= deadline):
            raise FixtureError("acknowledged_value_or_version_not_exact")
        time.sleep(.1)


def write_once(node, token, value, previous):
    # A timed out or uncertain mutation is never replayed.
    status, body = node.call("POST", KEY,
        {"data": {"value": value}, "options": {"cas": previous}}, token=token, timeout=15)
    version = body.get("data", {}).get("version")
    if type(status) is not int or status != 200 or type(version) is not int or version != previous + 1:
        raise FixtureError("write_not_exactly_acknowledged")


def complete_checks(checks):
    names = []
    for row in checks:
        if (not isinstance(row, dict) or set(row) != {"case", "passed"}
                or row["passed"] is not True or not isinstance(row["case"], str)
                or re.fullmatch(r"[a-z0-9_]{1,120}", row["case"]) is None):
            return False
        names.append(row["case"])
    return (bool(names) and names[-1] == "complete" and len(names) == len(set(names))
            and REQUIRED_PHASES.issubset(names))


def run(binary, root, checks, observations, inherited):
    cluster = None

    def check(name, passed):
        checks.append({"case": name, "passed": bool(passed)})
        if not passed:
            raise FixtureError(name)

    def visible(node, value, version, phase, *, recover=False, count=1):
        for ordinal in range(count):
            read_exact(node, cluster.root_token, value, version, recover=recover)
            check(f"{phase}_node_{node.node_id}_read_{ordinal}", True)

    def denied(node, phase, count=3):
        statuses = []
        for ordinal in range(count):
            status, body = node.call("GET", KEY, token=cluster.root_token, timeout=10)
            statuses.append(status)
            check(f"{phase}_node_{node.node_id}_denied_{ordinal}", read_denied(status, body))
        observations.append({"phase": phase, "node": node.node_id, "http_statuses": statuses})

    def all_visible(value, version, phase):
        for node in cluster.nodes:
            visible(node, value, version, phase, recover=True)

    try:
        cluster = PartitionCluster(binary, root / "cluster")
        cluster.bootstrap()
        inherited.extend(cluster.scenarios)
        leader = cluster.leader()
        original_pids = [node.process.pid for node in cluster.nodes]
        # Unique values avoid accidentally reading another fixture's data. No
        # payload, bearer, unseal key or raw response is included in the report.
        values = [secrets.token_hex(20) for _ in range(6)]
        write_once(leader, cluster.root_token, values[0], 0)
        check("initial_write_acknowledged", True)
        visible(leader, values[0], 1, "warm_initial", count=WARM_READS)
        all_visible(values[0], 1, "initial")
        check("warm_initial_complete", True)

        write_once(leader, cluster.root_token, values[1], 1)
        check("updated_write_acknowledged", True)
        visible(leader, values[1], 2, "warm_updated", count=WARM_READS)
        all_visible(values[1], 2, "updated")
        check("updated_value_visible", True)

        isolated = leader
        cluster._partition(isolated.node_id, outbound_only=False)
        leader = cluster.leader()
        check("majority_elected_new_leader", leader is not isolated)
        status, health = isolated.call("GET", "sys/health", timeout=10)
        check("isolated_authority_inactive", inactive_health(status, health))
        denied(isolated, "isolated_before_new_write")
        check("isolated_warm_reads_denied", True)
        visible(leader, values[1], 2, "majority_previous", recover=True)
        write_once(leader, cluster.root_token, values[2], 2)
        check("majority_write_acknowledged", True)
        for node in cluster.nodes:
            if node is not isolated:
                visible(node, values[2], 3, "majority_latest", recover=True)
        denied(isolated, "isolated_after_new_write")
        check("majority_new_value_visible", True)
        cluster._heal()
        leader = cluster.leader()
        all_visible(values[2], 3, "healed")
        check("partition_same_processes", original_pids == [node.process.pid for node in cluster.nodes])
        check("partition_healed", True)

        for node in cluster.nodes:
            visible(node, values[2], 3, "warm_before_full_partition", count=3)
        for link in cluster.links.values():
            link.set_blocked(True)
        # Existing HA fault fixtures use this bounded election/lease settling
        # interval. A health hint alone is insufficient: every data read below
        # must then refuse admission, including the formerly warmed leader.
        time.sleep(3)
        for node in cluster.nodes:
            status, health = node.call("GET", "sys/health", timeout=10)
            check(f"full_partition_node_{node.node_id}_inactive", inactive_health(status, health))
            denied(node, "full_partition")
        check("all_quorum_reads_denied", True)
        cluster._heal()
        leader = cluster.leader()
        write_once(leader, cluster.root_token, values[3], 3)
        check("quorum_restored_write_acknowledged", True)
        all_visible(values[3], 4, "quorum_restored_latest")
        check("quorum_restored", True)

        visible(leader, values[3], 4, "warm_before_seal", count=WARM_READS)
        sealed = leader
        check("seal_acknowledged", sealed.call("POST", "sys/seal", {}, token=cluster.root_token)[0] == 204)
        status, health = sealed.call("GET", "sys/health", timeout=10)
        check("sealed_health_confirmed", status == 503 and health.get("sealed") is True)
        denied(sealed, "sealed")
        check("sealed_reads_denied", True)
        check("unseal_acknowledged", sealed.call("POST", "sys/unseal", {"key": cluster.unseal_key})[0] == 200)
        leader = cluster.leader()
        write_once(leader, cluster.root_token, values[4], 4)
        check("unsealed_new_write_acknowledged", True)
        all_visible(values[4], 5, "unsealed_latest")
        check("unsealed_latest_visible", True)

        visible(leader, values[4], 5, "warm_before_restart", count=WARM_READS)
        restarted, previous_pid = leader, leader.process.pid
        restarted.stop()
        leader = cluster.leader()
        check("restart_successor_elected", leader is not restarted)
        visible(leader, values[4], 5, "restart_previous", recover=True)
        write_once(leader, cluster.root_token, values[5], 5)
        check("restart_successor_write_acknowledged", True)
        cluster.restart(restarted)
        check("restarted_distinct_process", restarted.process.pid != previous_pid)
        cluster.leader()
        all_visible(values[5], 6, "restart_latest")
        visible(restarted, values[5], 6, "restart_repeated", count=WARM_READS)
        check("restart_latest_visible", True)
        check("complete", True)
    finally:
        if cluster is not None:
            # PartitionCluster.close attempts every owned process/link, and
            # raises on cleanup failure rather than reporting a passing run.
            cluster.close()


def terminate(signum, frame):
    raise FixtureError("fixture_interrupted")


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--build-source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    binary, output = args.binary.resolve(strict=True), args.output.absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, binary)
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="heptabao-verified-read-ha-"))
    root.chmod(0o700)
    handlers = {kind: signal.signal(kind, terminate) for kind in (signal.SIGTERM, signal.SIGINT)}
    checks, observations, inherited = [], [], []
    failure = None
    try:
        run(binary, root, checks, observations, inherited)
    except Exception as error:
        failure = next((row["case"] for row in reversed(checks) if row["passed"] is False),
                       "fixture_" + type(error).__name__)
    finally:
        for kind, handler in handlers.items():
            signal.signal(kind, handler)
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary)
    runner_unchanged = runner_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if not unchanged or not runner_unchanged:
        failure = "source_binary_or_runner_changed"
    if not complete_checks(checks):
        failure = failure or "incomplete_or_invalid_observations"
    report = {"schema": "heptabao.ha-verified-read-observations.v1", **before,
        "build_source_commit": args.build_source_commit,
        "status": "passed" if failure is None else "failed", "failure": failure,
        "checks": checks, "observations": observations, "bootstrap_checks": inherited,
        "source_and_binary_unchanged": unchanged, "harness_sha256": runner_hash,
        "harness_unchanged": runner_unchanged, "node_count": 3, "same_host": True,
        "storage": "local_journal", "internal_cache_observed": False,
        "performance_measurement": False, "physical_fault_qualification": False,
        "full_openbao_compatibility": False, "independent_qualification": False,
        "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed_during_execution")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "checks": len(checks), "failure": failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
