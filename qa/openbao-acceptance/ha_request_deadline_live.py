#!/usr/bin/env python3
"""Observe original HTTPS deadlines under real HA quorum loss and read contention.

Only fixture-owned processes are paused. Responses and peer-initiated connection
termination are reported separately; a client watchdog timeout is never a pass.
This does not observe internal lock ownership or prove cancellation of writes,
filesystem calls or already-entered side effects.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import shutil
import signal
import tempfile
import threading
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT
from ha_destructive import FixtureError
from ha_network_partition import PartitionCluster
from ha_verified_read_live import KEY, exact_value, read_exact, write_once
from online_evidence import admit_output, complete_checks, source_identity

LISTENER_SECONDS = 5.0
OBSERVER_SLACK_SECONDS = .75
CLIENT_WATCHDOG_SECONDS = 8.0
BODY_HOLD_SECONDS = 3.5
CONTENDED_READS = 12
MAX_RESPONSE_BYTES = 64 * 1024
REQUIRED = frozenset({
    "listener_original_budget_confirmed", "warm_read_exact", "healthy_delayed_get_body_accepted",
    "followers_paused", "lost_quorum_explicit_http_503", "contended_headers_before_release",
    "contended_body_before_deadlines", "contended_explicit_http_denials_observed",
    "all_contended_reads_bounded", "contended_original_budget_exhausted", "same_processes_alive", "quorum_restored",
    "recovered_write_acknowledged", "recovered_all_voters_exact", "secrets_absent",
    "cleanup_complete", "complete",
} | {f"contended_denied_{i}" for i in range(CONTENDED_READS)})


class DeadlineCluster(PartitionCluster):
    def configure(self):
        super().configure()
        for node in self.nodes:
            path = node.root / "server.json"
            config = json.loads(path.read_text())
            if config.get("timeout_seconds") != LISTENER_SECONDS:
                raise FixtureError("unexpected_listener_budget")
            # A lifecycle worker has no HTTP request deadline; remove that
            # independent workload from this narrowly attributed test.
            config["lifecycle_interval_seconds"] = 0
            path.write_text(json.dumps(config))


def safe_outcome(row):
    expected = {"ordinal", "status", "termination", "elapsed_ms", "body_sent_ms", "no_payload"}
    if not isinstance(row, dict) or set(row) != expected:
        return False
    for field in ("elapsed_ms", "body_sent_ms"):
        value = row[field]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            return False
    if (type(row["ordinal"]) is not int or row["ordinal"] < 0
            or row["body_sent_ms"] >= (LISTENER_SECONDS - .2) * 1000
            or row["elapsed_ms"] < row["body_sent_ms"]
            or row["elapsed_ms"] > (LISTENER_SECONDS + OBSERVER_SLACK_SECONDS) * 1000
            or row["no_payload"] is not True):
        return False
    if row["termination"] == "http":
        return type(row["status"]) is int and row["status"] == 503
    return row["termination"] == "peer_eof" and row["status"] is None


def complete(checks):
    return (complete_checks(checks, required_cases=REQUIRED)
            and checks[-1]["case"] == "complete")


def complete_observations(observations):
    if not isinstance(observations, list) or len(observations) != 3:
        return False
    try:
        control, lost, contended = observations
        rows, gate = contended["requests"], contended["gate"]
        if (control["phase"] != "healthy_same_delayed_get" or control["http_status"] != 200
                or control["gate"]["body_hold_seconds"] != BODY_HOLD_SECONDS
                or not BODY_HOLD_SECONDS * 1000 <= control["elapsed_ms"] < LISTENER_SECONDS * 1000
                or lost["phase"] != "lost_quorum" or len(lost["requests"]) != 1
                or not safe_outcome(lost["requests"][0])
                or lost["requests"][0]["termination"] != "http"
                or contended["phase"] != "contended_read_admission"
                or gate["request_count"] != CONTENDED_READS
                or gate["all_headers_sent_before_body_release"] is not True
                or gate["all_bodies_released_before_original_deadlines"] is not True
                or gate["body_hold_seconds"] != BODY_HOLD_SECONDS
                or len(rows) != CONTENDED_READS
                or {row["ordinal"] for row in rows} != set(range(CONTENDED_READS))
                or not all(safe_outcome(row) and row["body_sent_ms"] >= BODY_HOLD_SECONDS * 1000 for row in rows)
                or max(row["elapsed_ms"] for row in rows) < (LISTENER_SECONDS - .2) * 1000):
            return False
        explicit = sum(row["termination"] == "http" for row in rows)
        return (explicit > 0 and contended["http_503_count"] == explicit
                and contended["peer_termination_count"] == len(rows) - explicit
                and contended["all_requests_returned_http_503"] is (explicit == len(rows)))
    except (KeyError, TypeError, ValueError):
        return False


def delayed_get(node, bearer, ordinal, headers, release):
    """One connection, one GET, no retry; watchdog failure propagates."""
    started = time.monotonic()
    connection = http.client.HTTPSConnection(
        "127.0.0.1", node.http_port, context=node.context, timeout=CLIENT_WATCHDOG_SECONDS)
    body_sent = None
    try:
        connection.connect()
        connection.putrequest("GET", "/v1/" + KEY)
        connection.putheader("X-Vault-Token", bearer)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "2")
        connection.putheader("Connection", "close")
        connection.endheaders()
        headers.put((ordinal, started, time.monotonic()))
        if not release.wait(CLIENT_WATCHDOG_SECONDS - (time.monotonic() - started)):
            raise FixtureError("body_gate_not_released")
        body_sent = time.monotonic() - started
        if body_sent >= LISTENER_SECONDS - .2:
            raise FixtureError("body_not_sent_before_original_deadline")
        connection.send(b"{}")
        body_sent = time.monotonic() - started
        if body_sent >= LISTENER_SECONDS - .2:
            raise FixtureError("body_not_completed_before_original_deadline")
        # Client watchdog is later than the server deadline, and is absolute.
        connection.sock.settimeout(max(.001, CLIENT_WATCHDOG_SECONDS - (time.monotonic() - started)))
        try:
            response = connection.getresponse()
        except http.client.RemoteDisconnected:
            termination, status, body = "peer_eof", None, {}
        else:
            # Partial/truncated/malformed responses fail; they are not evidence
            # that no payload was released. Nothing raw is put in a receipt.
            with response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise FixtureError("response_exceeds_bound")
                body = json.loads(raw) if raw else {}
                if not isinstance(body, dict):
                    raise FixtureError("response_not_object")
                termination, status = "http", int(response.status)
        row = {"ordinal": ordinal, "status": status, "termination": termination,
               "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
               "body_sent_ms": round(body_sent * 1000, 3),
               "no_payload": not any(body.get(k) for k in ("data", "auth", "wrap_info"))}
        return row, body
    finally:
        connection.close()


def read_group(node, bearer, count, hold_seconds):
    headers, release = queue.Queue(), threading.Event()
    with ThreadPoolExecutor(max_workers=count, thread_name_prefix="deadline-get") as pool:
        futures = [pool.submit(delayed_get, node, bearer, i, headers, release) for i in range(count)]
        try:
            received = []
            header_limit = time.monotonic() + 2
            while len(received) < count:
                remaining = header_limit - time.monotonic()
                if remaining <= 0:
                    raise FixtureError("concurrent_tls_headers_not_ready")
                received.append(headers.get(timeout=remaining))
            if {row[0] for row in received} != set(range(count)):
                raise FixtureError("duplicate_or_missing_header_event")
            all_pending = all(not future.done() for future in futures)
            time.sleep(hold_seconds)
            release_at = time.monotonic()
            in_time = all(release_at - started < LISTENER_SECONDS - .2 for _, started, _ in received)
            if not all_pending or not in_time:
                raise FixtureError("concurrent_body_gate_did_not_prove_order")
            release.set()
            results = [future.result(timeout=CLIENT_WATCHDOG_SECONDS) for future in futures]
            return results, {"request_count": count,
                "all_headers_sent_before_body_release": all_pending,
                "all_bodies_released_before_original_deadlines": in_time,
                "header_spread_ms": round((max(r[2] for r in received) - min(r[2] for r in received)) * 1000, 3),
                "body_hold_seconds": hold_seconds}
        finally:
            release.set()


def pause_followers(nodes):
    for node in nodes:
        os.kill(node.process.pid, signal.SIGSTOP)
    limit = time.monotonic() + 1
    while True:
        stopped = []
        for node in nodes:
            if node.process.poll() is not None:
                raise FixtureError("follower_exited_before_pause")
            # Linux guest only: an alive PID alone does not prove SIGSTOP took
            # effect before the first fault request.
            status = Path(f"/proc/{node.process.pid}/status").read_text()
            state = next((line.split()[1] for line in status.splitlines() if line.startswith("State:")), None)
            stopped.append(state in ("T", "t"))
        if all(stopped):
            return
        if time.monotonic() >= limit:
            raise FixtureError("followers_did_not_stop")
        time.sleep(.01)


def scan_secrets(cluster, samples, report_parts):
    needles = [sample.encode() for sample in samples]
    for node in cluster.nodes:
        files = [p for folder in (node.data_dir, node.root / "raft") if folder.exists()
                 for p in folder.rglob("*") if p.is_file()]
        files += [node.root / "audit.jsonl", node.root / "process.log"]
        for path in files:
            if path.exists():
                content = path.read_bytes()
                if any(needle in content for needle in needles):
                    return False
    return not any(needle in json.dumps(report_parts).encode() for needle in needles)


def run(binary, root, checks, observations, inherited):
    cluster = None
    def check(name, passed):
        checks.append({"case": name, "passed": bool(passed)})
        if not passed:
            raise FixtureError(name)
    try:
        cluster = DeadlineCluster(binary, root / "cluster")
        cluster.bootstrap()
        inherited.extend(cluster.scenarios)
        check("listener_original_budget_confirmed", all(
            json.loads((node.root / "server.json").read_text())["timeout_seconds"] == LISTENER_SECONDS
            for node in cluster.nodes))
        leader = cluster.leader()
        pids = [node.process.pid for node in cluster.nodes]
        old, new = secrets.token_hex(24), secrets.token_hex(24)
        write_once(leader, cluster.root_token, old, 0)
        for _ in range(4):
            read_exact(leader, cluster.root_token, old, 1)
        check("warm_read_exact", True)
        control, gate = read_group(leader, cluster.root_token, 1, BODY_HOLD_SECONDS)
        row, body = control[0]
        check("healthy_delayed_get_body_accepted", row["termination"] == "http"
              and exact_value(row["status"], body, old, 1)
              and row["elapsed_ms"] < LISTENER_SECONDS * 1000)
        observations.append({"phase": "healthy_same_delayed_get", "gate": gate,
                             "elapsed_ms": row["elapsed_ms"], "http_status": row["status"]})
        followers = [node for node in cluster.nodes if node is not leader]
        pause_followers(followers)
        check("followers_paused", len(followers) == 2)
        # These are stopped fixture followers, not a network listener timeout.
        # The target HTTPS leader stays scheduled throughout both phases.
        single, _ = read_group(leader, cluster.root_token, 1, 0)
        row, _ = single[0]
        check("lost_quorum_explicit_http_503", safe_outcome(row) and row["termination"] == "http")
        observations.append({"phase": "lost_quorum", "requests": [row]})
        results, gate = read_group(leader, cluster.root_token, CONTENDED_READS, BODY_HOLD_SECONDS)
        check("contended_headers_before_release", gate["all_headers_sent_before_body_release"])
        check("contended_body_before_deadlines", gate["all_bodies_released_before_original_deadlines"])
        rows = [row for row, _ in results]
        for row in rows:
            check(f"contended_denied_{row['ordinal']}", safe_outcome(row))
        http_count = sum(row["termination"] == "http" for row in rows)
        check("contended_explicit_http_denials_observed", http_count > 0)
        observations.append({"phase": "contended_read_admission", "gate": gate, "requests": rows,
            "http_503_count": http_count, "peer_termination_count": len(rows) - http_count,
            "all_requests_returned_http_503": http_count == len(rows)})
        check("all_contended_reads_bounded", all(safe_outcome(row) for row in rows))
        check("contended_original_budget_exhausted",
              max(row["elapsed_ms"] for row in rows) >= (LISTENER_SECONDS - .2) * 1000)
        check("same_processes_alive", pids == [node.process.pid for node in cluster.nodes]
              and all(node.process.poll() is None for node in cluster.nodes))
        for node in followers:
            os.kill(node.process.pid, signal.SIGCONT)
        cluster._heal()
        leader = cluster.leader()
        read_exact(leader, cluster.root_token, old, 1, recover=True)
        check("quorum_restored", True)
        # No mutation is attempted during the fault. Recovery writes once; an
        # ambiguous acknowledgement fails immediately and is never retried.
        write_once(leader, cluster.root_token, new, 1)
        check("recovered_write_acknowledged", True)
        for node in cluster.nodes:
            read_exact(node, cluster.root_token, new, 2, recover=True)
        check("recovered_all_voters_exact", True)
        check("secrets_absent", scan_secrets(cluster,
            [old, new, cluster.root_token, cluster.unseal_key], {"checks": checks, "observations": observations}))
    finally:
        if cluster is not None:
            # Always unstop every still-owned process, even if a prior phase
            # fails, then close all six links and kill/reap every child.
            try:
                for node in cluster.nodes:
                    if node.process is not None and node.process.poll() is None:
                        os.kill(node.process.pid, signal.SIGCONT)
            finally:
                cluster.close()
    check("cleanup_complete", True)
    check("complete", True)


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
    root = Path(tempfile.mkdtemp(prefix="heptabao-ha-request-deadline-"))
    root.chmod(0o700)
    checks, observations, inherited, failure = [], [], [], None
    def interrupted(signum, frame):
        raise FixtureError("fixture_interrupted")
    handlers = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGINT, signal.SIGTERM)}
    try:
        if before["source_dirty"]:
            raise FixtureError("source_not_clean")
        run(binary, root, checks, observations, inherited)
    except Exception as error:
        failure = next((r["case"] for r in reversed(checks) if r["passed"] is False), "fixture_" + type(error).__name__)
    finally:
        for kind, handler in handlers.items():
            signal.signal(kind, handler)
        shutil.rmtree(root)
    after = source_identity(ROOT, binary)
    same_runner = runner_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if before != after or not same_runner:
        failure = "source_binary_or_runner_changed"
    if not complete(checks) or not complete_observations(observations):
        failure = failure or "incomplete_observations"
    report = {"schema": "heptabao.ha-request-deadline.v1", **before,
        "status": "passed" if failure is None else "failed", "failure": failure,
        "build_source_commit": args.build_source_commit, "checks": checks,
        "observations": observations, "bootstrap_checks": inherited,
        "source_and_binary_unchanged": before == after, "runner_sha256": runner_hash,
        "runner_unchanged": same_runner, "listener_timeout_seconds": LISTENER_SECONDS,
        "observer_slack_seconds": OBSERVER_SLACK_SECONDS, "client_watchdog_seconds": CLIENT_WATCHDOG_SECONDS,
        "original_deadline_basis": "listener accepts before TLS handshake and all request body bytes",
        "internal_lock_or_read_index_wait_observed": False,
        "server_connection_termination_is_http_503": False,
        "write_cancellation_proven": False, "mutation_retries": 0, "mutations_during_fault": 0,
        "synthetic_same_host_three_processes": True, "full_openbao_compatibility": False,
        "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "checks": len(checks), "failure": failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
