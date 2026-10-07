#!/usr/bin/env python3
"""Exercise authenticated Raft leadership transfer under bounded real-process load.

Every application write uses a unique key plus CAS=0 and is attempted exactly
once. Only a returned HTTP 200 with version 1 is counted as acknowledged. The
interrupted phase writes a complete step-down HTTP request, deliberately reads
no response, then terminates the serving leader without retrying the admin
operation. This is same-version loopback evidence, not multi-host, WAN,
power-loss, mixed-version, or production qualification.
"""
from __future__ import annotations

import concurrent.futures
from pathlib import Path
import secrets
import socket
import threading
import time
import urllib.error

from ha_destructive import Cluster, FixtureError
from wrapping_ha import main as run_ha


REQUIRED_SCENARIOS = frozenset({
    "step_down.initial_acknowledged_values",
    "step_down.concurrent_load_started",
    "step_down.accepted_by_current_leader",
    "step_down.changed_leader",
    "step_down.concurrent_requests_overlap_transfer",
    "step_down.unique_single_attempt_load",
    "step_down.acknowledged_load_survives_transfer",
    "step_down.successor_reports_authority",
    "step_down.old_leader_forwards_after_transfer",
    "step_down.old_leader_restart",
    "step_down.acknowledged_load_survives_restart",
    "step_down.rejects_nonempty_body",
    "step_down.requires_authentication",
    "step_down.interrupted_request_sent_without_response",
    "step_down.successor_after_interrupted_request_and_leader_exit",
    "step_down.no_blind_admin_retry",
    "step_down.interrupted_phase_acknowledged_values_survive",
    "step_down.old_leader_rejoined_after_interruption",
    "step_down.fresh_write_after_recovery",
    "step_down.complete",
})


class StepDownCluster(Cluster):
    LOAD_WORKERS = 3
    WRITES_PER_WORKER = 8

    def _write_once(self, node, path: str, value: str) -> dict[str, object]:
        """Attempt one unique CAS=0 mutation and classify only observed facts."""
        started = time.monotonic()
        try:
            status, body = node.call(
                "POST",
                f"secret/data/{path}",
                {"data": {"value": value}, "options": {"cas": 0}},
                token=self.root_token,
                timeout=8,
            )
        except (OSError, urllib.error.URLError, TimeoutError):
            return {
                "path": path,
                "value": value,
                "started": started,
                "finished": time.monotonic(),
                "outcome": "unknown_no_retry",
            }
        finished = time.monotonic()
        version = body.get("data", {}).get("version") if isinstance(body, dict) else None
        if status == 200:
            if type(version) is not int or version != 1:
                raise FixtureError("step_down_acknowledged_write_not_exact_version_one")
            outcome = "acknowledged"
        elif status in (429, 503):
            if isinstance(body, dict) and body.get("data") not in (None, {}):
                raise FixtureError("step_down_refusal_released_application_data")
            outcome = "refused_no_retry"
        else:
            raise FixtureError("step_down_write_returned_unexpected_status")
        return {
            "path": path,
            "value": value,
            "started": started,
            "finished": finished,
            "outcome": outcome,
        }

    def _read_exact(self, node, path: str, value: str) -> None:
        """Retry only unavailable reads; a successful stale/wrong read fails."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status, body = node.call(
                    "GET", f"secret/data/{path}", token=self.root_token, timeout=5
                )
            except (OSError, urllib.error.URLError, TimeoutError):
                time.sleep(0.05)
                continue
            if status == 200:
                data = body.get("data", {}) if isinstance(body, dict) else {}
                if (
                    data.get("data", {}).get("value") != value
                    or data.get("metadata", {}).get("version") != 1
                ):
                    raise FixtureError("step_down_successful_read_not_exact")
                return
            if status not in (429, 503):
                raise FixtureError("step_down_acknowledged_value_not_visible")
            time.sleep(0.05)
        raise FixtureError("step_down_readback_timeout")

    def _verify_acknowledged(self, values: dict[str, str], nodes=None) -> None:
        selected = self.nodes if nodes is None else list(nodes)
        for node in selected:
            for path, value in values.items():
                self._read_exact(node, path, value)

    def _load_during_transfer(self, original) -> tuple[object, dict[str, str]]:
        records: list[dict[str, object]] = []
        lock = threading.Lock()
        start = threading.Barrier(self.LOAD_WORKERS + 1)

        def writer(worker: int) -> None:
            start.wait(timeout=5)
            for index in range(self.WRITES_PER_WORKER):
                path = f"step-down-load-{worker}-{index}"
                record = self._write_once(original, path, secrets.token_hex(16))
                with lock:
                    records.append(record)
                time.sleep(0.01)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.LOAD_WORKERS) as pool:
            futures = [pool.submit(writer, worker) for worker in range(self.LOAD_WORKERS)]
            start.wait(timeout=5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with lock:
                    if len(records) >= self.LOAD_WORKERS:
                        break
                time.sleep(0.005)
            with lock:
                started_count = len(records)
            self.check("step_down.concurrent_load_started", started_count >= self.LOAD_WORKERS)
            transfer_started = time.monotonic()
            status, body = original.call(
                "POST", "sys/step-down", {}, token=self.root_token, timeout=10
            )
            transfer_finished = time.monotonic()
            self.check(
                "step_down.accepted_by_current_leader", status == 204 and body == {}
            )
            for future in futures:
                future.result(timeout=20)

        successor = self.leader()
        self.check("step_down.changed_leader", successor is not original)
        with lock:
            snapshot = list(records)
        expected = self.LOAD_WORKERS * self.WRITES_PER_WORKER
        self.check(
            "step_down.unique_single_attempt_load",
            len(snapshot) == expected
            and len({record["path"] for record in snapshot}) == expected,
        )
        overlap = [
            record
            for record in snapshot
            if record["started"] <= transfer_finished
            and record["finished"] >= transfer_started
        ]
        self.check("step_down.concurrent_requests_overlap_transfer", bool(overlap))
        acknowledged = {
            str(record["path"]): str(record["value"])
            for record in snapshot
            if record["outcome"] == "acknowledged"
        }
        self.check(
            "step_down.acknowledged_load_survives_transfer",
            len(acknowledged) >= self.LOAD_WORKERS,
        )
        self._verify_acknowledged(acknowledged)
        return successor, acknowledged

    def _send_step_down_without_read(self, node) -> None:
        """Write one complete authenticated request and deliberately lose its reply."""
        token = self.root_token
        if not token or any(character in token for character in "\r\n"):
            raise FixtureError("invalid_fixture_root_token")
        body = b"{}"
        request = (
            f"POST /v1/sys/step-down HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{node.http_port}\r\n"
            "Accept: application/json\r\n"
            "Content-Type: application/json\r\n"
            f"X-Vault-Token: {token}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        raw = socket.create_connection(("127.0.0.1", node.http_port), timeout=3)
        stream = node.context.wrap_socket(raw, server_hostname="localhost")
        try:
            stream.settimeout(3)
            stream.sendall(request)
            try:
                stream.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            # Give the listener a bounded chance to consume the complete frame;
            # never receive, parse, or infer an acknowledgement.
            time.sleep(0.05)
        finally:
            stream.close()

    def run(self) -> None:
        # Keep this profile focused: use the inherited real-process bootstrap but
        # do not duplicate the complete destructive/network campaigns.
        self.bootstrap()
        original = self.leader()
        initial: dict[str, str] = {}
        for index in range(4):
            path, value = f"step-down-initial-{index}", secrets.token_hex(16)
            record = self._write_once(original, path, value)
            if record["outcome"] != "acknowledged":
                raise FixtureError("step_down_initial_write_not_acknowledged")
            initial[path] = value
        self._verify_acknowledged(initial)
        self.check("step_down.initial_acknowledged_values", True)

        successor, acknowledged = self._load_during_transfer(original)
        status, leader = successor.call("GET", "sys/leader", token=self.root_token)
        self.check(
            "step_down.successor_reports_authority",
            status == 200 and leader.get("is_self") is True,
        )
        forwarded_path, forwarded_value = "after-explicit-step-down", secrets.token_hex(16)
        forwarded = self._write_once(original, forwarded_path, forwarded_value)
        self.check(
            "step_down.old_leader_forwards_after_transfer",
            forwarded["outcome"] == "acknowledged",
        )
        acknowledged[forwarded_path] = forwarded_value
        self._verify_acknowledged(acknowledged)

        original.stop()
        self.leader()
        self.restart(original)
        self.leader()
        self.check("step_down.old_leader_restart", True)
        self._verify_acknowledged({**initial, **acknowledged})
        self.check("step_down.acknowledged_load_survives_restart", True)

        current = self.leader()
        status, denied = current.call(
            "POST", "sys/step-down", {"unexpected": True}, token=self.root_token
        )
        self.check(
            "step_down.rejects_nonempty_body",
            status == 400 and bool(denied.get("errors")),
        )
        status, denied = current.call("POST", "sys/step-down", {}, token="")
        self.check(
            "step_down.requires_authentication",
            status == 403 and bool(denied.get("errors")),
        )

        interrupted_values: dict[str, str] = {}
        for index in range(6):
            path, value = f"step-down-interrupted-{index}", secrets.token_hex(16)
            record = self._write_once(current, path, value)
            if record["outcome"] != "acknowledged":
                raise FixtureError("step_down_interrupted_seed_write_not_acknowledged")
            interrupted_values[path] = value
        self._send_step_down_without_read(current)
        self.check("step_down.interrupted_request_sent_without_response", True)
        # The client has no terminal response and does not retry. Terminating the
        # serving leader forces reconciliation from committed cluster state.
        current.stop()
        recovered = self.leader()
        self.check(
            "step_down.successor_after_interrupted_request_and_leader_exit",
            recovered is not current,
        )
        self.check("step_down.no_blind_admin_retry", True)
        self._verify_acknowledged(interrupted_values, self.running())
        self.check("step_down.interrupted_phase_acknowledged_values_survive", True)
        self.restart(current)
        self.leader()
        self._verify_acknowledged(interrupted_values)
        self.check("step_down.old_leader_rejoined_after_interruption", True)

        fresh_path, fresh_value = "step-down-after-recovery", secrets.token_hex(16)
        fresh = self._write_once(current, fresh_path, fresh_value)
        self.check(
            "step_down.fresh_write_after_recovery",
            fresh["outcome"] == "acknowledged",
        )
        self._verify_acknowledged({fresh_path: fresh_value})
        missing = REQUIRED_SCENARIOS.difference(self.scenarios).difference(
            {"step_down.complete"}
        )
        if missing:
            raise FixtureError("step_down_required_scenarios_missing")
        self.check("step_down.complete", True)


if __name__ == "__main__":
    raise SystemExit(
        run_ha(
            cluster_type=StepDownCluster,
            profile="ha-step-down",
            runner_path=Path(__file__),
            scope=(
                "same-version loopback three-voter leadership transfer under unique CAS load; "
                "complete request/response-loss plus serving-leader exit, restart, and exact "
                "readback of every acknowledged write; no mixed-version, multi-host, WAN, "
                "power-loss, or independent qualification"
            ),
        )
    )
