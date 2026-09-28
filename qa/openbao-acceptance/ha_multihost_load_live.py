#!/usr/bin/env python3
"""Compose bounded concurrent writes with the existing private three-host lifecycle.

Every synthetic mutation is submitted once. Exact version-one readback is
required before and after faults. This sample is not a throughput benchmark,
long-horizon linearizability proof, or full replacement admission.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import math
import secrets
import time

import ha_multihost_live as ha

REQUIRED_CHECKS = frozenset({
    "load_healthy_writes_once", "load_healthy_exact_readback",
    "load_snapshot_acknowledgements", "load_two_voter_writes_once",
    "load_two_voter_exact_readback", "load_rejoined_acknowledgements",
    "load_recovered_writes_once", "load_recovered_exact_readback",
    "load_all_hosts_converged", "load_cleanup_once", "load_cleanup_absence",
})


def latency_summary(samples):
    ordered = sorted(samples)
    if not ordered or any(not math.isfinite(value) or value < 0 for value in ordered):
        raise ha.FixtureError("load_invalid_latency_sample")
    return {"requests": len(ordered), "p50_ms": round(ordered[(len(ordered) - 1) // 2] * 1000, 3),
            "p95_ms": round(ordered[math.ceil(len(ordered) * .95) - 1] * 1000, 3),
            "max_ms": round(ordered[-1] * 1000, 3)}


class LoadLifecycle:
    required_checks = REQUIRED_CHECKS
    runner_path = Path(__file__)
    schema = "heptabao.multihost-load-ha.v1"
    scope = "bounded-concurrent-CAS-writes-and-fault-recovery-not-long-horizon"

    def __init__(self):
        self.context = None
        self.check = None
        self.root = ""
        self.prefix = ""
        self.nodes = []
        self.values = {}
        self.phases = set()

    def runtime_secrets(self):
        return (self.root,) if self.root else ()

    def clear(self):
        self.root = ""
        self.values.clear()
        self.nodes.clear()

    def _read_once(self, node, path, value):
        status, body = ha.api(self.context, node, "GET", "secret/data/" + path,
                              token=self.root, timeout=12)
        data = body.get("data", {})
        if not (status == 200 and data.get("data") == {"value": value}
                and data.get("metadata", {}).get("version") == 1):
            raise ha.FixtureError("load_readback_not_exact_version_one_" + ha.response_failure_code(status, body))

    def _batch(self, phase, nodes, per_worker):
        if phase in self.phases or not nodes or not 1 <= per_worker <= 8:
            raise ha.FixtureError("load_invalid_or_repeated_phase")
        self.phases.add(phase)
        batches = []
        for worker, node in enumerate(nodes):
            items = [(f"{self.prefix}/{phase}-{worker}-{index}", secrets.token_hex(16))
                     for index in range(per_worker)]
            for path, value in items:
                if path in self.values:
                    raise ha.FixtureError("load_duplicate_operation_identity")
                self.values[path] = value
            batches.append((node, items))

        def execute(batch):
            node, items = batch
            samples = []
            for path, value in items:
                start = time.monotonic()
                # No retry loop, including for transport loss or HTTP 503.
                ha.write_once(self.context, node, self.root, path, value)
                samples.append(time.monotonic() - start)
                self._read_once(node, path, value)
            return samples

        # Executor completion drains in-flight requests even if another worker
        # fails; it does not resubmit them or turn uncertainty into success.
        with ThreadPoolExecutor(max_workers=len(nodes)) as executor:
            futures = [executor.submit(execute, batch) for batch in batches]
            samples = [sample for future in futures for sample in future.result()]
        self.check(f"load_{phase}_writes_once", len(samples) == len(nodes) * per_worker,
                   writers=len(nodes), mutations_retried=False, **latency_summary(samples))
        for node in nodes:
            for _, items in batches:
                for path, value in items:
                    self._read_once(node, path, value)
        self.check(f"load_{phase}_exact_readback", True,
                   reads=len(nodes) * len(samples), expected_version=1)

    def _verify_all(self, nodes):
        for node in nodes:
            for path, value in self.values.items():
                self._read_once(node, path, value)

    def setup(self, context, nodes, leader, standby, root_token, check):
        del leader, standby
        if self.root or self.phases:
            raise ha.FixtureError("load_setup_repeated")
        self.context, self.check, self.root = context, check, root_token
        self.nodes = list(nodes)
        self.prefix = "load-mh-" + secrets.token_hex(12)
        self._batch("healthy", self.nodes, 6)

    def after_snapshot(self, node):
        self._verify_all([node])
        self.check("load_snapshot_acknowledgements", True, writes=len(self.values))

    def after_failover(self, survivors, successor):
        del successor
        if len(survivors) != 2:
            raise ha.FixtureError("load_two_voter_scope_mismatch")
        self._batch("two_voter", survivors, 8)

    def after_rejoin(self, node):
        self._verify_all([node])
        self.check("load_rejoined_acknowledgements", True, writes=len(self.values))

    def after_quorum_recovery(self, nodes):
        self._batch("recovered", nodes, 6)
        self._verify_all(nodes)
        self.check("load_all_hosts_converged", True, writes=len(self.values), hosts=len(nodes))

    def cleanup(self, leader):
        for path in self.values:
            status, _ = ha.api(self.context, leader, "DELETE", "secret/metadata/" + path,
                               token=self.root, timeout=12)
            if status != 204:
                raise ha.FixtureError("load_cleanup_not_acknowledged_once")
        self.check("load_cleanup_once", True, deletes=len(self.values), mutations_retried=False)
        for node in self.nodes:
            for path in self.values:
                ha.wait_absent(self.context, node, self.root, path)
        self.check("load_cleanup_absence", True, hosts=len(self.nodes))


if __name__ == "__main__":
    raise SystemExit(ha.main(extension=LoadLifecycle()))
