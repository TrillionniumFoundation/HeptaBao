#!/usr/bin/env python3
"""Exercise real three-process HA through bounded, opaque loopback fault links.

Only services created by the inherited synthetic fixture are addressed. The links
relay encrypted bytes without terminating TLS or collecting payloads. This is a
repository-controlled process/network test, not independent qualification, a WAN
model, power-cut evidence, or a proof of arbitrary concurrent linearizability.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import secrets
import select
import signal
import socket
import subprocess
import sys
import threading
import time

# Keep script imports independent of the caller's current directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ha_destructive import Cluster, FixtureError, checked_binary


def shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def inactive_health(status: int, health: dict) -> bool:
    """Classify inactivity, never liveness or quorum health from a leader hint.

    A follower can retain a leader hint during a pre-vote partition and report
    standby (429). Data admission is checked separately and must refuse reads
    and writes without a reachable quorum. A 200 response is always a failure
    in the isolated set, even when it contradicts its own active flag.
    """
    return (type(status) is int and status in (429, 503)
            and health.get("ha_active") is False
            and (status != 429 or health.get("standby") is True))


class LoopbackLink:
    """A bounded TCP relay whose endpoints are exclusively fixture-owned ports."""

    MAX_CONNECTIONS = 32
    CHUNK_BYTES = 16 * 1024

    def __init__(self, target_port: int, owned_ports: set[int]):
        if type(target_port) is not int or not 0 < target_port < 65536 or target_port not in owned_ports:
            raise FixtureError("link_destination_not_owned_by_fixture")
        self.target_port = target_port
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._slots = threading.BoundedSemaphore(self.MAX_CONNECTIONS)
        self._threads: set[threading.Thread] = set()
        self._channels: set[socket.socket] = set()
        self._blocked = False
        self._generation = 0
        self._failed = False
        self._listener = socket.socket()
        # Node ports have been selected but may not yet be bound. Never reserve one.
        for attempt in range(16):
            self._listener.bind(("127.0.0.1", 0))
            self.port = int(self._listener.getsockname()[1])
            if self.port not in owned_ports:
                break
            self._listener.close()
            self._listener = socket.socket()
        else:
            self._listener.close()
            raise FixtureError("link_port_reservation_failed")
        self._listener.listen(self.MAX_CONNECTIONS)
        self._listener.settimeout(0.1)
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._failed = True
                return
            if address[0] != "127.0.0.1" or not self._slots.acquire(blocking=False):
                shutdown(client)
                continue
            with self._lock:
                if self._blocked or self._stop.is_set():
                    shutdown(client)
                    self._slots.release()
                    continue
                generation = self._generation
                self._channels.add(client)
                worker = threading.Thread(target=self._relay, args=(client, generation), daemon=True)
                self._threads.add(worker)
                try:
                    worker.start()
                except RuntimeError:
                    self._threads.remove(worker)
                    self._channels.remove(client)
                    shutdown(client)
                    self._slots.release()
                    self._failed = True

    def _relay(self, client: socket.socket, generation: int) -> None:
        remote = None
        try:
            remote = socket.create_connection(("127.0.0.1", self.target_port), timeout=0.5)
            client.settimeout(0.5)
            remote.settimeout(0.5)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self._lock:
                if self._blocked or self._stop.is_set() or generation != self._generation:
                    return
                self._channels.add(remote)
            while not self._stop.is_set():
                with self._lock:
                    if self._blocked or generation != self._generation:
                        return
                readable, _, _ = select.select([client, remote], [], [], 0.1)
                for source in readable:
                    payload = source.recv(self.CHUNK_BYTES)
                    if not payload:
                        return
                    destination = remote if source is client else client
                    destination.sendall(payload)
        except (OSError, ValueError):
            # Connection loss is the deliberate fault model. It is never replayed.
            pass
        except Exception:
            self._failed = True
        finally:
            with self._lock:
                self._channels.discard(client)
                if remote is not None:
                    self._channels.discard(remote)
                self._threads.discard(threading.current_thread())
            shutdown(client)
            if remote is not None:
                shutdown(remote)
            self._slots.release()

    def set_blocked(self, blocked: bool) -> None:
        if type(blocked) is not bool:
            raise FixtureError("invalid_link_fault_state")
        with self._lock:
            if self._blocked == blocked:
                return
            self._blocked = blocked
            self._generation += 1
            channels = tuple(self._channels)
        # Close established streams as well as refusing new connections. A worker
        # which is still connecting must recheck this generation before relaying.
        for channel in channels:
            shutdown(channel)

    def close(self) -> None:
        self._stop.set()
        self.set_blocked(True)
        self._listener.close()
        deadline = time.monotonic() + 5
        self._acceptor.join(timeout=1)
        with self._lock:
            workers = tuple(self._threads)
        for worker in workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._acceptor.is_alive() or any(worker.is_alive() for worker in workers) or self._failed:
            raise FixtureError("loopback_link_cleanup_or_worker_failed")


class PartitionCluster(Cluster):
    def __init__(self, binary: Path, root: Path):
        self.links: dict[tuple[int, int], LoopbackLink] = {}
        self.health_observations: list[dict] = []
        super().__init__(binary, root)

    def configure_ha(self) -> None:
        super().configure_ha()
        owned_ports = {port for node in self.nodes for port in (node.http_port, node.raft_port)}
        for source in self.nodes:
            config = json.loads(source.ha_config.read_text())
            peers = copy.deepcopy(config["peers"])
            for target in self.nodes:
                if source is target:
                    continue
                link = LoopbackLink(target.raft_port, owned_ports)
                self.links[(source.node_id, target.node_id)] = link
                peers[str(target.node_id)]["address"] = f"127.0.0.1:{link.port}"
            config["peers"] = peers
            # Reuse the inherited wrong-cluster check's fixed ha.json restoration
            # path. The original private file is ours, under a fresh synthetic root.
            source.ha_config.write_text(json.dumps(config))
        self.check("six_directed_opaque_loopback_links", len(self.links) == 6)

    def _partition(self, node_id: int, outbound_only: bool) -> None:
        for (source, target), link in self.links.items():
            link.set_blocked(source == node_id or (not outbound_only and target == node_id))

    def _heal(self) -> None:
        for link in self.links.values():
            link.set_blocked(False)

    def _new_value(self, node, path: str, value: str) -> None:
        status, body = node.call("POST", f"secret/data/{path}",
                                 {"data": {"value": value}, "options": {"cas": 0}},
                                 token=self.root_token)
        version = body.get("data", {}).get("version")
        if status != 200 or type(version) is not int or version != 1:
            raise FixtureError("partition_write_not_exactly_acknowledged")

    def _read_exact(self, node, path: str, value: str) -> None:
        # Read-only retry is permitted for unavailability, never for successful but
        # stale/missing data. Each new key has one acknowledged CAS=0 version.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status, body = node.call("GET", f"secret/data/{path}", token=self.root_token)
            if status == 200:
                data = body.get("data", {})
                version = data.get("metadata", {}).get("version")
                if data.get("data", {}).get("value") != value or type(version) is not int or version != 1:
                    raise FixtureError("partition_successful_read_not_exact")
                return
            if status not in (429, 503):
                raise FixtureError("partition_acknowledged_value_not_visible")
            time.sleep(0.1)
        raise FixtureError("partition_readback_timeout")

    def partition_round(self, label: str, outbound_only: bool) -> None:
        isolated = self.leader()
        pids = [node.process.pid for node in self.nodes]
        self._partition(isolated.node_id, outbound_only)
        leader = self.leader()
        self.check(f"{label}_majority_elected_without_process_kill", leader is not isolated)
        status, health = isolated.call("GET", "sys/health", timeout=8)
        self.health_observations.append({"phase": label, "node": isolated.node_id,
                                         "status": status, "ha_active": health.get("ha_active"),
                                         "standby": health.get("standby")})
        self.check(f"{label}_minority_not_active", inactive_health(status, health))
        status, _ = isolated.call("GET", "secret/data/ha-probe", token=self.root_token)
        self.check(f"{label}_minority_read_refused", status == 503)
        refused = f"partition-refused-{label}"
        status, _ = isolated.call("POST", f"secret/data/{refused}",
                                   {"data": {"value": "must-not-commit"}}, token=self.root_token)
        self.check(f"{label}_minority_write_refused", status == 503)
        path, value = f"partition-accepted-{label}", secrets.token_hex(16)
        self._new_value(leader, path, value)
        for node in self.nodes:
            if node is not isolated:
                self._read_exact(node, path, value)
        self.check(f"{label}_majority_acknowledged_cas_and_readback", True)
        self._heal()
        self.leader()
        for node in self.nodes:
            self._read_exact(node, path, value)
            status, _ = node.call("GET", f"secret/data/{refused}", token=self.root_token)
            self.check(f"{label}_node_{node.node_id}_no_refused_effect", status == 404)
        self.check(f"{label}_same_processes_recovered", pids == [node.process.pid for node in self.nodes])

    def full_partition(self) -> None:
        pids = [node.process.pid for node in self.nodes]
        for link in self.links.values():
            link.set_blocked(True)
        time.sleep(3)
        for node in self.nodes:
            status, health = node.call("GET", "sys/health", timeout=8)
            self.health_observations.append({"phase": "full", "node": node.node_id,
                                             "status": status, "ha_active": health.get("ha_active"),
                                             "standby": health.get("standby")})
            self.check(f"full_partition_node_{node.node_id}_inactive", inactive_health(status, health))
            status, _ = node.call("GET", "secret/data/ha-probe", token=self.root_token)
            self.check(f"full_partition_node_{node.node_id}_read_refused", status == 503)
            status, _ = node.call("POST", f"secret/data/full-refused-{node.node_id}",
                                   {"data": {"value": "must-not-commit"}}, token=self.root_token)
            self.check(f"full_partition_node_{node.node_id}_write_refused", status == 503)
        self._heal()
        leader = self.leader()
        value = secrets.token_hex(16)
        self._new_value(leader, "after-full-partition", value)
        for node in self.nodes:
            self._read_exact(node, "after-full-partition", value)
            for source in self.nodes:
                status, _ = node.call("GET", f"secret/data/full-refused-{source.node_id}", token=self.root_token)
                self.check(f"full_partition_node_{node.node_id}_no_effect_from_{source.node_id}", status == 404)
        self.check("full_partition_healed_without_restarting_processes", pids == [node.process.pid for node in self.nodes])

    def run(self) -> None:
        super().run()
        self.partition_round("bidirectional", outbound_only=False)
        self.partition_round("outbound_only", outbound_only=True)
        self.full_partition()

    def close(self) -> None:
        failed = False
        try:
            super().close()
        except (FixtureError, OSError, subprocess.SubprocessError):
            failed = True
        for link in self.links.values():
            try:
                link.close()
            except (FixtureError, OSError):
                failed = True
        if failed:
            raise FixtureError("partition_fixture_cleanup_failed")


def terminate(signum, frame) -> None:
    raise FixtureError("partition_fixture_interrupted")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "heptabao.loopback-network-partition.v1", "status": "not_run", "scenarios": [],
              "qualification": False, "compatibility_claim": False, "production_authority": False,
              "release_authority": False, "independent_attestation": False,
              "uncovered": ["multi_host_wan", "power_loss", "disk_full", "forced_snapshot_install",
                            "rolling_version_upgrade", "membership_change", "longitudinal_linearizability"]}
    started, cluster, code = time.monotonic(), None, 1
    handlers = {kind: signal.signal(kind, terminate) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        report["binary_sha256"] = checked_binary(args.binary, args.expected_binary_sha256)
        cluster = PartitionCluster(args.binary, args.work_dir)
        report["status"] = "running"
        cluster.run()
        checked_binary(args.binary, args.expected_binary_sha256)
        report["status"], report["node_count"], code = "pass_scoped_repository_fixture", 3, 0
    except (FixtureError, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError) as error:
        report["status"] = "failed"
        report["failure_class"] = str(error) if isinstance(error, FixtureError) else type(error).__name__
    finally:
        if cluster is not None:
            report["scenarios"] = cluster.scenarios
            report["health_observations"] = cluster.health_observations
            try:
                cluster.close()
            except (FixtureError, OSError, subprocess.SubprocessError):
                report["status"], report["failure_class"], code = "failed", "cleanup_failed", 1
        for kind, handler in handlers.items():
            signal.signal(kind, handler)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["scenario_count"] = len(report["scenarios"])
    print(json.dumps(report, sort_keys=True, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
