#!/usr/bin/env python3
"""Run bounded three-process HA faults against private, synthetic loopback state.

Never attach to a real service. A passing result is NOT independent qualification,
full linearizability proof, power-cut evidence, or rolling-version-upgrade evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


class FixtureError(RuntimeError):
    """A safe fixed classification; never include credential-bearing responses."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def private_write(path: Path, value: str | bytes) -> None:
    data = value.encode() if isinstance(value, str) else value
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def openssl(*arguments: str) -> None:
    subprocess.run(["openssl", *arguments], check=True, timeout=30,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def checked_binary(path: Path, expected: str) -> str:
    if not path.is_absolute() or path.resolve() != path or not path.is_file() or not os.access(path, os.X_OK):
        raise FixtureError("binary_not_an_absolute_regular_executable")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if len(expected) != 64 or actual != expected:
        raise FixtureError("binary_digest_mismatch")
    return actual


class Node:
    def __init__(self, node_id: int, binary: Path, root: Path, context: ssl.SSLContext):
        self.node_id, self.binary, self.root = node_id, binary, root
        self.context = context
        self.ha_config = root / "ha.json"
        self.http_port, self.raft_port = free_port(), free_port()
        self.process = None
        self.log = None
        self.started_pids: list[int] = []

    @property
    def data_dir(self) -> Path:
        return self.root / "data"

    def call(self, method: str, path: str, body=None, *, token: str = "", timeout: float = 8.0):
        if not path or path.startswith("/") or "://" in path or ".." in path.split("/"):
            raise FixtureError("invalid_fixture_request_path")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(
            f"https://127.0.0.1:{self.http_port}/v1/{path}",
            data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                             urllib.request.HTTPSHandler(context=self.context))
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise FixtureError("response_exceeds_fixture_bound")
            parsed = json.loads(raw) if raw else {}
            if not isinstance(parsed, dict):
                raise FixtureError("non_object_response")
            return int(response.status), parsed

    def start(self, ha: bool = True) -> None:
        if self.process is not None:
            raise FixtureError("node_already_running")
        # Created inside a fresh owner-only synthetic directory, never an existing log.
        fd = os.open(self.root / "process.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self.log = os.fdopen(fd, "ab")
        command = [str(self.binary), "--config", str(self.root / "server.json")]
        if ha:
            command.extend(["--ha-config", str(self.ha_config)])
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log, start_new_session=True)
        self.started_pids.append(self.process.pid)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise FixtureError("node_exited_during_startup")
            try:
                if self.call("GET", "sys/health", timeout=1)[0] in (200, 429, 501, 503):
                    return
            except (OSError, urllib.error.URLError, TimeoutError):
                pass
            time.sleep(0.05)
        raise FixtureError("node_listener_timeout")

    def stop(self) -> None:
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=10)
                self.process = None
        finally:
            if self.log is not None:
                self.log.close()
                self.log = None


class Cluster:
    def __init__(self, binary: Path, root: Path):
        if not root.is_absolute() or root.resolve() != root or root.exists() or not root.parent.is_dir():
            raise FixtureError("work_directory_must_be_new_absolute_non_symlink")
        root.mkdir(mode=0o700)
        self.root, self.binary = root, binary
        self.nodes: list[Node] = []
        self.scenarios: list[str] = []
        self.root_token = ""
        self.unseal_key = ""
        self.cluster_id = ""
        self.replication_key = secrets.token_bytes(32)
        self.configure()

    def check(self, name: str, condition: bool) -> None:
        if not condition:
            raise FixtureError(name)
        self.scenarios.append(name)

    def configure(self) -> None:
        ca_key, ca_cert = self.root / "ca.key", self.root / "ca.crt"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=HeptaBao Synthetic HA CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        ca_key.chmod(0o600)
        context = ssl.create_default_context(cafile=str(ca_cert))
        peers = {}
        for number in (1, 2, 3):
            root = self.root / f"node-{number}"
            root.mkdir(mode=0o700)
            node = Node(number, self.binary, root, context)
            self.nodes.append(node)
            key, cert, csr = root / "tls.key", root / "tls.crt", root / "tls.csr"
            openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(csr), "-subj", f"/CN=heptabao-synthetic-{number}")
            key.chmod(0o600)
            extension = root / "tls.ext"
            private_write(extension, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
            openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-out", str(cert), "-days", "2", "-sha256", "-extfile", str(extension))
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            peers[str(number)] = {"node_name": f"node-{number}", "address": f"127.0.0.1:{node.raft_port}",
                                  "server_name": "localhost", "certificate_sha256": fingerprint}
            private_write(root / "server.json", json.dumps({
                "listen": f"127.0.0.1:{node.http_port}", "data_dir": str(node.data_dir),
                "audit_file": str(root / "audit.jsonl"), "tls_cert_file": str(cert), "tls_key_file": str(key),
                "max_connections": 32, "timeout_seconds": 5,
                "rate_limit_per_second": 1000, "rate_limit_burst": 2000, "rate_limit_entries": 256}))
        ports = [port for node in self.nodes for port in (node.http_port, node.raft_port)]
        if len(set(ports)) != 6:
            raise FixtureError("ephemeral_port_collision")
        self.peers = peers

    def configure_ha(self) -> None:
        if not self.cluster_id:
            raise FixtureError("unbound_seed_cluster_identity")
        ca_cert = self.root / "ca.crt"
        peers = self.peers
        for node in self.nodes:
            private_write(node.root / "replication.key", self.replication_key)
            private_write(node.root / "ha.json", json.dumps({
                "node_id": node.node_id, "cluster_id": self.cluster_id,
                "raft_dir": str(node.root / "raft"), "listen": f"127.0.0.1:{node.raft_port}",
                "ca_file": str(ca_cert), "cert_file": str(node.root / "tls.crt"),
                "key_file": str(node.root / "tls.key"), "replication_key_file": str(node.root / "replication.key"),
                "peers": peers, "bootstrap": node.node_id == 1, "peer_timeout_ms": 500, "max_inflight": 32}))

    def running(self) -> list[Node]:
        return [node for node in self.nodes if node.process is not None]

    def wait_quorum(self) -> None:
        """Read-only readiness: a sealed listener is not a committed quorum."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            active = 0
            for node in self.running():
                try:
                    _, health = node.call("GET", "sys/health", timeout=2)
                except (OSError, urllib.error.URLError, TimeoutError):
                    continue
                if health.get("ha_active") is True:
                    active += 1
            if active > 1:
                raise FixtureError("multiple_raft_leaders_during_readiness")
            if active == 1:
                return
            time.sleep(0.1)
        raise FixtureError("raft_quorum_readiness_timeout")

    def leader(self) -> Node:
        # Fault phases permit a bounded election settling period. Do not retry a
        # write after ambiguity: establish stable, read-only leadership first.
        deadline = time.monotonic() + 30
        previous, stable_since = None, None
        while time.monotonic() < deadline:
            active = []
            for node in self.running():
                try:
                    status, health = node.call("GET", "sys/health", timeout=2)
                except (OSError, urllib.error.URLError, TimeoutError):
                    continue
                if status == 200:
                    if health.get("ha_active") is not True or health.get("standby") is not False:
                        raise FixtureError("health_success_without_active_authority")
                    active.append(node)
            if len(active) > 1:
                raise FixtureError("multiple_active_health_responses")
            if len(active) == 1:
                node = active[0]
                status, body = node.call("GET", "sys/leader", token=self.root_token)
                if status == 200 and body.get("is_self") is True:
                    observed = time.monotonic()
                    if previous is not node:
                        previous, stable_since = node, observed
                    elif observed - stable_since >= 2.2:
                        return node
                else:
                    previous, stable_since = None, None
            else:
                previous, stable_since = None, None
            time.sleep(0.1)
        raise FixtureError("unique_active_leader_not_observed")

    def write(self, node: Node, path: str, value: str) -> None:
        # Exactly one write attempt. Lost/ambiguous responses fail rather than replay.
        status, body = node.call("POST", f"secret/data/{path}", {"data": {"value": value}}, token=self.root_token)
        if status != 200 or type(body.get("data", {}).get("version")) is not int:
            raise FixtureError("write_not_acknowledged")

    def read(self, node: Node, path: str, value: str) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status, body = node.call("GET", f"secret/data/{path}", token=self.root_token)
            except (OSError, urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
                continue
            if status == 200:
                if body.get("data", {}).get("data", {}).get("value") != value:
                    raise FixtureError("successful_read_returned_stale_or_wrong_data")
                return
            if status not in (429, 503):
                raise FixtureError("acknowledged_write_not_visible")
            time.sleep(0.1)
        raise FixtureError("readback_timeout")

    def restart(self, node: Node) -> None:
        node.start()
        if node.call("POST", "sys/unseal", {"key": self.unseal_key})[0] != 200:
            raise FixtureError("restart_unseal_failed")

    def run(self) -> None:
        seed = self.nodes[0]
        seed.start(ha=False)
        self.check("fresh_seed_uninitialized", seed.call("GET", "sys/health")[0] == 501)
        status, body = seed.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        self.check("fresh_seed_initialized", status == 200 and bool(body.get("root_token")) and bool(body.get("keys_base64")))
        self.root_token, self.unseal_key = body["root_token"], body["keys_base64"][0]
        self.check("seed_unsealed_before_ha", seed.call("POST", "sys/unseal", {"key": self.unseal_key})[0] == 200)
        status, health = seed.call("GET", "sys/health")
        self.check("seed_cluster_identity_read_back", status == 200 and isinstance(health.get("cluster_id"), str) and bool(health["cluster_id"]))
        self.cluster_id = health["cluster_id"]
        seed.stop()
        self.configure_ha()
        for node in self.nodes[1:]:
            shutil.copytree(seed.data_dir, node.data_dir)
        # Test that a legitimate peer cannot unseal a different application cluster.
        wrong = self.nodes[2]
        wrong_config = json.loads((wrong.root / "ha.json").read_text())
        wrong_config["cluster_id"] = "deliberately-wrong-application-cluster"
        wrong.ha_config = wrong.root / "wrong-cluster.json"
        private_write(wrong.ha_config, json.dumps(wrong_config))
        # This intentionally tests a cold-cloned encrypted seed, NOT production enrollment.
        for node in [self.nodes[1], self.nodes[2], self.nodes[0]]:
            node.start()
        self.check("three_distinct_service_processes", len({node.process.pid for node in self.nodes}) == 3)
        self.wait_quorum()
        status, denied = wrong.call("POST", "sys/unseal", {"key": self.unseal_key})
        self.check("misbound_cluster_unseal_denied", status == 503 and denied.get("errors") == ["HA configuration belongs to a different cluster"])
        status, health = wrong.call("GET", "sys/health")
        self.check("misbound_cluster_remains_sealed", status == 503 and health.get("sealed") is True)
        wrong.stop()
        wrong.ha_config = wrong.root / "ha.json"
        wrong.start()
        self.wait_quorum()
        for node in self.nodes:
            self.check(f"node_{node.node_id}_unsealed", node.call("POST", "sys/unseal", {"key": self.unseal_key})[0] == 200)
        leader = self.leader()
        marker = secrets.token_hex(16)
        self.write(leader, "ha-probe", marker)
        for node in self.nodes:
            self.read(node, "ha-probe", marker)
        self.check("acknowledged_value_readable_through_all_nodes", True)
        standby = next(node for node in self.nodes if node is not leader)
        forwarded = secrets.token_hex(16)
        self.write(standby, "forwarded-probe", forwarded)
        self.read(leader, "forwarded-probe", forwarded)
        self.check("standby_write_forwarded_to_leader", True)
        standby.stop()
        for index in range(8):
            self.write(leader, f"snapshot-probe-{index}", secrets.token_hex(12))
        self.check("leader_snapshot_trigger", leader.call("GET", "sys/storage/raft/snapshot", token=self.root_token, timeout=15)[0] == 200)
        snapshot_value = secrets.token_hex(16)
        self.write(leader, "after-snapshot", snapshot_value)
        self.restart(standby)
        self.read(standby, "after-snapshot", snapshot_value)
        self.check("offline_follower_rejoined_after_snapshot_trigger", True)
        old_leader = self.leader()
        old_leader.stop()
        leader = self.leader()
        self.check("new_leader_after_sigkill", leader is not old_leader)
        failover_value = secrets.token_hex(16)
        self.write(leader, "after-failover", failover_value)
        for node in self.running():
            self.read(node, "after-failover", failover_value)
        self.check("acknowledged_post_failover_write", True)
        peer = next(node for node in self.running() if node is not leader)
        peer.stop()
        time.sleep(1.5)
        status, health = leader.call("GET", "sys/health", timeout=5)
        self.check("quorum_loss_health_denied", status == 503 and health.get("ha_active") is False)
        status, _ = leader.call("POST", "secret/data/quorum-denied", {"data": {"value": "must-not-commit"}}, token=self.root_token)
        self.check("quorum_loss_write_denied", status == 503)
        self.restart(peer)
        leader = self.leader()
        recovered_value = secrets.token_hex(16)
        self.write(leader, "quorum-recovered", recovered_value)
        self.restart(old_leader)
        self.leader()
        for node in self.nodes:
            self.read(node, "quorum-recovered", recovered_value)
            self.check(f"node_{node.node_id}_no_rejected_write_effect", node.call("GET", "secret/data/quorum-denied", token=self.root_token)[0] == 404)
        self.check("all_three_rejoined_after_quorum_recovery", True)

    def close(self) -> None:
        failed = False
        for node in self.nodes:
            try:
                node.stop()
            except (OSError, subprocess.SubprocessError):
                failed = True
        if failed:
            raise FixtureError("node_cleanup_failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "heptabao.destructive-ha.v2", "status": "not_run", "scenarios": [],
              "qualification": False, "compatibility_claim": False, "production_authority": False,
              "release_authority": False, "independent_attestation": False,
              "uncovered": ["network_partition", "power_loss", "disk_full", "forced_snapshot_install",
                            "rolling_version_upgrade", "membership_change", "longitudinal_linearizability"]}
    cluster = None
    started = time.monotonic()
    try:
        report["binary_sha256"] = checked_binary(args.binary, args.expected_binary_sha256)
        cluster = Cluster(args.binary, args.work_dir)
        report["status"] = "running"
        cluster.run()
        checked_binary(args.binary, args.expected_binary_sha256)
        report["status"] = "pass_scoped_repository_fixture"
        report["node_count"] = 3
        return_code = 0
    except (FixtureError, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, IndexError) as error:
        report["status"] = "failed"
        report["failure_class"] = str(error) if isinstance(error, FixtureError) else type(error).__name__
        return_code = 1
    finally:
        if cluster is not None:
            report["scenarios"] = cluster.scenarios
            try:
                cluster.close()
            except (FixtureError, OSError, subprocess.SubprocessError):
                report["status"], report["failure_class"] = "failed", "cleanup_failed"
                return_code = 1
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["scenario_count"] = len(report["scenarios"])
    print(json.dumps(report, sort_keys=True, indent=2))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
