#!/usr/bin/env python3
"""Destructive three-process HA qualification fixture using synthetic state only.

This repository-controlled fixture proves bounded product behavior; it does not issue
independent production, security-review, release, or compatibility authority.
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
    pass


def private_write(path: Path, data: str | bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    mode = "wb" if isinstance(data, bytes) else "w"
    with os.fdopen(fd, mode) as stream:
        stream.write(data)


def run_checked(argv: list[str]) -> None:
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def certificate_digest(path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(path.read_text())
    if isinstance(der, str):
        der = der.encode("latin1")
    return hashlib.sha256(der).hexdigest()


def generate_ca(root: Path) -> tuple[Path, Path]:
    ca_key = root / "ca.key"
    ca_cert = root / "ca.crt"
    run_checked([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", str(ca_key), "-out", str(ca_cert),
        "-subj", "/CN=HeptaBao HA Destructive Test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ])
    ca_key.chmod(0o600)
    return ca_key, ca_cert


def generate_node_certificate(root: Path, ca_key: Path, ca_cert: Path, node_id: int) -> tuple[Path, Path, str]:
    key = root / "tls.key"
    csr = root / "tls.csr"
    cert = root / "tls.crt"
    ext = root / "tls.ext"
    run_checked([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr), "-subj", f"/CN=heptabao-ha-node-{node_id}",
    ])
    private_write(
        ext,
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
    )
    run_checked([
        "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
        "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "2",
        "-sha256", "-extfile", str(ext),
    ])
    key.chmod(0o600)
    return key, cert, certificate_digest(cert)


class Node:
    def __init__(self, node_id: int, binary: Path, root: Path, context: ssl.SSLContext):
        self.node_id = node_id
        self.binary = binary
        self.root = root
        self.context = context
        self.http_port = free_port()
        self.raft_port = free_port()
        self.address = f"https://127.0.0.1:{self.http_port}"
        self.process: subprocess.Popen[bytes] | None = None
        self.log = None
        self.key_path: Path | None = None
        self.cert_path: Path | None = None
        self.cert_digest = ""

    @property
    def data_dir(self) -> Path:
        return self.root / "data"

    @property
    def audit_file(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def server_config(self) -> Path:
        return self.root / "server.json"

    @property
    def ha_config(self) -> Path:
        return self.root / "ha.json"

    def write_server_config(self) -> None:
        if self.key_path is None or self.cert_path is None:
            raise FixtureError("node TLS identity not configured")
        private_write(
            self.server_config,
            json.dumps({
                "listen": f"127.0.0.1:{self.http_port}",
                "data_dir": str(self.data_dir),
                "audit_file": str(self.audit_file),
                "tls_cert_file": str(self.cert_path),
                "tls_key_file": str(self.key_path),
                "max_connections": 32,
                "timeout_seconds": 5,
                "rate_limit_per_second": 1000,
                "rate_limit_burst": 2000,
                "rate_limit_entries": 256,
            }),
        )

    def start(self, *, ha: bool) -> None:
        if self.process is not None:
            raise FixtureError("node already running")
        self.log = open(self.root / "server.log", "ab")
        command = [str(self.binary), "--config", str(self.server_config)]
        if ha:
            command += ["--ha-config", str(self.ha_config)]
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log)
        self.wait_listener()

    def wait_listener(self, timeout: float = 25.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process is None or self.process.poll() is not None:
                raise FixtureError(f"node {self.node_id} exited during startup")
            try:
                status, _ = self.call("GET", "sys/health", timeout=1.0)
                if status in (200, 429, 501, 503):
                    return
            except (OSError, urllib.error.URLError, TimeoutError):
                pass
            time.sleep(0.05)
        raise FixtureError(f"node {self.node_id} listener did not become ready")

    def stop(self) -> None:
        if self.process is not None:
            self.process.kill()
            self.process.wait(timeout=10)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def call(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        *,
        token: str = "",
        timeout: float = 8.0,
    ) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(
            self.address + "/v1/" + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers,
            method=method,
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self.context)
        )
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise FixtureError("unbounded HTTP response")
            parsed = json.loads(raw) if raw else {}
            if not isinstance(parsed, dict):
                raise FixtureError("non-object HTTP response")
            return int(response.status), parsed


class Cluster:
    def __init__(self, binary: Path, root: Path):
        if root.exists():
            raise FixtureError("work directory must not exist")
        root.mkdir(mode=0o700, parents=True)
        self.root = root
        self.binary = binary
        self.ca_key, self.ca_cert = generate_ca(root)
        self.context = ssl.create_default_context(cafile=str(self.ca_cert))
        self.nodes: list[Node] = []
        for node_id in (1, 2, 3):
            node_root = root / f"node-{node_id}"
            node_root.mkdir(mode=0o700)
            node = Node(node_id, binary, node_root, self.context)
            node.key_path, node.cert_path, node.cert_digest = generate_node_certificate(
                node_root, self.ca_key, self.ca_cert, node_id
            )
            node.write_server_config()
            self.nodes.append(node)
        self.cluster_id = "heptabao-ha-destructive-" + secrets.token_hex(8)
        self.replication_key = secrets.token_bytes(32)
        self.root_token = ""
        self.unseal_key = ""
        self.scenarios: list[str] = []

    def close(self) -> None:
        for node in self.nodes:
            node.stop()

    def check(self, name: str, condition: bool) -> None:
        if not condition:
            raise FixtureError("failed scenario: " + name)
        self.scenarios.append(name)

    def initialize_seed(self) -> None:
        seed = self.nodes[0]
        seed.start(ha=False)
        self.check("single_node_seed_uninitialized", seed.call("GET", "sys/health")[0] == 501)
        status, body = seed.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        self.check(
            "single_node_seed_initialized",
            status == 200 and isinstance(body.get("root_token"), str) and bool(body.get("keys_base64")),
        )
        self.root_token = body["root_token"]
        self.unseal_key = body["keys_base64"][0]
        seed.stop()
        for node in self.nodes[1:]:
            shutil.copytree(seed.data_dir, node.data_dir)
        self.check("identical_encrypted_seed_materialized", all(node.data_dir.exists() for node in self.nodes))

    def write_ha_configs(self) -> None:
        peers = {
            str(node.node_id): {
                "node_name": f"node-{node.node_id}",
                "address": f"127.0.0.1:{node.raft_port}",
                "server_name": "localhost",
                "certificate_sha256": node.cert_digest,
            }
            for node in self.nodes
        }
        for node in self.nodes:
            key_path = node.root / "replication.key"
            private_write(key_path, self.replication_key)
            private_write(
                node.ha_config,
                json.dumps({
                    "node_id": node.node_id,
                    "cluster_id": self.cluster_id,
                    "raft_dir": str(node.root / "raft"),
                    "listen": f"127.0.0.1:{node.raft_port}",
                    "ca_file": str(self.ca_cert),
                    "cert_file": str(node.cert_path),
                    "key_file": str(node.key_path),
                    "replication_key_file": str(key_path),
                    "peers": peers,
                    "bootstrap": node.node_id == 1,
                    "peer_timeout_ms": 500,
                    "max_inflight": 32,
                }),
            )

    def start_ha(self) -> None:
        # Non-bootstrap listeners must exist before the bootstrap node admits them.
        self.nodes[1].start(ha=True)
        self.nodes[2].start(ha=True)
        self.nodes[0].start(ha=True)
        for node in self.nodes:
            status, _ = node.call("POST", "sys/unseal", {"key": self.unseal_key})
            self.check(f"node_{node.node_id}_unsealed", status == 200)

    def running(self) -> list[Node]:
        return [node for node in self.nodes if node.process is not None]

    def leader(self, nodes: list[Node] | None = None, timeout: float = 25.0) -> Node:
        nodes = self.running() if nodes is None else nodes
        deadline = time.time() + timeout
        last = []
        while time.time() < deadline:
            active: list[Node] = []
            last = []
            for node in nodes:
                try:
                    status, health = node.call("GET", "sys/health", timeout=2.0)
                except (OSError, urllib.error.URLError, TimeoutError):
                    continue
                last.append((node.node_id, status, health.get("ha_active")))
                if status == 200:
                    if health.get("ha_active") is not True or health.get("standby") is not False:
                        raise FixtureError("HTTP 200 HA health was not bound to active authority")
                    active.append(node)
            if len(active) == 1:
                candidate = active[0]
                status, leader = candidate.call("GET", "sys/leader", token=self.root_token)
                if status == 200 and leader.get("is_self") is True:
                    return candidate
            if len(active) > 1:
                raise FixtureError("multiple active HA health responses observed")
            time.sleep(0.1)
        raise FixtureError(f"unique active leader not observed: {last!r}")

    def assert_no_false_active(self, nodes: list[Node], duration: float) -> None:
        deadline = time.time() + duration
        while time.time() < deadline:
            active = 0
            for node in nodes:
                if node.process is None:
                    continue
                try:
                    status, body = node.call("GET", "sys/health", timeout=1.5)
                except (OSError, urllib.error.URLError, TimeoutError):
                    continue
                if status == 200:
                    active += 1
                    if body.get("ha_active") is not True:
                        raise FixtureError("health returned 200 without ha_active")
            if active > 1:
                raise FixtureError("multiple active health responses during election")
            time.sleep(0.05)

    def write(self, node: Node, path: str, value: str) -> None:
        status, body = node.call(
            "POST", f"secret/data/{path}", {"data": {"value": value}}, token=self.root_token
        )
        if status != 200 or not isinstance(body.get("data", {}).get("version"), int):
            raise FixtureError(f"HA write failed on node {node.node_id} with status {status}")

    def read(self, node: Node, path: str, expected: str, timeout: float = 20.0) -> None:
        deadline = time.time() + timeout
        last_status = None
        while time.time() < deadline:
            try:
                status, body = node.call("GET", f"secret/data/{path}", token=self.root_token)
            except (OSError, urllib.error.URLError, TimeoutError):
                time.sleep(0.1)
                continue
            last_status = status
            if status == 200 and body.get("data", {}).get("data", {}).get("value") == expected:
                return
            time.sleep(0.1)
        raise FixtureError(f"node {node.node_id} failed replicated readback; last status={last_status}")

    def unseal_restart(self, node: Node) -> None:
        node.start(ha=True)
        status, _ = node.call("POST", "sys/unseal", {"key": self.unseal_key})
        if status != 200:
            raise FixtureError(f"node {node.node_id} failed unseal after restart")

    def run(self) -> dict:
        self.initialize_seed()
        self.write_ha_configs()
        self.start_ha()
        self.assert_no_false_active(self.nodes, 1.0)
        leader = self.leader()
        self.check("unique_linearizable_leader_after_start", leader is not None)

        marker1 = "baseline-" + secrets.token_hex(16)
        self.write(leader, "ha-probe", marker1)
        for node in self.nodes:
            self.read(node, "ha-probe", marker1)
        self.check("three_node_replicated_readback", True)

        lagger = next(node for node in self.nodes if node is not leader)
        lagger.stop()
        for index in range(8):
            self.write(leader, f"snapshot-log-{index}", secrets.token_hex(12))
        status, _ = leader.call("GET", "sys/storage/raft/snapshot", token=self.root_token, timeout=15.0)
        self.check("leader_snapshot_trigger", status == 200)
        marker2 = "post-snapshot-" + secrets.token_hex(16)
        self.write(leader, "snapshot-final", marker2)
        self.unseal_restart(lagger)
        self.read(lagger, "snapshot-final", marker2, timeout=30.0)
        self.check("offline_follower_rejoined_after_snapshot", True)

        leader = self.leader()
        old_leader = leader
        old_leader.stop()
        survivors = self.running()
        self.assert_no_false_active(survivors, 2.0)
        new_leader = self.leader(survivors, timeout=30.0)
        self.check("leader_kill_elected_new_linearizable_leader", new_leader is not old_leader)
        marker3 = "post-failover-" + secrets.token_hex(16)
        self.write(new_leader, "ha-probe", marker3)
        for node in survivors:
            self.read(node, "ha-probe", marker3)
        self.check("post_failover_replicated_write", True)

        quorum_peer = next(node for node in survivors if node is not new_leader)
        quorum_peer.stop()
        time.sleep(1.5)
        status, body = new_leader.call("GET", "sys/health", timeout=4.0)
        self.check("quorum_loss_health_fails_closed", status == 503 and body.get("ha_active") is False)
        denied_status, _ = new_leader.call(
            "POST", "secret/data/quorum-denied", {"data": {"value": "must-not-commit"}},
            token=self.root_token, timeout=6.0,
        )
        self.check("quorum_loss_write_denied", denied_status == 503)

        self.unseal_restart(quorum_peer)
        recovered_leader = self.leader(self.running(), timeout=30.0)
        marker4 = "quorum-recovered-" + secrets.token_hex(16)
        self.write(recovered_leader, "quorum-recovered", marker4)
        for node in self.running():
            self.read(node, "quorum-recovered", marker4)
        self.check("quorum_restore_recovers_linearizable_write", True)

        self.unseal_restart(old_leader)
        final_leader = self.leader(self.nodes, timeout=30.0)
        for node in self.nodes:
            self.read(node, "quorum-recovered", marker4, timeout=30.0)
            denied, _ = node.call("GET", "secret/data/quorum-denied", token=self.root_token)
            self.check(f"node_{node.node_id}_rejected_quorum_loss_effect", denied == 404)
        self.check("all_three_rejoined_with_single_active_leader", final_leader is not None)

        return {
            "schema": "heptabao.destructive-ha.v1",
            "status": "pass",
            "node_count": 3,
            "scenario_count": len(self.scenarios),
            "scenarios": self.scenarios,
            "cluster_id_sha256": hashlib.sha256(self.cluster_id.encode()).hexdigest(),
            "qualification": False,
            "compatibility_claim": False,
            "production_authority": False,
            "release_authority": False,
            "independent_attestation": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute():
        parser.error("binary and work directory must be absolute")
    cluster: Cluster | None = None
    try:
        cluster = Cluster(args.binary, args.work_dir)
        report = cluster.run()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (FixtureError, OSError, subprocess.SubprocessError, urllib.error.URLError, ValueError, KeyError):
        print("destructive HA fixture failed; inspect synthetic node logs", file=sys.stderr)
        return 1
    finally:
        if cluster is not None:
            cluster.close()


if __name__ == "__main__":
    raise SystemExit(main())
