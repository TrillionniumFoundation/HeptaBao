#!/usr/bin/env python3
"""Interrupt real RADIUS renewals while their UDP provider reply is gated.

Three local Rust processes use encrypted, synthetic state. This checks the HA
publication boundary, not physical-host faults or full OpenBao compatibility.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import shutil
import socket
import struct
import tempfile
import threading
import time
import urllib.error

from bao_http import SafeArgumentParser
from ha_destructive import Cluster, FixtureError
from online_evidence import admit_output, source_identity, publish
from radius_renewal_live import SECRET, USERNAME, PASSWORD, pap_packet_response

ROOT = Path(__file__).resolve().parents[2]
GATE_BUDGET_SECONDS = 2.7


def profile_configuration(port, *, native=False):
    endpoint = {"origin": f"radius://127.0.0.1:{port}",
                "address": f"127.0.0.1:{port}", "server_name": "127.0.0.1",
                "ca_pem": "", "path_prefix": "/"}
    config = {"token_policies": ["default"], "token_ttl": 120, "token_max_ttl": 600}
    if native:
        # Keep the same three-second wire deadline as the legacy fault profile.
        # API credentials do not create an ambient DNS route or process secret.
        config.update(host="127.0.0.1", port=port, secret=SECRET.decode(),
                      read_timeout=3, dial_timeout=3)
    else:
        endpoint["shared_secret"] = SECRET.decode()
        config["url"] = endpoint["origin"]
    return endpoint, config


def native_nas_valid(packet):
    """Native default NAS-Port=10, no NAS-Identifier; full MA is checked separately."""
    ports, identifiers, offset = [], [], 20
    while offset < len(packet):
        if offset + 2 > len(packet):
            return False
        kind, length = packet[offset:offset + 2]
        if length < 2 or offset + length > len(packet):
            return False
        if kind == 5:
            ports.append(packet[offset + 2:offset + length])
        elif kind == 32:
            identifiers.append(packet[offset + 2:offset + length])
        offset += length
    return ports == [struct.pack("!I", 10)] and not identifiers


class GatedRadius:
    """Hold precisely one validated Accept; no packet/credential enters output."""
    def __init__(self, *, native=False):
        self.native = native
        self.lock = threading.Lock()
        self.received = threading.Event()
        self.replied = threading.Event()
        self.release = threading.Event()
        self.stopped = threading.Event()
        self.armed = False
        self.requests = 0
        self.sent = 0
        self.gate_elapsed = None
        self.failed = False
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def arm(self):
        with self.lock:
            if self.armed or self.failed:
                raise FixtureError("invalid_provider_gate_state")
            self.received.clear()
            self.replied.clear()
            self.release.clear()
            self.gate_elapsed = None
            self.armed = True

    def count(self):
        with self.lock:
            return self.requests

    def run(self):
        while not self.stopped.is_set():
            try:
                packet, peer = self.socket.recvfrom(4096)
                response, observation = pap_packet_response(packet, require_ma=True, allow=True)
                if observation != {"credentials_valid": True,
                                   "message_authenticator_present": True, "accepted": True}:
                    raise ValueError("invalid_synthetic_credentials")
                if self.native and not native_nas_valid(packet):
                    raise ValueError("invalid_native_nas_attributes")
                with self.lock:
                    gated = self.armed
                    self.armed = False
                    self.requests += 1
                if gated:
                    started = time.monotonic()
                    self.received.set()
                    if not self.release.wait(GATE_BUDGET_SECONDS):
                        raise ValueError("provider_gate_timeout")
                    self.gate_elapsed = time.monotonic() - started
                    # The production UDP timeout is three seconds. Never count
                    # an expired provider request as successful HA fencing.
                    if self.gate_elapsed >= GATE_BUDGET_SECONDS:
                        raise ValueError("provider_gate_exceeded_budget")
                self.socket.sendto(response, peer)
                with self.lock:
                    self.sent += 1
                if gated:
                    self.replied.set()
            except TimeoutError:
                continue
            except ValueError:
                self.failed = True
                self.received.set()
            except OSError:
                if not self.stopped.is_set():
                    self.failed = True
                break

    def close(self):
        self.release.set()
        self.stopped.set()
        self.socket.close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise FixtureError("provider_gate_shutdown_failed")


def safe_request(node, token):
    try:
        return node.call("POST", "auth/token/renew-self", {"increment": 240},
                         token=token, wrap_ttl="60s", timeout=8)
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        # SIGKILL may close the TLS stream before a response exists. Never
        # record exception text or automatically replay the mutation.
        return None, {}


def authority_denied(status, body, phase):
    if phase == "leader_killed" and status is None:
        return not body
    errors = body.get("errors", [])
    return status == 503 and isinstance(errors, list) and bool(errors) and all(
        isinstance(error, str) and (error.startswith("HA ")
        or error.endswith("renewal leader changed")
        or error == "online authentication leader changed"
        or phase == "sealed" and (error.endswith("renewal authority is unavailable")
            or error in {"online authentication authority changed", "online authentication authority unavailable"}))
        for error in errors)


def run(binary, root, checks, observations, inherited, *, native=False):
    cluster = None
    provider = GatedRadius(native=native)
    sensitive = [SECRET, PASSWORD]

    def check(name, passed):
        checks.append({"case": name, "passed": passed is True})
        if passed is not True:
            raise FixtureError(name)

    try:
        cluster = Cluster(binary, root / "cluster")
        endpoint, radius_config = profile_configuration(provider.port, native=native)
        for node in cluster.nodes:
            path = node.root / "server.json"
            config = json.loads(path.read_text())
            config["outbound_endpoints"] = [] if native else [endpoint]
            path.write_text(json.dumps(config))
            path.chmod(0o600)
        cluster.bootstrap()
        inherited.extend(cluster.scenarios)
        leader = cluster.leader()
        check("mount_radius", leader.call("POST", "sys/auth/radius", {"type": "radius"}, token=cluster.root_token)[0] == 204)
        check("configure_radius", leader.call("POST", "auth/radius/config", radius_config,
              token=cluster.root_token)[0] == 204)

        def expiry(node, token, label):
            status, body = node.call("GET", "auth/token/lookup-self", token=token)
            value = body.get("data", {}).get("expire_time_unix")
            check(label + "_lookup", status == 200 and type(value) is int and value > time.time())
            return value

        def login(node, label):
            status, body = node.call("POST", "auth/radius/login", {
                "username": USERNAME.decode(), "password": PASSWORD.decode()})
            token = body.get("auth", {}).get("client_token")
            check(label + "_login", status == 200 and isinstance(token, str) and bool(token))
            sensitive.append(token.encode())
            return token, expiry(node, token, label)

        token, before = login(leader, "healthy")
        follower = next(node for node in cluster.nodes if node is not leader)
        count = provider.count()
        status, body = follower.call("POST", "auth/token/renew-self", {"increment": 240}, token=token)
        check("healthy_forwarded_renewal", status == 200 and body.get("auth", {}).get("client_token") == token)
        check("healthy_provider_exactly_once", provider.count() == count + 1)
        check("healthy_extension_committed", expiry(leader, token, "healthy_after") > before)

        for phase in ("leader_killed", "quorum_lost", "sealed"):
            leader = cluster.leader()
            token, before = login(leader, phase)
            count = provider.count()
            provider.arm()
            stopped = []
            with ThreadPoolExecutor(max_workers=3) as pool:
                future = pool.submit(safe_request, leader, token)
                check(phase + "_provider_inflight", provider.received.wait(2) and not provider.failed)
                try:
                    if phase == "leader_killed":
                        leader.stop()
                        stopped.append(leader)
                    elif phase == "quorum_lost":
                        stopped = [node for node in cluster.nodes if node is not leader]
                        deaths = [pool.submit(node.stop) for node in stopped]
                        for death in deaths:
                            death.result(timeout=2)
                    else:
                        check("seal_acknowledged", leader.call("POST", "sys/seal", {},
                              token=cluster.root_token, timeout=2.6)[0] == 204)
                finally:
                    provider.release.set()
                status, body = future.result(timeout=10)
            check(phase + "_accept_sent_before_timeout", provider.replied.wait(.5) and not provider.failed
                  and provider.gate_elapsed is not None and provider.gate_elapsed < GATE_BUDGET_SECONDS
                  and provider.count() == count + 1 and provider.sent == provider.count())
            # Classify every received 503 in memory, including the death case:
            # a provider timeout before SIGKILL must not become an HA pass.
            denied = authority_denied(status, body, phase)
            check(phase + "_no_success_or_wrapper", denied and not body.get("auth") and not body.get("wrap_info"))
            observations[phase] = {"http_status": status, "provider_requests": provider.count() - count,
                                   "gate_elapsed_ms": round(provider.gate_elapsed * 1000, 2)}
            if phase == "quorum_lost":
                cluster.restart(stopped.pop())
            elif phase == "sealed":
                check("sealed_node_unsealed", leader.call("POST", "sys/unseal",
                      {"key": cluster.unseal_key})[0] == 200)
            successor = cluster.leader()
            check(phase + "_expiry_not_extended", expiry(successor, token, phase + "_successor") == before)
            for node in stopped:
                cluster.restart(node)
            cluster.leader()
            for node in cluster.nodes:
                label = f"{phase}_node_{node.node_id}"
                check(label + "_same_expiry", expiry(node, token, label) == before)

        leader = cluster.leader()
        count = provider.count()
        status, body = leader.call("POST", "auth/token/renew-self", {"increment": 240}, token=token)
        check("fresh_request_after_recovery_succeeds", status == 200 and body.get("auth", {}).get("client_token") == token)
        check("recovery_rechecks_provider", provider.count() == count + 1)
        after = expiry(leader, token, "recovered")
        check("recovery_extension_committed", after > before)
        leader.stop()
        successor = cluster.leader()
        check("acknowledged_renewal_survives_leader_death", expiry(successor, token, "durable") == after)
        cluster.restart(leader)
        files = []
        for node in cluster.nodes:
            files.extend(path for folder in (node.data_dir, node.root / "raft") for path in folder.rglob("*") if path.is_file())
            files.extend([node.root / "audit.jsonl", node.root / "process.log"])
        check("secrets_absent_from_storage_and_logs", all(not any(secret in path.read_bytes()
              for secret in sensitive) for path in files if path.is_file()))
    finally:
        try:
            provider.close()
        finally:
            if cluster is not None:
                cluster.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--native", action="store_true", help="use encrypted native host/port/secret configuration")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    parent = admit_output(output)
    binary = args.binary.resolve(strict=True)
    before = source_identity(ROOT, binary)
    root = Path(tempfile.mkdtemp(prefix="heptabao-radius-renewal-ha-"))
    root.chmod(0o700)
    checks, observations, inherited = [], {}, []
    failure = None
    try:
        run(binary, root, checks, observations, inherited, native=args.native)
    except Exception as error:
        failure = next((row["case"] for row in reversed(checks) if not row["passed"]),
                       "fixture_" + type(error).__name__)
    finally:
        shutil.rmtree(root)
    report = {"schema": "heptabao.radius-renewal-ha.v1", "checks": checks, "failure": failure,
              "execution_failure": failure,
              "profile": "native_config" if args.native else "legacy_process_secret",
              "same_host": True, "physical_fault_qualification": False,
              "full_openbao_compatibility": False, "observations": observations,
              "bootstrap_checks": inherited}
    if len(inherited) != 8 or len(set(inherited)) != 8:
        report["failure"] = report["failure"] or "incomplete_cluster_bootstrap"
    publish(output, parent, report, before, source_identity(ROOT, binary), 56)
    print(json.dumps({"status": report["status"], "checks": len(checks), "failure": report["failure"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
