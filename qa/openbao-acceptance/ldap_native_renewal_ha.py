#!/usr/bin/env python3
"""Gate real OpenLDAP success during three-process native LDAP renewal faults.

Same-host, local-journal HA only; no PostgreSQL or physical-fault qualification.
A TLS relay forwards actual LDAP frames and pauses only the final successful
SearchResultDone. No credential, LDAP payload or response body enters receipts.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import threading
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT
from ha_destructive import Cluster, FixtureError
from ldap_native_live import NativeDirectory, configuration
from ldap_renewal_live import USER_DN
from online_evidence import admit_output, source_identity
from radius_renewal_ha import GATE_BUDGET_SECONDS, authority_denied, safe_request
from radius_renewal_live import wrapped_renewal_shape

MAX_FRAME = 1 << 20
PHASES = ("leader_killed", "quorum_lost", "sealed")


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            if not result:
                raise EOFError
            raise ValueError("partial_ldap_frame")
        result.extend(part)
    return bytes(result)


def read_frame(stream):
    header = exact(stream, 2)
    if header[0] != 0x30:
        raise ValueError("invalid_ldap_envelope")
    first = header[1]
    if first & 0x80:
        size = first & 0x7f
        if not 1 <= size <= 3:
            raise ValueError("invalid_ldap_length")
        encoded = exact(stream, size)
        length = int.from_bytes(encoded, "big")
        header += encoded
        if encoded[0] == 0 or length < 128:
            raise ValueError("noncanonical_ldap_length")
    else:
        length = first
    if length > MAX_FRAME:
        raise ValueError("oversized_ldap_frame")
    return header + exact(stream, length)


def tlv(data, offset=0):
    if offset + 2 > len(data):
        raise ValueError("truncated_ldap_tlv")
    tag, first = data[offset:offset + 2]
    cursor = offset + 2
    if first & 0x80:
        count = first & 0x7f
        if not 1 <= count <= 3 or cursor + count > len(data):
            raise ValueError("invalid_ldap_tlv_length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        if data[cursor] == 0 or length < 128:
            raise ValueError("noncanonical_ldap_tlv_length")
        cursor += count
    else:
        length = first
    end = cursor + length
    if length > MAX_FRAME or end > len(data):
        raise ValueError("invalid_ldap_tlv_bound")
    return tag, data[cursor:end], end


def envelope(frame):
    tag, payload, end = tlv(frame)
    if tag != 0x30 or end != len(frame):
        raise ValueError("invalid_ldap_message")
    tag, message_id, offset = tlv(payload)
    if tag != 2 or not 1 <= len(message_id) <= 4 or message_id[0] & 0x80:
        raise ValueError("invalid_ldap_message_id")
    operation, value, end = tlv(payload, offset)
    if end != len(payload):
        raise ValueError("unexpected_ldap_controls")
    return int.from_bytes(message_id, "big"), operation, value


def successful_done(frame):
    message, operation, value = envelope(frame)
    if message != 5 or operation != 0x65:
        return False
    tag, code, offset = tlv(value)
    matched_tag, _, offset = tlv(value, offset)
    diagnostic_tag, _, end = tlv(value, offset)
    return (tag == 0x0a and code == b"\0" and matched_tag == diagnostic_tag == 4
            and end == len(value))


class GatedLdap:
    """Bounded TLS relay; never fabricates LDAP success or persists frame data."""
    def __init__(self, directory, cert, key, ca):
        self.directory = directory
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.load_cert_chain(cert, key)
        self.client_context = ssl.create_default_context(cafile=str(ca))
        self.lock = threading.Lock()
        self.received, self.replied, self.release = (threading.Event() for _ in range(3))
        self.stopped = threading.Event()
        self.armed = self.failed = False
        self.requests = 0
        self.gate_elapsed = None
        self.delivery_failed = False
        self.active = set()
        self.workers = []
        self.slots = threading.BoundedSemaphore(8)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(.2)
        self.port = self.socket.getsockname()[1]
        self.origin = f"ldaps://127.0.0.1:{self.port}"
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
            self.delivery_failed = False
            self.armed = True

    def count(self):
        with self.lock:
            return self.requests

    def run(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.stopped.is_set():
                    self.failed = True
                return
            if not self.slots.acquire(blocking=False):
                client.close()
                self.failed = True
                continue
            worker = threading.Thread(target=self.exchange, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def exchange(self, raw):
        client = upstream = None
        gated = False
        try:
            raw.settimeout(5)
            client = self.server_context.wrap_socket(raw, server_side=True)
            upstream = self.client_context.wrap_socket(socket.create_connection(
                ("127.0.0.1", self.directory.port), timeout=5), server_hostname="127.0.0.1")
            with self.lock:
                self.active.update((client, upstream))
            for expected in range(1, 6):
                request = read_frame(client)
                message, operation, _ = envelope(request)
                expected_operation = 0x63 if expected in (2, 5) else 0x60
                if message != expected or operation != expected_operation:
                    raise ValueError("unexpected_ldap_exchange")
                upstream.sendall(request)
                while True:
                    response = read_frame(upstream)
                    message, operation, _ = envelope(response)
                    if message != expected or operation not in (
                            (0x64, 0x65) if expected_operation == 0x63 else (0x61,)):
                        raise ValueError("unexpected_ldap_response")
                    if successful_done(response):
                        with self.lock:
                            self.requests += 1
                            gated, self.armed = self.armed, False
                        if gated:
                            started = time.monotonic()
                            self.received.set()
                            if not self.release.wait(GATE_BUDGET_SECONDS):
                                raise ValueError("provider_gate_timeout")
                            self.gate_elapsed = time.monotonic() - started
                            if self.gate_elapsed >= GATE_BUDGET_SECONDS:
                                raise ValueError("provider_gate_exceeded_budget")
                    try:
                        client.sendall(response)
                    except OSError:
                        if not gated:
                            raise
                        self.delivery_failed = True
                    if gated:
                        self.replied.set()
                    if operation in (0x61, 0x65):
                        break
        except (EOFError, OSError, ValueError):
            if not self.stopped.is_set():
                self.failed = True
                self.received.set()
        finally:
            with self.lock:
                self.active.difference_update((client, upstream))
            for stream in (client, upstream, raw):
                if stream is not None:
                    stream.close()
            self.slots.release()

    def close(self):
        self.release.set()
        self.stopped.set()
        self.socket.close()
        with self.lock:
            for stream in self.active:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.thread.join(timeout=3)
        for worker in self.workers:
            worker.join(timeout=5)
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise FixtureError("provider_gate_shutdown_failed")


def complete_checks(checks):
    if not checks or any(set(row) != {"case", "passed"} or row["passed"] is not True
                         or not isinstance(row["case"], str) for row in checks):
        return False
    names = [row["case"] for row in checks]
    required = {"healthy_forwarded_provider_once", "acknowledged_renewal_survives_leader_death",
                "secrets_absent_from_storage_and_logs", "complete"}
    for phase in PHASES:
        required.update(phase + suffix for suffix in (
            "_real_success_released", "_no_success_or_wrapper", "_expiry_not_extended",
            "_identity_not_partially_changed", "_fresh_provider_once", "_fresh_identity_refreshed"))
    return len(names) == len(set(names)) and required.issubset(names) and names[-1] == "complete"


def run(binary, root, checks, observations, inherited):
    cluster = directory = provider = None
    sensitive = []

    def check(name, passed):
        checks.append({"case": name, "passed": passed is True})
        if passed is not True:
            raise FixtureError(name)

    try:
        cluster = Cluster(binary, root / "cluster")
        node0 = cluster.nodes[0]
        cert, key, ca = node0.root / "tls.crt", node0.root / "tls.key", cluster.root / "ca.crt"
        directory = NativeDirectory(root / "directory", cert, key, ca)
        sensitive.extend((directory.admin_password.encode(), directory.user_password.encode()))
        provider = GatedLdap(directory, cert, key, ca)
        endpoint = {"origin": provider.origin, "address": f"127.0.0.1:{provider.port}",
                    "server_name": "127.0.0.1", "ca_pem": ca.read_text(), "path_prefix": "/"}
        for node in cluster.nodes:
            path = node.root / "server.json"
            config = json.loads(path.read_text())
            config["outbound_endpoints"] = [endpoint]
            private_write(path, config)
        cluster.bootstrap()
        inherited.extend(cluster.scenarios)
        leader = cluster.leader()

        def admin(label, method, path, payload=None, expected=204):
            status, body = leader.call(method, path, payload, token=cluster.root_token)
            check(label, status == expected)
            return body

        admin("mount_ldap", "POST", "sys/auth/ldap-native", {"type": "ldap"})
        config = configuration("candidate", directory, ca.read_text(), token_ttl=120,
                               token_max_ttl=600, groupfilter="(member={{.UserDN}})")
        config["url"] = provider.origin
        admin("configure_ldap", "POST", "auth/ldap-native/config", config)
        admin("mount_kv", "POST", "sys/mounts/ldap-secret", {"type": "kv", "options": {"version": "1"}})
        admin("write_kv", "POST", "ldap-secret/value", {"value": "synthetic"})
        admin("identity_policy", "PUT", "sys/policies/acl/ldap-identity", {
            "policy": 'path "ldap-secret/value" { capabilities = ["read"] }'})
        accessor = admin("read_mount", "GET", "sys/auth", expected=200)["data"]["ldap-native/"]["accessor"]
        group = admin("identity_group", "POST", "identity/group", {"name": "ldap-engineering",
            "type": "external", "policies": ["ldap-identity"]}, expected=200)["data"]["id"]
        admin("identity_alias", "POST", "identity/group-alias", {"name": "engineering",
            "mount_accessor": accessor, "canonical_id": group}, expected=200)

        def lookup(node, token):
            status, body = node.call("GET", "auth/token/lookup-self", token=token)
            if status != 200:
                raise FixtureError("token_lookup_failed")
            return body.get("data", {})

        def expiry(node, token):
            value = lookup(node, token).get("expire_time_unix")
            if type(value) is not int or value <= time.time():
                raise FixtureError("token_expiry_invalid")
            return value

        def identity(node, token, entity, present):
            data = lookup(node, token)
            status, body = node.call("GET", "identity/group/id/" + group, token=cluster.root_token)
            granted, _ = node.call("GET", "ldap-secret/value", token=token)
            return (status == 200 and (entity in (body.get("data", {}).get("member_entity_ids") or [])) == present
                    and ("ldap-identity" in data.get("identity_policies", [])) == present
                    and granted == (200 if present else 403))

        def login(label):
            status, body = leader.call("POST", "auth/ldap-native/login/alice", {"password": directory.user_password})
            auth = body.get("auth", {})
            check(label + "_login", status == 200 and all(isinstance(auth.get(key), str) and auth[key]
                  for key in ("client_token", "entity_id")))
            token, entity = auth["client_token"], auth["entity_id"]
            sensitive.append(token.encode())
            check(label + "_initial_identity", identity(leader, token, entity, True))
            return token, entity, expiry(leader, token)

        token, entity, before = login("healthy")
        count = provider.count()
        follower = next(node for node in cluster.nodes if node is not leader)
        status, body = follower.call("POST", "auth/token/renew-self", {"increment": 240}, token=token)
        check("healthy_forwarded_provider_once", status == 200 and body.get("auth", {}).get("client_token") == token
              and provider.count() == count + 1 and not provider.failed and expiry(leader, token) > before)

        for phase in PHASES:
            leader = cluster.leader()
            directory.replace_engineering_member(USER_DN)
            token, entity, before = login(phase)
            directory.replace_engineering_member(directory.admin_dn)
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
            check(phase + "_real_success_released", provider.replied.wait(.5) and not provider.failed
                  and provider.gate_elapsed is not None and provider.gate_elapsed < GATE_BUDGET_SECONDS
                  and provider.count() == count + 1 and (phase == "leader_killed" or not provider.delivery_failed))
            check(phase + "_no_success_or_wrapper", authority_denied(status, body, phase)
                  and not body.get("auth") and not body.get("wrap_info"))
            observations[phase] = {"http_status": status, "provider_requests": provider.count() - count,
                "gate_elapsed_ms": round(provider.gate_elapsed * 1000, 2),
                "client_closed_before_delivery": provider.delivery_failed}
            if phase == "quorum_lost":
                cluster.restart(stopped.pop())
            elif phase == "sealed":
                check("sealed_node_unsealed", leader.call("POST", "sys/unseal", {"key": cluster.unseal_key})[0] == 200)
            leader = cluster.leader()
            check(phase + "_expiry_not_extended", expiry(leader, token) == before)
            check(phase + "_identity_not_partially_changed", identity(leader, token, entity, True))
            for node in stopped:
                cluster.restart(node)
            leader = cluster.leader()
            for node in cluster.nodes:
                check(phase + "_node_" + str(node.node_id) + "_unchanged",
                      expiry(node, token) == before and identity(node, token, entity, True))
            count = provider.count()
            status, body = leader.call("POST", "auth/token/renew-self", {"increment": 240},
                                      token=token, wrap_ttl="60s")
            check(phase + "_fresh_provider_once", status == 200 and provider.count() == count + 1
                  and not provider.failed and wrapped_renewal_shape(body, token))
            wrapper = body["wrap_info"]["token"]
            sensitive.append(wrapper.encode())
            status, body = leader.call("POST", "sys/wrapping/unwrap", {"token": wrapper}, token=cluster.root_token)
            check(phase + "_fresh_unwrap", status == 200 and body.get("auth", {}).get("client_token") == token)
            check(phase + "_fresh_unwrap_once", leader.call("POST", "sys/wrapping/unwrap",
                  {"token": wrapper}, token=cluster.root_token)[0] == 400)
            check(phase + "_fresh_identity_refreshed", identity(leader, token, entity, False)
                  and expiry(leader, token) > before)

        after = expiry(leader, token)
        leader.stop()
        successor = cluster.leader()
        check("acknowledged_renewal_survives_leader_death", expiry(successor, token) == after
              and identity(successor, token, entity, False))
        cluster.restart(leader)
        files = []
        for node in cluster.nodes:
            files.extend(path for folder in (node.data_dir, node.root / "raft")
                         for path in folder.rglob("*") if path.is_file())
            files.extend((node.root / "audit.jsonl", node.root / "process.log"))
        check("secrets_absent_from_storage_and_logs", all(not any(secret in path.read_bytes()
              for secret in sensitive) for path in files if path.is_file()))
        check("complete", True)
    finally:
        try:
            if provider is not None:
                provider.close()
        finally:
            try:
                if directory is not None:
                    directory.stop()
            finally:
                if cluster is not None:
                    cluster.close()


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    admitted = admit_output(output)
    binary = args.binary.resolve(strict=True)
    before = source_identity(ROOT, binary)
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    root = Path(tempfile.mkdtemp(prefix="heptabao-ldap-native-ha-"))
    root.chmod(0o700)
    checks, observations, inherited = [], {}, []
    failure = None
    try:
        run(binary, root, checks, observations, inherited)
    except Exception as error:
        failure = next((row["case"] for row in reversed(checks) if not row["passed"]),
                       "fixture_" + type(error).__name__)
    finally:
        shutil.rmtree(root)
    unchanged = before == source_identity(ROOT, binary)
    script_unchanged = script_hash == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if not unchanged or not script_unchanged:
        failure = "source_or_binary_changed_during_execution"
    if not complete_checks(checks):
        failure = failure or "incomplete_or_invalid_observations"
    report = {"schema": "heptabao.ldap-native-renewal-ha.v1", **before,
        "status": "passed" if failure is None else "failed", "checks": checks, "failure": failure,
        "source_and_binary_unchanged": unchanged, "harness_sha256": script_hash,
        "harness_unchanged": script_unchanged, "observations": observations, "bootstrap_checks": inherited,
        "same_host": True, "storage": "local_journal", "physical_fault_qualification": False,
        "full_openbao_compatibility": False, "compatibility_claim": False,
        "independent_qualification": False, "production_authority": False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed_during_execution")
    private_write(output, report, replace=False)
    print(json.dumps({"status": report["status"], "checks": len(checks), "failure": failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
