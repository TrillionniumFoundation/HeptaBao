#!/usr/bin/env python3
"""Linux-only RabbitMQ secret-engine acceptance against a real broker.

The provider is the official, digest-pinned RabbitMQ 4.1-management image.
No AMQP or management mock is accepted. Docker and the pinned image are
prerequisites; missing prerequisites return 77 (blocked), never pass.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "qa" / "single-node"))
from smoke import Instance

IMAGE = "rabbitmq:4.1-management@sha256:3574a8edaca320282b9c848f0b2661566b7e74f52c1b590f401b10224d294642"


class Blocked(RuntimeError):
    pass


class Rabbitmq:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.name = "heptabao-rabbitmq-" + secrets.token_hex(8)
        self.manager = "hb_manager"
        self.manager_password = secrets.token_hex(32)
        self.env_file = self.root / "rabbitmq.env"
        self.created = False
        self.running = False
        self.amqp_port = 0
        self.http_port = 0

    @staticmethod
    def available() -> bool:
        return sys.platform.startswith("linux") and shutil.which("docker") is not None

    @staticmethod
    def image_present() -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return result.returncode == 0

    def start_fresh(self) -> None:
        self.env_file.write_text(
            f"RABBITMQ_DEFAULT_USER={self.manager}\n"
            f"RABBITMQ_DEFAULT_PASS={self.manager_password}\n",
            encoding="utf-8",
        )
        self.env_file.chmod(0o600)
        result = subprocess.run(
            [
                "docker", "run", "-d", "--name", self.name,
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
                "-p", "127.0.0.1::5672", "-p", "127.0.0.1::15672",
                "--env-file", str(self.env_file), IMAGE,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
        )
        self.env_file.unlink(missing_ok=True)
        if result.returncode != 0:
            raise RuntimeError("rabbitmq_container_start_failed")
        self.created = True
        self.running = True
        self.amqp_port = self._mapped_port("5672/tcp")
        self.http_port = self._mapped_port("15672/tcp")
        self.wait_ready()

    def _mapped_port(self, container_port: str) -> int:
        result = subprocess.run(
            ["docker", "port", self.name, container_port],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError("rabbitmq_port_mapping_failed")
        try:
            return int(result.stdout.strip().splitlines()[0].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            raise RuntimeError("rabbitmq_port_mapping_invalid") from None

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                status, _ = self.api("GET", "/api/whoami", self.manager, self.manager_password)
                if status == 200:
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.25)
        raise RuntimeError("rabbitmq_readiness_failed")

    def api(self, method: str, path: str, user: str, password: str, body=None):
        if not path.startswith("/api/") or any(c in path for c in "\r\n?#"):
            raise RuntimeError("invalid_management_path")
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        connection = http.client.HTTPConnection("127.0.0.1", self.http_port, timeout=4)
        try:
            connection.request(
                method, path, body=payload,
                headers={
                    "Accept": "application/json", "Authorization": "Basic " + auth,
                    "Content-Type": "application/json", "Content-Length": str(len(payload or b"")),
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            raw = response.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise RuntimeError("rabbitmq_management_response_too_large")
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()

    def restart(self) -> None:
        self.stop()
        result = subprocess.run(["docker", "start", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        if result.returncode != 0:
            raise RuntimeError("rabbitmq_container_restart_failed")
        self.running = True
        self.wait_ready()

    def stop(self) -> None:
        if self.created and self.running:
            subprocess.run(["docker", "stop", "-t", "1", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
            self.running = False

    def destroy(self) -> None:
        self.env_file.unlink(missing_ok=True)
        if self.created:
            subprocess.run(["docker", "rm", "-f", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            self.created = False
            self.running = False

    def amqp_login(self, user: str, password: str, vhost: str = "/") -> socket.socket | None:
        """Perform a real AMQP 0-9-1 connection.start/open handshake."""
        sock = socket.create_connection(("127.0.0.1", self.amqp_port), timeout=4)
        try:
            sock.sendall(b"AMQP\x00\x00\x09\x01")
            start = self._read_method(sock)
            if start[:2] != (10, 10):
                raise RuntimeError("rabbitmq_amqp_start_missing")
            response = b"\x00" + user.encode() + b"\x00" + password.encode()
            payload = struct.pack(">HHI", 10, 11, 0) + self._short("PLAIN") + self._long(response) + self._short("en_US")
            self._write_frame(sock, 1, 0, payload)
            tune = self._read_method(sock)
            if tune[:2] != (10, 30):
                raise RuntimeError("rabbitmq_amqp_tune_missing")
            self._write_frame(sock, 1, 0, struct.pack(">HHHIH", 10, 31, 0, 131072, 60))
            self._write_frame(sock, 1, 0, struct.pack(">HH", 10, 40) + self._short(vhost) + b"\x00")
            method = self._read_method(sock)
            if method[:2] == (10, 41):
                return sock
            sock.close()
            return None
        except Exception:
            sock.close()
            raise

    def amqp_read_permission_denied(self, user: str, password: str, queue: str) -> bool:
        sock = self.amqp_login(user, password, "/")
        if sock is None:
            return False
        try:
            self._write_frame(sock, 1, 1, struct.pack(">HH", 20, 10) + self._short(""))
            opened = self._read_method(sock)
            if opened[:2] != (20, 11):
                return False
            payload = (
                struct.pack(">HHH", 60, 20, 0)
                + self._short(queue)
                + self._short("")
                + b"\x00"
                + struct.pack(">I", 0)
            )
            self._write_frame(sock, 1, 1, payload)
            denied = self._read_method(sock)
            return (
                denied[:2] == (20, 40)
                and len(denied[2]) >= 6
                and struct.unpack(">H", denied[2][4:6])[0] == 403
            )
        finally:
            sock.close()

    def _read_method(self, sock: socket.socket):
        frame_type, channel, payload = self._read_frame(sock)
        if frame_type != 1 or channel != 0 or len(payload) < 4:
            raise RuntimeError("rabbitmq_amqp_method_frame_invalid")
        return struct.unpack(">HH", payload[:4]) + (payload[4:],)

    @staticmethod
    def _short(value: str) -> bytes:
        encoded = value.encode()
        if len(encoded) > 255:
            raise RuntimeError("rabbitmq_amqp_short_string_bound")
        return bytes([len(encoded)]) + encoded

    @staticmethod
    def _long(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    @staticmethod
    def _write_frame(sock: socket.socket, frame_type: int, channel: int, payload: bytes):
        sock.sendall(struct.pack(">BHI", frame_type, channel, len(payload)) + payload + b"\xce")

    @staticmethod
    def _read_frame(sock: socket.socket):
        header = sock.recv(7)
        if len(header) != 7:
            raise RuntimeError("rabbitmq_amqp_frame_truncated")
        frame_type, channel, length = struct.unpack(">BHI", header)
        if length > 131072:
            raise RuntimeError("rabbitmq_amqp_frame_too_large")
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                raise RuntimeError("rabbitmq_amqp_payload_truncated")
            payload += chunk
        if sock.recv(1) != b"\xce":
            raise RuntimeError("rabbitmq_amqp_frame_end_invalid")
        return frame_type, channel, payload


def private_bytes(root: Path) -> bytes:
    return b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())


def run(binary: Path, root: Path, output: Path) -> dict:
    if not sys.platform.startswith("linux"):
        raise Blocked("linux_required")
    if not Rabbitmq.available():
        raise Blocked("docker_linux_required")
    if not Rabbitmq.image_present():
        raise Blocked("pinned_rabbitmq_image_required")
    instance = Instance(binary, root / "candidate")
    broker = Rabbitmq(root / "rabbitmq")
    passed: list[str] = []
    existing = None

    def check(case: str, condition: bool):
        if not condition:
            raise RuntimeError(case)
        passed.append(case)

    try:
        broker.start_fresh()
        check("real_rabbitmq_4_1_ready", True)
        config = json.loads((instance.root / "server.json").read_text(encoding="utf-8"))
        config["lifecycle_interval_seconds"] = 1
        config["outbound_endpoints"] = [{
            "origin": f"rabbitmq://127.0.0.1:{broker.http_port}/",
            "address": f"127.0.0.1:{broker.http_port}",
            "server_name": "127.0.0.1",
            "ca_pem": "",
        }]
        (instance.root / "server.json").write_text(json.dumps(config), encoding="utf-8")
        (instance.root / "server.json").chmod(0o600)
        instance.start()
        status, init = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = init["root_token"]
        unseal = init["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)
        check("mount", instance.call("POST", "sys/mounts/rabbitmq", {"type": "rabbitmq"})[0] == 204)
        check("configuration", instance.call("POST", "rabbitmq/config/connection", {
            "connection_uri": f"rabbitmq://127.0.0.1:{broker.http_port}/",
            "username": broker.manager, "password": broker.manager_password,
            "verify_connection": True,
        })[0] == 204)
        status, readback = instance.call("GET", "rabbitmq/config/connection")
        check("configuration_readback", status == 200 and "password" not in json.dumps(readback))
        status, _ = broker.api(
            "PUT",
            "/api/queues/%2F/hb_probe",
            broker.manager,
            broker.manager_password,
            {"durable": False, "auto_delete": True, "arguments": {}},
        )
        check("manager_probe_queue", status in (201, 204))
        check("role", instance.call("POST", "rabbitmq/roles/app", {
            "vhosts": {"/": {"configure": "^$", "write": "^$", "read": "^$"}},
            "tags": "", "default_ttl": 30, "max_ttl": 60,
        })[0] == 204)
        status, roles = instance.call("LIST", "rabbitmq/roles")
        check("role_vhost_permission_enforcement", status == 200 and roles.get("data", {}).get("keys") == ["app"])
        status, role_readback = instance.call("GET", "rabbitmq/roles/app")
        check("role_readback", status == 200 and role_readback.get("data", {}).get("vhosts", {}).get("/") is not None)
        status, denied = instance.call("GET", "rabbitmq/creds/app", namespace="missing")
        status_auth, _ = instance.call("GET", "rabbitmq/roles", token="invalid-token")
        check(
            "default_deny_namespace_and_unauthorized",
            status in (403, 404) and status_auth == 403 and not denied.get("data"),
        )
        status, issued = instance.call("GET", "rabbitmq/creds/app")
        credential = issued.get("data", {})
        check("real_user_issuance", status == 200 and credential.get("username", "").startswith("hbr_"))
        lease_id = issued["lease_id"]
        status, lease = instance.call("POST", "sys/leases/lookup", {"lease_id": lease_id})
        check("lease_lookup_readback", status == 200 and lease.get("data", {}).get("renewable") is False)
        existing = broker.amqp_login(credential["username"], credential["password"], "/")
        check("issued_user_opens_configured_vhost", existing is not None)
        check(
            "issued_user_permission_denied",
            broker.amqp_read_permission_denied(credential["username"], credential["password"], "hb_probe"),
        )
        check("issued_user_denied_unconfigured_vhost", broker.amqp_login(credential["username"], credential["password"], "/missing") is None)
        status, _ = instance.call("POST", "sys/leases/renew", {"lease_id": lease_id, "increment": 30})
        check("renewal_rejected_without_provider_semantics", status == 400)
        instance.stop()
        instance.start()
        check("restart_is_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("user_survives_heptabao_restart", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200 and broker.amqp_login(credential["username"], credential["password"], "/") is not None)
        broker.restart()
        check("user_survives_rabbitmq_restart", broker.amqp_login(credential["username"], credential["password"], "/") is not None)
        if existing is not None:
            existing.settimeout(3)
        status, _ = instance.call("POST", "sys/leases/revoke", {"lease_id": lease_id})
        check("revoke_denies_new_connection", status == 204 and broker.amqp_login(credential["username"], credential["password"], "/") is None)
        if existing is not None:
            try:
                closed = existing.recv(7) == b""
            except OSError:
                closed = True
            existing.close()
            check("revoke_closes_existing_connection", closed)
        status, issued = instance.call("GET", "rabbitmq/creds/app")
        check("outage_seed", status == 200)
        outage_id = issued["lease_id"]
        outage_credential = issued["data"]
        outage_socket = broker.amqp_login(outage_credential["username"], outage_credential["password"], "/")
        check("outage_seed_provider_login", outage_socket is not None)
        if outage_socket is not None:
            outage_socket.close()
        broker.stop()
        status, pending = instance.call("POST", "sys/leases/revoke", {"lease_id": outage_id})
        check("provider_outage_retains_pending_revoke", status == 503 and pending.get("reconcile_required") is True and "data" not in pending)
        instance.stop()
        broker.restart()
        instance.start()
        check("restart_unseal_before_reconcile", instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200)
        status, _ = instance.call("POST", "sys/leases/reconcile/" + outage_id, {})
        check("restart_reconciles_pending_revoke", status == 204 and broker.amqp_login(outage_credential["username"], outage_credential["password"], "/") is None)
        instance.stop()
        credential_bytes = credential["password"].encode()
        check("no_plaintext_secret_persistence", credential_bytes not in private_bytes(instance.root / "data") and credential_bytes not in (instance.root / "audit.jsonl").read_bytes() and credential_bytes not in (instance.root / "server.log").read_bytes())
        result = {"schema": "heptabao.rabbitmq-live.v1", "passed": passed, "count": len(passed), "image": IMAGE, "compatibility_claim": False, "production_authority": False}
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        output.chmod(0o600)
        return result
    finally:
        if existing is not None:
            existing.close()
        instance.stop()
        broker.destroy()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute() or not args.output.is_absolute():
        parser.error("paths must be absolute")
    try:
        result = run(args.binary, args.work_dir, args.output)
    except Blocked as error:
        print("rabbitmq live acceptance blocked: " + str(error), file=sys.stderr)
        raise SystemExit(77) from None
    except Exception as error:
        print("rabbitmq live acceptance failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps({"schema": result["schema"], "count": result["count"], "image": IMAGE}))
