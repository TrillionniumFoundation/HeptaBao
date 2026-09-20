#!/usr/bin/env python3
"""Exercise the bounded Valkey ACL database profile against real Valkey TLS.

The fixture creates a private Valkey 7.x process with an ACL file, drives the
candidate through database/config, dynamic ACL issue/renew/revoke, provider
restart and HeptaBao restart, and records bounded evidence. It deliberately
does not claim OpenBao provider compatibility or independent qualification.
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
from contextlib import contextmanager
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
import sys

sys.path.insert(0, str(ROOT / "qa/single-node"))
from smoke import Instance


class ValkeyPermissionRejected(RuntimeError):
    """An explicit provider authorization rejection, never a transport failure."""


class Valkey:
    def __init__(self, root: Path, ca: Path, cert: Path, key: Path):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True)
        self.data = root / "data"
        self.data.mkdir(mode=0o700)
        self.ca, self.cert, self.key = ca, cert, key
        self.manager = "hb_manager"
        self.password = secrets.token_hex(32)
        self.acl = root / "users.acl"
        self.acl.write_text(
            "user default off\n"
            f"user {self.manager} on >{self.password} ~* &* +@all\n",
            encoding="ascii",
        )
        self.acl.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.process: subprocess.Popen[bytes] | None = None
        self.log = None

    @property
    def origin(self) -> str:
        return f"valkeys://localhost:{self.port}"

    @contextmanager
    def session(self, user, password):
        context = ssl.create_default_context(cafile=str(self.ca))
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                with tls.makefile("rwb", buffering=0) as stream:
                    def read():
                        prefix = stream.read(1)
                        line = stream.readline(65537)
                        if len(line) > 65536 or not line.endswith(b"\r\n"):
                            raise RuntimeError("valkey_fixture_invalid_frame")
                        value = line[:-2]
                        if prefix == b"-":
                            if value.split(b" ", 1)[0] in {b"NOPERM", b"WRONGPASS", b"NOAUTH"}:
                                raise ValkeyPermissionRejected("valkey_fixture_permission_rejected")
                            raise RuntimeError("valkey_fixture_command_rejected")
                        if prefix == b"+": return value.decode()
                        if prefix == b":": return int(value)
                        if prefix == b"$":
                            size = int(value)
                            if size == -1: return None
                            if not 0 <= size <= 65536: raise RuntimeError("valkey_fixture_frame_bound")
                            data = stream.read(size)
                            if stream.read(2) != b"\r\n": raise RuntimeError("valkey_fixture_terminator")
                            return data.decode()
                        if prefix == b"*":
                            size = int(value)
                            if size == -1: return None
                            if not 0 <= size <= 256: raise RuntimeError("valkey_fixture_array_bound")
                            return [read() for _ in range(size)]
                        raise RuntimeError("valkey_fixture_invalid_type")
                    def command(*args):
                        wire = [str(arg).encode() for arg in args]
                        stream.write(b"*%d\r\n" % len(wire) + b"".join(
                            b"$%d\r\n" % len(arg) + arg + b"\r\n" for arg in wire))
                        return read()
                    if command("AUTH", user, password) != "OK":
                        raise RuntimeError("valkey_fixture_authentication")
                    yield command

    def cli(self, user, password, *args):
        try:
            with self.session(user, password) as command:
                value = command(*args)
                return subprocess.CompletedProcess([], 0, "(nil)" if value is None else str(value), "")
        except ValkeyPermissionRejected:
            return subprocess.CompletedProcess([], 1, "", "provider_permission_rejected")
        except (RuntimeError, OSError):
            return subprocess.CompletedProcess([], 2, "", "provider_request_failed")

    def start(self) -> None:
        if self.process is not None:
            raise RuntimeError("valkey_already_started")
        self.log = (self.root / "valkey.log").open("ab")
        self.process = subprocess.Popen(
            [
                "valkey-server",
                "--bind", "127.0.0.1",
                "--port",
                "0",
                "--tls-port",
                str(self.port),
                "--tls-cert-file",
                str(self.cert),
                "--tls-key-file",
                str(self.key),
                "--tls-ca-cert-file",
                str(self.ca),
                "--tls-auth-clients",
                "no",
                "--aclfile",
                str(self.acl),
                "--dir",
                str(self.data),
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=self.log,
            start_new_session=True,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("valkey_start_failed")
            result = self.cli(self.manager, self.password, "PING")
            if result.returncode == 0 and result.stdout.strip() == "PONG":
                return
            time.sleep(0.1)
        raise RuntimeError("valkey_tls_readiness_failed")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--work-dir", required=True, type=Path, help="new private directory on the test volume")
    args = parser.parse_args()
    binary = Path(args.binary)
    output = Path(args.output)
    checks: list[dict[str, object]] = []
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    source_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=True
    ).stdout.strip()
    source_worktree_dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True, capture_output=True, check=True
        ).stdout.strip()
    )
    # Keep runtime secrets, TLS keys and provider state in the explicitly
    # supplied private work directory; the report contains only redacted checks.
    root = args.work_dir
    if not root.is_absolute() or not binary.is_absolute() or not output.is_absolute():
        parser.error("binary, work-dir and output must be absolute")
    root.mkdir(mode=0o700, exist_ok=False)
    instance = Instance(binary, root / "candidate")
    provider = Valkey(root / "valkey", instance.root / "ca.crt", instance.root / "tls.crt", instance.root / "tls.key")
    candidate_key = ""

    def check(name: str, passed: bool) -> None:
        checks.append({"case": name, "passed": bool(passed)})
        if not passed:
            raise RuntimeError(name)

    try:
        provider.start()
        check("real_valkey_tls_ping", provider.cli(provider.manager, provider.password, "PING").stdout.strip() == "PONG")
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["outbound_endpoints"] = [
            {
                "origin": provider.origin,
                "address": f"127.0.0.1:{provider.port}",
                "server_name": "localhost",
                "ca_pem": (instance.root / "ca.crt").read_text(encoding="ascii"),
            }
        ]
        config["lifecycle_interval_seconds"] = 1
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_path.chmod(0o600)
        instance.start()
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize", status == 200)
        instance.token = initialized["root_token"]
        candidate_key = initialized["keys_base64"][0]
        check("unseal", instance.call("POST", "sys/unseal", {"key": candidate_key})[0] == 200)
        check("mount_database", instance.call("POST", "sys/mounts/database", {"type": "database"})[0] == 204)
        config_body = {
            "plugin_name": "valkey-database-plugin",
            "connection_url": provider.origin + "/0",
            "username": provider.manager,
            "password": provider.password,
            "allowed_roles": ["readonly", "readwrite", "short"],
        }
        wrong_database = dict(config_body, connection_url=provider.origin + "/1")
        check("nonzero_database_rejected", instance.call("POST", "database/config/other", wrong_database)[0] == 400)
        check("unauthorized_config_rejected", instance.call("POST", "database/config/local", config_body, token="invalid")[0] == 403)
        check("valkey_tls_acl_configuration", instance.call("POST", "database/config/local", config_body)[0] == 204)
        check(
            "config_readback_hides_password",
            instance.call("GET", "database/config/local")[1].get("data", {}).get("password") is None,
        )
        check(
            "readonly_role",
            instance.call(
                "POST",
                "database/roles/readonly",
                {"db_name": "local", "provider_role": "readonly", "default_ttl": 30, "max_ttl": 120},
            )[0]
            == 204,
        )
        check(
            "privilege_escape_role_rejected",
            instance.call(
                "POST",
                "database/roles/admin",
                {"db_name": "local", "provider_role": "+@all", "default_ttl": 30, "max_ttl": 120},
            )[0]
            == 400,
        )
        status, issued = instance.call("GET", "database/creds/readonly")
        check("issue_acl_user", status == 200 and "key_pattern" in issued.get("data", {}))
        credential = issued["data"]
        lease_id = issued["lease_id"]
        key_pattern = credential["key_pattern"]
        allowed_key = key_pattern[:-1] + "seed"
        check(
            "manager_seeds_allowed_key",
            provider.cli(provider.manager, provider.password, "SET", allowed_key, "fixture-value").stdout.strip() == "OK",
        )
        check(
            "issued_user_ping",
            provider.cli(credential["username"], credential["password"], "PING").stdout.strip() == "PONG",
        )
        check(
            "issued_user_reads_bound_key",
            provider.cli(credential["username"], credential["password"], "GET", allowed_key).stdout.strip() == "fixture-value",
        )
        check(
            "issued_readonly_user_cannot_write",
            provider.cli(credential["username"], credential["password"], "SET", allowed_key, "denied").returncode == 1,
        )
        check(
            "issued_user_key_escape_denied",
            provider.cli(credential["username"], credential["password"], "GET", "outside-key").returncode == 1,
        )
        provider.stop()
        provider.start()
        check(
            "acl_user_survives_valkey_restart",
            provider.cli(credential["username"], credential["password"], "PING").stdout.strip() == "PONG",
        )
        instance.stop()
        instance.start()
        check("service_restart_is_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("service_restart_unseal", instance.call("POST", "sys/unseal", {"key": candidate_key})[0] == 200)
        check(
            "config_survives_service_restart",
            instance.call("GET", "database/config/local")[0] == 200,
        )
        status, renewed = instance.call("POST", "sys/leases/renew", {"lease_id": lease_id, "increment": 60})
        check("renew_after_both_restarts", status == 200 and renewed.get("renewable") is True)
        check(
            "renewed_user_remains_live",
            provider.cli(credential["username"], credential["password"], "PING").stdout.strip() == "PONG",
        )
        check("readwrite_role", instance.call("POST", "database/roles/readwrite", {
            "db_name": "local", "provider_role": "readwrite", "default_ttl": 60, "max_ttl": 120})[0] == 204)
        status, write_issued = instance.call("GET", "database/creds/readwrite")
        check("issue_readwrite", status == 200)
        writer = write_issued["data"]
        write_key = writer["key_pattern"][:-1] + "owned"
        check("readwrite_can_set", provider.cli(writer["username"], writer["password"], "SET", write_key, "value").stdout == "OK")
        for command in [("FLUSHALL",), ("FLUSHDB",), ("KEYS", "*"), ("SET", "outside", "denied"), ("ACL", "WHOAMI")]:
            check("readwrite_denies_" + command[0].lower(), provider.cli(writer["username"], writer["password"], *command).returncode == 1)
        # Hold a real authenticated session and a stale WATCH transaction over revoke.
        provider_id = key_pattern[len("hb:"):-2]
        marker = "hbf_" + provider_id[4:]
        watch_key = "__heptabao_fence:" + provider_id
        with provider.session(credential["username"], credential["password"]) as active:
            with provider.session(provider.manager, provider.password) as delayed:
                check("stale_writer_watch", delayed("WATCH", watch_key) == "OK")
                check("stale_writer_multi", delayed("MULTI") == "OK")
                check("stale_writer_queued", delayed("ACL", "SETUSER", credential["username"], "on", "nopass", "+@all", "~*") == "QUEUED")
                check("revoke_acl_user", instance.call("POST", "sys/leases/revoke", {"lease_id": lease_id})[0] == 204)
                check("stale_writer_aborted_after_revoke", delayed("EXEC") is None)
            try:
                active("PING")
                terminated = False
            except (RuntimeError, OSError):
                terminated = True
            check("revoke_terminates_existing_session", terminated)
        provider.stop(); provider.start()
        with provider.session(provider.manager, provider.password) as command:
            durable_marker = command("ACL", "GETUSER", marker)
            check("revocation_fence_survives_provider_restart", isinstance(durable_marker, list) and "off" in durable_marker[1])
        check(
            "revoked_user_denied",
            provider.cli(credential["username"], credential["password"], "PING").returncode == 1,
        )
        check(
            "revoked_user_absent_after_readback",
            "(nil)" in provider.cli(provider.manager, provider.password, "ACL", "GETUSER", credential["username"]).stdout,
        )
        status, drift = instance.call("GET", "database/creds/readonly")
        check("drift_test_issue", status == 200)
        with provider.session(provider.manager, provider.password) as command:
            check("external_selector_drift_installed", command("ACL", "SETUSER", drift["data"]["username"], "(+set ~*)") == "OK")
        status, refused = instance.call("POST", "sys/leases/renew", {"lease_id": drift["lease_id"], "increment": 60})
        check("selector_drift_blocks_renewal", status == 503 and refused.get("reconcile_required") is True)
        check("drifted_user_can_be_revoked", instance.call("POST", "sys/leases/revoke", {"lease_id": drift["lease_id"]})[0] == 204)
        check("short_role", instance.call("POST", "database/roles/short", {
            "db_name": "local", "provider_role": "readonly", "default_ttl": 2, "max_ttl": 10})[0] == 204)
        status, short = instance.call("GET", "database/creds/short")
        check("short_issue", status == 200)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if provider.cli(short["data"]["username"], short["data"]["password"], "PING").returncode == 1:
                break
            time.sleep(0.1)
        check("idle_expiry_removes_native_credential", provider.cli(short["data"]["username"], short["data"]["password"], "PING").returncode == 1)
        provider.stop()
        status, pending = instance.call("POST", "sys/leases/revoke", {"lease_id": write_issued["lease_id"]})
        check("provider_outage_retains_revoke_intent", status == 503 and pending.get("reconcile_required") is True and "data" not in pending)
        instance.stop(); provider.start(); instance.start()
        check("pending_revoke_restart_unseal", instance.call("POST", "sys/unseal", {"key": candidate_key})[0] == 200)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if provider.cli(writer["username"], writer["password"], "PING").returncode == 1:
                break
            time.sleep(0.1)
        check("restart_reconciles_pending_native_revoke", provider.cli(writer["username"], writer["password"], "PING").returncode == 1)
        instance.stop(); provider.stop(); provider.start(); instance.start()
        check("final_restart_unseal", instance.call("POST", "sys/unseal", {"key": candidate_key})[0] == 200)
        check("reconciled_revoke_survives_both_restarts", provider.cli(writer["username"], writer["password"], "PING").returncode == 1)
        report = {
            "schema": "heptabao.valkey-bounded-live.v1",
            "status": "passed",
            "checks": checks,
            "provider_version": subprocess.check_output(["valkey-server", "--version"], text=True).strip(),
            "tls_resp2": True,
            "acl_save_restart_persistence": True,
            "independent_observation": False,
            "uncovered": ["OpenBao differential parity", "HeptaBao multi-node failover", "Valkey replication/cluster failover", "physical power-loss and disk-full", "ACL marker retirement", "Valkey 9.x ACL extensions"],
            "bounded_profile": "Valkey 7.2 TLS; explicit command allowlists; generated key patterns; WATCH/EXEC; durable ACL marker and ACL SAVE; no provider cluster failover qualification",
            "full_openbao_valkey_compatibility": False,
            "independent_qualification": False,
            "production_authority": False,
            "candidate_binary_sha256": binary_sha256,
            "candidate_binary_source_head": source_head,
            "source_worktree_dirty": source_worktree_dirty,
            "execution_platform": "Linux aarch64 guest (Ubuntu Noble)",
        }
        with output.open("w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"status": "passed", "check_count": len(checks)}))
        return 0
    except Exception as error:
        report = {
            "schema": "heptabao.valkey-bounded-live.v1",
            "status": "failed",
            "checks": checks,
            "safe_error": type(error).__name__,
        }
        with output.open("w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"status": "failed", "check_count": len(checks)}))
        return 1
    finally:
        instance.stop()
        provider.stop()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
