"""Repository regressions for provider-fixture isolation and terminal recovery."""
from __future__ import annotations

import importlib.util
import json
import secrets
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "qa" / "openbao-acceptance"


def source(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class ProviderFixtureIsolationTests(unittest.TestCase):
    def test_cassandra_cql_auth_files_are_per_invocation(self) -> None:
        value = source("cassandra_live.py")
        self.assertGreaterEqual(value.count("/tmp/heptabao-cqlshrc-"), 2)
        self.assertNotIn('RC="/tmp/heptabao-cqlshrc"', value)
        self.assertNotIn('rc = "/tmp/heptabao-cqlshrc"\n', value)

    def test_docker_http_ports_are_stable_and_retry_bound(self) -> None:
        influx = source("influxdb_live.py")
        rabbit = source("rabbitmq_live.py")
        self.assertIn('f"127.0.0.1:{self.port}:8086"', influx)
        self.assertIn('f"127.0.0.1:{self.port}:15672"', rabbit)
        for value in (influx, rabbit):
            self.assertIn("socket.socket() as listener", value)
            self.assertIn("for _ in range(16):", value)
            self.assertNotIn('"127.0.0.1::', value)
            self.assertGreaterEqual(value.count("self._assert_port_binding()"), 2)

    def test_database_provider_proves_exact_credential_with_fresh_salt(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "database_fixture_isolation", FIXTURES / "plugin_database_live.py"
        )
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        password = secrets.token_hex(32)
        with tempfile.TemporaryDirectory() as temporary:
            roots = [Path(temporary) / name for name in ("first", "second")]
            configured = []
            for root in roots:
                root.mkdir()
                server = root / "server"
                server.mkdir()
                (server / "server.json").write_text("{}")
                configured.append(fixture.configure(SimpleNamespace(root=server), root))
            plugin, state_path, _, _, salt = configured[0]
            self.assertEqual(len(salt), 32)
            self.assertNotEqual(salt, configured[1][4])
            payload = json.dumps({
                "action": "issue", "manager_username": "manager",
                "manager_password": "manager-password",
                "provider_id": "hb1:" + "a" * 64, "username": "hbp_fixture",
                "seq": 1, "request_digest": "b" * 64, "expires": 60,
                "password": password,
            }).encode()
            response = subprocess.run(
                [str(plugin)], input=b"HBP1" + bytes([0, 1, 3]) + struct.pack(">I", len(payload)) + payload,
                capture_output=True, timeout=10, check=True,
            ).stdout
            self.assertEqual(response[:4], b"HBR1")
            self.assertEqual(struct.unpack(">I", response[4:8])[0], len(response) - 8)
            self.assertIs(json.loads(response[8:])["applied"], True)
            state = json.loads(state_path.read_text())
            fingerprint = state["password_transport_pbkdf2_sha256"]
            self.assertEqual(fingerprint, fixture.password_fingerprint(password, salt))
            changed_password = ("0" if password[0] != "0" else "1") + password[1:]
            self.assertNotEqual(fingerprint, fixture.password_fingerprint(changed_password, salt))
            self.assertNotEqual(fingerprint, fixture.password_fingerprint(password, configured[1][4]))
            self.assertNotIn(password, state_path.read_text())
            self.assertNotIn("password_hmac_sha256", state)

    def test_recovery_observes_durable_and_external_terminal_state(self) -> None:
        for name in (
            "cassandra_live.py",
            "influxdb_live.py",
            "mysql_live.py",
            "rabbitmq_live.py",
        ):
            with self.subTest(name=name):
                value = source(name)
                marker = value.rindex("restart_reconciles_pending_revoke")
                recovery = value[max(0, marker - 3000):marker + 1500]
                self.assertIn('"POST", "sys/leases/lookup"', recovery)
                self.assertIn('"POST", "sys/leases/revoke"', recovery)
                self.assertIn('revoke_status == 204', recovery)
                self.assertIn('phase == "Revoked"', recovery)
                self.assertIn('lookup_status in (400, 404)', recovery)


if __name__ == "__main__":
    unittest.main()
