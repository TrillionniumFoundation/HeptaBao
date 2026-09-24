"""Repository regressions for provider-fixture isolation and terminal recovery."""
from __future__ import annotations

import unittest
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
