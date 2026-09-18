#!/usr/bin/env python3
"""Real deployment-owned TCP socket-audit profile for HeptaBao.

The mandatory authenticated file device remains enabled. This profile proves
that a process-configured TCP collector receives the same bounded JSON records,
cannot be rebound through sys/audit, and that a bounded nonblocking socket
failure remains observable while the local file device preserves service.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socketserver
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke


class Collector:
    def __init__(self):
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.port = None

    def start(self, port: int | None = None):
        collector = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                raw = self.rfile.readline(128 * 1024 + 1)
                if not raw or len(raw) > 128 * 1024 or self.rfile.read(1):
                    return
                try:
                    value = json.loads(raw)
                except Exception:
                    return
                if isinstance(value, dict):
                    with collector.lock:
                        collector.records.append(value)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0 if port is None else port), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="audit-socket-collector",
        )
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError("audit socket collector did not stop")
            self.thread = None

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.records))


def configure(instance: smoke.Instance, collector: Collector):
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config["audit_socket"] = {
        "address": f"127.0.0.1:{collector.port}",
        "write_timeout_ms": 1000,
    }
    path.write_text(json.dumps(config), encoding="utf-8")
    path.chmod(0o600)


def run(binary: Path, work_dir: Path) -> int:
    os.umask(0o077)
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    collector = Collector()
    instance = smoke.Instance(binary, work_dir / "server")
    passed = []
    unseal = None

    def check(name, condition):
        if not condition:
            raise RuntimeError("audit_socket_failed_" + name)
        passed.append(name)

    try:
        collector.start()
        configure(instance, collector)
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialized_with_socket_audit", status == 200)
        instance.token = initialized["root_token"]
        unseal = initialized["keys_base64"][0]
        check(
            "unsealed_with_socket_audit",
            instance.call("POST", "sys/unseal", {"key": unseal})[0] == 200,
        )

        status, devices = instance.call("GET", "sys/audit")
        check(
            "sys_audit_lists_file_and_socket",
            status == 200
            and set(devices.get("data", {})) == {"file/", "socket/"},
        )
        status, device = instance.call("GET", "sys/audit/socket")
        check(
            "socket_device_is_process_owned",
            status == 200
            and device.get("data", {}).get("type") == "socket"
            and device.get("data", {}).get("options", {}).get("socket_type") == "tcp"
            and device.get("data", {}).get("failed_writes") == 0,
        )
        status, _ = instance.call(
            "POST",
            "sys/audit/socket",
            {"type": "socket", "options": {"address": "127.0.0.1:1"}},
        )
        check("api_cannot_rebind_socket_destination", status == 409)

        secret = "audit-socket-synthetic-value"
        check(
            "audited_mutation_succeeds",
            instance.call(
                "POST", "secret/data/audit-socket", {"data": {"value": secret}}
            )[0]
            == 200,
        )
        status, body = instance.call("GET", "secret/data/audit-socket")
        check(
            "audited_read_succeeds",
            status == 200
            and body.get("data", {}).get("data", {}).get("value") == secret,
        )

        remote = collector.snapshot()
        local = [
            json.loads(line)
            for line in (instance.root / "audit.jsonl").read_text().splitlines()
            if line
        ]
        check("socket_tail_matches_local_before_fault", remote == local)
        encoded = json.dumps(remote, sort_keys=True)
        check(
            "socket_records_do_not_expose_secret_or_bearer",
            secret not in encoded
            and instance.token not in encoded
            and "secret/data/audit-socket" not in encoded,
        )

        port = collector.port
        collector.stop()
        status, body = instance.call("GET", "secret/data/audit-socket")
        check(
            "bounded_socket_outage_uses_mandatory_file_device",
            status == 200
            and body.get("data", {}).get("data", {}).get("value") == secret,
        )
        status, device = instance.call("GET", "sys/audit/socket")
        failures = device.get("data", {}).get("failed_writes")
        check(
            "socket_outage_is_observable",
            status == 200 and isinstance(failures, int) and failures > 0,
        )

        collector.start(port)
        before = len(collector.snapshot())
        check(
            "collector_recovery_preserves_service",
            instance.call("GET", "secret/data/audit-socket")[0] == 200,
        )
        after = collector.snapshot()
        check("collector_receives_new_records_after_recovery", len(after) > before)

        result = {
            "schema": "heptabao.audit-socket-live.v1",
            "status": "passed_scoped_socket_audit",
            "checks": len(passed),
            "passed": passed,
            "socket_type": "tcp",
            "configuration_authority": "trusted_process_only",
            "api_rebind_allowed": False,
            "mandatory_file_device_retained": True,
            "socket_failures_observable": True,
            "udp_supported": False,
            "unix_socket_supported": False,
            "production_authority": False,
            "full_openbao_compatibility": False,
        }
        print(json.dumps(result, sort_keys=True))
        return 0
    finally:
        instance.stop()
        collector.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    return run(args.binary.resolve(), args.work_dir.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
