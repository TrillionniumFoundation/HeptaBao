#!/usr/bin/env python3
"""Exercise the real process-configured Unix syslog audit profile."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke


class SyslogCollector:
    def __init__(self, path: Path):
        self.path = path
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self):
        if self.sock is not None:
            raise RuntimeError("syslog collector already started")
        self.path.unlink(missing_ok=True)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(str(self.path))
        self.sock.settimeout(0.1)
        self.thread = threading.Thread(target=self._run, name="heptabao-syslog-fixture")
        self.thread.start()

    def _run(self):
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                frame = self.sock.recv(128 * 1024)
            except socket.timeout:
                continue
            except OSError:
                return
            prefix = b"<38>heptabao: "
            if not frame.startswith(prefix):
                continue
            try:
                record = json.loads(frame[len(prefix):])
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict):
                continue
            with self.lock:
                self.records.append(record)

    def stop(self):
        self.stop_event.set()
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError("syslog collector thread did not stop")
            self.thread = None
        self.path.unlink(missing_ok=True)

    def restart(self):
        self.stop_event = threading.Event()
        self.start()

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.records))

    def wait_for(self, count: int):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            current = self.snapshot()
            if len(current) >= count:
                return current
            time.sleep(0.01)
        raise RuntimeError("syslog collector did not receive expected records")


def local_records(instance: smoke.Instance):
    return [
        json.loads(line)
        for line in (instance.root / "audit.jsonl").read_text().splitlines()
        if line
    ]


def run(binary: Path, work_dir: Path) -> int:
    os.umask(0o077)
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    collector = SyslogCollector(work_dir / "s.sock")
    collector.start()
    instance = smoke.Instance(binary, work_dir / "server")
    passed: list[str] = []

    def check(name: str, condition: bool):
        if not condition:
            raise RuntimeError("audit_syslog_failed_" + name)
        passed.append(name)

    try:
        config_path = instance.root / "server.json"
        config = json.loads(config_path.read_text())
        config["audit_syslog"] = {
            "facility": "AUTH",
            "tag": "heptabao",
            "socket_path": str(collector.path),
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_path.chmod(0o600)

        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialized_with_syslog_audit", status == 200)
        instance.token = initialized["root_token"]
        key = initialized["keys_base64"][0]
        check(
            "unsealed_with_syslog_audit",
            instance.call("POST", "sys/unseal", {"key": key})[0] == 200,
        )

        status, devices = instance.call("GET", "sys/audit")
        check(
            "sys_audit_lists_file_and_syslog",
            status == 200 and set(devices.get("data", {})) == {"file/", "syslog/"},
        )
        status, device = instance.call("GET", "sys/audit/syslog")
        data = device.get("data", {})
        check(
            "syslog_device_reports_facility_and_tag_only",
            status == 200
            and data.get("type") == "syslog"
            and data.get("options") == {"facility": "AUTH", "tag": "heptabao"}
            and "socket_path" not in json.dumps(data),
        )
        check(
            "api_cannot_rebind_syslog_device",
            instance.call(
                "POST",
                "sys/audit/syslog",
                {"type": "syslog", "options": {"facility": "LOCAL0", "tag": "redirect"}},
            )[0]
            == 409,
        )

        secret = "synthetic-syslog-secret"
        check(
            "audited_mutation_succeeds",
            instance.call("POST", "secret/data/syslog", {"data": {"value": secret}})[0] == 200,
        )
        status, body = instance.call("GET", "secret/data/syslog")
        check(
            "audited_read_succeeds",
            status == 200
            and body.get("data", {}).get("data", {}).get("value") == secret,
        )
        local = local_records(instance)
        remote = collector.wait_for(len(local))
        check("syslog_tail_matches_local_authenticated_audit", remote == local)
        encoded = json.dumps(remote, sort_keys=True)
        check(
            "syslog_records_do_not_expose_secret_or_bearer",
            secret not in encoded
            and instance.token not in encoded
            and "secret/data/syslog" not in encoded,
        )

        before_fault_remote = len(remote)
        collector.stop()
        check(
            "syslog_outage_uses_mandatory_file_device",
            instance.call("GET", "secret/data/syslog")[0] == 200,
        )
        status, observed = instance.call("GET", "sys/audit/syslog")
        check(
            "syslog_outage_is_observable",
            status == 200 and observed.get("data", {}).get("failed_writes", 0) >= 1,
        )

        before_file = len(local_records(instance))
        collector.restart()
        check(
            "collector_recovery_preserves_service",
            instance.call("GET", "secret/data/syslog")[0] == 200,
        )
        recovered = collector.wait_for(before_fault_remote + 2)
        check(
            "collector_receives_new_records_after_recovery",
            len(recovered) >= before_fault_remote + 2,
        )
        check(
            "mandatory_file_audit_continues_through_syslog_fault",
            len(local_records(instance)) > before_file,
        )

        print(
            json.dumps(
                {
                    "status": "passed",
                    "checks": len(passed),
                    "passed": passed,
                    "facility": "AUTH",
                    "tag": "heptabao",
                    "local_unix_agent": True,
                    "api_mutation": False,
                    "production_authority": False,
                    "full_openbao_compatibility": False,
                },
                sort_keys=True,
            )
        )
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
