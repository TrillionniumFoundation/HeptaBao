#!/usr/bin/env python3
"""Real TLS HTTP-audit collector profile for the HeptaBao server.

The collector is loopback-only, has its own CA/leaf identity and returns 204.
The server may reach it only through the deployment-owned outbound allowlist.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "single-node"))
import smoke


class ReusableServer(ThreadingHTTPServer):
    allow_reuse_address = True


class Collector:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        smoke.private_write(
            root / "leaf.ext",
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:audit.local\n",
        )
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
            "-subj", "/CN=HeptaBao Audit Synthetic CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr"),
            "-subj", "/CN=audit.local",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([
            "openssl", "x509", "-req", "-in", str(root / "tls.csr"),
            "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"),
            "-CAcreateserial", "-out", str(root / "tls.crt"), "-days", "2",
            "-sha256", "-extfile", str(root / "leaf.ext"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / "ca.key").chmod(0o600)
        (root / "tls.key").chmod(0o600)
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.port = None

    def start(self, port: int | None = None):
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/audit/events":
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                value = self.headers.get("Content-Length")
                if value is None or not value.isdigit() or int(value) > 128 * 1024:
                    self.send_response(413)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                raw = self.rfile.read(int(value))
                try:
                    document = json.loads(raw)
                except Exception:
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if not isinstance(document, dict):
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                with collector.lock:
                    collector.records.append(document)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        self.server = ReusableServer(("127.0.0.1", 0 if port is None else port), Handler)
        self.port = self.server.server_address[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.root / "tls.crt"), str(self.root / "tls.key"))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, name="audit-collector")
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError("audit collector thread did not stop")
            self.thread = None

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.records))


def configure(instance: smoke.Instance, collector: Collector):
    path = instance.root / "server.json"
    config = json.loads(path.read_text())
    config["outbound_endpoints"] = [{
        "origin": f"https://audit.local:{collector.port}",
        "address": f"127.0.0.1:{collector.port}",
        "server_name": "audit.local",
        "ca_pem": (collector.root / "ca.crt").read_text(),
        "path_prefix": "/audit/",
    }]
    config["audit_http_url"] = f"https://audit.local:{collector.port}/audit/events"
    path.write_text(json.dumps(config), encoding="utf-8")
    path.chmod(0o600)


def run(binary: Path, work_dir: Path) -> int:
    os.umask(0o077)
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    collector = Collector(work_dir / "collector")
    instance = smoke.Instance(binary, work_dir / "server")
    passed = []
    unseal = None

    def check(name, condition):
        if not condition:
            raise RuntimeError("audit_http_failed_" + name)
        passed.append(name)

    try:
        collector.start()
        configure(instance, collector)
        instance.start()
        status, initialized = instance.call(
            "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}
        )
        check("initialized_with_http_audit", status == 200)
        instance.token = initialized["root_token"]
        unseal = initialized["keys_base64"][0]
        status, _ = instance.call("POST", "sys/unseal", {"key": unseal})
        check("unsealed_with_http_audit", status == 200)

        status, devices = instance.call("GET", "sys/audit")
        check(
            "sys_audit_lists_file_and_http",
            status == 200
            and set(devices.get("data", {})) == {"file/", "http/"},
        )
        status, device = instance.call("GET", "sys/audit/http")
        check(
            "sys_audit_http_is_fixed_host_enrolled_device",
            status == 200
            and device.get("data", {}).get("type") == "http"
            and device.get("data", {}).get("options", {}).get("address", "").endswith("/audit/events"),
        )
        status, _ = instance.call(
            "POST",
            "sys/audit/http",
            {"type": "http", "options": {"address": "https://attacker.invalid/"}},
        )
        check("api_cannot_rebind_http_audit_destination", status == 409)

        secret = "audit-http-synthetic-value"
        status, _ = instance.call("POST", "secret/data/audit-http", {"data": {"value": secret}})
        check("audited_mutation_succeeds", status == 200)
        status, body = instance.call("GET", "secret/data/audit-http")
        check(
            "audited_read_succeeds",
            status == 200 and body.get("data", {}).get("data", {}).get("value") == secret,
        )

        remote = collector.snapshot()
        local = [
            json.loads(line)
            for line in (instance.root / "audit.jsonl").read_text().splitlines()
            if line
        ]
        check("every_local_audit_record_delivered_to_http_collector", remote == local)
        encoded = json.dumps(remote, sort_keys=True)
        check(
            "http_audit_records_do_not_expose_secret_or_bearer",
            secret not in encoded
            and instance.token not in encoded
            and "secret/data/audit-http" not in encoded,
        )
        sequences = [item["event"]["sequence"] for item in remote]
        check(
            "http_audit_sequence_is_contiguous",
            sequences == list(range(1, len(sequences) + 1)),
        )

        # Collector outage is not converted into an unaudited request. The local
        # authenticated record may have been committed before the remote failure,
        # but dispatch is withheld and the process audit owner fences itself.
        port = collector.port
        collector.stop()
        status, _ = instance.call("GET", "secret/data/audit-http")
        check("collector_outage_fails_request_closed", status == 503)

        # Restart clears only process-local failure state. The authenticated file
        # tail is recovered, the exact collector endpoint is restored, and audit
        # delivery must resume before application traffic succeeds.
        instance.stop()
        collector.start(port)
        instance.start()
        status, _ = instance.call("POST", "sys/unseal", {"key": unseal})
        check("restart_after_collector_recovery_unseals", status == 200)
        status, body = instance.call("GET", "secret/data/audit-http")
        check(
            "collector_recovery_restores_audited_service",
            status == 200 and body.get("data", {}).get("data", {}).get("value") == secret,
        )
        remote_after = collector.snapshot()
        local_after = [
            json.loads(line)
            for line in (instance.root / "audit.jsonl").read_text().splitlines()
            if line
        ]
        check("post_recovery_http_tail_matches_local_authenticated_audit", remote_after[-2:] == local_after[-2:])

        result = {
            "status": "passed",
            "checks": len(passed),
            "passed": passed,
            "collector": "loopback_host_enrolled_tls",
            "redirects": "forbidden",
            "automatic_retry": False,
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
