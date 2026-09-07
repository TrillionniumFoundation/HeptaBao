#!/usr/bin/env python3
"""Run the real TLS server, then SIGKILL/reopen it using synthetic secrets only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def private_write(path: Path, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(value)


class Instance:
    def __init__(self, binary: Path, root: Path):
        self.root, self.binary = root, binary
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.address = f"https://127.0.0.1:{self.port}"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
            "-subj", "/CN=HeptaBao Synthetic Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr"),
                        "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private_write(root / "leaf.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        subprocess.run(["openssl", "x509", "-req", "-in", str(root / "tls.csr"),
                        "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
                        "-out", str(root / "tls.crt"), "-days", "2", "-sha256", "-extfile", str(root / "leaf.ext")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root / "ca.key").chmod(0o600)
        (root / "tls.key").chmod(0o600)
        self.context = ssl.create_default_context(cafile=str(root / "ca.crt"))
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self.context))
        private_write(root / "server.json", json.dumps({
            "listen": f"127.0.0.1:{self.port}", "data_dir": str(root / "data"),
            "audit_file": str(root / "audit.jsonl"), "tls_cert_file": str(root / "tls.crt"),
            "tls_key_file": str(root / "tls.key"),
        }))
        self.token = ""
        self.process = None

    def start(self):
        self.log = open(self.root / "server.log", "ab")
        self.process = subprocess.Popen([str(self.binary), "--config", str(self.root / "server.json")],
                                        stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError("server exited during startup; inspect redacted server.log")
            try:
                status, _ = self.call("GET", "sys/health")
                if status in (200, 501, 503):
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)
        raise RuntimeError("TLS listener did not become ready")

    def stop(self):
        if self.process is not None:
            self.process.kill()
            self.process.wait(timeout=5)
            self.log.close()
            self.process = None

    def call(self, method, path, body=None, *, token=None, namespace="", extra_headers=None):
        headers = {"Content-Type": "application/json", "X-Vault-Token": self.token if token is None else token}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        headers.update(extra_headers or {})
        request = urllib.request.Request(self.address + "/v1/" + path,
            data=None if body is None else json.dumps(body).encode(), headers=headers, method=method)
        try:
            response = self.client.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024 + 1)
            assert len(raw) <= 1024 * 1024, "unbounded response"
            return response.status, json.loads(raw) if raw else {}


def run(binary: Path, root: Path, keep_running: bool):
    instance = Instance(binary, root)
    passed = []
    def check(name, condition):
        if not condition:
            raise RuntimeError("failed scenario: " + name)
        passed.append(name)
    try:
        instance.start()
        check("uninitialized_health", instance.call("GET", "sys/health")[0] == 501)
        status, initialized = instance.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize_once", status == 200 and bool(initialized.get("root_token")))
        instance.token = initialized["root_token"]
        key = initialized["keys_base64"][0]
        private_write(root / "root-token", instance.token)
        private_write(root / "unseal-key", key)
        check("initialized_stays_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("sealed_secret_denied", instance.call("GET", "secret/data/item")[0] == 503)
        check("wrong_unseal_denied", instance.call("POST", "sys/unseal", {"key": "00" * 32})[0] >= 400)
        check("unseal", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        check("active_health", instance.call("GET", "sys/health")[0] == 200)
        marker = "synthetic-secret-" + secrets.token_hex(32)
        check("kv_write", instance.call("POST", "secret/data/item", {"data": {"value": marker}})[0] == 200)
        status, read = instance.call("GET", "secret/data/item?version=1")
        check("kv_read", status == 200 and read["data"]["data"]["value"] == marker)
        check("invalid_token_denied", instance.call("GET", "secret/data/item", token="invalid-synthetic")[0] == 403)
        check("unsupported_wrapping_withholds_secret", instance.call("GET", "secret/data/item", extra_headers={"X-Vault-Wrap-TTL": "60s"})[0] == 501)
        check("unsupported_mfa_fails_closed", instance.call("GET", "secret/data/item", extra_headers={"X-Vault-MFA": "synthetic"})[0] == 501)
        check("secret_query_rejected", instance.call("POST", "smoke-totp/keys/leak?url=synthetic", {})[0] == 400)
        # Equal path suffixes in distinct namespaces must not share bytes.
        check("namespace_write", instance.call("POST", "secret/data/item", {"data": {"value": "different"}}, namespace="isolated")[0] == 200)
        check("namespace_isolation", instance.call("GET", "secret/data/item")[1]["data"]["data"]["value"] == marker)
        policy = 'path "secret/data/item" { capabilities = ["read"] }'
        check("policy_write", instance.call("POST", "sys/policies/acl/smoke-reader", {"policy": policy})[0] == 204)
        status, created = instance.call("POST", "auth/token/create", {"policies": ["smoke-reader"], "ttl": "1h", "num_uses": 1})
        check("limited_token_create", status == 200)
        limited = created["auth"]["client_token"]
        check("denied_consumes_use", instance.call("POST", "secret/data/item", {"data": {"value": "forbidden"}}, token=limited)[0] == 403)
        check("limited_use_exhausted", instance.call("GET", "secret/data/item", token=limited)[0] == 403)
        check("totp_mount", instance.call("POST", "sys/mounts/smoke-totp", {"type": "totp"})[0] == 204)
        check("totp_import", instance.call("POST", "smoke-totp/keys/item", {"key": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits": 8, "period": 3600})[0] in (200, 204))
        status, generated = instance.call("GET", "smoke-totp/code/item")
        check("totp_generate", status == 200 and len(generated["data"]["code"]) == 8)
        used_code = generated["data"]["code"]
        status, validated = instance.call("POST", "smoke-totp/code/item", {"code": used_code})
        check("totp_validate", status == 200 and validated["data"]["valid"] is True)
        check("ha_explicitly_unimplemented", instance.call("POST", "sys/step-down", {})[0] == 501)
        instance.stop()  # SIGKILL, deliberately no clean seal/close.
        check("encrypted_disk", all(marker.encode() not in path.read_bytes() for path in (root / "data").rglob("*") if path.is_file()))
        check("redacted_audit", marker.encode() not in (root / "audit.jsonl").read_bytes())
        instance.start()
        check("restart_is_sealed", instance.call("GET", "sys/health")[0] == 503)
        check("restart_lock_released", instance.call("POST", "sys/unseal", {"key": key})[0] == 200)
        status, read = instance.call("GET", "secret/data/item")
        check("durable_secret_survives_sigkill", status == 200 and read["data"]["data"]["value"] == marker)
        check("consumed_use_survives_sigkill", instance.call("GET", "secret/data/item", token=limited)[0] == 403)
        status, replayed = instance.call("POST", "smoke-totp/code/item", {"code": used_code})
        check("totp_replay_denied_after_sigkill", status == 200 and replayed["data"]["valid"] is False)
        evidence = {"schema": "heptabao.single-node-smoke.v1", "passed": passed, "count": len(passed),
                    "compatibility_claim": False, "production_authority": False,
                    "address": instance.address, "pid": instance.process.pid if keep_running else None}
        private_write(root / "smoke-result.json", json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence))
        if keep_running:
            # Explicitly transfer the local test process to the caller.
            instance.process = None
            instance.log.close()
    finally:
        instance.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True, help="new absolute directory; contains owner-only synthetic credentials")
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()
    if not args.work_dir.is_absolute() or not args.binary.is_absolute():
        parser.error("paths must be absolute")
    try:
        run(args.binary, args.work_dir, args.keep_running)
    except Exception as error:
        # Never print HTTP payloads, bearer credentials, or private key material.
        print("single-node smoke failed: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
