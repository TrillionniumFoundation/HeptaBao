#!/usr/bin/env python3
"""Real TLS native candidate capacity/restart probe. Credentials stay private."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import time
import urllib.error
import urllib.request

def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--port", type=int, default=38296)
    parser.add_argument("--timeout-seconds", type=int, default=15)
    args = parser.parse_args()
    os.umask(0o077)
    args.evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    root = args.evidence.resolve()
    binary = args.binary.resolve(strict=True)
    cert, key = root / "server.crt", root / "server.key"
    (root / "cert.conf").write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\nextendedKeyUsage=serverAuth\n")
    with (root / "certificate-generation.log").open("wb") as log:
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-config", str(root / "cert.conf"),
                        "-keyout", str(key), "-out", str(cert)], check=True, stdout=log, stderr=log)
    config = root / "server.json"
    config.write_text(json.dumps({
        "listen": f"127.0.0.1:{args.port}", "data_dir": str(root / "data"),
        "audit_file": str(root / "audit.jsonl"), "tls_cert_file": str(cert),
        "tls_key_file": str(key), "lifecycle_interval_seconds": 0,
        "timeout_seconds": args.timeout_seconds, "max_connections": 8,
    }))
    context = ssl.create_default_context(cafile=str(cert))
    base = f"https://127.0.0.1:{args.port}/v1/"
    token = None
    key_text = None
    process = None
    server_log = None
    rows = []
    def request(name, method, path, body=None, expected=200, auth=True, credential=None):
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if auth and (credential or token):
            headers["X-Vault-Token"] = credential or token
        req = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, context=context, timeout=args.timeout_seconds + 5) as response:
                status, data = response.status, response.read()
        except urllib.error.HTTPError as response:
            status, data = response.code, response.read()
        parsed = json.loads(data) if data else None
        rows.append({"case": name, "status": status, "expected": expected, "passed": status == expected,
                     "elapsed_ms": int((time.monotonic() - started) * 1000), "response_bytes": len(data)})
        if status != expected:
            raise RuntimeError(f"{name}: expected {expected}, got {status}")
        return parsed
    def start(number):
        nonlocal process, server_log
        server_log = (root / f"server-{number}.log").open("wb")
        process = subprocess.Popen([str(binary), "--config", str(config), "--fixture-native-v6-service"],
                                   stdout=server_log, stderr=server_log, cwd="/")
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("candidate server exited before TLS readiness")
            try:
                req = urllib.request.Request(base + "sys/health", method="GET")
                urllib.request.urlopen(req, context=context, timeout=1).close()
                return
            except urllib.error.HTTPError:
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise RuntimeError("candidate TLS readiness timed out")
    def stop():
        nonlocal process, server_log
        if process is not None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=10)
            process = None
        if server_log is not None:
            server_log.close()
            server_log = None
    def check(condition, name):
        rows.append({"case": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError(name)
    failure = None
    try:
        start(1)
        initialized = request("initialize", "POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, auth=False)
        token = initialized["root_token"]
        key_text = initialized["keys_base64"][0]
        (root / "credentials.private.json").write_text(json.dumps({"root_token": token, "unseal_key": key_text}))
        request("unseal-v5-source", "POST", "sys/unseal", {"key": key_text}, auth=False)
        request("mount-root-kv2", "POST", "sys/mounts/secret", {"type": "kv", "options": {"version": "2"}}, expected=204)
        request("source-record-upgrade", "POST", "secret/data/source", {"data": {"value": "source"}})
        request("retain-32", "POST", "secret/config", {"max_versions": 32}, expected=204)
        finite = {}
        for name, policies in [("activation", ["root"]), ("permitted", ["root"]), ("denied", ["default"])]:
            created = request("mint-finite-" + name, "POST", "auth/token/create", {
                "policies": policies, "num_uses": 1, "ttl": "1h", "no_default_policy": True})
            finite[name] = created["auth"]["client_token"]
        (root / "credentials.private.json").write_text(json.dumps({
            "root_token": token, "unseal_key": key_text, "finite_tokens": finite}))
        request("activate-authenticated-native-root", "POST", "sys/internal/native-v6/activate", {},
                expected=204, credential=finite["activation"])
        request("activation-last-use-consumed", "GET", "secret/data/source", expected=403,
                credential=finite["activation"])
        request("finite-resource-permitted", "GET", "secret/data/source", credential=finite["permitted"])
        request("finite-resource-denied", "GET", "secret/data/source", expected=403,
                credential=finite["denied"])
        for name in ("permitted", "denied"):
            request("finite-second-use-" + name, "GET", "secret/data/source", expected=403,
                    credential=finite[name])
        payload_size = 2560 * 1024
        for version in range(1, 17):
            response = request(f"write-history-{version}", "POST", "secret/data/capacity", {
                "options": {"cas": version-1}, "data": {"payload": chr(65+version) * payload_size}})
            check(response["data"]["version"] == version, f"version-{version}")
        capacity = request("native-capacity-observation", "GET", "sys/internal/storage/capacity")
        check("v6" in capacity["data"]["state_storage_format"], "typed-native-format-observed")
        request("stale-cas", "POST", "secret/data/capacity", {"options": {"cas": 15}, "data": {"payload": "stale"}}, expected=400)
        response = request("history-first", "GET", "secret/data/capacity?version=1")
        check(response["data"]["data"]["payload"] == "B" * payload_size, "history-first-exact")
        request("delete-version-3", "POST", "secret/delete/capacity", {"versions": [3]}, expected=204)
        request("deleted-version-3", "GET", "secret/data/capacity?version=3", expected=404)
        stop()
        start(2)
        request("cold-unseal-40mib", "POST", "sys/unseal", {"key": key_text}, auth=False)
        for name in ("activation", "permitted", "denied"):
            request("finite-cold-reject-" + name, "GET", "secret/data/source", expected=403,
                    credential=finite[name])
        metadata = request("cold-metadata", "GET", "secret/metadata/capacity")["data"]
        check(metadata["current_version"] == 16 and metadata["versions"]["3"]["deletion_time"], "cold-history-delete-metadata")
        response = request("cold-history-first", "GET", "secret/data/capacity?version=1")
        check(response["data"]["data"]["payload"] == "B" * payload_size, "cold-history-first-exact")
        request("cold-deleted-3", "GET", "secret/data/capacity?version=3", expected=404)
        response = request("cold-point-write-cas16", "POST", "secret/data/capacity", {
            "options": {"cas": 16}, "data": {"payload": "after-cold"}})
        check(response["data"]["version"] == 17, "cold-point-version-17")
        stop()
        start(3)
        request("second-cold-unseal", "POST", "sys/unseal", {"key": key_text}, auth=False)
        response = request("second-cold-point-read", "GET", "secret/data/capacity")
        check(response["data"]["data"]["payload"] == "after-cold", "second-cold-point-exact")
        request("second-cold-deleted-3", "GET", "secret/data/capacity?version=3", expected=404)
        response = request("second-cold-history-first", "GET", "secret/data/capacity?version=1")
        check(response["data"]["data"]["payload"] == "B" * payload_size, "second-cold-history-first-exact")
    except Exception as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        stop()
        receipt = {"format": "heptabao-native-service-tls-capacity-trial-v1",
                   "candidate_profile": "explicit-feature-root-namespace-single-node",
                   "binary_sha256": digest_file(binary), "timeout_seconds": args.timeout_seconds,
                   "versions": 16, "payload_bytes_each": 2560 * 1024,
                   "history_payload_bytes": 16 * 2560 * 1024, "rows": rows,
                   "passed": failure is None, "failure": failure,
                   "production_default_admitted": False, "ha_qualified": False,
                   "namespace_qualified": False, "full_replacement_qualified": False}
        (root / "receipt.json").write_text(json.dumps(receipt, indent=2))
        print(json.dumps({"passed": receipt["passed"], "cases": len(rows),
                          "failure": failure, "receipt": str(root / "receipt.json")}))
    return 0 if failure is None else 1

if __name__ == "__main__":
    raise SystemExit(main())

