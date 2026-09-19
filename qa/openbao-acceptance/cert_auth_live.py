#!/usr/bin/env python3
"""Exercise certificate auth through the real HeptaBao TLS listener.

This is a bounded mTLS fixture, not a claim of complete OpenBao cert-auth
compatibility.  OpenSSL creates a root/intermediate/client chain and a real
server process is driven over HTTPS.  The fixture covers TLS chain and EKU
validation, exact certificate/subject selectors, metadata, renewal
re-authentication, and restart persistence.  OpenBao features outside this
profile (CRL/OCSP/distribution, forwarded client-cert headers, multi-role
cert semantics, and operational rotation) remain external qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write_private(path: Path, value: str | bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    mode = "wb" if isinstance(value, bytes) else "w"
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, mode) as stream:
        stream.write(value)


def cert_sha256(path: Path) -> str:
    der = subprocess.check_output(["openssl", "x509", "-in", str(path), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def issue_leaf(root: Path, name: str, subject: str, issuer_cert: Path, issuer_key: Path, ext: str) -> tuple[Path, Path]:
    key = root / f"{name}.key"
    csr = root / f"{name}.csr"
    cert = root / f"{name}.crt"
    ext_path = root / f"{name}.ext"
    serial = root / f"{name}.srl"
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", subject])
    write_private(ext_path, ext)
    run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(issuer_cert), "-CAkey", str(issuer_key),
         "-CAserial", str(serial), "-CAcreateserial", "-out", str(cert), "-days", "2", "-sha256",
         "-extfile", str(ext_path)])
    key.chmod(0o600)
    return cert, key


class Fixture:
    def __init__(self, binary: Path, root: Path):
        self.binary, self.root = binary, root
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.address = f"https://127.0.0.1:{self.port}"
        self._make_certs()
        self.good_context = self._client_context(self.root / "client-chain.pem", self.root / "client.key")
        self.wrong_context = self._client_context(self.root / "wrong-client-chain.pem", self.root / "wrong-client.key")
        self.bad_eku_context = self._client_context(self.root / "bad-eku-chain.pem", self.root / "bad-eku.key")
        self.untrusted_context = self._client_context(self.root / "untrusted-client.crt", self.root / "untrusted-client.key",
                                                       cafile=self.root / "root.crt")
        self.no_cert_client = self._opener(ssl.create_default_context(cafile=str(self.root / "root.crt")))
        self.good_client = self._opener(self.good_context)
        self.wrong_client = self._opener(self.wrong_context)
        self.bad_eku_client = self._opener(self.bad_eku_context)
        self.untrusted_client = self._opener(self.untrusted_context)
        write_private(root / "server.json", json.dumps({
            "listen": f"127.0.0.1:{self.port}",
            "data_dir": str(root / "data"),
            "audit_file": str(root / "audit.jsonl"),
            "tls_cert_file": str(root / "server.crt"),
            "tls_key_file": str(root / "server.key"),
            "tls_client_ca_file": str(root / "root.crt"),
        }))
        self.process: subprocess.Popen[bytes] | None = None
        self.log = None
        self.token = ""
        self.unseal_key = ""
        self.cert_digest = cert_sha256(root / "client.crt")

    def _make_certs(self) -> None:
        root = self.root
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", str(root / "root.key"), "-out", str(root / "root.crt"),
             "-subj", "/CN=HeptaBao mTLS fixture root",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        (root / "root.key").chmod(0o600)
        intermediate, intermediate_key = issue_leaf(
            root, "intermediate", "/CN=HeptaBao mTLS fixture intermediate",
            root / "root.crt", root / "root.key",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
        )
        server, server_key = issue_leaf(
            root, "server", "/CN=localhost",
            root / "root.crt", root / "root.key",
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )
        client_ext = (
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=clientAuth\nsubjectAltName=DNS:client.example.test,email:user@example.test,"
            "URI:spiffe://example/client\nsubjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n1.2.3.4.5=ASN1:UTF8String:tenant-a\n"
        )
        client, client_key = issue_leaf(root, "client", "/CN=client.example.test/OU=Engineering",
                                         intermediate, intermediate_key, client_ext)
        wrong, wrong_key = issue_leaf(root, "wrong-client", "/CN=intruder.example.test/OU=Other",
                                      intermediate, intermediate_key,
                                      "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                                      "extendedKeyUsage=clientAuth\nsubjectAltName=DNS:intruder.example.test\n")
        bad_eku, bad_eku_key = issue_leaf(
            root, "bad-eku", "/CN=server-only.example.test/OU=Other", intermediate, intermediate_key,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:server-only.example.test\n",
        )
        untrusted_ca, untrusted_ca_key = issue_leaf(
            root, "untrusted-ca", "/CN=HeptaBao untrusted fixture root",
            root / "root.crt", root / "root.key",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n",
        )
        untrusted, untrusted_key = issue_leaf(
            root, "untrusted-client", "/CN=untrusted.example.test",
            untrusted_ca, untrusted_ca_key,
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=clientAuth\nsubjectAltName=DNS:untrusted.example.test\n",
        )
        # The issuer helper already wrote the leaf/key files.  The server only
        # needs its leaf; clients present leaf + intermediate as a chain.
        write_private(root / "client-chain.pem", client.read_bytes() + intermediate.read_bytes())
        write_private(root / "wrong-client-chain.pem", wrong.read_bytes() + intermediate.read_bytes())
        write_private(root / "bad-eku-chain.pem", bad_eku.read_bytes() + intermediate.read_bytes())
        for name in ("server.key", "client.key", "wrong-client.key", "untrusted-client.key"):
            (root / name).chmod(0o600)

    def _client_context(self, cert: Path, key: Path, *, cafile: Path | None = None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(cafile or self.root / "root.crt"))
        context.load_cert_chain(str(cert), str(key))
        return context

    def _opener(self, context: ssl.SSLContext):
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

    def start(self) -> None:
        self.log = open(self.root / "server.log", "ab")
        self.process = subprocess.Popen([str(self.binary), "--config", str(self.root / "server.json")],
                                        stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError("server exited during cert fixture startup")
            try:
                status, _ = self.call("GET", "sys/health")
                if status in (200, 501, 503):
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.05)
        raise RuntimeError("mTLS listener did not become ready")

    def stop(self) -> None:
        if self.process is not None:
            self.process.kill()
            self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def call(self, method: str, path: str, body=None, *, token: str | None = None, client=None):
        opener = client or self.good_client
        headers = {"Content-Type": "application/json", "X-Vault-Token": self.token if token is None else token}
        request = urllib.request.Request(self.address + "/v1/" + path,
                                          data=None if body is None else json.dumps(body).encode(),
                                          headers=headers, method=method)
        try:
            response = opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise RuntimeError("unbounded response")
            return response.status, json.loads(payload) if payload else {}


def run_fixture(binary: Path, root: Path) -> dict:
    fixture = Fixture(binary, root)
    checks: list[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            raise RuntimeError(f"failed scenario: {name}")
        checks.append(name)

    try:
        fixture.start()
        try:
            fixture.call("GET", "sys/health", client=fixture.no_cert_client)
            missing_client_failed = False
        except (ssl.SSLError, urllib.error.URLError, ConnectionError, OSError):
            missing_client_failed = True
        check("mTLS_listener_rejects_missing_client_chain", missing_client_failed)
        check("mTLS_listener_requires_client_chain", fixture.call("GET", "sys/health")[0] in (501, 503))
        status, init = fixture.call("POST", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        check("initialize_over_mTLS", status == 200 and bool(init.get("root_token")))
        fixture.token = init["root_token"]
        fixture.unseal_key = init["keys_base64"][0]
        check("unseal_over_mTLS", fixture.call("POST", "sys/unseal", {"key": fixture.unseal_key})[0] == 200)
        check("cert_auth_mount", fixture.call("POST", "sys/auth/cert", {"type": "cert"})[0] == 204)
        policy = 'path "secret/data/cert-fixture" { capabilities = ["read"] }'
        check("cert_policy", fixture.call("POST", "sys/policies/acl/cert-reader", {"policy": policy})[0] == 204)
        role = {
            "certificate_sha256": fixture.cert_digest,
            "token_policies": ["cert-reader"],
            "allowed_common_names": ["client.example.test"],
            "allowed_dns_sans": ["client.example.test"],
            "allowed_organizational_units": ["Engineering"],
            "required_extensions": ["1.2.3.4.5:tenant-*"],
            "allowed_metadata_extensions": ["1.2.3.4.5"],
            "token_ttl": "30s",
            "token_max_ttl": "2m",
        }
        check("cert_role_with_chain_selectors", fixture.call("POST", "auth/cert/certs/operator", role)[0] == 204)
        status, login = fixture.call("POST", "auth/cert/login", {}, token="", client=fixture.good_client)
        metadata = login.get("auth", {}).get("metadata", {}) if isinstance(login, dict) else {}
        check("cert_login_chain_eku_and_selectors", status == 200 and login.get("auth", {}).get("client_token"))
        check("cert_metadata_subject_san_ou_extension", metadata.get("common_name") == "client.example.test"
              and metadata.get("1-2-3-4-5") == "tenant-a")
        cert_token = login["auth"]["client_token"]
        status, secret = fixture.call("POST", "secret/data/cert-fixture", {"data": {"value": "fixture"}}, token=fixture.token)
        check("root_secret_for_readback", status == 200)
        status, read = fixture.call("GET", "secret/data/cert-fixture", token=cert_token)
        check("cert_token_policy_read", status == 200 and read.get("data", {}).get("data", {}).get("value") == "fixture")
        status, renewed = fixture.call("POST", "auth/token/renew-self", {}, token=cert_token, client=fixture.good_client)
        check("cert_renewal_reauthenticates_same_leaf", status == 200 and renewed.get("auth", {}).get("renewable") is True)
        status, _ = fixture.call("POST", "auth/cert/login", {}, token="", client=fixture.wrong_client)
        check("same_CA_wrong_leaf_denied_by_role_digest", status == 403)
        try:
            fixture.call("POST", "auth/cert/login", {}, token="", client=fixture.bad_eku_client)
            bad_eku_failed = False
        except (ssl.SSLError, urllib.error.URLError, ConnectionError, OSError):
            bad_eku_failed = True
        check("client_auth_EKU_rejects_server_only_certificate", bad_eku_failed)
        try:
            fixture.call("POST", "auth/cert/login", {}, token="", client=fixture.untrusted_client)
            untrusted_failed = False
        except (ssl.SSLError, urllib.error.URLError, ConnectionError, OSError):
            untrusted_failed = True
        check("untrusted_chain_rejected_by_TLS", untrusted_failed)
        fixture.stop()
        fixture.start()
        check("restart_starts_sealed", fixture.call("GET", "sys/health")[0] == 503)
        check("restart_unseal_over_mTLS", fixture.call("POST", "sys/unseal", {"key": fixture.unseal_key})[0] == 200)
        status, renewed_after_restart = fixture.call("POST", "auth/token/renew-self", {}, token=cert_token,
                                                    client=fixture.good_client)
        check("cert_renewal_reauthenticates_after_restart", status == 200
              and renewed_after_restart.get("auth", {}).get("renewable") is True)
        return {"schema": "heptabao.cert-auth-live.v1", "status": "passed", "checks": checks,
                "count": len(checks), "compatibility_claim": False, "production_authority": False}
    finally:
        fixture.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.work_dir.is_absolute() or args.work_dir.exists():
        parser.error("--binary and a new absolute --work-dir are required")
    try:
        report = run_fixture(args.binary, args.work_dir)
    except Exception as error:
        print(f"cert-auth live fixture failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
