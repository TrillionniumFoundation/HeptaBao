#!/usr/bin/env python3
"""Start only the pinned official OpenBao 2.6.2 Linux amd64 artifact locally.

Set HB_ORACLE_BINARY and HB_ORACLE_ARCHIVE to existing operator-provided files.
There is no network download, development mode, insecure TLS, or external host.
The caller owns synthetic credentials retained in the returned private root.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time

from bao_http import BaoError, Client, private_write

VERSION = "2.6.2"
ARTIFACT_SHA256 = "8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa"
BINARY_SHA256 = "8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00"
PROVENANCE_URL = "https://github.com/openbao/openbao/releases/tag/v2.6.2"


def stream_digest(handle):
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def file_digest(path):
    with Path(path).open("rb") as handle:
        return stream_digest(handle)


def verify_inputs():
    binary = Path(os.environ["HB_ORACLE_BINARY"]).resolve(strict=True)
    archive = Path(os.environ["HB_ORACLE_ARCHIVE"]).resolve(strict=True)
    if file_digest(archive) != ARTIFACT_SHA256 or file_digest(binary) != BINARY_SHA256:
        raise BaoError("official_oracle_pinned_digest_mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        members = [entry for entry in bundle.getmembers() if entry.name.removeprefix("./") == "bao"]
        if len(members) != 1 or not members[0].isfile():
            raise BaoError("official_oracle_archive_binary_missing")
        with bundle.extractfile(members[0]) as stream:
            if stream_digest(stream) != BINARY_SHA256:
                raise BaoError("official_oracle_binary_not_archive_member")
    return binary


def private_text(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value)


def certificates(root):
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
         "-subj", "/CN=Official OpenBao Synthetic Oracle CA",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr"), "-subj", "/CN=localhost"],
        ["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(root / "ca.crt"),
         "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(root / "tls.crt"),
         "-days", "2", "-sha256", "-extfile", str(root / "leaf.ext")],
    ]
    private_text(root / "leaf.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in (root / "ca.key", root / "tls.key"):
        path.chmod(0o600)


def stop_oracle(oracle):
    process = oracle.get("process")
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    log = oracle.get("log")
    if log is not None and not log.closed:
        log.close()


def start_oracle(port):
    if type(port) is not int or not 1024 <= port <= 65534:
        raise BaoError("official_oracle_invalid_loopback_port")
    binary = verify_inputs()
    root = Path(tempfile.mkdtemp(prefix="official-openbao-2.6.2-", dir=os.environ.get("HB_ORACLE_WORK_ROOT")))
    root.chmod(0o700)
    old_mask = os.umask(0o077)
    oracle = {"root": str(root), "address": f"https://127.0.0.1:{port}",
              "ca_file": str(root / "ca.crt"), "token_file": str(root / "root.token"),
              "artifact_sha256": ARTIFACT_SHA256, "binary_sha256": BINARY_SHA256}
    try:
        certificates(root)
        private_text(root / "server.json", json.dumps({
            "disable_mlock": True, "ui": False,
            "api_addr": oracle["address"], "cluster_addr": f"https://127.0.0.1:{port + 1}",
            "storage": {"file": {"path": str(root / "data")}},
            "listener": [{"tcp": {"address": f"127.0.0.1:{port}",
                                    "tls_cert_file": str(root / "tls.crt"),
                                    "tls_key_file": str(root / "tls.key"),
                                    "tls_min_version": "tls12"}}],
        }))
        oracle["log"] = open(root / "server.log", "ab")
        # Configuration contains no credential. Never use -dev or a token argument.
        oracle["process"] = subprocess.Popen(
            [str(binary), "server", "-config=" + str(root / "server.json")],
            stdout=oracle["log"], stderr=oracle["log"],
        )
        client = Client(oracle["address"], oracle["ca_file"], "synthetic-uninitialized-client", timeout=2)
        for _ in range(100):
            if oracle["process"].poll() is not None:
                raise BaoError("official_oracle_exited_before_ready")
            try:
                response = client.request("GET", "/v1/sys/health")
                if response.status == 501:
                    break
            except BaoError:
                pass
            time.sleep(0.05)
        else:
            raise BaoError("official_oracle_tls_startup_timeout")
        initialized = client.request("POST", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if initialized.status != 200:
            raise BaoError("official_oracle_init_failed")
        token, key = initialized.body["root_token"], initialized.body["keys_base64"][0]
        private_text(root / "root.token", token)
        private_text(root / "unseal.key", key)
        if client.request("POST", "/v1/sys/unseal", {"key": key}).status != 200:
            raise BaoError("official_oracle_unseal_failed")
        health = Client(oracle["address"], oracle["ca_file"], token).health()
        if health["version"] != VERSION:
            raise BaoError("official_oracle_live_version_mismatch")
        identity = {"product": "OpenBao", "version": VERSION, "artifact_sha256": ARTIFACT_SHA256,
                    "binary_sha256": BINARY_SHA256, "provenance_url": PROVENANCE_URL,
                    "endpoint": oracle["address"], "cluster_id": health["cluster_id"],
                    "archive_member_matches_executable": True, "server_mode": "server_not_dev",
                    "storage": "file", "tls_verified": True, "synthetic_only": True,
                    "launcher_source_sha256": file_digest(__file__)}
        private_write(root / "oracle-identity.json", identity)
        oracle["identity_file"] = str(root / "oracle-identity.json")
        return oracle
    except Exception:
        stop_oracle(oracle)
        raise
    finally:
        os.umask(old_mask)
