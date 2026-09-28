#!/usr/bin/env python3
"""Start only an explicitly version-pinned official OpenBao Linux artifact locally.

Set HB_ORACLE_BINARY and HB_ORACLE_ARCHIVE to existing operator-provided files.
There is no network download, development mode, insecure TLS, or external host.
The caller owns synthetic credentials retained in the returned private root.
"""

import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time

from bao_http import BaoError, Client, private_write

VERSION = "2.6.2"
# The release publishes independent archives for Linux amd64 and arm64.  Keep
# both pins here so the same launcher can run in the amd64 CI runner and the
# arm64 Linux qualification VM without accepting an unpinned or cross-arch
# executable.  The amd64 constants remain the compatibility default on hosts
# where no runnable official artifact exists (for example macOS development).
PINNED_ARTIFACTS = {
    ("linux", "amd64"): {
        "artifact_sha256": "8dc11cc5fca0b539a9e352727dacb4e2d304daffcf9a66e0718ac325a20d05aa",
        "binary_sha256": "8d18052337908a74f0d7dfacc8da7a1bff5f8a4ab6a2ad136fbf5ffeae243b00",
    },
    ("linux", "arm64"): {
        "artifact_sha256": "1b408e01f3565ac0cbcb88d637dca271d0515148fb72efdeff4473a34fa50c4e",
        "binary_sha256": "1c3f62018046ec72be8720b576a55105b64b4cbd634d98483a93c642e69dc153",
    },
}


# Historical 2.6.2 receipts and default callers retain their original pins.
# A new minor version must supply an independently verified archive AND binary
# digest; an unverified architecture is deliberately not admitted by this table.
PINNED_RELEASES = {
    VERSION: PINNED_ARTIFACTS,
    "2.7.0": {
        ("linux", "amd64"): {
            "artifact_sha256": "c3ab5de9e778223445487ccbfb16c291bf491642b688f3a3df5aeba23d9b3667",
            "binary_sha256": "9403c2b121e13fe79b3182051320d2096d10519b597ee587e322dab5e359c51e",
        },
    },
}
SUPPORTED_VERSIONS = tuple(PINNED_RELEASES)


def release_artifacts(version):
    if not isinstance(version, str) or version not in PINNED_RELEASES:
        raise BaoError("official_oracle_unsupported_version")
    return PINNED_RELEASES[version]


def _platform_key(system=None, machine=None):
    system = (platform.system() if system is None else system).lower()
    machine = (platform.machine() if machine is None else machine).lower()
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)
    return system, machine


def pinned_artifact(system=None, machine=None, *, version=VERSION):
    """Return the immutable release pins for the current runnable host.

    Unsupported hosts retain the amd64 constants for report/import stability,
    but ``verify_inputs`` rejects execution before it can launch a binary.
    """
    artifacts = release_artifacts(version)
    return dict(artifacts.get(_platform_key(system, machine), artifacts[("linux", "amd64")]))


_CURRENT_PIN = pinned_artifact()
ARTIFACT_SHA256 = _CURRENT_PIN["artifact_sha256"]
BINARY_SHA256 = _CURRENT_PIN["binary_sha256"]
PROVENANCE_URL = "https://github.com/openbao/openbao/releases/tag/v2.6.2"


def stream_digest(handle):
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def file_digest(path):
    with Path(path).open("rb") as handle:
        return stream_digest(handle)


def verify_inputs(*, version=VERSION):
    artifacts = release_artifacts(version)
    if _platform_key() not in artifacts:
        raise BaoError("official_oracle_unsupported_platform")
    expected = pinned_artifact(version=version)
    binary = Path(os.environ["HB_ORACLE_BINARY"]).resolve(strict=True)
    archive = Path(os.environ["HB_ORACLE_ARCHIVE"]).resolve(strict=True)
    if file_digest(archive) != expected["artifact_sha256"] or file_digest(binary) != expected["binary_sha256"]:
        raise BaoError("official_oracle_pinned_digest_mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        members = [entry for entry in bundle.getmembers() if entry.name.removeprefix("./") == "bao"]
        if len(members) != 1 or not members[0].isfile():
            raise BaoError("official_oracle_archive_binary_missing")
        with bundle.extractfile(members[0]) as stream:
            if stream_digest(stream) != expected["binary_sha256"]:
                raise BaoError("official_oracle_binary_not_archive_member")
    return binary


def private_text(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value)


def oracle_environment(root):
    """Do not inherit caller tokens, TLS overrides, namespaces or proxies."""
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ}
    environment["TMPDIR"] = str(root)
    return environment


def oracle_cli_environment(oracle, token):
    environment = oracle_environment(oracle["root"])
    for prefix in ("BAO", "VAULT"):
        environment.update({prefix + "_ADDR": oracle["address"],
                            prefix + "_CACERT": oracle["ca_file"],
                            prefix + "_TOKEN": token,
                            prefix + "_MAX_RETRIES": "0"})
    return environment


def certificates(root):
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt"),
         "-subj", "/CN=Official OpenBao Synthetic Oracle CA",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(root / "tls.key"), "-out", str(root / "tls.csr"), "-subj", "/CN=localhost"],
        ["openssl", "x509", "-req", "-in", str(root / "tls.csr"), "-CA", str(root / "ca.crt"),
         "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(root / "tls.crt"),
         "-days", "2", "-sha256", "-extfile", str(root / "leaf.ext")],
    ]
    private_text(root / "leaf.ext", "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
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


def restart_oracle(oracle):
    """Restart the same private synthetic Oracle root without reinitializing it."""
    version = oracle.get("version", VERSION)
    binary = verify_inputs(version=version)
    root = Path(oracle["root"]).resolve(strict=True)
    process = oracle.get("process")
    if process is not None and process.poll() is None:
        raise BaoError("official_oracle_restart_requires_stopped_process")
    for name in ("server.json", "ca.crt", "tls.crt", "tls.key", "root.token", "unseal.key"):
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise BaoError("official_oracle_restart_input_missing")
    token = (root / "root.token").read_text().strip()
    key = (root / "unseal.key").read_text().strip()
    if not token or not key:
        raise BaoError("official_oracle_restart_secret_missing")
    oracle["log"] = open(root / "server.log", "ab")
    oracle["process"] = subprocess.Popen(
        [str(binary), "server", "-config=" + str(root / "server.json")],
        stdout=oracle["log"], stderr=oracle["log"], env=oracle_environment(root),
    )
    client = Client(oracle["address"], oracle["ca_file"], token, timeout=2)
    observed_health = None
    for _ in range(100):
        if oracle["process"].poll() is not None:
            raise BaoError("official_oracle_exited_during_restart")
        try:
            response = client.request("GET", "/v1/sys/health")
            if response.status in (200, 429, 503):
                observed_health = response.body
                break
        except BaoError:
            pass
        time.sleep(0.05)
    else:
        stop_oracle(oracle)
        raise BaoError("official_oracle_restart_timeout")
    if not isinstance(observed_health, dict) or observed_health.get("initialized") is not True:
        stop_oracle(oracle)
        raise BaoError("official_oracle_restart_health_invalid")
    if observed_health.get("sealed") is True:
        if client.request("POST", "/v1/sys/unseal", {"key": key}).status != 200:
            stop_oracle(oracle)
            raise BaoError("official_oracle_restart_unseal_failed")
    health = client.health()
    if health["version"] != version:
        stop_oracle(oracle)
        raise BaoError("official_oracle_restart_version_mismatch")
    expected_cluster = oracle.get("cluster_id")
    if expected_cluster is not None and health["cluster_id"] != expected_cluster:
        stop_oracle(oracle)
        raise BaoError("official_oracle_restart_cluster_identity_changed")
    oracle["cluster_id"] = health["cluster_id"]
    return oracle


def storage_configuration(root, *, version=VERSION, raft_storage=False):
    """Keep non-HA fixtures non-HA across the removal of file in OpenBao 2.7.

    Reference: https://openbao.org/docs/configuration/storage/pebbledb/
    A Raft fixture remains an explicit opt-in, not a silent topology change.
    """
    release_artifacts(version)
    if type(raft_storage) is not bool:
        raise BaoError("official_oracle_invalid_storage_profile")
    if raft_storage:
        return {"raft": {"path": str(root / "data"), "node_id": "synthetic-openbao-1"}}
    backend = "pebbledb" if version == "2.7.0" else "file"
    return {backend: {"path": str(root / "data")}}


def start_oracle(port, *, audit_file=False, raft_storage=False, version=VERSION):
    if type(audit_file) is not bool or type(raft_storage) is not bool:
        raise BaoError("official_oracle_invalid_audit_profile")
    if type(port) is not int or not 1024 <= port <= 65534:
        raise BaoError("official_oracle_invalid_loopback_port")
    binary = verify_inputs(version=version)
    expected = pinned_artifact(version=version)
    root = Path(tempfile.mkdtemp(prefix="official-openbao-" + version + "-", dir=os.environ.get("HB_ORACLE_WORK_ROOT")))
    root.chmod(0o700)
    old_mask = os.umask(0o077)
    oracle = {"root": str(root), "address": f"https://127.0.0.1:{port}",
              "ca_file": str(root / "ca.crt"), "token_file": str(root / "root.token"),
              "version": version, "artifact_sha256": expected["artifact_sha256"],
              "binary_sha256": expected["binary_sha256"]}
    try:
        certificates(root)
        storage = storage_configuration(root, version=version, raft_storage=raft_storage)
        oracle["storage_backend"] = next(iter(storage))
        if raft_storage or version == "2.7.0":
            (root / "data").mkdir(mode=0o700)
        config = {
            "disable_mlock": True, "ui": False,
            "api_addr": oracle["address"], "cluster_addr": f"https://127.0.0.1:{port + 1}",
            "storage": storage,
            "listener": [{"tcp": {"address": f"127.0.0.1:{port}",
                                    "tls_cert_file": str(root / "tls.crt"),
                                    "tls_key_file": str(root / "tls.key"),
                                    "tls_min_version": "tls12"}}],
        }
        if audit_file:
            # Fixed synthetic deployment configuration; no arbitrary caller path,
            # API-enrollment opt-in, or raw secret logging is introduced.
            config["audit"] = [{"file": {"file": {
                "description": "Synthetic declarative file audit device",
                "options": {"file_path": str(root / "audit.jsonl"), "mode": "0600"},
            }}}]
        private_text(root / "server.json", json.dumps(config))
        oracle["log"] = open(root / "server.log", "ab")
        # Configuration contains no credential. Never use -dev or a token argument.
        oracle["process"] = subprocess.Popen(
            [str(binary), "server", "-config=" + str(root / "server.json")],
            stdout=oracle["log"], stderr=oracle["log"], env=oracle_environment(root),
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
        # A fresh Raft peer elects its first leader during init. The readiness
        # polling timeout (2s) is too short for that one-time operation. Send
        # exactly one request with a longer deadline; never retry an init with
        # unknown outcome, which would lose the generated custody material.
        if raft_storage:
            client = Client(oracle["address"], oracle["ca_file"], "synthetic-uninitialized-client", timeout=30)
        initialized = client.request("POST", "/v1/sys/init", {"secret_shares": 1, "secret_threshold": 1})
        if initialized.status != 200:
            raise BaoError("official_oracle_init_failed")
        token, key = initialized.body["root_token"], initialized.body["keys_base64"][0]
        private_text(root / "root.token", token)
        private_text(root / "unseal.key", key)
        if client.request("POST", "/v1/sys/unseal", {"key": key}).status != 200:
            raise BaoError("official_oracle_unseal_failed")
        health = Client(oracle["address"], oracle["ca_file"], token).health()
        if health["version"] != version:
            raise BaoError("official_oracle_live_version_mismatch")
        identity = {"product": "OpenBao", "version": version,
                    "artifact_sha256": expected["artifact_sha256"],
                    "binary_sha256": expected["binary_sha256"],
                    "provenance_url": "https://github.com/openbao/openbao/releases/tag/v" + version,
                    "endpoint": oracle["address"], "cluster_id": health["cluster_id"],
                    "archive_member_matches_executable": True, "server_mode": "server_not_dev",
                    "storage": oracle["storage_backend"], "tls_verified": True, "synthetic_only": True,
                    "launcher_source_sha256": file_digest(__file__)}
        private_write(root / "oracle-identity.json", identity)
        oracle["identity_file"] = str(root / "oracle-identity.json")
        oracle["cluster_id"] = health["cluster_id"]
        return oracle
    except Exception:
        stop_oracle(oracle)
        raise
    finally:
        os.umask(old_mask)
