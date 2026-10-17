#!/usr/bin/env python3
"""Fail-closed, read-only mTLS peer preflight for PRIVATE synthetic HA fixtures.

Never initializes/unseals a service, changes firewall/routes, sends business
data, or grants HA/root-commit authority. By default no network connection is
made. An explicit --probe-peer checks one existing mTLS listener.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import stat

ALPN = "heptabao-raft/1"
SCHEMA = "heptabao.synthetic-three-host-peer-preflight.v1"


class Refusal(Exception):
    def __init__(self, label: str):
        if not label.isascii() or not label.replace("_", "").isupper():
            raise ValueError("invalid redacted refusal label")
        self.label = label
        super().__init__(label)


def private_regular(path: Path) -> Path:
    """Validate a regular, owner-only file without following a leaf symlink."""
    if path.is_symlink():
        raise Refusal("SYMLINK_REFUSED")
    try:
        info = path.lstat()
    except OSError as e:
        raise Refusal("FILE_UNAVAILABLE") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise Refusal("PRIVATE_FILE_REQUIRED")
    return path


def read_json(path: Path) -> dict:
    try:
        raw = private_regular(path).read_bytes()
        if len(raw) > 65536:
            raise Refusal("CONFIG_BOUND_EXCEEDED")
        value = json.loads(raw)
    except Refusal:
        raise
    except (OSError, UnicodeError, ValueError):
        raise Refusal("INVALID_CONFIG") from None
    if not isinstance(value, dict):
        raise Refusal("INVALID_CONFIG")
    return value


def peer_address(value: object) -> tuple[str, int]:
    if not isinstance(value, str) or ":" not in value:
        raise Refusal("INVALID_PEER_ADDRESS")
    host, raw_port = value.rsplit(":", 1)
    try:
        ip = ipaddress.ip_address(host)
        port = int(raw_port)
    except ValueError:
        raise Refusal("INVALID_PEER_ADDRESS") from None
    if (ip.is_unspecified or ip.is_multicast or ip.is_reserved or
            ip.is_link_local or not 1024 <= port <= 65535):
        raise Refusal("INVALID_PEER_ADDRESS")
    return str(ip), port


def pinned_hash(cert_path: Path) -> str:
    try:
        pem = private_regular(cert_path).read_text()
        der = ssl.PEM_cert_to_DER_cert(pem)
    except Refusal:
        raise
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        raise Refusal("INVALID_CERTIFICATE") from None
    return hashlib.sha256(der).hexdigest()


def load_fixture(fixture_root: Path, manifest_path: Path) -> tuple[dict, dict, Path]:
    # Intentional private fixture-only boundary: cannot be used to inventory
    # arbitrary production cluster credentials merely by supplying a path.
    root = fixture_root.absolute()
    if root.is_symlink():
        raise Refusal("SYMLINK_REFUSED")
    try:
        info = root.stat()
    except OSError:
        raise Refusal("FIXTURE_UNAVAILABLE") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise Refusal("PRIVATE_FIXTURE_REQUIRED")
    marker = read_json(manifest_path.absolute())
    if (marker.get("synthetic_only") is not True
            or marker.get("allow_production") is True
            or marker.get("v6_ha_admitted") is True):
        raise Refusal("NON_SYNTHETIC_FIXTURE_DENIED")
    config = read_json(root / "ha.json")
    if (not isinstance(config.get("cluster_id"), str) or
            marker.get("cluster_id") != config.get("cluster_id") or
            type(config.get("node_id")) is not int or
            type(config.get("peers")) is not dict):
        raise Refusal("CLUSTER_IDENTITY_MISMATCH")
    local = str(config["node_id"])
    peers = config["peers"]
    if not 3 <= len(peers) <= 9 or local not in peers:
        raise Refusal("INVALID_MEMBERSHIP")
    pins = set()
    names = set()
    for peer_id, peer in peers.items():
        if not peer_id.isdecimal() or type(peer) is not dict:
            raise Refusal("INVALID_MEMBERSHIP")
        peer_address(peer.get("address"))
        label = peer.get("node_name")
        server_name = peer.get("server_name")
        digest = peer.get("certificate_sha256")
        if (not isinstance(label, str) or not label or label in names
                or not isinstance(server_name, str) or not server_name.endswith(".heptabao.synthetic")
                or not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest) or digest in pins):
            raise Refusal("INVALID_ENROLLMENT")
        pins.add(digest)
        names.add(label)
    # Only fixture-owned leaf certificate is opened. It is never sent or logged.
    for name in ("ca.crt", "tls.crt", "tls.key"):
        private_regular(root / name)
    if peers[local]["certificate_sha256"] != pinned_hash(root / "tls.crt"):
        raise Refusal("LOCAL_CERT_PIN_MISMATCH")
    return config, marker, root


def probe_peer(config: dict, root: Path, peer_id: int, timeout: float) -> str:
    if peer_id == config["node_id"] or str(peer_id) not in config["peers"]:
        raise Refusal("INVALID_PEER_ID")
    if not 0.15 <= timeout <= 8:
        raise Refusal("INVALID_DEADLINE")
    peer = config["peers"][str(peer_id)]
    host, port = peer_address(peer["address"])
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(root / "ca.crt"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(str(root / "tls.crt"), str(root / "tls.key"))
        ctx.set_alpn_protocols([ALPN])
        with socket.create_connection((host, port), timeout=timeout) as tcp:
            with ctx.wrap_socket(tcp, server_hostname=peer["server_name"]) as tls:
                if tls.selected_alpn_protocol() != ALPN:
                    raise Refusal("RAFT_ALPN_REQUIRED")
                actual = tls.getpeercert(binary_form=True)
                if not actual or hashlib.sha256(actual).hexdigest() != peer["certificate_sha256"]:
                    raise Refusal("SERVER_LEAF_PIN_MISMATCH")
                return tls.version() or "TLS_UNKNOWN"
    except Refusal:
        raise
    except ssl.SSLCertVerificationError:
        raise Refusal("TLS_CHAIN_INVALID") from None
    except ssl.SSLError:
        raise Refusal("TLS_HANDSHAKE_FAILED") from None
    except (ConnectionRefusedError, ConnectionResetError):
        raise Refusal("TCP_REFUSED") from None
    except TimeoutError:
        raise Refusal("TCP_TIMEOUT") from None
    except OSError:
        raise Refusal("TCP_UNREACHABLE") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--probe-peer", type=int, default=None)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    args = parser.parse_args()
    report = {"schema": SCHEMA, "test_only": True, "production_authority": False,
              "v6_ha_qualified": False, "status": "refused"}
    try:
        config, _, root = load_fixture(args.fixture_root, args.manifest)
        report["node_id"] = config["node_id"]
        report["members"] = len(config["peers"])
        if args.probe_peer is None:
            report["status"] = "offline_passed"
            report["network_attempts"] = 0
        else:
            report["peer_id"] = args.probe_peer
            report["tls_version"] = probe_peer(config, root, args.probe_peer, args.timeout_seconds)
            report["status"] = "peer_mtls_passed"
            report["network_attempts"] = 1
    except Refusal as error:
        report["reason"] = error.label
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] in ("offline_passed", "peer_mtls_passed") else 77


if __name__ == "__main__":
    raise SystemExit(main())
