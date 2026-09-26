#!/usr/bin/env python3
"""Bounded three-process mTLS leaf-certificate rotation for the HA peer plane.

This proves repository-controlled overlap-pin rotation on one loopback host. It
is not independent multi-host PKI, HSM custody, CA rotation, or release authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import time

from ha_destructive import Cluster, FixtureError, checked_binary, openssl, private_write


def replace_json(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + ".next")
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if tmp.exists():
            tmp.unlink()


def issue_replacement(cluster: Cluster, node_id: int) -> tuple[Path, Path, str]:
    node = next(node for node in cluster.nodes if node.node_id == node_id)
    key = node.root / "tls-next.key"
    cert = node.root / "tls-next.crt"
    csr = node.root / "tls-next.csr"
    extension = node.root / "tls-next.ext"
    openssl(
        "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(csr),
        "-subj", f"/CN=heptabao-synthetic-{node_id}-rotated",
    )
    key.chmod(0o600)
    private_write(
        extension,
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
    )
    openssl(
        "x509", "-req", "-in", str(csr),
        "-CA", str(cluster.root / "ca.crt"),
        "-CAkey", str(cluster.root / "ca.key"),
        "-CAcreateserial", "-out", str(cert), "-days", "2",
        "-sha256", "-extfile", str(extension),
    )
    digest = cert_digest(cert)
    if len(digest) != 64:
        raise FixtureError("replacement_certificate_digest_invalid")
    return cert, key, digest


def cert_digest(path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(path.read_text())
    if isinstance(der, str):
        der = der.encode("latin1")
    return hashlib.sha256(der).hexdigest()


def update_overlap(cluster: Cluster, node_id: int, next_digest: str) -> None:
    for node in cluster.nodes:
        config = json.loads(node.ha_config.read_text())
        peer = config["peers"][str(node_id)]
        if peer.get("certificate_sha256") == next_digest:
            raise FixtureError("rotation_primary_already_changed")
        peer["certificate_sha256_next"] = next_digest
        replace_json(node.ha_config, config)


def update_rotating_identity(node, cert: Path, key: Path) -> None:
    config = json.loads(node.ha_config.read_text())
    config["cert_file"] = str(cert)
    config["key_file"] = str(key)
    replace_json(node.ha_config, config)


def retire_old_pin(cluster: Cluster, node_id: int, digest: str) -> None:
    for node in cluster.nodes:
        config = json.loads(node.ha_config.read_text())
        peer = config["peers"][str(node_id)]
        peer["certificate_sha256"] = digest
        peer.pop("certificate_sha256_next", None)
        replace_json(node.ha_config, config)


def restart_one(cluster: Cluster, node) -> None:
    node.stop()
    cluster.restart(node)
    cluster.leader()


def run(binary: Path, work_dir: Path, binary_sha256: str) -> dict:
    cluster = Cluster(binary, work_dir)
    try:
        cluster.bootstrap()
        leader = cluster.leader()
        baseline = "rotation-baseline"
        cluster.write(leader, "cert-rotation-before", baseline)
        for node in cluster.nodes:
            cluster.read(node, "cert-rotation-before", baseline)
        cluster.check("baseline_visible_before_rotation", True)

        rotating = next(node for node in cluster.nodes if node is not leader)
        old_cert = rotating.root / "tls.crt"
        old_key = rotating.root / "tls.key"
        old_digest = cert_digest(old_cert)
        new_cert, new_key, new_digest = issue_replacement(cluster, rotating.node_id)
        cluster.check("replacement_leaf_has_distinct_digest", new_digest != old_digest)

        update_overlap(cluster, rotating.node_id, new_digest)
        acceptors = [node for node in cluster.nodes if node is not rotating]
        for node in acceptors:
            restart_one(cluster, node)
        cluster.check("acceptors_reopened_with_overlap_pin", True)

        update_rotating_identity(rotating, new_cert, new_key)
        restart_one(cluster, rotating)
        cluster.check("rotating_node_reopened_with_next_pin", True)

        via_rotated = "rotation-through-new-leaf"
        cluster.write(rotating, "cert-rotation-overlap", via_rotated)
        for node in cluster.nodes:
            cluster.read(node, "cert-rotation-overlap", via_rotated)
        cluster.check("new_leaf_participates_in_forwarding_and_consensus", True)

        retire_old_pin(cluster, rotating.node_id, new_digest)
        for node in cluster.nodes:
            restart_one(cluster, node)
        cluster.check("all_nodes_reopened_after_old_pin_retirement", True)

        after = "rotation-after-retirement"
        leader = cluster.leader()
        cluster.write(leader, "cert-rotation-after", after)
        for node in cluster.nodes:
            cluster.read(node, "cert-rotation-after", after)
        cluster.check("cluster_writes_and_reads_after_pin_retirement", True)

        rotating.stop()
        final_config = json.loads(rotating.ha_config.read_text())
        stale_config = dict(final_config)
        stale_config["cert_file"] = str(old_cert)
        stale_config["key_file"] = str(old_key)
        stale_path = rotating.root / "ha-stale-cert.json"
        private_write(stale_path, json.dumps(stale_config, sort_keys=True))
        rotating.ha_config = stale_path
        stale_denied = False
        try:
            rotating.start()
        except FixtureError:
            stale_denied = True
        finally:
            rotating.stop()
        cluster.check("retired_local_leaf_cannot_rejoin", stale_denied)

        rotating.ha_config = rotating.root / "ha.json"
        cluster.restart(rotating)
        cluster.leader()
        cluster.check("rotated_node_recovers_with_current_leaf", True)
        final = "rotation-final"
        cluster.write(rotating, "cert-rotation-final", final)
        for node in cluster.nodes:
            cluster.read(node, "cert-rotation-final", final)
        cluster.check("final_cluster_is_live_on_new_leaf_only", True)

        return {
            "schema": "heptabao.ha-certificate-rotation.v1",
            "binary_sha256": binary_sha256,
            "status": "pass_scoped_repository_fixture",
            "scenarios": cluster.scenarios,
            "rotated_node_id": rotating.node_id,
            "overlap_pins": 2,
            "same_ca_only": True,
            "same_host_loopback_only": True,
            "qualification": False,
            "production_authority": False,
            "release_authority": False,
            "independent_attestation": False,
            "uncovered": [
                "ca_rotation",
                "multi_host_rotation",
                "hsm_or_kms_key_custody",
                "power_loss_during_rotation",
                "independent_reproduction",
            ],
        }
    finally:
        cluster.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {
        "schema": "heptabao.ha-certificate-rotation.v1",
        "status": "failed",
        "failure": "not_started",
    }
    try:
        binary = args.binary.resolve(strict=True)
        checked_binary(binary, args.expected_binary_sha256)
        root = args.work_dir.resolve()
        if root.exists():
            raise FixtureError("work_directory_must_not_exist")
        report = run(binary, root, args.expected_binary_sha256.lower())
        if args.output:
            output = args.output.resolve()
            if output.exists() or not output.parent.is_dir():
                raise FixtureError("invalid_output_path")
            private_write(output, json.dumps(report, sort_keys=True))
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as error:
        # Never emit exception text: provider/config/certificate paths are not
        # user-facing evidence and may contain environment-specific details.
        report["failure"] = type(error).__name__
        print(json.dumps(report, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
