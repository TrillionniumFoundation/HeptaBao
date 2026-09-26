#!/usr/bin/env python3
"""Inspect a real OpenBao 2.6.2 Raft snapshot without restoring it.

The fixture starts the pinned single-node OpenBao oracle, obtains its snapshot
through the official ``bao operator raft snapshot save`` command, and feeds
that archive to the HeptaBao inspection CLI.  The negative cases exercise the
same CLI with a tampered archive, a state-size ceiling, and an unexpected tar
path.  No OpenBao state is restored, converted, or written by the candidate.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile

from bao_http import Client
from official_openbao_launcher import (
    BINARY_SHA256,
    VERSION,
    oracle_cli_environment,
    start_oracle,
    stop_oracle,
    verify_inputs,
)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_inspector(inspector: Path, snapshot: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(inspector), "--input", str(snapshot), *extra],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def append_unknown_path(source: Path, destination: Path) -> None:
    """Repack a valid archive and add one regular file outside the format."""
    with gzip.open(source, "rb") as compressed, tarfile.open(fileobj=compressed, mode="r:") as archive:
        entries = []
        for member in archive.getmembers():
            if not member.isreg():
                raise RuntimeError("official snapshot contains a non-regular entry")
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError("official snapshot entry cannot be read")
            entries.append((member, stream.read()))
    with gzip.open(destination, "wb", compresslevel=6) as compressed, tarfile.open(
        fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT
    ) as archive:
        for member, payload in entries:
            member = copy.copy(member)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        extra = tarfile.TarInfo("unexpected-path")
        extra.mode = 0o600
        payload = b"fixture-only unexpected member\n"
        extra.size = len(payload)
        archive.addfile(extra, io.BytesIO(payload))


def authentic_member_digests(snapshot: Path) -> tuple[str, str, int]:
    """Read only the two declared members to bind CLI output to the archive."""
    members: dict[str, bytes] = {}
    with gzip.open(snapshot, "rb") as compressed, tarfile.open(fileobj=compressed, mode="r:") as archive:
        for member in archive.getmembers():
            if member.isreg() and member.name in {"meta.json", "state.bin"}:
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeError("declared snapshot member cannot be read")
                members[member.name] = stream.read()
    if set(members) != {"meta.json", "state.bin"}:
        raise RuntimeError("declared snapshot members are incomplete")
    return (
        hashlib.sha256(members["meta.json"]).hexdigest(),
        hashlib.sha256(members["state.bin"]).hexdigest(),
        len(members["state.bin"]),
    )


def run_fixture(inspector: Path, work: Path) -> dict:
    if not inspector.is_absolute() or not work.is_absolute() or work.exists():
        raise RuntimeError("inspector and a new absolute work directory are required")
    work.mkdir(mode=0o700, parents=False)
    oracle_root = work / "oracle-temp"
    oracle_root.mkdir(mode=0o700)
    previous_work_root = os.environ.get("HB_ORACLE_WORK_ROOT")
    os.environ["HB_ORACLE_WORK_ROOT"] = str(oracle_root)
    oracle = None
    checks: list[str] = []
    snapshot = work / "raft.snap"
    try:
        oracle = start_oracle(free_port(), raft_storage=True)
        token = Path(oracle["token_file"]).read_text(encoding="ascii").strip()
        # A health read proves that the snapshot command is talking to the
        # same pinned, TLS-verified oracle returned by the launcher.
        health = Client(oracle["address"], oracle["ca_file"], token).health()
        if health.get("version") != VERSION:
            raise RuntimeError("official oracle version mismatch")
        checks.append("official_openbao_2_6_2_tls_oracle_ready")

        environment = oracle_cli_environment(oracle, token)
        official_binary = verify_inputs()
        saved = subprocess.run(
            [str(official_binary), "operator", "raft", "snapshot", "save", str(snapshot)],
            cwd=work,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if saved.returncode != 0 or not snapshot.is_file() or snapshot.stat().st_size == 0:
            raise RuntimeError("official snapshot save failed")
        checks.append("official_snapshot_saved")

        accepted = run_inspector(inspector, snapshot)
        if accepted.returncode != 0:
            raise RuntimeError("candidate rejected authentic OpenBao snapshot")
        try:
            summary = json.loads(accepted.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("candidate inspection output is not JSON") from error
        meta_digest, state_digest, state_size = authentic_member_digests(snapshot)
        if (
            summary.get("schema") != "heptabao.openbao-raft-snapshot-inspection.v1"
            or summary.get("status") != "passed"
            or summary.get("metadata_version") != 1
            or summary.get("state_size") != state_size
            or summary.get("meta_sha256") != meta_digest
            or summary.get("state_sha256") != state_digest
            or summary.get("restore_performed") is not False
            or summary.get("conversion_performed") is not False
            or summary.get("migration_authority") is not False
        ):
            raise RuntimeError("candidate inspection summary is incomplete")
        checks.append("authentic_snapshot_inspected")

        tampered = work / "raft-tampered.snap"
        tampered.write_bytes(snapshot.read_bytes())
        bytes_ = bytearray(tampered.read_bytes())
        bytes_[len(bytes_) // 2] ^= 0x01
        tampered.write_bytes(bytes_)
        if run_inspector(inspector, tampered).returncode == 0:
            raise RuntimeError("tampered archive was accepted")
        checks.append("tampered_archive_rejected")

        limited = run_inspector(inspector, snapshot, "--max-state-bytes", "1")
        if limited.returncode == 0:
            raise RuntimeError("state-size limit was ignored")
        checks.append("state_size_limit_rejected")

        unknown = work / "raft-unknown-path.snap"
        append_unknown_path(snapshot, unknown)
        if run_inspector(inspector, unknown).returncode == 0:
            raise RuntimeError("unknown archive path was accepted")
        checks.append("unknown_archive_path_rejected")

        return {
            "schema": "heptabao.migration-snapshot-live.v1",
            "status": "passed",
            "checks": checks,
            "count": len(checks),
            "official_openbao_version": VERSION,
            "official_binary_sha256": BINARY_SHA256,
            "official_snapshot_sha256": file_digest(snapshot),
            "candidate_inspector_sha256": file_digest(inspector),
            "inspection_only": True,
            "restore_performed": False,
            "conversion_performed": False,
            "migration_authority": False,
            "full_format_migration": False,
            "production_authority": False,
            "scope": "authentic OpenBao 2.6.2 snapshot format and integrity inspection only",
        }
    finally:
        if oracle is not None:
            stop_oracle(oracle)
        if previous_work_root is None:
            os.environ.pop("HB_ORACLE_WORK_ROOT", None)
        else:
            os.environ["HB_ORACLE_WORK_ROOT"] = previous_work_root
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspector", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run_fixture(args.inspector.resolve(strict=True), args.work_dir)
    except Exception as error:
        print(f"migration snapshot live fixture failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
