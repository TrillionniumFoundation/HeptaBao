"""Bounded file and JSON I/O for HeptaBao external evidence V2.5."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1 << 40
READ_CHUNK = 1024 * 1024


class EvidenceIoError(ValueError):
    """Evidence bytes or artifact storage are not admissible."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceIoError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_json_file(path: Path) -> tuple[bytes, Any]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceIoError(f"cannot inspect JSON file: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceIoError("JSON input must be a regular non-symlink file")
    if not 1 <= metadata.st_size <= MAX_JSON_BYTES:
        raise EvidenceIoError("JSON input size is outside its bound")
    raw = _read_regular_file(path, metadata, MAX_JSON_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceIoError("JSON input is not canonical UTF-8 JSON") from exc
    return raw, value


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_artifacts(evidence: Mapping[str, Any], artifact_root: Path) -> None:
    raw_artifacts = evidence.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise EvidenceIoError("evidence artifacts are absent")
    try:
        root_metadata = artifact_root.lstat()
    except OSError as exc:
        raise EvidenceIoError("cannot inspect artifact root") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceIoError("artifact root must be a non-symlink directory")
    root = artifact_root.resolve(strict=True)

    observed_paths: set[str] = set()
    for index, raw in enumerate(raw_artifacts):
        if not isinstance(raw, dict):
            raise EvidenceIoError(f"artifacts[{index}] is not an object")
        path_text = raw.get("path")
        digest = raw.get("sha256")
        expected_bytes = raw.get("bytes")
        if not isinstance(path_text, str):
            raise EvidenceIoError("artifact path is not a string")
        relative = PurePosixPath(path_text)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in path_text
        ):
            raise EvidenceIoError("artifact path escapes its root")
        if path_text in observed_paths:
            raise EvidenceIoError("duplicate artifact path")
        observed_paths.add(path_text)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise EvidenceIoError("artifact digest is invalid")
        if (
            not isinstance(expected_bytes, int)
            or isinstance(expected_bytes, bool)
            or not 1 <= expected_bytes <= MAX_ARTIFACT_BYTES
        ):
            raise EvidenceIoError("artifact byte count is invalid")
        candidate = root.joinpath(*relative.parts)
        _verify_one_artifact(
            root=root,
            candidate=candidate,
            expected_bytes=expected_bytes,
            expected_sha256=digest,
        )


def _verify_one_artifact(
    *,
    root: Path,
    candidate: Path,
    expected_bytes: int,
    expected_sha256: str,
) -> None:
    current = root
    for component in candidate.relative_to(root).parts[:-1]:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise EvidenceIoError("artifact parent is missing") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceIoError("artifact parent is not a real directory")
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise EvidenceIoError("artifact file is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceIoError("artifact must be a regular non-symlink file")
    if metadata.st_size != expected_bytes:
        raise EvidenceIoError("artifact byte count does not match evidence")
    resolved = candidate.resolve(strict=True)
    if root != resolved and root not in resolved.parents:
        raise EvidenceIoError("artifact resolves outside its root")
    raw = _read_regular_file(candidate, metadata, expected_bytes)
    if len(raw) != expected_bytes:
        raise EvidenceIoError("artifact changed while being read")
    if not hashlib.sha256(raw).hexdigest() == expected_sha256:
        raise EvidenceIoError("artifact SHA-256 does not match evidence")


def _read_regular_file(path: Path, before: os.stat_result, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceIoError(f"cannot open regular file: {path}") from exc
    try:
        after_open = os.fstat(descriptor)
        if not stat.S_ISREG(after_open.st_mode):
            raise EvidenceIoError("opened object is not a regular file")
        if (
            getattr(before, "st_dev", None) != getattr(after_open, "st_dev", None)
            or getattr(before, "st_ino", None) != getattr(after_open, "st_ino", None)
            or before.st_size != after_open.st_size
        ):
            raise EvidenceIoError("file identity changed before open")
        if after_open.st_size > maximum:
            raise EvidenceIoError("file exceeds its declared bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK, maximum - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EvidenceIoError("file exceeds its declared bound")
        after_read = os.fstat(descriptor)
        if (
            after_read.st_size != after_open.st_size
            or getattr(after_read, "st_mtime_ns", None)
            != getattr(after_open, "st_mtime_ns", None)
            or getattr(after_read, "st_ctime_ns", None)
            != getattr(after_open, "st_ctime_ns", None)
        ):
            raise EvidenceIoError("file changed during verification")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
