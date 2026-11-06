#!/usr/bin/env python3
"""Phase B R3 evidence: bounded native archive and append-only audit observations.

This is a NEW implementation. It does not reproduce the unavailable R2 helper.
A valid archive here means the exact public envelope contract and clear sums.
It does not authenticate sealed checksums, decrypt state, or prove CLI framing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import zlib

SCHEMA = "heptabao.official271-native-cli-phaseb-r3.evidence.v1"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_AUDIT = 8 * 1024 * 1024
MAX_PUBLIC_FILE = 16 * 1024 * 1024
NODES = (1, 2, 3)
MEMBERS = ("meta.json", "state.bin", "SHA256SUMS", "SHA256SUMS.sealed")


class EvidenceError(RuntimeError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise EvidenceError(code)


def remaining(until_ns: int) -> float:
    need(type(until_ns) is int, "deadline_type")
    value = (until_ns - time.monotonic_ns()) / 1e9
    need(value > 0, "original_deadline_expired")
    return value


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def duplicate_free(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode_json(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), object_pairs_hook=duplicate_free)


def identity(st: os.stat_result) -> dict:
    return {
        "device": st.st_dev, "inode": st.st_ino, "uid": st.st_uid,
        "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode),
        "links": st.st_nlink, "bytes": st.st_size,
        "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
    }


def checked_bytes(path: Path, maximum: int, until_ns: int, *,
                  owner: int | None = None, private: bool = True) -> tuple[bytes, dict]:
    remaining(until_ns)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_single_link_required")
    need(owner is None or before.st_uid == owner, "file_owner_changed")
    need(not private or not stat.S_IMODE(before.st_mode) & 0o077, "private_file_permissions")
    need(0 <= before.st_size <= maximum, "file_size_bound")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd)) == identity(before), "file_changed_before_open")
        data = bytearray()
        while True:
            remaining(until_ns)
            piece = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
            need(len(data) <= maximum, "file_size_bound")
        after = os.fstat(fd)
        need(identity(after) == identity(before), "file_changed_during_read")
        need(identity(path.lstat()) == identity(before), "file_name_changed_during_read")
        remaining(until_ns)
        return bytes(data), {**identity(before), "sha256": sha(data)}
    finally:
        os.close(fd)


def canonical_header(name: str, length: int) -> bytes:
    need(type(length) is int and 0 <= length < 8 ** 11, "tar_length_bound")
    encoded = name.encode("ascii")
    need(len(encoded) <= 99, "tar_name_bound")
    block = bytearray(512)
    block[:len(encoded)] = encoded
    block[100:108] = b"0000600\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = ("%011o\0" % length).encode("ascii")
    block[136:148] = b"00000000000\0"
    block[148:156] = b"        "
    block[156] = ord("0")
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    block[148:156] = ("%06o\0 " % sum(block)).encode("ascii")
    return bytes(block)


def inspect_archive_bytes(raw: bytes, until_ns: int) -> dict:
    remaining(until_ns)
    need(10 <= len(raw) <= MAX_ARCHIVE and raw[:4] == b"\x1f\x8b\x08\x00", "native_gzip_header")
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = inflater.decompress(raw, MAX_EXPANDED + 1)
    remaining(until_ns)
    need(len(expanded) <= MAX_EXPANDED, "expanded_archive_bound")
    need(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
         "single_complete_gzip_member")
    offset = 0
    values = {}
    for name in MEMBERS:
        remaining(until_ns)
        block = expanded[offset:offset + 512]
        need(len(block) == 512 and block[135] == 0
             and all(48 <= byte <= 55 for byte in block[124:135]), "canonical_tar_length")
        length = int(block[124:135], 8)
        maximum = MAX_EXPANDED if name == "state.bin" else 8191
        need(length <= maximum and block == canonical_header(name, length), "canonical_tar_header")
        offset += 512
        value = expanded[offset:offset + length]
        need(len(value) == length, "complete_tar_member")
        offset += length
        padding = (-length) % 512
        need(expanded[offset:offset + padding] == b"\0" * padding, "zero_tar_padding")
        offset += padding
        values[name] = value
    need(expanded[offset:] == b"\0" * 1024, "exact_tar_terminator_no_trailing_data")
    metadata = decode_json(values["meta.json"])
    need(type(metadata) is dict and set(metadata) == {
        "format", "state_format", "generation", "state_bytes", "seal_identity"
    }, "native_ha_metadata_exact_fields")
    need(metadata["format"] == "heptabao-native-ha-object-snapshot-v1"
         and metadata["state_format"] == "heptabao-encrypted-ha-object-backup/HBV6HA01",
         "native_ha_metadata_format")
    need(type(metadata["generation"]) is int and 0 < metadata["generation"] < 2 ** 64,
         "native_ha_generation")
    state = values["state.bin"]
    need(type(metadata["state_bytes"]) is int
         and 237 <= metadata["state_bytes"] == len(state) <= MAX_EXPANDED
         and state[:8] == b"HBV6HA01", "native_ha_state_magic_and_length")
    seal = metadata["seal_identity"]
    need(type(seal) is dict and set(seal) == {"format", "sha256"}
         and seal["format"] == "heptabao-seal-metadata-digest-v1"
         and isinstance(seal["sha256"], str)
         and re.fullmatch(r"[0-9a-f]{64}", seal["sha256"]) is not None,
         "native_seal_identity_shape")
    sums = (sha(values["meta.json"]) + "  meta.json\n"
            + sha(state) + "  state.bin\n").encode("ascii")
    need(values["SHA256SUMS"] == sums, "native_clear_checksums")
    need(bool(values["SHA256SUMS.sealed"]), "sealed_checksums_present")
    remaining(until_ns)
    return {
        "archive_valid": True, "archive_bytes": len(raw), "archive_sha256": sha(raw),
        "expanded_bytes": len(expanded), "member_names": list(MEMBERS),
        "members": [{"name": name, "bytes": len(values[name]), "sha256": sha(values[name])}
                    for name in MEMBERS],
        "format": metadata["format"], "state_format": metadata["state_format"],
        "generation": metadata["generation"], "state_bytes": metadata["state_bytes"],
        "seal_identity_sha256": seal["sha256"],
        "sealed_checksum_cryptographically_authenticated": False,
        "state_decrypted_by_observer": False,
        "official_openbao_state_format_claimed": False,
    }


def archive_observation(path: Path, until_ns: int) -> tuple[dict, bytes | None]:
    try:
        path.lstat()
    except FileNotFoundError:
        return {"exists": False, "archive_valid": False}, None
    raw, fence = checked_bytes(path, MAX_ARCHIVE, until_ns, owner=os.getuid())
    result = {"exists": True, "file": fence, "archive_valid": False}
    try:
        result.update(inspect_archive_bytes(raw, until_ns))
    except (EvidenceError, ValueError, UnicodeError, zlib.error) as error:
        result["archive_error_type"] = type(error).__name__
        result["archive_error_code"] = str(error) if isinstance(error, EvidenceError) else None
    return result, raw


def b64_32(value: object) -> bytes:
    need(type(value) is str, "audit_digest_type")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise EvidenceError("audit_digest_encoding") from None
    need(len(raw) == 32 and base64.b64encode(raw).decode("ascii") == value, "audit_digest_shape")
    return raw


def parse_audit(raw: bytes, until_ns: int) -> list[dict]:
    remaining(until_ns)
    need(len(raw) <= MAX_AUDIT and (not raw or raw.endswith(b"\n")), "complete_bounded_audit_lines")
    records = []
    previous = b"\0" * 32
    sequence = 0
    for line in raw.splitlines(keepends=True):
        remaining(until_ns)
        need(line.endswith(b"\n") and line != b"\n", "audit_line_termination")
        record = decode_json(line[:-1])
        need(type(record) is dict and set(record) == {"event", "mac"}, "audit_record_exact_fields")
        event = record["event"]
        need(type(event) is dict and set(event) == {
            "schema", "sequence", "previous", "time", "kind", "path_digest", "status"
        }, "audit_event_exact_fields")
        need(type(event["schema"]) is int and event["schema"] == 2, "audit_schema")
        need(type(event["sequence"]) is int and event["sequence"] == sequence + 1
             and event["sequence"] < 2 ** 64, "audit_sequence_contiguous")
        need(type(event["time"]) is int and 0 <= event["time"] < 2 ** 64, "audit_time_u64")
        need(b64_32(event["previous"]) == previous, "audit_previous_mac_chain")
        mac = b64_32(record["mac"])
        b64_32(event["path_digest"])
        need(type(event["kind"]) is str and len(event["kind"]) <= 128
             and re.fullmatch(r"[a-z][a-z0-9-]*", event["kind"]) is not None, "audit_kind_shape")
        status = event["status"]
        need(status is None or type(status) is int and 100 <= status <= 599, "audit_status_shape")
        records.append({
            "sequence": event["sequence"], "kind": event["kind"], "status": status,
            "path_digest": event["path_digest"], "line_sha256": sha(line),
        })
        sequence, previous = event["sequence"], mac
    remaining(until_ns)
    return records


def capture_audits(root: Path, until_ns: int) -> dict:
    captured = {}
    for node in NODES:
        raw, fence = checked_bytes(root / ("node%d" % node) / "audit.jsonl",
                                   MAX_AUDIT, until_ns, owner=os.getuid())
        captured[node] = {"bytes": raw, "file": fence, "records": parse_audit(raw, until_ns)}
    remaining(until_ns)
    return captured


def audit_delta(before: dict, after: dict, until_ns: int) -> dict:
    remaining(until_ns)
    nodes = []
    pairs = []
    complete = True
    unexpected = False
    veto = False
    for node in NODES:
        old, new = before[node], after[node]
        for key in ("device", "inode", "uid", "gid", "mode", "links"):
            need(new["file"][key] == old["file"][key], "audit_file_identity_changed")
        need(new["bytes"].startswith(old["bytes"]), "audit_prefix_changed")
        old_count = len(old["records"])
        events = new["records"][old_count:]
        need(new["records"][:old_count] == old["records"], "audit_record_prefix_changed")
        pending = None
        local_pairs = []
        projected = []
        for event in events:
            remaining(until_ns)
            projected.append({key: event[key] for key in ("sequence", "kind", "status", "line_sha256")})
            kind = event["kind"]
            if kind in ("request", "wire-rejection"):
                if pending is not None or event["status"] is not None:
                    complete = False
                pending = event
            elif kind in ("response", "wire-response"):
                expected_kind = "request" if kind == "response" else "wire-rejection"
                if (pending is None or pending["kind"] != expected_kind
                        or pending["path_digest"] != event["path_digest"]
                        or event["status"] is None):
                    complete = False
                else:
                    local_pairs.append({
                        "node": node, "request_sequence": pending["sequence"],
                        "response_sequence": event["sequence"], "status": event["status"],
                        "kind": expected_kind, "same_opaque_fingerprint": True,
                    })
                pending = None
            else:
                unexpected = True
                veto = veto or kind == "native-ha-historical-restore-delivery-veto"
        complete = complete and pending is None
        pairs.extend(local_pairs)
        nodes.append({
            "node": node, "before_file": old["file"], "after_file": new["file"],
            "before_records": old_count, "after_records": len(new["records"]),
            "delta_records": len(events), "events": projected, "pairs": local_pairs,
        })
    remaining(until_ns)
    return {
        "nodes": nodes, "pairs": pairs,
        "complete_known_request_response_pairs": complete and not unexpected,
        "unexpected_event_kind": unexpected, "historical_delivery_veto_observed": veto,
        "request_count": len(pairs),
        "route_authenticated_or_reversed_from_fingerprint": False,
        "audit_mac_authenticated_by_observer": False,
        "client_http_framing_proven_by_audit": False,
        "association_scope": "single_owned_cli_window_without_other_controller_http",
    }


def secret_variants(values: list[bytes]) -> set[bytes]:
    variants = set()
    for raw in values:
        need(type(raw) is bytes and bool(raw), "secret_literal_type")
        if len(raw) >= 8:
            variants.add(raw)
            variants.add(base64.b64encode(raw))
            variants.add(raw.hex().encode("ascii"))
        try:
            decoded = raw.decode("utf-8")
        except UnicodeError:
            decoded = None
        if decoded is not None:
            for ensure_ascii in (False, True):
                escaped = json.dumps(decoded, ensure_ascii=ensure_ascii)[1:-1].encode("utf-8")
                if len(escaped) >= 8:
                    variants.add(escaped)
            if b"-----BEGIN " in raw and b"PRIVATE KEY-----" in raw:
                for line in raw.splitlines():
                    if len(line) >= 32 and re.fullmatch(rb"[A-Za-z0-9+/=]+", line):
                        variants.add(line)
    return variants


def public_literal_scan(files: list[Path], values: list[bytes], until_ns: int) -> dict:
    variants = secret_variants(values)
    members = []
    for path in files:
        raw, fence = checked_bytes(path, MAX_PUBLIC_FILE, until_ns, owner=os.getuid())
        need(not any(value in raw for value in variants), "fixture_secret_literal_in_public_output")
        members.append({"name": path.name, "bytes": len(raw), "sha256": fence["sha256"]})
    return {
        "scope": "actual_fixture_literals_and_captured_encoding_variants",
        "members": len(members), "literal_inputs": len(values),
        "encoding_variants": len(variants), "hits": 0,
        "universal_secret_detection_claimed": False,
        "members_sha256": sha(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()),
    }
