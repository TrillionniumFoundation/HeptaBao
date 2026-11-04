#!/usr/bin/env python3
"""Offline synthetic evidence components. Not executed by the draft publisher.

No socket, child, provider, native snapshot restore, or product process is used.
Synthetic envelopes only exercise observer syntax/integrity rejection; they
are never described as authenticated or restorable product archives.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import zlib

def load(path):
    spec = importlib.util.spec_from_file_location("new_phaseb_r3_evidence_components", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

def run(evidence):
    checks = []
    def check(name, result):
        checks.append({"name": name, "passed": bool(result)})
        if not result:
            raise AssertionError(name)
    def until():
        return time.monotonic_ns() + 15_000_000_000
    def rejected(name, function):
        try:
            function()
        except (evidence.EvidenceError, ValueError, UnicodeError, zlib.error):
            check(name, True)
        else:
            check(name, False)
    state = b"HBV6HA01" + b"synthetic-component-only".ljust(229, b".")
    metadata = {
        "format": "heptabao-native-ha-object-snapshot-v1",
        "state_format": "heptabao-encrypted-ha-object-backup/HBV6HA01",
        "generation": 1, "state_bytes": len(state),
        "seal_identity": {"format": "heptabao-seal-metadata-digest-v1", "sha256": "a" * 64},
    }
    meta = json.dumps(metadata, separators=(",", ":")).encode()
    sums = (hashlib.sha256(meta).hexdigest() + "  meta.json\n"
            + hashlib.sha256(state).hexdigest() + "  state.bin\n").encode()
    parts = [meta, state, sums, b"opaque-synthetic-sealed-sums-not-authenticated"]
    def tar(values=parts, names=evidence.MEMBERS):
        return b"".join(evidence.canonical_header(name, len(value)) + value
                        + b"\0" * ((-len(value)) % 512)
                        for name, value in zip(names, values)) + b"\0" * 1024
    def gzip(raw):
        compressor = zlib.compressobj(level=1, wbits=31)
        return compressor.compress(raw) + compressor.flush()
    good = gzip(tar())
    observed = evidence.inspect_archive_bytes(good, until())
    check("synthetic_envelope_shape_accepted", observed["archive_valid"])
    check("synthetic_envelope_not_claimed_authenticated",
          observed["sealed_checksum_cryptographically_authenticated"] is False
          and observed["state_decrypted_by_observer"] is False
          and observed["official_openbao_state_format_claimed"] is False)
    rejected("gzip_truncated", lambda: evidence.inspect_archive_bytes(good[:-3], until()))
    rejected("gzip_concatenated", lambda: evidence.inspect_archive_bytes(good + good, until()))
    rejected("gzip_trailing_bytes", lambda: evidence.inspect_archive_bytes(good + b"x", until()))
    rejected("extra_tar_member", lambda: evidence.inspect_archive_bytes(gzip(tar()[:-1024] + tar()), until()))
    rejected("tar_nonzero_padding", lambda: evidence.inspect_archive_bytes(
        gzip(tar()[:512 + len(meta)] + b"x" + tar()[513 + len(meta):]), until()))
    rejected("noncanonical_member_name", lambda: evidence.inspect_archive_bytes(
        gzip(tar(names=("meta.json", "state.bin", "SHA256SUMS", "other"))), until()))
    rejected("wrong_clear_sums", lambda: evidence.inspect_archive_bytes(
        gzip(tar(values=[meta, state, b"not-the-sums", parts[3]])), until()))
    rejected("empty_sealed_sums", lambda: evidence.inspect_archive_bytes(
        gzip(tar(values=[meta, state, sums, b""])), until()))
    rejected("tar_trailing_zero_block", lambda: evidence.inspect_archive_bytes(gzip(tar() + b"\0" * 512), until()))
    changed = bytearray(tar())
    changed[156] = ord("2")
    rejected("symlink_header", lambda: evidence.inspect_archive_bytes(gzip(bytes(changed)), until()))
    changed = bytearray(good)
    changed[-8] ^= 1
    rejected("gzip_crc_mismatch", lambda: evidence.inspect_archive_bytes(bytes(changed), until()))
    rejected("duplicate_metadata_keys", lambda: evidence.decode_json(b'{"same":1,"same":2}'))

    zero = base64.b64encode(b"\0" * 32).decode()
    fingerprint = base64.b64encode(b"f" * 32).decode()
    def line(sequence, previous, kind, status, tag, when=1):
        return (json.dumps({"event": {
            "schema": 2, "sequence": sequence, "previous": previous, "time": when,
            "kind": kind, "path_digest": fingerprint, "status": status,
        }, "mac": base64.b64encode(tag).decode()}, separators=(",", ":")) + "\n").encode()
    request = line(1, zero, "request", None, b"a" * 32)
    response = line(2, base64.b64encode(b"a" * 32).decode(), "response", 200, b"b" * 32)
    good_audit = request + response
    records = evidence.parse_audit(good_audit, until())
    check("actual_nested_audit_schema", len(records) == 2 and records[1]["status"] == 200)
    rejected("audit_missing_newline", lambda: evidence.parse_audit(good_audit[:-1], until()))
    rejected("audit_sequence_gap", lambda: evidence.parse_audit(
        request + line(3, base64.b64encode(b"a" * 32).decode(), "response", 200, b"b" * 32), until()))
    rejected("audit_previous_chain", lambda: evidence.parse_audit(
        request + line(2, zero, "response", 200, b"b" * 32), until()))
    for bad_time, label in ((-1, "negative"), (2 ** 64, "overflow"), (True, "bool")):
        rejected("audit_time_" + label, lambda value=bad_time:
                 evidence.parse_audit(line(1, zero, "request", None, b"a" * 32, value), until()))
    def captured(raw, inode):
        return {"bytes": raw, "file": {
            "device": 1, "inode": inode, "uid": 1000, "gid": 1000, "mode": 0o600,
            "links": 1, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        }, "records": evidence.parse_audit(raw, until())}
    before = {node: captured(b"", node) for node in (1, 2, 3)}
    after = {node: captured(good_audit if node == 1 else b"", node) for node in (1, 2, 3)}
    delta = evidence.audit_delta(before, after, until())
    check("complete_request_response_pair", delta["complete_known_request_response_pairs"]
          and delta["request_count"] == 1)
    check("audit_does_not_prove_client_framing", delta["client_http_framing_proven_by_audit"] is False)
    partial = {node: captured(request if node == 1 else b"", node) for node in (1, 2, 3)}
    check("missing_response_not_complete",
          not evidence.audit_delta(before, partial, until())["complete_known_request_response_pairs"])
    veto_line = line(3, base64.b64encode(b"b" * 32).decode(),
                     "native-ha-historical-restore-delivery-veto", 503, b"c" * 32)
    veto_after = {node: captured(good_audit + veto_line if node == 1 else b"", node)
                  for node in (1, 2, 3)}
    veto = evidence.audit_delta(before, veto_after, until())
    check("historical_delivery_veto_not_known", veto["historical_delivery_veto_observed"]
          and not veto["complete_known_request_response_pairs"])
    changed_identity = {node: captured(good_audit if node == 1 else b"", node + 100)
                        for node in (1, 2, 3)}
    rejected("audit_inode_replaced", lambda: evidence.audit_delta(before, changed_identity, until()))

    pem = (b"-----BEGIN PRIVATE KEY-----\n"
           b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789abcdefABCD\n"
           b"-----END PRIVATE KEY-----\n")
    token = b"synthetic-owned-token-never-a-real-credential"
    variants = evidence.secret_variants([pem, token, bytes(range(32))])
    for label, raw in (
        ("pem_literal", pem),
        ("pem_json_escape", json.dumps({"private": pem.decode()}).encode()),
        ("pem_json_escape_ascii_false", json.dumps({"private": pem.decode()}, ensure_ascii=False).encode()),
        ("pem_base64_line", pem.splitlines()[1]),
        ("token_literal", token),
        ("replication_hex", bytes(range(32)).hex().encode()),
        ("replication_base64", base64.b64encode(bytes(range(32)))),
    ):
        check("secret_variant_" + label, any(value in raw for value in variants))
    check("clean_public_example", not any(value in b'{"schema":"public","hits":0}' for value in variants))
    print(json.dumps({
        "schema": "heptabao.official271-native-cli-phaseb-r3.synthetic-evidence-components.v1",
        "checks": checks, "passed": sum(item["passed"] for item in checks), "total": len(checks),
        "actual_product_archive": False, "network_calls": 0, "children_spawned": 0,
        "runtime_qualification": False, "actual_credential_literals_used": False,
    }, sort_keys=True))
    return 0

def main():
    if len(sys.argv) != 2:
        raise SystemExit("explicit evidence source path required")
    return run(load(Path(sys.argv[1])))

if __name__ == "__main__":
    raise SystemExit(main())
