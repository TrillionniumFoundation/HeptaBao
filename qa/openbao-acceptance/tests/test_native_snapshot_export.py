"""Offline snapshot source qualification with synthetic records only.

The fake receipt digests below exercise the trusted-owner interface. They are
not actual backup, locator, source-build or target-import evidence.
"""
import contextlib
import copy
import decimal
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "native_snapshot_export_subject", ROOT / "tools/migration/openbao270_kv2_snapshot_export.py")
subject = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = subject
SPEC.loader.exec_module(subject)
d = subject.decoder
MOUNT = "11111111-1111-1111-1111-111111111111"
BACKEND = "22222222-2222-2222-2222-222222222222"
RAW_ROOT = "logical/" + MOUNT + "/" + BACKEND + "/"
DEFAULTS = {"max_versions": 0, "cas_required": False,
            "metadata_cas_required": False, "delete_version_after": "0s"}


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128); value >>= 7
    out.append(value)
    return bytes(out)


def scalar(number, value):
    return varint(number * 8) + varint(value)


def blob(number, value):
    return varint(number * 8 + 2) + varint(len(value)) + value


def fixture(count=2, config=False, *, metadata_only=False, destroyed_only=False, extra_version=False):
    stamp = scalar(1, 1700000000) + scalar(2, 123456789)
    salt = b"synthetic-snapshot-source-salt"
    rows = [(RAW_ROOT + "salt", salt),
            (RAW_ROOT + "upgrading", blob(1, stamp) + scalar(2, 1)),
            (RAW_ROOT + "policy/metadata", b'{"synthetic":true}'),
            (RAW_ROOT + "archive/metadata", b'{"synthetic":true}')]
    if config:
        rows.append((RAW_ROOT + "config", scalar(1, 17) + scalar(2, 1)))
    for number in range(count):
        name = f"synthetic/key-{number:05d}"
        metadata = blob(1, name.encode()) + blob(5, stamp) + blob(6, stamp)
        if not metadata_only:
            versions = (1, 2) if not destroyed_only or extra_version and number == 0 else (1,)
            for version in versions:
                vm = blob(1, stamp)
                destroyed = destroyed_only or version == 2
                if destroyed:
                    vm += scalar(3, 1)
                else:
                    vm += blob(2, stamp)
                    hashed = hashlib.sha256(salt + (name + "|" + str(version)).encode()).hexdigest()
                    payload = b'{"large":9007199254740993,"tiny":1e-100,"arr":[null,true,"synthetic"]}'
                    rows.append((RAW_ROOT + "versions/" + hashed[:3] + "/" + hashed[3:],
                                 blob(1, payload) + blob(2, stamp) + blob(3, stamp)))
                metadata += blob(2, scalar(1, version) + blob(2, vm))
            metadata += scalar(3, max(versions)) + scalar(4, 1)
        rows.append((RAW_ROOT + "metadata/" + str(number), metadata))
    return rows


def spool_bytes(records):
    return b"".join(struct.pack(">QQ", len(path.encode()), len(raw)) + path.encode() + raw
                    for path, raw in records)


def document(records, *, total_records=None):
    total_records = records if total_records is None else total_records
    selected = d.snapshot_raw_manifest(records)
    full = d.snapshot_raw_manifest(total_records)
    wire = spool_bytes(total_records)
    metadata = [d.key_metadata(raw, bounds=d.NATIVE_LARGE_BOUNDS)[1]
                for path, raw in records if path.startswith(RAW_ROOT + "metadata/")]
    physical = dict(records).get(RAW_ROOT + "config")
    return {
        "schema": d.SNAPSHOT_SOURCE_SCHEMA,
        "source": {"version": "2.7.0", "git_commit": d.SNAPSHOT_SOURCE_COMMIT,
                   "binary_sha256": d.SNAPSHOT_SOURCE_BINARY_SHA256},
        "mount": {"path": "synthetic/", "namespace": "", "uuid": MOUNT, "backend_uuid": BACKEND},
        "snapshot": {"sha256": "1" * 64, "state_sha256": "2" * 64, "index": 7, "term": 3},
        "spool": {"sha256": hashlib.sha256(wire).hexdigest(), "bytes": len(wire),
                  **{key: full[key] for key in ("records", "raw_bytes", "path_bytes")},
                  "roots": sorted({"/".join(path.split("/")[:3]) + "/" for path, _ in total_records})},
        "inventory": {**selected, "logical_paths": len(metadata),
                      "retained_versions": sum(len(meta["versions"]) for meta in metadata),
                      "payload_versions": sum(path.startswith(RAW_ROOT + "versions/") for path, _ in records)},
        "configuration": {"origin": "exact_270_absent_record_default" if physical is None else "actual_raw_protobuf",
                          "raw_sha256": None if physical is None else hashlib.sha256(physical).hexdigest(),
                          "source_code_sha256": d.SNAPSHOT_CONFIG_SOURCE_SHA256},
        "evidence": {**{key: hashlib.sha256(("synthetic-" + key).encode()).hexdigest()
                        for key in ("capture", "restore", "tree", "values", "locator", "oracle")},
                     "predicate": "two_cold_raw_equal_and_every_metadata_current_get_locator_exact"},
    }


def encode_document(value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    return raw, hashlib.sha256(raw).hexdigest()


def source_for(records, value=None):
    raw, digest = encode_document(document(records) if value is None else value)
    return d.admit_snapshot_source(raw, digest)


def private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


class DecoderSourceTests(unittest.TestCase):
    def test_absence_without_trusted_profile_remains_rejected(self):
        for bounds in (d.LEGACY_BOUNDS, d.NATIVE_LARGE_BOUNDS):
            with self.assertRaises(d.DecodeError):
                d.decode_records(fixture(), bounds=bounds)

    def test_complete_witnessed_absence_preserves_history_and_exact_numbers(self):
        rows = fixture()
        bundle = d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(rows))
        self.assertEqual(bundle["config"], DEFAULTS)
        self.assertEqual(len(rows), 8)
        self.assertNotIn(RAW_ROOT + "config", dict(rows))
        self.assertEqual(len(bundle["entries"]), 2)
        for meta in bundle["entries"].values():
            self.assertEqual(meta["versions"]["1"]["data"]["large"], decimal.Decimal(9007199254740993))
            self.assertEqual(meta["versions"]["1"]["data"]["tiny"], decimal.Decimal("1e-100"))
            self.assertEqual(meta["versions"]["1"]["deletion_time"], "2023-11-14T22:13:20.123456789Z")
            self.assertEqual(meta["versions"]["1"]["source_deletion_time"], meta["versions"]["1"]["deletion_time"])
            self.assertTrue(meta["versions"]["2"]["destroyed"])
            self.assertIsNone(meta["versions"]["2"]["data"])

    def test_existing_config_is_identical_to_legacy_projection(self):
        rows = fixture(config=True)
        expected = d.decode_records(rows)
        self.assertEqual(d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(rows)), expected)
        self.assertEqual(expected["config"]["max_versions"], 17)
        self.assertTrue(expected["config"]["cas_required"])

    def test_malformed_present_config_never_becomes_defaults(self):
        rows = fixture() + [(RAW_ROOT + "config", scalar(999, 1))]
        with self.assertRaises(d.DecodeError):
            d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(rows))

    def test_physical_presence_and_provenance_must_agree(self):
        for present in (False, True):
            rows = fixture(config=present); value = document(rows)
            value["configuration"]["origin"] = "exact_270_absent_record_default" if present else "actual_raw_protobuf"
            value["configuration"]["raw_sha256"] = None if present else "3" * 64
            with self.assertRaises(d.DecodeError):
                d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(rows, value))

    def test_missing_duplicate_and_modified_raw_records_are_refused(self):
        rows = fixture(); source = source_for(rows)
        altered = [(path, raw + b"x" if number == 0 else raw) for number, (path, raw) in enumerate(rows)]
        for candidate in (rows[:-1], rows + [rows[0]], altered):
            with self.assertRaises(d.DecodeError):
                d.decode_records(candidate, bounds=d.NATIVE_LARGE_BOUNDS, source=source)

    def test_out_of_mount_record_is_refused_even_with_matching_digest(self):
        rows = fixture() + [("logical/33333333-3333-3333-3333-333333333333/" + BACKEND + "/salt", b"other")]
        with self.assertRaises(d.DecodeError):
            d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(rows))

    def test_source_release_commit_binary_and_default_source_are_explicit(self):
        for group, key, value in (("source", "version", "2.7.1"), ("source", "git_commit", "0" * 40),
                                  ("source", "binary_sha256", "0" * 64),
                                  ("configuration", "source_code_sha256", "0" * 64)):
            with self.subTest(key=key):
                rows = fixture(); witness = document(rows); witness[group][key] = value
                with self.assertRaises(d.DecodeError): source_for(rows, witness)

    def test_mount_namespace_and_backend_must_match_complete_raw_set(self):
        for key, value in (("namespace", "elsewhere"), ("uuid", "3" * 36),
                           ("backend_uuid", "33333333-3333-3333-3333-333333333333")):
            rows = fixture(); witness = document(rows); witness["mount"][key] = value
            with self.assertRaises(d.DecodeError): source_for(rows, witness)

    def test_external_sha_is_required_not_read_from_witness(self):
        wire, expected = encode_document(document(fixture()))
        for digest in (None, "", "0" * 64, True):
            with self.assertRaises(d.DecodeError): d.admit_snapshot_source(wire, digest)
        self.assertEqual(d.admit_snapshot_source(wire, expected).sha256, expected)

    def test_closed_schema_duplicate_keys_and_nonfinite_are_refused(self):
        value = document(fixture()); value["unexpected"] = True
        with self.assertRaises(d.DecodeError): source_for(fixture(), value)
        raw, _ = encode_document(document(fixture()))
        for candidate in (raw.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
                          raw.replace(b'"index": 7', b'"index": NaN', 1)):
            with self.assertRaises(d.DecodeError): d.admit_snapshot_source(candidate, hashlib.sha256(candidate).hexdigest())

    def test_all_evidence_and_exact_predicate_are_required(self):
        for key in ("capture", "restore", "tree", "values", "locator", "oracle", "predicate"):
            rows = fixture(); value = document(rows); del value["evidence"][key]
            with self.assertRaises(d.DecodeError): source_for(rows, value)

    def test_witness_does_not_accept_boolean_or_out_of_bound_counts(self):
        for group, key, value in (("inventory", "logical_paths", True),
                                  ("inventory", "logical_paths", 50001),
                                  ("inventory", "retained_versions", 99999),
                                  ("spool", "records", 100001), ("spool", "bytes", True),
                                  ("snapshot", "term", 0)):
            rows = fixture(); witness = document(rows); witness[group][key] = value
            with self.assertRaises(d.DecodeError): source_for(rows, witness)

    def test_logical_and_version_count_claims_are_recomputed(self):
        rows = fixture()
        for field in ("logical_paths", "retained_versions", "payload_versions"):
            value = document(rows); value["inventory"][field] -= 1
            with self.assertRaises(d.DecodeError):
                d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(rows, value))

    def test_snapshot_profile_cannot_be_used_with_legacy_bounds(self):
        rows = fixture(config=True)
        with self.assertRaises(d.DecodeError): d.decode_records(rows, source=source_for(rows))

    def test_native_more_than_ten_thousand_raw_records_and_legacy_unchanged(self):
        rows = fixture(5001, config=True)
        self.assertGreater(len(rows), 10000)
        with self.assertRaises(d.DecodeError): d.decode_records(rows)
        value = d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS)
        self.assertEqual(len(value["entries"]), 5001)

    def test_native_joint_record_boundary_includes_destroyed_history(self):
        # Destroyed versions have no payload frame; their retained records
        # still count. Raw record admission alone would miss this boundary.
        rows = fixture(49999, config=True, destroyed_only=True, extra_version=True)
        value = d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS)
        self.assertEqual(1 + len(value["entries"]) + sum(len(x["versions"]) for x in value["entries"].values()), 100000)
        del value
        rows = fixture(50000, config=True, destroyed_only=True)
        with self.assertRaises(d.DecodeError): d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS)

    def test_native_path_boundary_without_payload_history(self):
        rows = fixture(50000, config=True, metadata_only=True)
        value = d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS)
        self.assertEqual(len(value["entries"]), 50000)
        del value
        rows += [(RAW_ROOT + "metadata/extra", blob(1, b"synthetic/extra"))]
        with self.assertRaises(d.DecodeError): d.decode_records(rows, bounds=d.NATIVE_LARGE_BOUNDS)

    def test_original_orphan_unknown_and_destroyed_payload_checks_remain(self):
        rows = fixture()
        unknown = rows + [(RAW_ROOT + "unknown", b"synthetic")]
        orphan = rows + [(RAW_ROOT + "versions/000/" + "0" * 61, blob(1, b"{}"))]
        salt = dict(rows)[RAW_ROOT + "salt"]
        digest = hashlib.sha256(salt + b"synthetic/key-00000|2").hexdigest()
        destroyed = rows + [(RAW_ROOT + "versions/" + digest[:3] + "/" + digest[3:], b"synthetic")]
        for changed in (unknown, orphan, destroyed):
            with self.assertRaises(d.DecodeError):
                d.decode_records(changed, bounds=d.NATIVE_LARGE_BOUNDS, source=source_for(changed))


class OfflineExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-snapshot-synthetic-")
        self.home = Path(self.temp.name).resolve(); self.home.chmod(0o700)
        self.rows = fixture(); self.doc = document(self.rows)
        self.wire, self.digest = encode_document(self.doc)
        self.witness = self.home / "witness.json"; private(self.witness, self.wire)
        self.spool = self.home / "raw.bin"; private(self.spool, spool_bytes(self.rows))
        self.output = self.home / "bundle.json"; self.provenance = self.home / "provenance.json"

    def tearDown(self):
        self.temp.cleanup()

    def run_export(self, **extra):
        return subject.export_snapshot(self.witness, self.digest, self.spool, self.output, self.provenance, **extra)

    def test_complete_offline_projection_has_readback_and_separate_provenance(self):
        before = [(subject.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
                  for path in (self.witness, self.spool)]
        report = self.run_export()
        self.assertEqual(report["status"], "complete_offline_source_projection")
        self.assertFalse(report["target_import_qualified"])
        self.assertFalse(report["formal_live_export_5_360_qualified"])
        self.assertEqual(report["source_http_requests"], 0)
        for key in ("bundle", "provenance"):
            row = report[key]; path = Path(row["path"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"])
            self.assertEqual(list(subject.identity(path.stat())), row["identity"])
        proof = json.loads(self.provenance.read_bytes())
        self.assertEqual(proof["bundle_sha256"], report["bundle"]["sha256"])
        self.assertTrue(proof["successful_export_receipt_required"])
        self.assertFalse(proof["source_config_record_synthesized"])
        self.assertEqual(set(json.loads(self.output.read_bytes())), {"schema", "config", "entries"})
        after = [(subject.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
                 for path in (self.witness, self.spool)]
        self.assertEqual(before, after)

    def test_snapshot_witness_and_spool_cannot_be_changed(self):
        for path in (self.witness, self.spool):
            original = path.read_bytes(); path.write_bytes(original + b"x")
            with self.assertRaises(d.DecodeError): self.run_export()
            self.assertFalse(self.output.exists()); path.write_bytes(original)

    def test_capture_frame_order_does_not_change_projected_bundle(self):
        first = self.run_export()["bundle"]["sha256"]
        self.output = self.home / "bundle-reordered.json"
        self.provenance = self.home / "provenance-reordered.json"
        rows = list(reversed(self.rows)); wire, self.digest = encode_document(document(rows))
        self.witness.write_bytes(wire); self.spool.write_bytes(spool_bytes(rows))
        self.assertEqual(first, self.run_export()["bundle"]["sha256"])

    def test_source_permission_hardlink_and_symlink_are_refused(self):
        self.spool.chmod(0o640)
        with self.assertRaises(d.DecodeError): self.run_export()
        self.spool.chmod(0o600)
        link = self.home / "hardlink"; os.link(self.spool, link)
        with self.assertRaises(d.DecodeError): self.run_export()
        link.unlink(); saved = self.home / "original.bin"; self.spool.rename(saved); self.spool.symlink_to(saved)
        with self.assertRaises(d.DecodeError): self.run_export()

    def test_wrong_owner_is_refused(self):
        with self.assertRaises(d.DecodeError):
            subject.open_private(self.spool, 65536, end=time.monotonic()+3, owner_uid=os.getuid()+1)

    def test_output_parent_and_create_only_paths_are_checked(self):
        self.home.chmod(0o750)
        with self.assertRaises(d.DecodeError): self.run_export()
        self.home.chmod(0o700); private(self.output, b"original")
        with self.assertRaises(FileExistsError): self.run_export()
        self.assertEqual(self.output.read_bytes(), b"original")
        self.assertFalse(self.provenance.exists())

    def test_spool_partial_duplicate_and_out_of_scope_frames_refused(self):
        for records in (self.rows[:-1], self.rows + [self.rows[0]],
                        self.rows + [("logical/elsewhere/value", b"unexpected")]):
            raw = spool_bytes(records); self.spool.write_bytes(raw)
            document_ = copy.deepcopy(self.doc)
            document_["spool"].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                records=len(records), raw_bytes=sum(len(value) for _, value in records),
                path_bytes=sum(len(path.encode()) for path, _ in records))
            wire, self.digest = encode_document(document_); self.witness.write_bytes(wire)
            with self.assertRaises(d.DecodeError): self.run_export()
            self.assertFalse(self.output.exists())

    def test_other_admitted_mount_is_covered_but_not_imported(self):
        other_root = "logical/33333333-3333-3333-3333-333333333333/" + BACKEND + "/"
        full = self.rows + [(other_root + "salt", b"other-synthetic-mount")]
        wire, self.digest = encode_document(document(self.rows, total_records=full))
        self.witness.write_bytes(wire); self.spool.write_bytes(spool_bytes(full))
        report = self.run_export()
        self.assertEqual(report["raw_records"], len(self.rows))
        self.assertEqual(report["logical_paths"], 2)

    def test_source_changed_during_projection_refuses_before_outputs(self):
        original = subject.read_spool
        def changed(*args):
            records = original(*args); raw = self.spool.read_bytes()
            self.spool.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1])); return records
        with mock.patch.object(subject, "read_spool", changed):
            with self.assertRaises(d.DecodeError): self.run_export()
        self.assertFalse(self.output.exists())

    def test_new_output_actual_bytes_are_read_back(self):
        original = subject.create_private
        def corrupted(path, raw, end):
            record = original(path, raw, end)
            if Path(path) == self.output:
                value = self.output.read_bytes(); self.output.write_bytes(value[:-1] + b" ")
            return record
        with mock.patch.object(subject, "create_private", corrupted):
            with self.assertRaises(d.DecodeError): self.run_export()
        self.assertTrue(self.output.exists())
        self.assertTrue(self.provenance.exists())

    def test_new_output_same_bytes_inode_replacement_is_refused(self):
        original = subject.create_private
        def replaced(path, raw, end):
            record = original(path, raw, end)
            if Path(path) == self.output:
                self.output.rename(self.home / "retained-original")
                private(self.output, raw)
            return record
        with mock.patch.object(subject, "create_private", replaced):
            with self.assertRaises(d.DecodeError): self.run_export()

    def test_all_open_source_descriptors_close_on_projection_error(self):
        original = subject.open_private; observed = []
        def opening(*args, **kwargs):
            result = original(*args, **kwargs); observed.append(result[0]); return result
        with mock.patch.object(subject, "open_private", opening), \
             mock.patch.object(subject, "read_spool", side_effect=RuntimeError("synthetic private detail")):
            with self.assertRaises(RuntimeError): self.run_export()
        self.assertEqual(len(observed), 2)
        for fd in observed:
            with self.assertRaises(OSError) as caught: os.fstat(fd)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_expired_maintenance_deadline_refuses_without_output(self):
        with self.assertRaises(d.DecodeError): self.run_export(end=time.monotonic()-1)
        self.assertFalse(self.output.exists())

    def test_sigterm_main_returns_refusal_and_restores_handler(self):
        handler = signal.getsignal(signal.SIGTERM)
        argv = ["--witness", str(self.witness), "--witness-sha256", self.digest,
                "--raw-spool", str(self.spool), "--output", str(self.output), "--provenance", str(self.provenance)]
        stream = io.StringIO()
        with mock.patch.object(subject, "export_snapshot", side_effect=lambda *a, **k: os.kill(os.getpid(), signal.SIGTERM)), \
             contextlib.redirect_stdout(stream):
            status = subject.main(argv)
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(stream.getvalue())["status"], "refused")
        self.assertEqual(signal.getsignal(signal.SIGTERM), handler)

    def test_main_sanitizes_private_decode_error(self):
        argv = ["--witness", str(self.witness), "--witness-sha256", self.digest,
                "--raw-spool", str(self.spool), "--output", str(self.output), "--provenance", str(self.provenance)]
        stream = io.StringIO()
        with mock.patch.object(subject, "export_snapshot", side_effect=RuntimeError("private synthetic payload must not appear")), \
             contextlib.redirect_stdout(stream):
            status = subject.main(argv)
        self.assertEqual(status, 1)
        self.assertNotIn("private synthetic payload", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
