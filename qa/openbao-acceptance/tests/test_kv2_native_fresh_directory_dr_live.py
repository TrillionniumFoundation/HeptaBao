"""DR controller guards only. These tests never start HeptaBao or OpenBao."""
from __future__ import annotations

import copy
import contextlib
import errno
import gzip
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import kv2_native_fresh_directory_dr_live as dr


def write_private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def fixture_archive(path, *, state=b"HBV6PK01encrypted-fixture", format_name=None,
                    checksum_state=None, terminal=b"\0" * 1024, sealed=b"fixture-aead-not-authenticated",
                    generation=5, seal_identity="a" * 64):
    meta = dr.encoded({"format": format_name or "heptabao-native-object-snapshot-v1",
                       "state_format": "heptabao-encrypted-object-backup/HBV6PK01", "generation": generation,
                       "state_bytes": len(state), "seal_identity": {
                           "format": "heptabao-seal-metadata-digest-v1", "sha256": seal_identity}})
    sums = (dr.digest(meta) + "  meta.json\n" + dr.digest(checksum_state or state) + "  state.bin\n").encode()
    raw = bytearray()
    for name, content in zip(dr.ARCHIVE_NAMES, (meta, state, sums, sealed)):
        raw.extend(dr.tar_header(name, len(content)))
        raw.extend(content)
        raw.extend(b"\0" * ((-len(content)) % 512))
    raw.extend(terminal)
    write_private(path, gzip.compress(bytes(raw), mtime=0))
    return bytes(raw)


def full34_report():
    return {"status": "passed", "profile": "full34", "migration_lane": "native-large",
            "full34_qualified": True, "production_authority": False,
            "checks": [{"case": name, "passed": True} for name in dr.full.CHECKS],
            "target_storage_witnesses": [{"stage": name, "versions": list(range(19))}
                                         for name in dr.full.STORAGE_CHECKS],
            "source_api_wire_observations": list(range(19))}


def snapshot_capture_report():
    """Fictional observations for parser guards, never a live history receipt."""
    names = dr.full.CHECKS[:dr.full.CHECKS.index("snapshot_download") + 1]
    return {"profile": "full34", "migration_lane": "native-large", "production_authority": False,
            "retained_live_versions": 17, "live_payload_bytes": 34 * dr.MIB, "native_before_import": True,
            "capacity_after_import": {"state_storage_format": "heptabao-state-records-v6",
                "native_kv2_reader_format": 2, "native_kv2_logical_payload_bytes": 34 * dr.MIB},
            "checks": [{"case": name, "passed": True} for name in names],
            "source_api_wire_observations": [{"endpoint": "source", "method": "GET", "status": 200,
                "path": "secret/data/history?version=" + str(v), "body_bytes": 100,
                "same_response_decoded": True} for v in dr.VERSIONS],
            "target_storage_witnesses": [{"stage": name, "source_raw_bound": True, "versions": [
                {"version": v, "payload_present": v != 2, "destroyed": v == 2,
                 "payload_canonical_bytes": 0 if v == 2 else 1024 if v == 1 else 2 * dr.MIB}
                for v in dr.VERSIONS]} for name in dr.full.STORAGE_CHECKS[:2]]}


def build_fixture():
    """Fictional parser inputs; these are never an admitted product build."""
    server, seed = {"sha256": "b" * 64, "bytes": 100}, {"sha256": "c" * 64, "bytes": 90}
    commit, tree = "a" * 40, "d" * 40
    denominators = {"total_unique_cases": 107, "server_total": 90, "ha_service_total": 17}
    selection = {"schema": "heptabao.normal-rust-execution-selection.v1",
                 "execution_source_commit": commit, "execution_source_tree": tree,
                 "denominators": denominators, "legacy_groups": [], "legacy_additional_groups": [],
                 "added_groups": []}
    receipt = {"schema": "heptabao.convergence-normal-build-tests.v1", "status": "passed",
               "failure": None, "source_commit": commit, "source_tree": tree,
               "source_and_artifacts_unchanged": True, "passed_cases": 107,
               "executed_passed_cases": 107, "not_qualified_cases": 0,
               "expected_denominators": copy.deepcopy(denominators),
               "toolchain_pins": {name: "e" * 64 for name in ("cargo", "rustc", "rustfmt")},
               "artifacts": {}, "groups": [], "enumeration": {}}
    for label, count, crate in (("fixture-server", 90, "heptabao-server"),
                                ("fixture-peer", 17, "heptabao-ha-service")):
        tests = [f"{label}::case_{index}" for index in range(count)]
        selection["added_groups"].append({"label": label, "crate": crate, "tests": tests,
            "expected_count": count, "argv_suffix": [label, "--test-threads=1"]})
        receipt["groups"].append({"label": label, "crate": crate, "tests": list(tests),
            "expected_count": count, "passed": count, "status": "passed", "results": [{
                "passed": count, "failed": 0, "ignored": 0, "measured": 0,
                "reported_state": "ok", "exact_denominator_passed": True}]})
        receipt["enumeration"][label] = {"matched_names": sorted(tests), "matched_count": count}
    for name, actual in (("heptabao-server", server), ("heptabao-seed", seed)):
        receipt["artifacts"][name] = {**actual, "source_commit": commit, "source_tree": tree,
                                     "normal_features_profile_and_source_verified": True}
    selection_sha = dr.digest(dr.encoded(selection))
    receipt["selection_sha256"] = selection_sha
    return receipt, commit, server, seed, selection, selection_sha


class ControllerGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dr25-controller-")
        self.parent = Path(self.temporary.name).resolve(strict=True)
        self.parent.chmod(0o700)
        self.root = self.parent / "work"
        self.root.mkdir(mode=0o700)
        for name in ("dr-phases", "commands"):
            (self.root / name).mkdir(mode=0o700)
        actual_python = Path(sys.executable).resolve(strict=True)
        self.args = SimpleNamespace(private_work_root=self.root, binary=actual_python,
                                    seed_binary=actual_python, build_log=self.parent / "build.log",
                                    build_source_commit="a" * 40,
                                    backup_parent=self.parent / "backup", key_parent=self.parent / "keys")
        self.args.backup_parent.mkdir(mode=0o700)
        self.args.key_parent.mkdir(mode=0o700)
        self.run = dr.DisasterRecovery(self.args)

    def tearDown(self):
        self.temporary.cleanup()

    def test_dr25_requires_exact_unique_denominator_and_real_evidence(self):
        rows = [{"case": name, "passed": True, "evidence": {"observed_status": 200}} for name in dr.CHECKS]
        self.assertEqual(len(dr.CHECKS), 25)
        self.assertTrue(dr.complete(rows))
        for changed in (rows[:-1], rows + [copy.deepcopy(rows[0])], rows[:-1] + [copy.deepcopy(rows[0])]):
            self.assertFalse(dr.complete(changed))
        for key, value in (("passed", 1), ("passed", "skipped"), ("evidence", {}), ("evidence", True)):
            changed = copy.deepcopy(rows)
            changed[3][key] = value
            self.assertFalse(dr.complete(changed))

    def test_original_full34_gate_cannot_be_replaced_by_dr_checks(self):
        original = full34_report()
        self.assertTrue(dr.full34_complete(original))
        variants = []
        changed = copy.deepcopy(original); changed["checks"].pop(); variants.append(changed)
        changed = copy.deepcopy(original); changed["checks"][-1] = changed["checks"][0]; variants.append(changed)
        changed = copy.deepcopy(original); changed["checks"][2]["passed"] = False; variants.append(changed)
        changed = copy.deepcopy(original); changed["target_storage_witnesses"][1]["versions"].pop(); variants.append(changed)
        for key, value in (("profile", "native-small"), ("full34_qualified", False),
                           ("migration_lane", "legacy"), ("production_authority", True)):
            changed = copy.deepcopy(original); changed[key] = value; variants.append(changed)
        self.assertTrue(all(not dr.full34_complete(value) for value in variants))

    def test_build_receipt_binds_both_actual_executables_and_completed_source(self):
        receipt, commit, server, seed, selection, selection_sha = build_fixture()
        bound = dr.validate_build_receipt(receipt, commit, server, seed, selection, selection_sha)
        self.assertEqual(bound["artifacts"]["heptabao-seed"]["sha256"], seed["sha256"])
        for key, value in (("status", "running"), ("source_commit", "f" * 40),
                           ("source_and_artifacts_unchanged", False), ("toolchain_pins", {})):
            wrong = copy.deepcopy(receipt); wrong[key] = value
            with self.assertRaises(dr.Failure):
                dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)
        for key, value in (("sha256", "f" * 64), ("bytes", 91),
                           ("source_tree", "f" * 40), ("normal_features_profile_and_source_verified", False)):
            wrong = copy.deepcopy(receipt); wrong["artifacts"]["heptabao-seed"][key] = value
            with self.assertRaisesRegex(dr.Failure, "build_artifact_identity_mismatch"):
                dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)
        wrong = copy.deepcopy(receipt); del wrong["artifacts"]["heptabao-seed"]
        with self.assertRaisesRegex(dr.Failure, "build_artifact_identity_mismatch"):
            dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)

    def test_build_receipt_cannot_claim_passed_with_missing_or_partial_107_results(self):
        receipt, commit, server, seed, selection, selection_sha = build_fixture()
        for value in (None, 0, 106, True):
            wrong = copy.deepcopy(receipt); wrong["passed_cases"] = value
            with self.assertRaisesRegex(dr.Failure, "completed_107_build_test_counts_required"):
                dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)
        for field, value in (("executed_passed_cases", 106), ("not_qualified_cases", 1)):
            wrong = copy.deepcopy(receipt); wrong[field] = value
            with self.assertRaises(dr.Failure):
                dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)
        for field, value in (("passed", 89), ("status", "running"), ("results", [])):
            wrong = copy.deepcopy(receipt); wrong["groups"][0][field] = value
            with self.assertRaises(dr.Failure):
                dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)
        for field in ("failed", "ignored", "measured"):
            wrong = copy.deepcopy(receipt); wrong["groups"][0]["results"][0][field] = 1
            with self.assertRaisesRegex(dr.Failure, "build_test_result_not_passed"):
                dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)

    def test_build_receipt_requires_pinned_selection_and_matching_enumeration(self):
        receipt, commit, server, seed, selection, selection_sha = build_fixture()
        with self.assertRaisesRegex(dr.Failure, "build_test_selection_binding_required"):
            dr.validate_build_receipt(receipt, commit, server, seed, selection, "f" * 64)
        wrong = copy.deepcopy(receipt)
        wrong["enumeration"]["fixture-server"]["matched_names"][0] = "a_different_case"
        with self.assertRaisesRegex(dr.Failure, "build_test_enumeration_mismatch"):
            dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)
        wrong = copy.deepcopy(receipt); wrong["expected_denominators"]["total_unique_cases"] = 106
        with self.assertRaisesRegex(dr.Failure, "completed_107_build_test_counts_required"):
            dr.validate_build_receipt(wrong, commit, server, seed, selection, selection_sha)

    def test_build_receipt_cannot_count_one_test_twice_across_groups(self):
        receipt, commit, server, seed, selection, _ = build_fixture()
        duplicate = selection["added_groups"][0]["tests"][0]
        selection["added_groups"][1]["tests"][0] = duplicate
        receipt["groups"][1]["tests"][0] = duplicate
        receipt["enumeration"]["fixture-peer"]["matched_names"] = sorted(selection["added_groups"][1]["tests"])
        selection_sha = dr.digest(dr.encoded(selection))
        receipt["selection_sha256"] = selection_sha
        with self.assertRaisesRegex(dr.Failure, "build_test_unique_107_required"):
            dr.validate_build_receipt(receipt, commit, server, seed, selection, selection_sha)

    def test_archive_inspection_requires_v6_and_does_not_claim_aead(self):
        archive = self.root / "good.snap"
        fixture_archive(archive)
        result = dr.inspect_v6_archive(archive)
        self.assertTrue(result["outer_checksums_verified"])
        self.assertFalse(result["standalone_aead_verified"])
        self.assertEqual([r["name"] for r in result["members"]], list(dr.ARCHIVE_NAMES))
        for index, format_name in enumerate(("heptabao-native-snapshot-v2", "heptabao-native-ha-object-snapshot-v1")):
            other = self.root / f"wrong-{index}.snap"
            fixture_archive(other, format_name=format_name)
            with self.assertRaisesRegex(dr.Failure, "archive_v6_contract"):
                dr.inspect_v6_archive(other)

    def test_archive_rejects_truncation_trailing_members_and_changed_state(self):
        archive = self.root / "archive.snap"
        fixture_archive(archive)
        original = archive.read_bytes()
        for raw in (original[:-1], original + b"\0", original + gzip.compress(b"", mtime=0)):
            write_private(archive, raw)
            with self.assertRaises((dr.Failure, EOFError, OSError, ValueError)):
                dr.inspect_v6_archive(archive)
        fixture_archive(archive, checksum_state=b"different-state")
        with self.assertRaisesRegex(dr.Failure, "archive_v6_contract"):
            dr.inspect_v6_archive(archive)
        fixture_archive(archive, terminal=b"\0" * 1024 + b"x")
        with self.assertRaisesRegex(dr.Failure, "archive_exact_end"):
            dr.inspect_v6_archive(archive)

    def test_archive_refuses_noncanonical_tar_header_before_extraction(self):
        archive = self.root / "link.snap"
        raw = bytearray(fixture_archive(archive))
        raw[156] = ord("2")
        write_private(archive, gzip.compress(bytes(raw), mtime=0))
        with self.assertRaisesRegex(dr.Failure, "archive_canonical_header"):
            dr.inspect_v6_archive(archive)
        self.assertEqual({p.name for p in self.root.iterdir()}, {"link.snap", "dr-phases", "commands"})

    def capture_archive_check(self, report, *, seal_identity="a" * 64, truncate=False):
        """Exercise the real capture gate; stop before any oracle/kit creation."""
        self.run.backup = self.args.backup_parent
        archive = self.run.backup / "native-v6.snap"
        fixture_archive(archive, generation=6, seal_identity=seal_identity)
        fixture_archive(self.root / "native-snapshot.tar.gz", generation=5)
        if truncate:
            write_private(archive, archive.read_bytes()[:-1])
        base = SimpleNamespace(root=self.root, report=report, candidate=object())
        original_check = self.run.check

        class CaptureComplete(Exception):
            pass

        def record_then_stop(name, passed, evidence):
            original_check(name, passed, evidence)
            if name == "complete_v6_archive_seal_binding":
                raise CaptureComplete()

        with patch.object(self.run, "cli", return_value={"fixture_only_no_product": True}), \
             patch.object(self.run, "check", side_effect=record_then_stop):
            try:
                self.run.capture_backup(base)
            except CaptureComplete:
                return self.run.report["checks"][-1]
        self.fail("capture did not reach the archive gate")

    def test_snapshot_capture_accepts_small_physical_pack_with_full_logical_history(self):
        row = self.capture_archive_check(snapshot_capture_report())
        self.assertTrue(row["passed"])
        evidence = row["evidence"]
        self.assertLess(evidence["cli_archive"]["metadata"]["state_bytes"], 34 * dr.MIB)
        history = evidence["full34_logical_history"]
        self.assertEqual(history["capacity_after_import"]["native_kv2_logical_payload_bytes"], 34 * dr.MIB)
        self.assertEqual(len(history["capture_checks"]), 18)
        self.assertEqual(len(history["source_api_observations"]), 19)
        self.assertEqual([len(stage["versions"]) for stage in history["storage_witnesses"]], [19, 19])
        self.assertNotEqual(evidence["cli_archive"]["metadata"]["generation"],
                            evidence["normal_http_archive"]["metadata"]["generation"])
        self.assertFalse(evidence["cli_archive"]["standalone_aead_verified"])
        self.assertTrue(history["archive_aead_and_restored_history_still_required"])
        self.assertFalse(dr.complete(self.run.report["checks"]))
        self.assertFalse(dr.full34_complete(snapshot_capture_report()))

    def test_snapshot_capture_refuses_logical_shortfall_and_wrong_profile(self):
        for field, value in (("profile", "bundle34"), ("migration_lane", "legacy"),
                             ("retained_live_versions", 16), ("live_payload_bytes", 34 * dr.MIB - 1),
                             ("native_before_import", False), ("production_authority", True)):
            report = snapshot_capture_report()
            report[field] = value
            with self.subTest(field=field):
                self.assertFalse(dr.full34_snapshot_history(report)[0])
        for value in (34 * dr.MIB - 1, 0, None, True, str(34 * dr.MIB)):
            report = snapshot_capture_report()
            report["capacity_after_import"]["native_kv2_logical_payload_bytes"] = value
            with self.subTest(logical_bytes=value):
                self.assertFalse(dr.full34_snapshot_history(report)[0])
        with self.assertRaisesRegex(dr.Failure, "complete_v6_archive_seal_binding"):
            self.capture_archive_check(report)
        self.assertFalse(self.run.report["checks"][-1]["passed"])

    def test_snapshot_capture_requires_exact_checks_and_19_source_api_observations(self):
        variants = []
        report = snapshot_capture_report(); report["checks"].pop(); variants.append(report)
        report = snapshot_capture_report(); report["checks"][0] = report["checks"][1]; variants.append(report)
        report = snapshot_capture_report(); report["checks"][8]["passed"] = False; variants.append(report)
        report = snapshot_capture_report(); report["checks"][0]["case"] = "snapshot_restore_once"; variants.append(report)
        report = snapshot_capture_report(); report["source_api_wire_observations"].pop(); variants.append(report)
        report = snapshot_capture_report(); report["source_api_wire_observations"][0] = report["source_api_wire_observations"][1]; variants.append(report)
        report = snapshot_capture_report(); report["source_api_wire_observations"][0]["same_response_decoded"] = False; variants.append(report)
        for index, report in enumerate(variants):
            with self.subTest(variant=index):
                self.assertFalse(dr.full34_snapshot_history(report)[0])

    def test_snapshot_capture_requires_both_unique_raw_19_version_witnesses(self):
        for stage_index in (0, 1):
            for mutation in ("missing_stage", "missing_version", "duplicate_version", "not_source_bound",
                             "short_payload", "destroyed_payload_present"):
                report = snapshot_capture_report()
                stage = report["target_storage_witnesses"][stage_index]
                if mutation == "missing_stage":
                    report["target_storage_witnesses"].pop(stage_index)
                elif mutation == "missing_version":
                    stage["versions"].pop()
                elif mutation == "duplicate_version":
                    stage["versions"][0] = stage["versions"][1]
                elif mutation == "not_source_bound":
                    stage["source_raw_bound"] = False
                elif mutation == "short_payload":
                    stage["versions"][2]["payload_canonical_bytes"] = 2 * dr.MIB - 1
                else:
                    stage["versions"][1]["payload_present"] = True
                with self.subTest(stage=stage_index, mutation=mutation):
                    self.assertFalse(dr.full34_snapshot_history(report)[0])

    def test_snapshot_capture_still_refuses_mismatched_seal_with_full_history(self):
        with self.assertRaisesRegex(dr.Failure, "complete_v6_archive_seal_binding"):
            self.capture_archive_check(snapshot_capture_report(), seal_identity="b" * 64)
        row = self.run.report["checks"][-1]
        self.assertFalse(row["passed"])
        self.assertEqual(row["evidence"]["full34_logical_history"]["live_payload_bytes"], 34 * dr.MIB)

    def test_snapshot_capture_still_refuses_truncated_archive_with_full_history(self):
        with self.assertRaisesRegex(dr.Failure, "archive_gzip_truncated"):
            self.capture_archive_check(snapshot_capture_report(), truncate=True)
        self.assertEqual([row["case"] for row in self.run.report["checks"]], ["official_cli_v6_save_complete"])
        self.assertFalse(dr.complete(self.run.report["checks"]))

    def test_tree_manifest_preserves_rename_boundary_and_detects_byte_change(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        write_private(source / "state.hbs", b"encrypted original closure")
        before = dr.tree_manifest(source)
        isolated = self.root / "quarantined"
        source.rename(isolated)
        self.assertFalse(source.exists())
        self.assertEqual(before, dr.tree_manifest(isolated))
        write_private(isolated / "state.hbs", b"changed closure")
        self.assertNotEqual(before, dr.tree_manifest(isolated))

    def test_tree_manifest_refuses_hardlinks_and_symlinked_closures(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        write_private(self.root / "original", b"old store")
        (source / "linked").symlink_to(self.root / "original")
        with self.assertRaises((dr.Failure, OSError)):
            dr.tree_manifest(source)
        (source / "linked").unlink()
        os.link(self.root / "original", source / "hardlinked")
        with self.assertRaisesRegex(dr.Failure, "regular_unlinked_file_required"):
            dr.tree_manifest(source)

    def test_public_tree_summary_withholds_direct_and_aggregate_credential_fingerprints(self):
        source = self.root / "closed-source"
        source.mkdir(mode=0o700)
        write_private(source / "root.token", b"low-entropy-controller-fixture")
        write_private(source / "unseal.key", b"another-controller-fixture")
        manifest = dr.tree_manifest(source)
        summary = dr.tree_summary(manifest)
        public = dr.encoded(summary).decode()
        self.assertNotIn(dr.digest(dr.encoded(manifest)), public)
        for row in manifest["entries"]:
            self.assertNotIn(row["sha256"], public)
        retained = self.root / "private-tree.json"
        dr.write_private_tree(retained, manifest)
        private = json.loads(retained.read_text())
        self.assertEqual(private["manifest_sha256"], dr.digest(dr.encoded(manifest)))
        self.assertFalse(private["publishable"])
        self.assertEqual(dr.file_pin(retained, private=True)["mode"], 0o600)
        write_private(source / "root.token", b"a-different-controller-fixture")
        changed = dr.tree_manifest(source)
        self.assertNotEqual(changed, manifest)
        self.assertEqual(dr.tree_summary(changed), summary)

    def test_parent_fd_retirement_detects_real_open_file_directory_and_closed_boundary(self):
        source = self.root / "closed-source"
        source.mkdir(mode=0o700)
        leaf = source / "retained-data"
        write_private(leaf, b"synthetic original file")
        manifest = dr.tree_manifest(source)
        owner = SimpleNamespace(children=[])
        with leaf.open("rb") as held:
            leaf.unlink()  # Already recorded inode stays detectable after unlink.
            receipt = dr.parent_handle_retirement(owner, manifest)
            self.assertFalse(receipt["passed"])
            self.assertEqual(len(receipt["scans"]), 2)
            self.assertTrue(all(any(row["fd"] == held.fileno() for row in scan["matches_original_manifest"])
                                for scan in receipt["scans"]))
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            receipt = dr.parent_handle_retirement(owner, manifest)
            self.assertFalse(receipt["passed"])
            self.assertTrue(all(any(row["fd"] == descriptor for row in scan["matches_original_manifest"])
                                for scan in receipt["scans"]))
        finally:
            os.close(descriptor)
        receipt = dr.parent_handle_retirement(owner, manifest)
        self.assertTrue(receipt["passed"])
        self.assertTrue(receipt["no_parent_fd_matches_manifest"])
        self.assertNotIn(str(source), dr.encoded(receipt).decode())

    def test_parent_fd_retirement_rejects_unclosed_stdio_and_observation_gaps(self):
        manifest = dr.tree_manifest(self.root)
        stream = io.BytesIO()
        owner = SimpleNamespace(children=[SimpleNamespace(pid=os.getpid(), stdin=None, stdout=stream, stderr=None)])
        receipt = dr.parent_handle_retirement(owner, manifest)
        self.assertFalse(receipt["passed"])
        self.assertFalse(receipt["all_tracked_stdio_closed"])
        stream.close()
        self.assertTrue(dr.parent_handle_retirement(owner, manifest)["passed"])
        with patch.object(dr.os, "fstat", side_effect=OSError(errno.EPERM, "synthetic denied observation")):
            receipt = dr.parent_handle_retirement(owner, manifest)
        self.assertFalse(receipt["passed"])
        self.assertEqual(receipt["failure"], "PermissionError")
        self.assertFalse(receipt["scans"][0]["complete"])
        self.assertEqual(receipt["scans"][0]["observation_error"]["errno"], errno.EPERM)

    def test_nonregular_input_is_rejected_without_waiting_for_a_pipe_writer(self):
        fifo = self.root / "pretend-build-receipt"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(dr.Failure, "regular_unlinked_file_required"):
            dr.file_pin(fifo, private=True)

    def test_seed_stage_requires_exact_receipt_destination_and_four_private_files(self):
        seed = self.root / "seed"
        seed.mkdir(mode=0o700)
        rows = []
        for name in dr.SEED_FILES:
            raw = ("encrypted-" + name).encode()
            write_private(seed / name, raw)
            rows.append({"leaf": name, "bytes": len(raw), "sha256": dr.digest(raw)})
        identity = dr.directory_identity(seed)
        receipt = {"schema": 1, "operation": "export", "original_writer_fence_held": True,
                   "every_file_synced_and_read_back": True, "directory_publication_synced": True,
                   "cryptographic_state_admission_performed": False, "ha_qualified": False,
                   "destination_directory": {"device": identity["device"], "inode": identity["inode"],
                                             "owner": identity["uid"], "mode": identity["mode"]},
                   "seed_manifest_sha256": "a" * 64,
                   "seed": {"profile": "four-file-shamir-cipher-seed", "artifacts": rows}}
        self.assertEqual(len(dr.validate_seed_receipt(receipt, "export", seed)), 4)
        changed = copy.deepcopy(receipt); changed["destination_directory"]["inode"] += 1
        with self.assertRaisesRegex(dr.Failure, "seed_receipt_destination_identity"):
            dr.validate_seed_receipt(changed, "export", seed)
        write_private(seed / "old-object.hbo", b"old closure")
        with self.assertRaisesRegex(dr.Failure, "seed_exact_four_files"):
            dr.validate_seed_receipt(receipt, "export", seed)
        (seed / "old-object.hbo").unlink()
        (seed / "seal.json").chmod(0o644)
        with self.assertRaisesRegex(dr.Failure, "private_file_custody_required"):
            dr.validate_seed_receipt(receipt, "export", seed)

    def test_same_filesystem_fails_before_any_server_or_official_cli(self):
        with patch.object(dr.CapturedFull34, "execute", side_effect=AssertionError("must not start")) as execute:
            with self.assertRaisesRegex(dr.Failure, "independent_backup_filesystem_verified"):
                self.run.execute()
        execute.assert_not_called()
        self.assertIsNone(self.run.baseline)
        self.assertEqual(len(self.run.report["checks"]), 1)
        self.assertFalse(self.run.report["checks"][0]["passed"])
        self.assertEqual(self.run.report["commands"], [])

    def test_backup_and_key_parent_overlap_refuses_before_product_execution(self):
        self.args.key_parent = self.args.backup_parent / "nested-keys"
        self.args.key_parent.mkdir(mode=0o700)
        with patch.object(dr.CapturedFull34, "execute") as execute:
            with self.assertRaisesRegex(dr.Failure, "backup_key_directory_overlap"):
                self.run.execute()
        execute.assert_not_called()
        self.assertEqual(self.run.report["commands"], [])

    def test_main_publishes_same_filesystem_refusal_with_real_custody_and_no_children(self):
        new_root = self.parent / "main-work"
        receipt, build_log = self.parent / "build-result.json", self.parent / "build.log"
        write_private(receipt, b"{}")
        write_private(build_log, b"synthetic controller-only input")
        original_popen = subprocess.Popen
        argv = ["--binary", sys.executable, "--seed-binary", sys.executable,
                "--build-source-commit", "a" * 40, "--build-log", str(build_log),
                "--build-receipt", str(receipt), "--build-receipt-sha256", dr.digest(b"{}"),
                "--private-work-root", str(new_root), "--backup-parent", str(self.args.backup_parent),
                "--key-parent", str(self.args.key_parent)]
        old_mask = os.umask(0o077)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = dr.main(argv)
        finally:
            os.umask(old_mask)
        self.assertEqual(code, 1)
        self.assertIs(subprocess.Popen, original_popen)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")
        report = json.loads((new_root / "dr25-summary.json").read_text())
        self.assertEqual(report["failure"], "independent_backup_filesystem_verified")
        self.assertEqual(report["process_custody"]["original_count"], 0)
        self.assertFalse(report["fresh_directory_same_seal_v6_recovery_verified"])

    def test_full34_subclass_observes_original_check_before_callback(self):
        base_root = self.root / "baseline"
        base_root.mkdir(mode=0o700)
        (base_root / "phases").mkdir(mode=0o700)
        args = SimpleNamespace(binary=Path(sys.executable), private_work_root=base_root,
                               profile="full34", migration_lane="native-large")
        observer = Mock()
        base = dr.CapturedFull34(args, observer)
        base.check("snapshot_download", True)
        self.assertEqual(base.report["checks"], [{"case": "snapshot_download", "passed": True}])
        observer.capture_backup.assert_called_once_with(base)
        with self.assertRaisesRegex(dr.Failure, "unique_required_check"):
            base.check("snapshot_download", True)
        self.assertEqual(observer.capture_backup.call_count, 1)

    def test_child_rejection_requires_real_status_and_never_retries_label(self):
        script = "import sys; sys.stderr.write('Code: 400. synthetic rejection\\n'); sys.exit(1)"
        _, row = self.run.child("reject", [sys.executable, "-c", script], expected_status=400)
        self.assertEqual(row["http_status_codes"], [400])
        self.assertTrue(row["original_wait_completed"])
        self.assertEqual(row["outcome"], "response_received")
        self.assertEqual(row["stderr"]["mode"], 0o600)
        with self.assertRaisesRegex(dr.Failure, "child_must_not_retry"):
            self.run.child("reject", [sys.executable, "-c", "raise SystemExit(0)"])
        with self.assertRaisesRegex(dr.Failure, "negative_cli_requires_exact_http_rejection"):
            self.run.child("wrong_status", [sys.executable, "-c", script], expected_status=403)

    def test_child_timeout_retains_failure_and_joins_owned_original(self):
        with patch.object(dr.full, "HTTP_SECONDS", 0.15):
            with self.assertRaisesRegex(dr.Failure, "child_deadline_unknown_outcome_no_retry"):
                self.run.child("deadline", [sys.executable, "-c", "import time; time.sleep(30)"])
        row = self.run.report["commands"][0]
        self.assertEqual(row["outcome"], "unknown")
        self.assertTrue(row["original_wait_completed"])
        self.assertLess(row["returncode"], 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(row["pid"], 0)
        self.assertTrue(Path(row["private_stdout"]).is_file())
        self.assertTrue(Path(row["private_stderr"]).is_file())
        self.assertTrue(any("command_outcome" in p.name for p in (self.root / "dr-phases").iterdir()))

    def test_child_output_fingerprint_is_private_even_if_utility_echoes_a_credential(self):
        credential = "low-entropy-private-controller-fixture"
        self.run.secrets = [credential]
        script = "import os; print(os.environ['HB_CONTROLLER_FIXTURE'])"
        _, row = self.run.child("private_output", [sys.executable, "-c", script],
                                env={"HB_CONTROLLER_FIXTURE": credential})
        fingerprint = dr.digest((credential + "\n").encode())
        self.assertNotIn(fingerprint, dr.encoded(row).decode())
        self.assertNotIn(credential, dr.encoded(row).decode())
        self.assertNotIn("sha256", row["stdout"])
        self.assertFalse(row["stdout"]["content_fingerprint_published"])
        pins = json.loads(Path(row["private_output_pins"]).read_text())
        self.assertFalse(pins["publishable"])
        self.assertEqual(pins["files"]["stdout"]["sha256"], fingerprint)

    def test_child_custody_failure_still_retains_private_outputs_and_phase(self):
        child = SimpleNamespace(pid=123, returncode=None,
            poll=Mock(side_effect=RuntimeError("synthetic observer failure")))
        with patch.object(dr.subprocess, "Popen", return_value=child):
            with self.assertRaises(RuntimeError):
                self.run.child("custody_failure", [sys.executable, "-c", "pass"])
        row = self.run.report["commands"][0]
        self.assertEqual(row["failure"], "RuntimeError")
        self.assertEqual(row["cleanup_failure"], "RuntimeError")
        self.assertEqual(row["outcome"], "unknown")
        self.assertFalse(row["original_wait_completed"])
        self.assertTrue(Path(row["private_output_pins"]).is_file())
        self.assertTrue(any("command_outcome" in p.name for p in (self.root / "dr-phases").iterdir()))

    def test_incomplete_finish_cannot_grant_authority_and_redacts_runtime_token(self):
        self.run.secrets = ["private-synthetic-token"]
        self.run.report["diagnostic"] = "contains private-synthetic-token"
        self.run.report["checks"] = [{"case": name, "passed": True, "evidence": {"status": 200}}
                                     for name in dr.CHECKS]
        self.run.report["baseline"] = {"qualified": True}
        self.assertEqual(self.run.finish(), 1)
        raw = (self.root / "dr25-summary.json").read_text()
        self.assertNotIn("private-synthetic-token", raw)
        result = json.loads(raw)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["fresh_directory_same_seal_v6_recovery_verified"])
        for name in ("production_authority", "replacement_authority", "independent_qualification", "ha_qualified"):
            self.assertFalse(result[name])

    def test_finish_redacts_credential_hashes_as_well_as_plaintext(self):
        credential = "private-controller-token"
        self.run.secrets = [credential]
        self.run.report["injected_diagnostic"] = {"plain": credential,
            "sha256": dr.digest(credential.encode()), "file_sha256": dr.digest((credential + "\n").encode())}
        self.assertEqual(self.run.finish(), 1)
        public = (self.root / "dr25-summary.json").read_text()
        self.assertFalse(any(marker in public for marker in dr.credential_markers([credential])))
        self.assertEqual(json.loads(public)["status"], "failed")

    def final_gate_fixture(self, *, custody_passed=False):
        run = self.run
        run.before = {"controller_only_fixture": True}
        run.source_identity = Mock(return_value=run.before)
        run.seed_pin = dr.file_pin(self.args.seed_binary)
        run.bao = Path(sys.executable).resolve(strict=True)
        run.cli_pin = dr.file_pin(run.bao)
        self.args.build_receipt = self.parent / "synthetic-build.json"
        run.build_selection_path = self.parent / "test-selection.public.json"
        for path in (self.args.build_receipt, self.args.build_log, run.build_selection_path):
            write_private(path, b"controller-only fixture; never an admitted build")
        run.build_receipt_pin = dr.file_pin(self.args.build_receipt, private=True)
        run.build_log_pin = dr.file_pin(self.args.build_log)
        run.build_selection_pin = dr.file_pin(run.build_selection_path, private=True)
        run.backup = self.args.backup_parent / "fixture"
        run.backup.mkdir(mode=0o700)
        run.backup_manifest = {"files": []}
        write_private(run.backup / "manifest.json", dr.encoded(run.backup_manifest))
        run.manifest_pin = dr.file_pin(run.backup / "manifest.json", private=True)
        run.quarantined = self.root / "quarantined"
        run.quarantined.mkdir(mode=0o700)
        write_private(run.quarantined / "synthetic-closed-store", b"closed")
        run.quarantine_manifest = dr.tree_manifest(run.quarantined)
        run.baseline = SimpleNamespace(root=self.root / "absent-original", secrets=[])
        run.baseline_finished = True
        run.keys = self.args.key_parent / "fixture"
        run.keys.mkdir(mode=0o700)
        run.key, run.token = "synthetic-key", "synthetic-token"
        run.secrets = [run.key, run.token]
        write_private(run.keys / "unseal.key", run.key.encode())
        write_private(run.keys / "root.token", run.token.encode())
        run.directory_custody = run.directory_observations()
        run.report["checks"] = [{"case": name, "passed": True, "evidence": {"controller_only_fixture": True}}
                                for name in dr.CHECKS[:-1]]
        run.report["baseline"] = {"qualified": True}
        run.process_owner = SimpleNamespace(failed=False, finish=Mock(return_value={
            "passed_process_custody": custody_passed, "original_count": 1,
            "unfinished_originals": 0 if custody_passed else 1}))
        return run

    def test_final_gate_requires_complete_custody_receipt_even_without_failed_flag(self):
        run = self.final_gate_fixture()
        self.assertEqual(run.finish(), 1)
        self.assertEqual(run.report["failure"], "final_custody_cleanup_and_redaction")
        self.assertFalse(run.report["checks"][-1]["passed"])
        self.assertFalse(run.report["fresh_directory_same_seal_v6_recovery_verified"])

    def test_final_gate_rechecks_private_key_directory_even_when_files_remain_private(self):
        run = self.final_gate_fixture(custody_passed=True)
        run.keys.chmod(0o755)
        self.assertEqual(dr.file_pin(run.keys / "unseal.key", private=True)["mode"], 0o600)
        self.assertEqual(run.finish(), 1)
        self.assertEqual(run.report["failure"], "owned_private_parent_required")
        self.assertFalse(run.report["fresh_directory_same_seal_v6_recovery_verified"])

    def test_recovery_api_requires_exact_official_response_tokens(self):
        expected = {"config": {}, "metadata": {}, "versions": {"1": {
            "status": 200, "data": {"value": 9007199254740993}}}}
        self.run.oracle = dr.history_witness(expected)
        self.run.endpoint = object()
        wrong = copy.deepcopy(expected)
        wrong["versions"]["1"]["data"]["value"] = 9007199254740992
        with patch.object(dr.full, "observations", return_value=wrong):
            with self.assertRaisesRegex(dr.Failure, "recovered_api_history_mismatch"):
                self.run.observe_api()

    def cas_denial_mutation(self, mutate_data):
        value = {"value": "retained deleted payload"}
        self.run.oracle = {"source_api_live_payload_sha256": {"1": dr.json_hash(value)}}
        replies = [(204, {}), (200, {"data": {"data": value, "metadata": {"deletion_time": ""}}}),
                   (204, {}), (404, {"data": {"data": None, "metadata": {"destroyed": True}}}),
                   (200, {"data": {"payload_present": False, "payload_canonical_bytes": 0,
                                   "payload_canonical_sha256": None}}), (400, {}), (400, {}), (204, {})]
        self.run.endpoint = Mock()
        self.run.endpoint.call.side_effect = replies
        before = {"history_sha256": "a" * 64, "metadata": {"current_metadata_version": 2}}
        after_data, after_meta = copy.deepcopy(before), copy.deepcopy(before)
        (after_data if mutate_data else after_meta)["history_sha256"] = "b" * 64
        valid = {"history_sha256": "c" * 64,
                 "metadata": {"current_metadata_version": 3, "custom_metadata": {"revision": "dr25"}}}
        with patch.object(self.run, "observe_api", side_effect=[before, after_data, after_meta, valid]):
            with self.assertRaisesRegex(dr.Failure, "data_and_metadata_cas_guards_exact"):
                self.run.behavior_after_recovery()
        row = self.run.report["checks"][-1]
        self.assertFalse(row["passed"])
        self.assertEqual(set(row["evidence"]), {"data_cas", "metadata_cas"})
        self.assertEqual(row["evidence"]["data_cas"]["status"], 400)
        self.assertEqual(row["evidence"]["metadata_cas"]["denied_status"], 400)

    def test_data_cas_denial_with_effect_fails_and_keeps_subobservations(self):
        self.cas_denial_mutation(True)

    def test_metadata_cas_denial_with_effect_fails_and_keeps_subobservations(self):
        self.cas_denial_mutation(False)


if __name__ == "__main__":
    unittest.main()
