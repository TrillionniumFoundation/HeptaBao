"""Synthetic source-only regressions for the additive current fault-lab lane.

These fixtures exercise evidence handling. They are not native execution receipts,
qualification evidence, or replacements for the frozen historical V1 fixtures.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError
import yaml


ROOT = Path(__file__).resolve().parents[2]
COMMIT, TREE = "a" * 40, "b" * 40
RUN_ID, RUN_ATTEMPT, RUNNER = "23099", "2", "synthetic-fault-lab-runner"
RECEIPT = "fault-lab-evidence.json"
RECEIPT_SCHEMA = ROOT / "schemas/heptabao_h02_openraft_fault_lab_evidence_v2.schema.json"


def load_source(name: str, relative: str, expected_sha256: str | None = None):
    """Execute captured source bytes, never an import cache or second path read."""
    path = ROOT / relative
    captured = path.read_bytes()
    digest = hashlib.sha256(captured).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise AssertionError(f"unexpected source digest: {relative}")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(captured, str(path), "exec"), module.__dict__)
    return module


collector = load_source("_fault_lab_v2_test_collector", "scripts/h02_openraft_fault_lab_evidence_v2.py")
checker = load_source(
    "_fault_lab_v2_test_checker", "scripts/h02_linearizability_checker_v1.py",
    "c70b875ae90b2675ed24de5a49a05c154abbadf106112e5ce260932620ea4b69",
)
guard = load_source("_fault_lab_v2_test_guard", "scripts/validate_h02_openraft_fault_lab_v2.py")


def source_value():
    probe = ROOT / collector.PROBE
    return {
        "repository": "TrillionniumFoundation/HeptaBao", "commit": COMMIT,
        "tree": TREE, "clean_tree": True,
        "manifest_sha256": collector.sha((probe / "Cargo.toml").read_bytes()),
        "cargo_lock_sha256": collector.sha((probe / "Cargo.lock").read_bytes()),
    }


def operation(op_id, kind, invoke, complete, value=None, output=None, node=1):
    return {
        "id": op_id, "client": f"client-{op_id}", "kind": kind,
        "invoke": invoke, "complete": complete, "input": value, "output": output,
        "status": "ok", "node_id": node, "error": None,
    }


def history_value(seed=None, *, schedule=0, status="EXECUTED_PASS"):
    seed = seed or collector.SEEDS[0]
    if schedule == 0:
        operations = [operation("w1", "write", 1, 2, "A"),
                      operation("r1", "read", 3, 4, output="A")]
    else:
        # A genuinely different legal execution: a read before the write,
        # another leader/node, different RPC counts, and a different witness.
        operations = [operation("read-before", "read", 7, 8, node=2),
                      operation("write-later", "write", 10, 14, "B", node=3),
                      operation("read-after", "read", 16, 21, output="B", node=2)]
    value = {
        "schema": checker.HISTORY_SCHEMA, "model": "single-register-v1",
        "candidate_id": checker.EXPECTED_CANDIDATE, "version": checker.EXPECTED_VERSION,
        "profile_id": checker.EXPECTED_PROFILE, "seed": seed, "initial_value": None,
        "operations": operations,
        "execution_scope": "REAL_OPENRAFT_READINDEX_SINGLE_REGISTER_HISTORY",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
        "qualification": False, "selection_effect": "NONE", "authority_effect": "NONE",
        "metadata": {"synthetic_unit_test": True, "leader_id": 1 if not schedule else 3,
                     "rpc_counts": {"append_entries": 11 if not schedule else 29}},
    }
    if status == "EXECUTED_FAIL":
        value["operations"][-1]["output"] = "impossible-value"
    elif status == "BLOCKED":
        # Structurally schema-valid, but unusable by the checker because the
        # native operation interval is not ordered.
        value["operations"][0]["complete"] = value["operations"][0]["invoke"]
    return value


def surface_value():
    return {
        "last_log_index": 11, "local_committed": "Some(11)",
        "cluster_committed": "Some(11)", "last_applied": "Some(11)",
        "snapshot": "Some(8)", "purged": "Some(8)",
        # Pinned memstore source: HashMap<String, String>, with no fixed key set.
        "state_machine_last_applied": "Some(11)", "client_status": {"synthetic-client": "A"},
    }


def hostile_value(seed=None, *, status="EXECUTED_PASS", mode="noop"):
    seed = seed or collector.SEEDS[0]
    before = surface_value()
    child = {
        "classification": "IGNORED_STALE_NO_STATE_CHANGE",
        "candidate_response": "Ok(InstallSnapshotResponse)",
        "guarded_state_unchanged": True, "metrics_unchanged": True,
        "state_machine_unchanged": True, "before": before, "after": copy.deepcopy(before),
    }
    detail = {
        "reason": "synthetic guarded stale snapshot observation",
        "child_reported_outcome": "REJECTED", "child_reported_detail": child,
        "stderr_tail": "", "availability_note": "no additional process-fatal availability claim",
        "os_process_suspend": "NOT_EXECUTED_PROMOTION_BLOCKER",
        "disk_and_clock_faults": "NOT_EXECUTED_PROMOTION_BLOCKER",
    }
    value = {
        "schema": "heptabao.h02-openraft-hostile-snapshot-result.v1",
        "candidate_id": checker.EXPECTED_CANDIDATE, "version": checker.EXPECTED_VERSION,
        "profile_id": checker.EXPECTED_PROFILE, "seed": seed, "status": status,
        "phase_reached": status != "BLOCKED",
        "outcome": {"EXECUTED_PASS": "REJECTED_OR_ABORTED_AFTER_INJECTION",
                    "EXECUTED_FAIL": "ACCEPTED", "BLOCKED": "SETUP_OR_EXECUTION_BLOCKED"}[status],
        "child_exit_code": 0, "child_signal": None, "stdout_lines": 2, "stderr_bytes": 0,
        "execution_scope": "ISOLATED_CHILD_REAL_OPENRAFT_STALE_COMMITTED_SNAPSHOT_INJECTION",
        "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM", "detail": detail,
        "qualification": False, "selection_effect": "NONE", "authority_effect": "NONE",
    }
    if status == "EXECUTED_FAIL":
        detail["child_reported_outcome"] = "ACCEPTED"
        child.update(classification="STALE_SNAPSHOT_STATE_REGRESSION",
                     guarded_state_unchanged=False, metrics_unchanged=False)
        if mode == "membership-only":
            child.update(metrics_unchanged=True, state_machine_unchanged=False)
        else:
            child["after"]["last_log_index"] = 4
    elif status == "BLOCKED":
        if mode == "timeout-after-phase":
            value["phase_reached"] = True
            detail["child_reported_outcome"] = "TIMED_OUT_AFTER_INJECTION"
            detail["child_reported_detail"] = "snapshot RPC exceeded child deadline"
        else:
            value["child_exit_code"] = None
            value["stdout_lines"] = 0
            value["detail"] = {"reason": "child spawn/output failed in synthetic test"}
    elif mode == "explicit-rejection":
        detail["child_reported_detail"] = "candidate rejected stale committed snapshot"
    elif mode in {"fatal-exit", "fatal-signal"}:
        value["child_exit_code"] = 101 if mode == "fatal-exit" else None
        value["stderr_bytes"] = 10
        detail.update(child_reported_outcome=None, child_reported_detail=None,
                      stderr_tail="fatal abort", availability_note="process-fatal rejection remains an availability blocker")
    return value


class EntryFixture:
    def __init__(self, evidence_root, execution_root, toolchain, seed, *,
                 hostile_status="EXECUTED_PASS", checker_status="EXECUTED_PASS", schedule=0,
                 hostile_mode="noop", codes=None):
        self.toolchain, self.seed = toolchain, seed
        self.entry = evidence_root / collector.entry_name(toolchain, seed)
        self.entry.mkdir(parents=True)
        self.work = execution_root / self.entry.name / "probe"
        self.context = collector.new_context(
            toolchain, seed, self.work, self.entry, source_value(), RUN_ID, RUN_ATTEMPT, RUNNER,
        )
        self.context["source_after"] = copy.deepcopy(self.context["source_before"])
        self.context["return_codes"] = dict.fromkeys(collector.STAGES, 0)
        self.context["return_codes"].update(
            hostile=collector.EXIT[hostile_status], checker=collector.EXIT[checker_status],
        )
        if codes:
            self.context["return_codes"].update(codes)
        self.context["configuration_checks"] = {
            stage: None if code is None else {"before": True, "after": True}
            for stage, code in self.context["return_codes"].items()
        }
        self.hostile = hostile_value(seed, status=hostile_status, mode=hostile_mode)
        self.history = history_value(seed, schedule=schedule, status=checker_status)
        self.linear = checker.evaluate(self.history)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / collector.PROBE / name, self.entry / name)
        for stage, code in self.context["return_codes"].items():
            if code is not None:
                (self.entry / f"{stage}.stderr").write_text("", encoding="utf-8")
                if stage in {"test", "checker"}:
                    (self.entry / f"{stage}.stdout").write_text("synthetic unit test\n", encoding="utf-8")
        if self.context["return_codes"]["rustc"] is not None:
            (self.entry / "rustc.stdout").write_text(
                f"rustc {toolchain} (synthetic-unit-test)\nbinary: rustc\n"
                f"host: x86_64-unknown-linux-gnu\nrelease: {toolchain}\n", encoding="utf-8",
            )
        for kind, value in (("hostile", self.hostile), ("history", self.history), ("checker", self.linear)):
            if self.context["return_codes"][kind] is not None:
                self.write_raw(kind, value)
        self.seal()

    def write_raw(self, kind, value):
        collector.write(self.entry / collector.RAW_FILES[kind], value)

    def seal(self):
        collector.write(self.entry / "execution-context.json", self.context)
        self.receipt = collector.collect(self.entry, self.context)
        collector.write(self.entry / RECEIPT, self.receipt)
        return self.receipt

    def collect(self):
        collector.write(self.entry / "execution-context.json", self.context)
        return collector.collect(self.entry, self.context)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h02-fault-v2-tests-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.execution_root = self.root / "execution"
        self.evidence_root = self.root / "evidence"

    def fixture(self, **kwargs):
        # Give each subtest independent directories and context paths.
        sequence = len(list(self.root.glob("case-*")))
        case = self.root / f"case-{sequence}"
        return EntryFixture(case / "evidence", case / "execution",
                            collector.TOOLCHAINS[0], collector.SEEDS[0], **kwargs)

    def assert_closed(self, value):
        self.assertIs(value["qualification"], False)
        self.assertEqual("NONE", value["selection_effect"])
        self.assertEqual("NONE", value["authority_effect"])
        self.assertEqual(checker.BLOCK_PROMOTION, value["promotion_effect"])


class CollectorEvidenceTests(FixtureTests):
    def test_full_native_fixtures_validate_against_frozen_raw_schemas(self):
        for status, mode in (("EXECUTED_PASS", "noop"), ("EXECUTED_PASS", "explicit-rejection"),
                             ("EXECUTED_PASS", "fatal-exit"), ("EXECUTED_PASS", "fatal-signal"),
                             ("EXECUTED_FAIL", "noop"), ("EXECUTED_FAIL", "membership-only"),
                             ("BLOCKED", "noop"), ("BLOCKED", "timeout-after-phase")):
            with self.subTest(status=status, mode=mode):
                value = hostile_value(status=status, mode=mode)
                schema = collector.strict_json(ROOT / "schemas" / collector.RAW_SCHEMAS["hostile"])
                Draft202012Validator(schema).validate(value)
                collector.validate_raw("hostile", value, collector.SEEDS[0])
        for status in collector.EXIT:
            history = history_value(status=status)
            collector.validate_raw("history", history, collector.SEEDS[0])
            collector.validate_raw("checker", checker.evaluate(history), collector.SEEDS[0])

    def test_pass_requires_both_components_and_keeps_authority_closed(self):
        fixture = self.fixture()
        self.assertEqual("EXECUTED_PASS", fixture.receipt["status"])
        self.assertTrue(fixture.receipt["results"]["linearizability"]["linearizable"])
        self.assertEqual([], fixture.receipt["problems"])
        self.assert_closed(fixture.receipt)

    def test_exact_hostile_status_exit_pairs_and_all_mismatches(self):
        for status, required_code in collector.EXIT.items():
            for actual_code in (0, 1, 2):
                with self.subTest(status=status, code=actual_code):
                    fixture = self.fixture(hostile_status=status, codes={"hostile": actual_code})
                    result = fixture.receipt
                    expected = status if required_code == actual_code else "BLOCKED"
                    self.assertEqual(expected, result["status"])
                    self.assertEqual(required_code == actual_code, result["results"]["hostile_snapshot"] is not None)

    def test_exact_checker_status_exit_pairs_and_all_mismatches(self):
        for status, required_code in collector.EXIT.items():
            for actual_code in (0, 1, 2):
                with self.subTest(status=status, code=actual_code):
                    fixture = self.fixture(checker_status=status, codes={"checker": actual_code})
                    self.assertEqual(status if required_code == actual_code else "BLOCKED", fixture.receipt["status"])
                    self.assertEqual(required_code == actual_code, fixture.receipt["results"]["linearizability"] is not None)

    def test_true_hostile_failure_survives_invalid_checker(self):
        fixture = self.fixture(hostile_status="EXECUTED_FAIL")
        fixture.linear["history_sha256"] = "0" * 64
        fixture.write_raw("checker", fixture.linear)
        result = fixture.collect()
        self.assertEqual("EXECUTED_FAIL", result["status"])
        self.assertEqual("EXECUTED_FAIL", result["results"]["hostile_snapshot"]["status"])
        self.assertIsNone(result["results"]["linearizability"])
        self.assertTrue(result["problems"])

    def test_genuine_non_linearizable_history_survives_blocked_hostile(self):
        fixture = self.fixture(hostile_status="BLOCKED", checker_status="EXECUTED_FAIL")
        self.assertEqual("EXECUTED_FAIL", fixture.receipt["status"])
        self.assertIs(fixture.receipt["results"]["linearizability"]["linearizable"], False)

    def test_membership_only_regression_does_not_require_visible_state_difference(self):
        fixture = self.fixture(hostile_status="EXECUTED_FAIL", hostile_mode="membership-only")
        detail = fixture.hostile["detail"]["child_reported_detail"]
        self.assertEqual(detail["before"], detail["after"])
        self.assertIs(detail["metrics_unchanged"], True)
        self.assertIs(detail["state_machine_unchanged"], False)
        self.assertIs(detail["guarded_state_unchanged"], False)
        self.assertEqual("EXECUTED_FAIL", fixture.receipt["status"])

    def test_native_rejection_and_post_phase_fatal_modes_can_pass(self):
        for mode in ("noop", "explicit-rejection", "fatal-exit", "fatal-signal"):
            with self.subTest(mode=mode):
                self.assertEqual("EXECUTED_PASS", self.fixture(hostile_mode=mode).receipt["status"])

    def test_unreached_phase_and_post_phase_timeout_are_blocked(self):
        for mode in ("noop", "timeout-after-phase"):
            with self.subTest(mode=mode):
                fixture = self.fixture(hostile_status="BLOCKED", hostile_mode=mode)
                self.assertEqual("BLOCKED", fixture.receipt["status"])

    def test_hostile_surface_types_reject_objects_lists_booleans_and_invalid_unsigned_indices(self):
        optional_strings = ("local_committed", "cluster_committed", "last_applied",
                            "snapshot", "purged", "state_machine_last_applied")
        cases = [("last_log_index", value) for value in
                 ({"fabricated": "object"}, [], True, False, "11", 1.0, -1, 2 ** 64)]
        cases.extend((field, value) for field in optional_strings for value in ({}, [], True, 11, 1.0))
        for field, invalid in cases:
            with self.subTest(field=field, invalid=invalid):
                fixture = self.fixture()
                child = fixture.hostile["detail"]["child_reported_detail"]
                # Keep both sides equal so rejection cannot be explained away
                # by the existing unchanged-state comparison.
                for side in ("before", "after"):
                    child[side][field] = copy.deepcopy(invalid)
                fixture.write_raw("hostile", fixture.hostile)
                result = fixture.collect()
                self.assertEqual("BLOCKED", result["status"])
                self.assertIsNone(result["results"]["hostile_snapshot"])
                self.assertTrue(result["problems"])

    def test_native_optional_unsigned_and_string_state_values_remain_legal(self):
        for index in (None, 0, 2 ** 64 - 1):
            with self.subTest(index=index):
                fixture = self.fixture()
                child = fixture.hostile["detail"]["child_reported_detail"]
                for side in ("before", "after"):
                    child[side]["last_log_index"] = index
                    for field in ("local_committed", "cluster_committed", "last_applied",
                                  "snapshot", "purged", "state_machine_last_applied"):
                        child[side][field] = None
                fixture.write_raw("hostile", fixture.hostile)
                self.assertEqual("EXECUTED_PASS", fixture.collect()["status"])

    def test_client_status_is_an_arbitrary_string_to_string_map(self):
        for clients in ({}, {"": ""}, {"alice": "A", "bob": "B"}, {"任意客户端": "任意值"}):
            with self.subTest(clients=clients):
                fixture = self.fixture()
                child = fixture.hostile["detail"]["child_reported_detail"]
                for side in ("before", "after"):
                    child[side]["client_status"] = copy.deepcopy(clients)
                fixture.write_raw("hostile", fixture.hostile)
                self.assertEqual("EXECUTED_PASS", fixture.collect()["status"])
        for invalid in ("Running", None, [], True, 1, {"client": None}, {"client": 1},
                        {"client": True}, {"client": []}, {"client": {"nested": "value"}}):
            with self.subTest(invalid=invalid):
                fixture = self.fixture()
                child = fixture.hostile["detail"]["child_reported_detail"]
                for side in ("before", "after"):
                    child[side]["client_status"] = copy.deepcopy(invalid)
                fixture.write_raw("hostile", fixture.hostile)
                result = fixture.collect()
                self.assertEqual("BLOCKED", result["status"])
                self.assertIsNone(result["results"]["hostile_snapshot"])
                self.assertTrue(result["problems"])

    def test_child_exit_domain_cannot_grant_fatal_pass_or_valid_blocked(self):
        for status in collector.EXIT:
            for invalid in (-123, -1, 256, 2 ** 64, True, False, 0.0, 1.0, "0", {}, []):
                with self.subTest(status=status, invalid=invalid):
                    fixture = self.fixture(hostile_status=status)
                    fixture.hostile["child_exit_code"] = invalid
                    fixture.write_raw("hostile", fixture.hostile)
                    result = fixture.collect()
                    self.assertEqual("BLOCKED", result["status"])
                    self.assertIsNone(result["results"]["hostile_snapshot"])
                    self.assertTrue(result["problems"])

    def test_all_legal_native_parent_decision_branches_remain_supported(self):
        cases = []
        for code in (1, 2, 255, None):
            for phase in (False, True):
                value = hostile_value(mode="fatal-exit")
                status = "EXECUTED_PASS" if phase else "BLOCKED"
                value.update(status=status, phase_reached=phase, child_exit_code=code,
                             outcome="REJECTED_OR_ABORTED_AFTER_INJECTION" if phase else "SETUP_OR_EXECUTION_BLOCKED")
                cases.append((f"fatal-{code}-{phase}", value))
        for phase in (False, True):
            for outcome in (None, "UNRECOGNIZED_CHILD_OUTCOME"):
                value = hostile_value()
                value.update(status="BLOCKED", outcome="SETUP_OR_EXECUTION_BLOCKED", phase_reached=phase)
                value["detail"].update(child_reported_outcome=outcome, child_reported_detail=None)
                cases.append((f"unrecognized-{outcome}-{phase}", value))
        cases.extend((mode, hostile_value(status=status, mode=mode)) for status, mode in
                     (("EXECUTED_PASS", "explicit-rejection"), ("EXECUTED_PASS", "noop"),
                      ("EXECUTED_FAIL", "noop"), ("EXECUTED_FAIL", "membership-only"),
                      ("BLOCKED", "noop"), ("BLOCKED", "timeout-after-phase")))
        for label, raw in cases:
            with self.subTest(label=label):
                fixture = self.fixture(hostile_status=raw["status"])
                fixture.write_raw("hostile", raw)
                result = fixture.collect()
                self.assertEqual(raw["status"], result["status"])
                self.assertEqual([], result["problems"])
                self.assertEqual(raw, result["results"]["hostile_snapshot"])

    def test_blocked_labels_cannot_hide_recognized_child_pass_fail_or_postphase_fatal(self):
        for original_status, mode in (("EXECUTED_PASS", "noop"), ("EXECUTED_FAIL", "noop"),
                                      ("EXECUTED_PASS", "fatal-exit"), ("EXECUTED_PASS", "fatal-signal")):
            with self.subTest(original_status=original_status, mode=mode):
                fixture = self.fixture(hostile_status=original_status, hostile_mode=mode)
                fixture.hostile.update(status="BLOCKED", outcome="SETUP_OR_EXECUTION_BLOCKED")
                fixture.context["return_codes"]["hostile"] = 2
                fixture.write_raw("hostile", fixture.hostile)
                result = fixture.collect()
                self.assertEqual("BLOCKED", result["status"])
                self.assertIsNone(result["results"]["hostile_snapshot"])
                self.assertTrue(result["problems"], "a downgraded native outcome must expose the contradiction")

    def test_early_blocked_shape_cannot_claim_phase_exit_or_output(self):
        for field, invalid in (("phase_reached", True), ("child_exit_code", 0),
                               ("child_exit_code", 2), ("stdout_lines", 1), ("stderr_bytes", 1)):
            with self.subTest(field=field):
                fixture = self.fixture(hostile_status="BLOCKED")
                fixture.hostile[field] = invalid
                fixture.write_raw("hostile", fixture.hostile)
                result = fixture.collect()
                self.assertIsNone(result["results"]["hostile_snapshot"])
                self.assertTrue(result["problems"])

    def test_blocked_detail_and_timeout_shapes_fail_closed(self):
        mutations = (
            lambda v: v["detail"].update(child_reported_outcome=123),
            lambda v: v["detail"].update(child_reported_outcome=True),
            lambda v: v["detail"].update(child_reported_detail=None),
            lambda v: v["detail"].update(child_reported_detail={}),
            lambda v: v["detail"].update(child_reported_detail=""),
            lambda v: v.update(phase_reached=False),
            lambda v: v["detail"].update(extra="forged"),
            lambda v: v["detail"].pop("stderr_tail"),
            lambda v: v["detail"].update(child_reported_outcome=None, child_reported_detail="non-null detail"),
            lambda v: v["detail"].update(child_reported_outcome="UNKNOWN", child_reported_detail=[1, 2]),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                fixture = self.fixture(hostile_status="BLOCKED", hostile_mode="timeout-after-phase")
                mutate(fixture.hostile)
                fixture.write_raw("hostile", fixture.hostile)
                result = fixture.collect()
                self.assertIsNone(result["results"]["hostile_snapshot"])
                self.assertTrue(result["problems"])

    def test_forged_native_safety_claims_are_blocked(self):
        mutations = {
            "changed-state": lambda v: v["detail"]["child_reported_detail"]["after"].update(last_log_index=3),
            "false-guard": lambda v: v["detail"]["child_reported_detail"].update(guarded_state_unchanged=False),
            "bool-as-guard": lambda v: v["detail"]["child_reported_detail"].update(metrics_unchanged=1),
            "wrong-classification": lambda v: v["detail"]["child_reported_detail"].update(classification="STALE_SNAPSHOT_STATE_REGRESSION"),
            "wrong-child-outcome": lambda v: v["detail"].update(child_reported_outcome="ACCEPTED"),
            "missing-state-surface": lambda v: v["detail"]["child_reported_detail"]["before"].pop("purged"),
            "extra-detail": lambda v: v["detail"].update(extra="forged"),
            "phase-not-reached": lambda v: v.update(phase_reached=False),
            "invented-signal": lambda v: v.update(child_signal=9),
            "promotion-claim": lambda v: v["detail"].update(disk_and_clock_faults="EXECUTED"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                fixture = self.fixture()
                mutate(fixture.hostile)
                fixture.write_raw("hostile", fixture.hostile)
                self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_false_regression_claim_is_not_preserved_as_safety_failure(self):
        fixture = self.fixture(hostile_status="EXECUTED_FAIL")
        fixture.hostile["detail"]["child_reported_detail"].update(
            guarded_state_unchanged=True, metrics_unchanged=True, state_machine_unchanged=True,
        )
        fixture.write_raw("hostile", fixture.hostile)
        self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_dirty_changed_or_missing_source_blocks_pass(self):
        for defect in ("dirty", "changed-source", "missing-lock", "changed-lock", "changed-manifest"):
            with self.subTest(defect=defect):
                fixture = self.fixture()
                if defect == "dirty":
                    fixture.context["source_before"]["clean_tree"] = False
                elif defect == "changed-source":
                    fixture.context["source_after"]["tree"] = "c" * 40
                elif defect == "missing-lock":
                    (fixture.entry / "Cargo.lock").unlink()
                else:
                    name = "Cargo.lock" if defect == "changed-lock" else "Cargo.toml"
                    (fixture.entry / name).write_text("synthetic mutation\n", encoding="utf-8")
                self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_failed_or_unexecuted_stages_never_pass(self):
        stage_codes = (
            {"rustc": 1, "test": None, "hostile": None, "history": None, "checker": None},
            {"test": 101, "hostile": None, "history": None, "checker": None},
            {"history": 101, "checker": None}, {"checker": 125}, {"hostile": 125},
        )
        for codes in stage_codes:
            with self.subTest(codes=codes):
                self.assertEqual("BLOCKED", self.fixture(codes=codes).receipt["status"])

    def test_actual_compiler_release_mismatch_blocks(self):
        for content in ("rustc 1.98.0 (stale)\nrelease: 1.98.0\n",
                        "rustc 1.88.0 (synthetic)\nrelease: 1.99.0\n",
                        "rustc 1.88.0 (synthetic)\nrelease: 1.88.0\nrelease: 1.88.0\n", ""):
            with self.subTest(content=content):
                fixture = self.fixture()
                (fixture.entry / "rustc.stdout").write_text(content, encoding="utf-8")
                self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_candidate_profile_seed_version_and_authority_mismatches_block(self):
        for kind in ("hostile", "history"):
            for field, wrong in (("candidate_id", "other-candidate"), ("version", "0.9.0"),
                                 ("profile_id", "other-profile"), ("seed", collector.SEEDS[1]),
                                 ("qualification", True), ("selection_effect", "SELECTED"),
                                 ("authority_effect", "PRODUCTION")):
                with self.subTest(kind=kind, field=field):
                    fixture = self.fixture()
                    raw = copy.deepcopy(fixture.hostile if kind == "hostile" else fixture.history)
                    raw[field] = wrong
                    fixture.write_raw(kind, raw)
                    self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_strict_json_rejects_duplicates_nonfinite_and_invalid_syntax(self):
        for kind in collector.RAW_FILES:
            for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}',
                        '{"x":-Infinity}', '{"x":1e9999}', '{"unterminated":'):
                with self.subTest(kind=kind, raw=raw):
                    fixture = self.fixture()
                    (fixture.entry / collector.RAW_FILES[kind]).write_text(raw, encoding="utf-8")
                    self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_full_raw_shapes_reject_missing_extra_and_boolean_integers(self):
        mutations = (
            ("hostile", lambda v: v.pop("stdout_lines")),
            ("hostile", lambda v: v.update(extra=True)),
            ("hostile", lambda v: v.update(child_exit_code=False)),
            ("hostile", lambda v: v.update(stdout_lines=True)),
            ("hostile", lambda v: v.update(stderr_bytes=False)),
            ("history", lambda v: v["operations"][0].update(invoke=True)),
            ("history", lambda v: v["operations"][0].update(node_id=True)),
            ("history", lambda v: v["operations"][0].update(extra=1)),
            ("history", lambda v: v.pop("model")),
            ("checker", lambda v: v.update(operation_count=True)),
            ("checker", lambda v: v.update(extra=1)),
            ("checker", lambda v: v.pop("checker")),
        )
        for index, (kind, mutate) in enumerate(mutations):
            with self.subTest(index=index, kind=kind):
                fixture = self.fixture()
                raw = copy.deepcopy({"hostile": fixture.hostile, "history": fixture.history, "checker": fixture.linear}[kind])
                mutate(raw)
                fixture.write_raw(kind, raw)
                self.assertEqual("BLOCKED", fixture.collect()["status"])
        for kind in collector.RAW_FILES:
            for raw in (None, [], "not-an-object", 0, True):
                with self.subTest(kind=kind, raw=raw):
                    fixture = self.fixture()
                    fixture.write_raw(kind, raw)
                    self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_checker_digest_witness_and_status_must_match_actual_history(self):
        for field, wrong in (("history_sha256", "0" * 64), ("witness_order", ["r1", "w1"]),
                             ("explored_states", 10000), ("reason", "invented reason")):
            with self.subTest(field=field):
                fixture = self.fixture()
                fixture.linear[field] = wrong
                fixture.write_raw("checker", fixture.linear)
                self.assertEqual("BLOCKED", fixture.collect()["status"])
        fixture = self.fixture(checker_status="EXECUTED_FAIL")
        fixture.linear.update(status="EXECUTED_PASS", linearizable=True, witness_order=["w1", "r1"])
        fixture.context["return_codes"]["checker"] = 0
        fixture.write_raw("checker", fixture.linear)
        self.assertEqual("BLOCKED", fixture.collect()["status"])

    def test_independent_legal_schedules_rpc_metadata_and_witnesses_both_pass(self):
        first, second = self.fixture(schedule=0), self.fixture(schedule=1)
        self.assertEqual("EXECUTED_PASS", first.receipt["status"])
        self.assertEqual("EXECUTED_PASS", second.receipt["status"])
        self.assertNotEqual(first.history["metadata"], second.history["metadata"])
        self.assertNotEqual(first.linear["witness_order"], second.linear["witness_order"])
        for kind in ("history", "checker"):
            filename = collector.RAW_FILES[kind]
            self.assertNotEqual(first.receipt["artifacts"][filename], second.receipt["artifacts"][filename])

    def test_collector_hashes_actual_bytes_and_writes_no_files(self):
        fixture = self.fixture()
        before = {path.name: path.read_bytes() for path in fixture.entry.iterdir()}
        result = collector.collect(fixture.entry, fixture.context)
        after = {path.name: path.read_bytes() for path in fixture.entry.iterdir()}
        self.assertEqual(before, after)
        for filename, digest in result["artifacts"].items():
            self.assertEqual(hashlib.sha256(before[filename]).hexdigest(), digest)


class MatrixEvidenceTests(FixtureTests):
    def matrix(self, **first_options):
        sequence = len(list(self.root.glob("matrix-*")))
        case = self.root / f"matrix-{sequence}"
        root, execution = case / "evidence", case / "execution"
        entries = []
        for toolchain in collector.TOOLCHAINS:
            for seed in collector.SEEDS:
                entries.append(EntryFixture(root, execution, toolchain, seed,
                                            **(first_options if not entries else {})))
        return root, execution, entries

    def validate(self, matrix, *, require_pass=True, **overrides):
        root, execution, _ = matrix
        expected = dict(source_commit=COMMIT, source_tree=TREE, run_id=RUN_ID,
                        run_attempt=RUN_ATTEMPT, runner_name=RUNNER,
                        execution_root=execution, require_pass=require_pass)
        expected.update(overrides)
        return guard.validate_evidence_directory(root, **expected)

    def assert_rejected(self, matrix, **kwargs):
        with self.assertRaises((ValueError, ValidationError, OSError)):
            self.validate(matrix, **kwargs)

    def test_exact_two_compilers_three_seeds_validate(self):
        matrix = self.matrix()
        self.assertEqual(6, len(matrix[2]))
        self.assertEqual({"1.88.0", "1.99.0"}, {entry.toolchain for entry in matrix[2]})
        self.validate(matrix)

    def test_unchanged_independent_review_resealed_reproductions_cannot_bypass_validation(self):
        # Preserve the independent review's mutations and full six-entry
        # recollection flow verbatim; self-consistent hashes are not authority.
        for mutation in ("bad_surface_type", "downgrade_fail_to_blocked", "bad_child_exit"):
            with self.subTest(mutation=mutation):
                options = {"hostile_status": "EXECUTED_FAIL"} if mutation == "downgrade_fail_to_blocked" else {}
                matrix = self.matrix(**options)
                fixture = matrix[2][0]
                self.assertEqual("EXECUTED_FAIL" if options else "EXECUTED_PASS", fixture.receipt["status"])
                self.assertEqual([], fixture.receipt["problems"])
                if mutation == "bad_surface_type":
                    for side in ("before", "after"):
                        fixture.hostile["detail"]["child_reported_detail"][side]["last_log_index"] = {"fabricated": "object"}
                elif mutation == "downgrade_fail_to_blocked":
                    fixture.hostile["status"] = "BLOCKED"
                    fixture.hostile["outcome"] = "SETUP_OR_EXECUTION_BLOCKED"
                    fixture.context["return_codes"]["hostile"] = 2
                else:
                    fixture.hostile["child_exit_code"] = -123
                fixture.write_raw("hostile", fixture.hostile)
                fixture.seal()
                self.assertEqual("BLOCKED", fixture.receipt["status"])
                self.assertTrue(fixture.receipt["problems"])
                self.assertIsNone(fixture.receipt["results"]["hostile_snapshot"])
                if mutation == "downgrade_fail_to_blocked":
                    self.assertTrue(any("EXECUTED_FAIL" in problem for problem in fixture.receipt["problems"]))
                self.assert_rejected(matrix, require_pass=True)
                # The retained invalid observation may still be inspected; it
                # must carry a diagnostic and cannot silently become valid BLOCKED.
                self.validate(matrix, require_pass=False)

    def test_retain_genuine_fail_and_blocked_but_final_gate_requires_pass(self):
        modes = ({"hostile_status": "EXECUTED_FAIL"}, {"checker_status": "EXECUTED_FAIL"},
                 {"hostile_status": "BLOCKED"}, {"checker_status": "BLOCKED"},
                 {"codes": {"test": 101, "hostile": None, "history": None, "checker": None}},
                 {"codes": {"history": 101, "checker": None}})
        for options in modes:
            with self.subTest(options=options):
                matrix = self.matrix(**options)
                self.validate(matrix, require_pass=False)
                self.assert_rejected(matrix)

    def test_missing_extra_stale_and_non_directory_entries_rejected(self):
        for defect in ("missing", "extra-directory", "extra-file", "stale-name", "entry-is-file"):
            with self.subTest(defect=defect):
                matrix = self.matrix()
                root, _, entries = matrix
                entry = entries[0].entry
                if defect == "missing":
                    shutil.rmtree(entry)
                elif defect == "extra-directory":
                    (root / "1.98.0-5eed20260828cafe").mkdir()
                elif defect == "extra-file":
                    (root / "unbound-receipt.json").write_text("{}", encoding="utf-8")
                elif defect == "stale-name":
                    entry.rename(root / "1.98.0-5eed20260828cafe")
                else:
                    shutil.rmtree(entry)
                    entry.write_text("not a directory", encoding="utf-8")
                self.assert_rejected(matrix)

    def test_expected_commit_tree_run_attempt_runner_and_execution_path_bind_independently(self):
        changes = ({"source_commit": "c" * 40}, {"source_tree": "d" * 40},
                   {"run_id": "23098"}, {"run_attempt": "3"}, {"runner_name": "another-runner"},
                   {"execution_root": self.root / "another-execution"},
                   {"execution_root": Path("relative-execution")}, {"source_commit": "invalid"})
        matrix = self.matrix()
        for override in changes:
            with self.subTest(override=override):
                self.assert_rejected(matrix, **override)

    def test_coordinated_context_relabeling_and_recomputed_context_hashes_rejected(self):
        mutations = {
            "compiler": lambda c: c.update(toolchain=collector.TOOLCHAINS[1]),
            "seed": lambda c: c.update(seed=collector.SEEDS[1]),
            "profile": lambda c: c.update(execution_profile_id="other-profile"),
            "run": lambda c: c.update(run_id="88888"),
            "attempt": lambda c: c.update(run_attempt="17"),
            "runner": lambda c: c.update(runner_name="forged-runner"),
            "runner-id": lambda c: c.update(runner_id="forged-runner-id"),
            "environment-id": lambda c: c.update(environment_id="forged-environment"),
            "executor": lambda c: c.update(executor_kind="local-unattested"),
            "working-directory": lambda c: c.update(cwd="/synthetic-other-source"),
            "target-directory": lambda c: c["environment"].update(CARGO_TARGET_DIR="/synthetic-other-target"),
            "extra-field": lambda c: c.update(forged=True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                matrix = self.matrix()
                fixture = matrix[2][0]
                mutate(fixture.context)
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)

    def test_wrong_argv_even_with_recomputed_argv_digest_rejected(self):
        for stage in collector.STAGES:
            with self.subTest(stage=stage):
                matrix = self.matrix()
                fixture = matrix[2][0]
                fixture.context["argv"][stage].append("--forged-argument")
                fixture.context["argv_sha256"] = collector.sha(collector.canonical(fixture.context["argv"]))
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)
        matrix = self.matrix()
        fixture = matrix[2][0]
        fixture.context["argv_sha256"] = "0" * 64
        fixture.seal()
        self.assert_rejected(matrix, require_pass=False)

    def test_config_policy_paths_observations_and_resealed_environment_are_independently_bound(self):
        mutations = (
            lambda c: c.update(configuration_policy="UNRESTRICTED"),
            lambda c: c["configuration_paths"].pop(),
            lambda c: c["configuration_paths"].append("/forged/.cargo/config.toml"),
            lambda c: c.update(environment_sha256="0" * 64),
            lambda c: c["configuration_checks"].pop("test"),
            lambda c: c["configuration_checks"].update(extra={"before": True, "after": True}),
            lambda c: c["configuration_checks"].update(test=None),
            lambda c: c["configuration_checks"].update(test={"before": 1, "after": True}),
            lambda c: c["configuration_checks"].update(test={"before": True, "after": True, "extra": True}),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                matrix = self.matrix()
                fixture = matrix[2][0]
                mutate(fixture.context)
                # Missing observations are serialized directly because collect
                # legitimately expects the declared stage-key set.
                if "test" not in fixture.context["configuration_checks"]:
                    collector.write(fixture.entry / "execution-context.json", fixture.context)
                else:
                    fixture.seal()
                self.assert_rejected(matrix, require_pass=False)
        for key, value in (("RUSTC_WRAPPER", "/forged/wrapper"), ("CARGO_HOME", "/forged/cargo-home"),
                           ("HOME", "/forged/home"), ("TMPDIR", "/forged/tmp"),
                           ("PATH", "/forged/bin"), ("RUSTUP_HOME", "/forged/rustup")):
            with self.subTest(environment_key=key):
                matrix = self.matrix()
                fixture = matrix[2][0]
                fixture.context["environment"][key] = value
                fixture.context["environment_sha256"] = collector.sha(collector.canonical(fixture.context["environment"]))
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)

    def test_archived_runtime_path_and_rustup_are_independent_expected_inputs(self):
        matrix = self.matrix()
        base = {"PATH": "/synthetic-producer/bin:/usr/bin", "RUSTUP_HOME": "/synthetic-producer/rustup"}
        for fixture in matrix[2]:
            fixture.context = collector.new_context(
                fixture.toolchain, fixture.seed, fixture.work, fixture.entry, source_value(),
                RUN_ID, RUN_ATTEMPT, RUNNER, runtime_environment=base,
            )
            fixture.context["source_after"] = copy.deepcopy(fixture.context["source_before"])
            fixture.context["return_codes"] = dict.fromkeys(collector.STAGES, 0)
            fixture.context["configuration_checks"] = {
                stage: {"before": True, "after": True} for stage in collector.STAGES
            }
            fixture.seal()
        self.validate(matrix, runtime_environment=base)
        self.assert_rejected(matrix, require_pass=False)
        for key, value in (("PATH", "/wrong/bin"), ("RUSTUP_HOME", "/wrong/rustup")):
            with self.subTest(key=key):
                self.assert_rejected(matrix, require_pass=False, runtime_environment={**base, key: value})

    def test_changed_committed_source_cannot_be_hidden_by_new_hashes(self):
        for filename, source_key in (("Cargo.toml", "manifest_sha256"), ("Cargo.lock", "cargo_lock_sha256")):
            with self.subTest(filename=filename):
                matrix = self.matrix()
                fixture = matrix[2][0]
                path = fixture.entry / filename
                path.write_bytes(path.read_bytes() + b"\n# uncommitted synthetic mutation\n")
                fixture.context["source_before"][source_key] = collector.file_sha(path)
                fixture.context["source_after"] = copy.deepcopy(fixture.context["source_before"])
                fixture.seal()
                self.assertEqual("EXECUTED_PASS", fixture.receipt["status"])
                self.assert_rejected(matrix, require_pass=False)

    def test_source_commit_tree_repository_or_cleanliness_relabeling_rejected(self):
        for key, wrong in (("commit", "c" * 40), ("tree", "d" * 40),
                           ("repository", "other/repository"), ("clean_tree", False)):
            with self.subTest(key=key):
                matrix = self.matrix()
                fixture = matrix[2][0]
                fixture.context["source_before"][key] = wrong
                fixture.context["source_after"] = copy.deepcopy(fixture.context["source_before"])
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)

    def test_invalid_return_code_types_and_stage_shapes_rejected(self):
        for wrong in (False, True, 0.0, -1, 256, "0"):
            with self.subTest(wrong=wrong):
                matrix = self.matrix()
                fixture = matrix[2][0]
                fixture.context["return_codes"]["rustc"] = wrong
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)
        for defect in ("missing", "extra"):
            with self.subTest(defect=defect):
                matrix = self.matrix()
                fixture = matrix[2][0]
                context = copy.deepcopy(fixture.context)
                if defect == "missing":
                    context["return_codes"].pop("checker")
                else:
                    context["return_codes"]["extra"] = 0
                collector.write(fixture.entry / "execution-context.json", context)
                self.assert_rejected(matrix, require_pass=False)

    def test_impossible_stage_order_is_rejected(self):
        for changes in ({"rustc": 1}, {"test": 101}, {"history": 101}):
            with self.subTest(changes=changes):
                matrix = self.matrix()
                fixture = matrix[2][0]
                fixture.context["return_codes"].update(changes)
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)

    def test_missing_executed_stage_logs_rejected_even_after_recollection(self):
        for filename in ("rustc.stderr", "test.stdout", "test.stderr", "hostile.stderr",
                         "history.stderr", "checker.stdout", "checker.stderr"):
            with self.subTest(filename=filename):
                matrix = self.matrix()
                fixture = matrix[2][0]
                (fixture.entry / filename).unlink()
                fixture.seal()
                self.assert_rejected(matrix, require_pass=False)

    def test_receipt_artifact_hash_mismatch_is_rejected(self):
        matrix = self.matrix()
        fixture = matrix[2][0]
        fixture.receipt["artifacts"]["hostile-result.json"] = "0" * 64
        collector.write(fixture.entry / RECEIPT, fixture.receipt)
        self.assert_rejected(matrix, require_pass=False)

    def test_forged_pass_and_recomputed_file_hashes_do_not_override_actual_history(self):
        matrix = self.matrix(checker_status="EXECUTED_FAIL")
        fixture = matrix[2][0]
        forged = copy.deepcopy(fixture.linear)
        forged.update(status="EXECUTED_PASS", linearizable=True, witness_order=["w1", "r1"],
                      reason="linearization witness found")
        fixture.write_raw("checker", forged)
        fixture.context["return_codes"]["checker"] = 0
        receipt = fixture.seal()
        self.assertEqual("BLOCKED", receipt["status"])
        receipt.update(status="EXECUTED_PASS", problems=[])
        receipt["results"]["linearizability"] = forged
        self.assertEqual(collector.file_sha(fixture.entry / collector.RAW_FILES["checker"]),
                         receipt["artifacts"][collector.RAW_FILES["checker"]])
        collector.write(fixture.entry / RECEIPT, receipt)
        self.assert_rejected(matrix, require_pass=False)

    def test_top_level_and_nested_authority_forgery_rejected(self):
        for place in ("receipt", "hostile", "checker"):
            with self.subTest(place=place):
                matrix = self.matrix()
                fixture = matrix[2][0]
                value = fixture.receipt if place == "receipt" else fixture.receipt["results"][
                    "hostile_snapshot" if place == "hostile" else "linearizability"]
                value["authority_effect"] = "PRODUCTION"
                collector.write(fixture.entry / RECEIPT, fixture.receipt)
                self.assert_rejected(matrix, require_pass=False)

    def test_receipt_and_context_duplicate_keys_nonfinite_and_wrong_shapes_rejected(self):
        for filename in (RECEIPT, "execution-context.json"):
            for malformed in ('{"status":"EXECUTED_PASS","status":"BLOCKED"}',
                              '{"nonfinite":NaN}', '{"nonfinite":1e9999}', "[]", "null"):
                with self.subTest(filename=filename, malformed=malformed):
                    matrix = self.matrix()
                    (matrix[2][0].entry / filename).write_text(malformed, encoding="utf-8")
                    self.assert_rejected(matrix, require_pass=False)

    def test_symlinked_evidence_root_entry_and_inputs_rejected(self):
        for location in ("root", "entry", "rustc.stderr", "hostile-result.json", RECEIPT):
            with self.subTest(location=location):
                matrix = self.matrix()
                root, execution, entries = matrix
                original = root if location == "root" else entries[0].entry if location == "entry" else entries[0].entry / location
                target = original.with_name(original.name + ".actual")
                original.rename(target)
                original.symlink_to(target, target_is_directory=target.is_dir())
                self.assert_rejected((root, execution, entries), require_pass=False)

    def test_distinct_independent_legal_executions_validate_without_replay_equality(self):
        first = self.matrix(schedule=0)
        second = self.matrix(schedule=1)
        self.validate(first)
        self.validate(second)
        self.assertNotEqual(first[2][0].linear["history_sha256"], second[2][0].linear["history_sha256"])

    def test_relocated_artifacts_preserve_original_context_and_validate_with_independent_producer_roots(self):
        matrix = self.matrix()
        original_root, execution, entries = matrix
        producer_source = Path("/synthetic-producer/checked-out-source")
        for fixture in entries:
            fixture.context = collector.new_context(
                fixture.toolchain, fixture.seed, fixture.work, fixture.entry, source_value(),
                RUN_ID, RUN_ATTEMPT, RUNNER, source_root=producer_source,
            )
            fixture.context["source_after"] = copy.deepcopy(fixture.context["source_before"])
            fixture.context["return_codes"] = dict.fromkeys(collector.STAGES, 0)
            fixture.context["configuration_checks"] = {
                stage: {"before": True, "after": True} for stage in collector.STAGES
            }
            fixture.seal()
        captured = {str(path.relative_to(original_root)): path.read_bytes()
                    for path in original_root.rglob("*") if path.is_file()}
        relocated = self.root / "downloaded-artifacts"
        shutil.copytree(original_root, relocated)
        self.validate((relocated, execution, entries), producer_source_root=producer_source,
                      producer_evidence_root=original_root)
        self.assertEqual(captured, {str(path.relative_to(relocated)): path.read_bytes()
                                    for path in relocated.rglob("*") if path.is_file()})
        self.assert_rejected((relocated, execution, entries), require_pass=False)
        for wrong in ({"producer_source_root": ROOT, "producer_evidence_root": original_root},
                      {"producer_source_root": producer_source, "producer_evidence_root": relocated},
                      {"producer_source_root": Path("relative-source"), "producer_evidence_root": original_root},
                      {"producer_source_root": producer_source, "producer_evidence_root": Path("relative-evidence")}):
            with self.subTest(expected_roots=wrong):
                self.assert_rejected((relocated, execution, entries), require_pass=False, **wrong)

    def test_producer_paths_are_not_admitted_from_self_consistent_receipt_claims(self):
        matrix = self.matrix()
        fixture = matrix[2][0]
        forged_source = Path("/forged-producer/source")
        forged_evidence = Path("/forged-producer/evidence")
        fixture.context = collector.new_context(
            fixture.toolchain, fixture.seed, fixture.work, forged_evidence / fixture.entry.name,
            source_value(), RUN_ID, RUN_ATTEMPT, RUNNER, source_root=forged_source,
        )
        fixture.context["source_after"] = copy.deepcopy(fixture.context["source_before"])
        fixture.context["return_codes"] = dict.fromkeys(collector.STAGES, 0)
        fixture.context["configuration_checks"] = {
            stage: {"before": True, "after": True} for stage in collector.STAGES
        }
        fixture.seal()
        self.assertEqual("EXECUTED_PASS", fixture.receipt["status"])
        self.assert_rejected(matrix, require_pass=False)

    def test_relocated_fail_blocked_and_unexecuted_receipts_remain_reproducible(self):
        cases = ({"hostile_status": "EXECUTED_FAIL"}, {"checker_status": "EXECUTED_FAIL"},
                 {"hostile_status": "BLOCKED"}, {"checker_status": "BLOCKED"},
                 {"codes": {"rustc": 125, "test": None, "hostile": None, "history": None, "checker": None}},
                 {"codes": {"test": 101, "hostile": None, "history": None, "checker": None}},
                 {"codes": {"history": 101, "checker": None}})
        for index, options in enumerate(cases):
            with self.subTest(options=options):
                matrix = self.matrix(**options)
                producer_root, execution, entries = matrix
                relocated = self.root / f"downloaded-nonpass-{index}"
                shutil.copytree(producer_root, relocated)
                captured = {str(path.relative_to(relocated)): path.read_bytes()
                            for path in relocated.rglob("*") if path.is_file()}
                self.validate((relocated, execution, entries), require_pass=False,
                              producer_source_root=ROOT, producer_evidence_root=producer_root)
                self.assertEqual(captured, {str(path.relative_to(relocated)): path.read_bytes()
                                            for path in relocated.rglob("*") if path.is_file()})
                self.assert_rejected((relocated, execution, entries), require_pass=True,
                                     producer_source_root=ROOT, producer_evidence_root=producer_root)


class ReceiptSchemaTests(FixtureTests):
    def setUp(self):
        super().setUp()
        self.schema = collector.strict_json(RECEIPT_SCHEMA)
        Draft202012Validator.check_schema(self.schema)
        self.validator = collector.StrictValidator(self.schema)

    def test_pass_fail_blocked_and_unexecuted_receipts_validate(self):
        cases = ({}, {"hostile_status": "EXECUTED_FAIL"}, {"checker_status": "EXECUTED_FAIL"},
                 {"hostile_status": "BLOCKED"}, {"checker_status": "BLOCKED"},
                 {"codes": {"rustc": 125, "test": None, "hostile": None, "history": None, "checker": None}})
        for options in cases:
            with self.subTest(options=options):
                fixture = self.fixture(**options)
                self.validator.validate(fixture.receipt)
                self.assert_closed(fixture.receipt)

    def test_aggregate_embeds_complete_frozen_raw_result_schemas(self):
        for definition, kind in (("hostile", "hostile"), ("linear", "checker")):
            raw = collector.strict_json(ROOT / "schemas" / collector.RAW_SCHEMAS[kind])
            raw.pop("$id")
            raw.pop("$schema")
            self.assertEqual(raw, self.schema["$defs"][definition])

    def test_schema_rejects_forged_pass_missing_results_problems_and_dirty_source(self):
        for change in (lambda v: v["results"].update(hostile_snapshot=None),
                       lambda v: v["results"].update(linearizability=None),
                       lambda v: v.update(problems=["unresolved error"]),
                       lambda v: v["source"].update(clean_tree=False),
                       lambda v: v["results"]["hostile_snapshot"].update(status="BLOCKED")):
            fixture = self.fixture()
            change(fixture.receipt)
            self.assertTrue(list(self.validator.iter_errors(fixture.receipt)))

    def test_schema_rejects_missing_extra_authority_profile_and_wrong_primitive_types(self):
        mutations = (
            lambda v: v.pop("execution"), lambda v: v.update(extra=True),
            lambda v: v.update(qualification=True), lambda v: v.update(authority_effect="PRODUCTION"),
            lambda v: v.update(selection_effect="SELECTED"), lambda v: v.update(promotion_effect="PROMOTE"),
            lambda v: v.update(execution_profile_id="historical-profile"),
            lambda v: v["execution"].update(toolchain="1.98.0"),
            lambda v: v["execution"]["return_codes"].update(test=False),
            lambda v: v["execution"]["return_codes"].update(test=0.0),
            lambda v: v["results"]["hostile_snapshot"].update(stdout_lines=True),
            lambda v: v["artifacts"].update(**{"Cargo.lock": "not-a-digest"}),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                fixture = self.fixture()
                mutate(fixture.receipt)
                self.assertTrue(list(self.validator.iter_errors(fixture.receipt)))


class SourceAdmissionTests(FixtureTests):
    """Test the V2 admission layer without running any shell or native command."""

    def setUp(self):
        super().setUp()
        self.parser = load_source("_fault_lab_workflow_parser", "scripts/validate_workflow_trust_v1.py")
        self.workflow = self.parser.parse_workflow(guard.WORKFLOW.read_text(encoding="utf-8"))

    def validate_workflow(self, workflow):
        path = self.root / guard.WORKFLOW.name
        path.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")
        original_load = guard.load

        def isolated_load(name, relative, expected=None):
            if relative == "scripts/validate_workflow_trust.py":
                # The workflow trust validator has its own regression suite.
                # Here failures must come from the new V2 admission checks.
                return types.SimpleNamespace(validate_text=lambda *_: None)
            if relative == "scripts/validate_workflow_trust_v1.py":
                return self.parser
            return original_load(name, relative, expected)

        with patch.object(guard, "WORKFLOW", path), patch.object(guard, "load", side_effect=isolated_load), \
                patch.object(guard.historical, "main", return_value=0), \
                patch.object(guard.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            guard.validate_source_contract()
            for call in run.call_args_list:
                self.assertEqual(["bash", "-n"], call.args[0])

    def test_unmodified_source_admission_contract_is_accepted(self):
        self.validate_workflow(self.workflow)

    def test_swapped_omitted_stale_compilers_and_wrong_seeds_rejected(self):
        for defect in ("swapped", "omitted", "stale", "wrong-seed", "missing-seeds", "missing-env"):
            with self.subTest(defect=defect):
                workflow = copy.deepcopy(self.workflow)
                job = workflow["jobs"]["fault-sequential"]
                if defect == "swapped":
                    job["env"]["TOOLCHAINS"] = "1.99.0 1.88.0"
                elif defect == "omitted":
                    job["env"].pop("TOOLCHAINS")
                elif defect == "stale":
                    job["env"]["TOOLCHAINS"] = "1.88.0 1.98.0"
                elif defect == "wrong-seed":
                    job["env"]["SEEDS"] = "0x0000000000000001 " + " ".join(collector.SEEDS[1:])
                elif defect == "missing-seeds":
                    job["env"].pop("SEEDS")
                else:
                    job.pop("env")
                with self.assertRaisesRegex(ValueError, "environment drift"):
                    self.validate_workflow(workflow)

    def test_missing_runner_expected_commit_and_other_binding_flags_rejected(self):
        for index, flag in ((4, "--runner-name"), (4, "--expected-commit"), (4, "--run-attempt"),
                            (5, "--source-tree"), (5, "--producer-source-root"),
                            (7, "--runner-name"), (7, "--require-pass")):
            with self.subTest(index=index, flag=flag):
                workflow = copy.deepcopy(self.workflow)
                step = workflow["jobs"]["fault-sequential"]["steps"][index]
                self.assertIn(flag, step["run"])
                step["run"] = step["run"].replace(flag, "--omitted-binding")
                with self.assertRaisesRegex(ValueError, "command wiring drift"):
                    self.validate_workflow(workflow)

    def test_swapped_omitted_or_conditional_execution_validation_and_gate_rejected(self):
        for index in (4, 5, 7):
            for defect in ("missing-run", "no-op", "wrong-step", "missing-always", "wrong-shell"):
                with self.subTest(index=index, defect=defect):
                    workflow = copy.deepcopy(self.workflow)
                    steps = workflow["jobs"]["fault-sequential"]["steps"]
                    if defect == "missing-run":
                        steps[index].pop("run")
                    elif defect == "no-op":
                        steps[index]["run"] = "echo omitted\n"
                    elif defect == "wrong-step":
                        other = 5 if index == 4 else 4
                        steps[index], steps[other] = steps[other], steps[index]
                    elif defect == "missing-always":
                        steps[index].pop("if")
                    else:
                        steps[index]["shell"] = "sh"
                    with self.assertRaisesRegex(ValueError, "command wiring drift"):
                        self.validate_workflow(workflow)

    def test_missing_extra_and_duplicate_trigger_inputs_rejected(self):
        for defect in ("missing", "extra", "duplicate"):
            with self.subTest(defect=defect):
                workflow = copy.deepcopy(self.workflow)
                paths = workflow["on"]["pull_request"]["paths"]
                if defect == "missing":
                    paths.remove("scripts/h02_linearizability_checker_v1.py")
                elif defect == "extra":
                    paths.append("**")
                else:
                    paths.append(paths[0])
                with self.assertRaisesRegex(ValueError, "PR (paths|filter)"):
                    self.validate_workflow(workflow)


class MockedExecutionTests(FixtureTests):
    """All compiler, native probe, checker, and git processes are replaced here."""

    def test_execute_records_actual_argv_cwd_environment_and_exit_codes(self):
        for native_code, expected in ((0, 0), (1, 1), (2, 2), (101, 101), (-9, 137), (-15, 143), (999, 255)):
            with self.subTest(native_code=native_code):
                fixture = self.fixture()
                with patch.object(collector.subprocess, "run", return_value=types.SimpleNamespace(returncode=native_code)) as run:
                    actual = collector.execute(fixture.context, "hostile", fixture.entry)
                self.assertEqual(expected, actual)
                call = run.call_args
                self.assertEqual(fixture.context["argv"]["hostile"], call.args[0])
                self.assertEqual(str(fixture.work), call.kwargs["cwd"])
                self.assertEqual(fixture.context["environment"], call.kwargs["env"])
                self.assertIs(call.kwargs["check"], False)
                self.assertEqual(fixture.entry / "hostile-result.json", Path(call.kwargs["stdout"].name))
                self.assertEqual(fixture.entry / "hostile.stderr", Path(call.kwargs["stderr"].name))
                saved = collector.strict_json(fixture.entry / "execution-context.json")
                self.assertEqual(expected, saved["return_codes"]["hostile"])

    def test_execute_records_spawn_error_as_125_with_stderr(self):
        fixture = self.fixture()
        with patch.object(collector.subprocess, "run", side_effect=OSError("synthetic missing executable")):
            self.assertEqual(125, collector.execute(fixture.context, "rustc", fixture.entry))
        saved = collector.strict_json(fixture.entry / "execution-context.json")
        self.assertEqual(125, saved["return_codes"]["rustc"])
        self.assertIn("synthetic missing executable", (fixture.entry / "rustc.stderr").read_text())

    def run_synthetic(self, failure):
        evidence = self.root / f"evidence-{failure}"
        execution = self.root / f"execution-{failure}"
        entries = {collector.entry_name(t, s): (t, s) for t in collector.TOOLCHAINS for s in collector.SEEDS}
        first_name = next(iter(entries))
        calls = []

        def copy_probe(source, destination, commit):
            self.assertEqual(ROOT, source)
            self.assertEqual(COMMIT, commit)
            if destination.parent.name == first_name and failure == "copy":
                raise OSError("synthetic committed-copy failure")
            destination.mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(source / collector.PROBE / name, destination / name)
            if destination.parent.name == first_name and failure in {"manifest", "lock"}:
                filename = "Cargo.toml" if failure == "manifest" else "Cargo.lock"
                (destination / filename).write_bytes(b"synthetic wrong committed bytes\n")

        def process(argv, *, stdout, stderr, check, cwd, env):
            entry = Path(stdout.name).parent
            toolchain, seed = entries[entry.name]
            profile = collector.command_profile(toolchain, seed, execution / entry.name / "probe", entry)
            stage = next(key for key, command in profile.items() if command == argv)
            calls.append((entry.name, stage))
            self.assertEqual(str(execution / entry.name / "probe"), cwd)
            self.assertEqual(str(execution / ("target-" + toolchain)), env["CARGO_TARGET_DIR"])
            self.assertIs(check, False)
            stderr.write(b"")
            code = 0
            if stage == "rustc":
                stdout.write(f"rustc {toolchain} (synthetic)\nhost: x86_64-unknown-linux-gnu\nrelease: {toolchain}\n".encode())
            elif stage == "test":
                stdout.write(b"synthetic build/test only\n")
                if entry.name == first_name and failure == "build":
                    code = 101
            elif stage == "hostile":
                status = "EXECUTED_FAIL" if entry.name == first_name and failure == "hostile" else "EXECUTED_PASS"
                stdout.write(json.dumps(hostile_value(seed, status=status)).encode())
                code = collector.EXIT[status]
            elif stage == "history":
                stdout.write(json.dumps(history_value(seed)).encode())
            else:
                history = collector.strict_json(entry / collector.RAW_FILES["history"])
                result = checker.evaluate(history)
                collector.write(entry / collector.RAW_FILES["checker"], result)
                stdout.write(b"synthetic checker output\n")
                code = collector.EXIT[result["status"]]
            return types.SimpleNamespace(returncode=code)

        args = types.SimpleNamespace(source_root=ROOT, evidence_root=evidence, execution_root=execution,
                                     expected_commit=COMMIT, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                                     runner_name=RUNNER)
        snapshot_count = 0

        def snapshot(_):
            nonlocal snapshot_count
            snapshot_count += 1
            if failure == "source-after" and snapshot_count == 2:
                raise ValueError("synthetic after-source observation failure")
            return source_value()

        with patch.object(collector, "source_snapshot", side_effect=snapshot) as snapshots, \
                patch.object(collector, "copy_committed_probe", side_effect=copy_probe), \
                patch.object(collector.subprocess, "run", side_effect=process):
            self.assertEqual(0, collector.run(args))
        self.assertEqual(7, snapshots.call_count)
        self.assertEqual(set(entries), {path.name for path in evidence.iterdir()})
        values = {name: collector.strict_json(evidence / name / RECEIPT) for name in entries}
        self.assertEqual(6, len(values))
        self.assertEqual("EXECUTED_FAIL" if failure == "hostile" else "BLOCKED", values[first_name]["status"])
        self.assertTrue(all(value["status"] == "EXECUTED_PASS" for name, value in values.items() if name != first_name))
        for name in entries:
            expected_stages = list(collector.STAGES)
            if name == first_name:
                if failure == "build":
                    expected_stages = ["rustc", "test"]
                elif failure in {"copy", "manifest", "lock"}:
                    expected_stages = []
                    self.assertTrue(values[name]["execution"]["setup_error"])
                    self.assertEqual(dict.fromkeys(collector.STAGES), values[name]["execution"]["return_codes"])
                elif failure == "source-after":
                    self.assertIsNone(values[name]["execution"]["source_after"])
            self.assertEqual(expected_stages, [stage for entry, stage in calls if entry == name])
            self.assert_closed(values[name])
        guard.validate_evidence_directory(evidence, COMMIT, TREE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                                          runner_name=RUNNER, execution_root=execution)

    def test_build_failure_still_materializes_all_six_entries(self):
        self.run_synthetic("build")

    def test_hostile_failure_still_runs_history_checker_and_all_six_entries(self):
        self.run_synthetic("hostile")

    def test_copy_manifest_or_lock_failure_prevents_native_execution_and_retains_all_six(self):
        for failure in ("copy", "manifest", "lock"):
            with self.subTest(failure=failure):
                self.run_synthetic(failure)

    def test_after_source_snapshot_failure_blocks_without_losing_any_entry(self):
        self.run_synthetic("source-after")


class CargoConfigurationTests(FixtureTests):
    def test_controlled_environment_has_exact_allowlist_and_no_ambient_wrapper_inputs(self):
        fixture = self.fixture()
        base = {"PATH": "/trusted/bin:/usr/bin", "RUSTUP_HOME": "/trusted/rustup"}
        execution = fixture.work.parents[1]
        expected = {
            **base, "HOME": str(execution / "home"), "CARGO_HOME": str(execution / "cargo-home"),
            "TMPDIR": str(execution / "tmp"), "CARGO_TARGET_DIR": str(execution / "target-1.88.0"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        injected = {
            "RUSTC_WRAPPER": "/untrusted/wrapper", "RUSTC_WORKSPACE_WRAPPER": "/untrusted/workspace-wrapper",
            "CARGO_BUILD_RUSTC_WRAPPER": "/untrusted/config-wrapper", "RUSTFLAGS": "--cfg forged",
            "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fforged", "RUSTC": "/untrusted/rustc",
            "RUSTDOC": "/untrusted/rustdoc", "RUSTDOCFLAGS": "--cfg forged",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/untrusted/linker",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "/untrusted/runner",
            "HOME": "/untrusted/home", "CARGO_HOME": "/untrusted/cargo", "TMPDIR": "/untrusted/tmp",
            "PYTHONPATH": "/untrusted/python", "PYTHONHOME": "/untrusted/python-home",
            "LD_PRELOAD": "/untrusted/lib.so", "DYLD_INSERT_LIBRARIES": "/untrusted/mac.dylib",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.sshCommand",
            "GIT_CONFIG_VALUE_0": "/untrusted/ssh", "SECRET_TOKEN": "synthetic-not-a-secret",
        }
        with patch.dict(os.environ, injected):
            fixture.context = collector.new_context(
                fixture.toolchain, fixture.seed, fixture.work, fixture.entry, source_value(),
                RUN_ID, RUN_ATTEMPT, RUNNER, runtime_environment=base,
            )
            self.assertEqual(expected, fixture.context["environment"])
            self.assertEqual(collector.sha(collector.canonical(expected)), fixture.context["environment_sha256"])
            self.assertEqual(str(fixture.work), fixture.context["cwd"])
            for stage in collector.STAGES:
                with patch.object(collector.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
                    self.assertEqual(0, collector.execute(fixture.context, stage, fixture.entry))
                self.assertEqual(expected, run.call_args.kwargs["env"])
                self.assertEqual(str(fixture.work), run.call_args.kwargs["cwd"])
                self.assertEqual({"before": True, "after": True}, fixture.context["configuration_checks"][stage])

    def test_runtime_base_is_bounded_to_absolute_path_and_rustup_only(self):
        base = {"PATH": "/trusted/bin:/usr/bin", "RUSTUP_HOME": "/trusted/rustup"}
        self.assertEqual(base, collector.runtime_base_environment({**base, "RUSTC_WRAPPER": "/not-inherited"}))
        self.assertEqual({"PATH": "/usr/bin", "RUSTUP_HOME": "/trusted/home/.rustup"},
                         collector.runtime_base_environment({"PATH": "/usr/bin", "HOME": "/trusted/home"}))
        for invalid in ({**base, "PATH": ""}, {**base, "PATH": "relative/bin"},
                        {**base, "PATH": "/usr/bin:"}, {**base, "PATH": "/usr/bin:relative"},
                        {**base, "RUSTUP_HOME": "relative-rustup"}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    collector.runtime_base_environment(invalid)
        fixture = self.fixture()
        with self.assertRaises(ValueError):
            collector.controlled_environment(fixture.work, fixture.toolchain, {**base, "RUSTC_WRAPPER": "/forged"})

    def test_configuration_discovery_covers_cwd_every_ancestor_and_cargo_home(self):
        fixture = self.fixture()
        home = Path(fixture.context["environment"]["CARGO_HOME"])
        expected = []
        directory = fixture.work
        while True:
            expected.extend(str(directory / ".cargo" / name) for name in ("config", "config.toml"))
            if directory == directory.parent:
                break
            directory = directory.parent
        expected.extend(str(home / name) for name in ("config", "config.toml"))
        self.assertEqual(expected, fixture.context["configuration_paths"])
        self.assertEqual(expected, collector.cargo_configuration_paths(fixture.work, home))
        self.assertEqual(collector.CONFIG_POLICY, fixture.context["configuration_policy"])

    def test_each_owned_ancestor_and_cargo_home_config_blocks_before_execution(self):
        fixture = self.fixture()
        candidates = [Path(raw) for raw in fixture.context["configuration_paths"]
                      if Path(raw).is_relative_to(self.root)]
        self.assertTrue(candidates)
        for config in candidates:
            with self.subTest(config=config):
                config.parent.mkdir(parents=True, exist_ok=True)
                config.write_text('[build]\nrustc-wrapper = "/synthetic/untrusted-wrapper"\n', encoding="utf-8")
                try:
                    self.assertFalse(collector.configuration_absent(fixture.context))
                    with patch.object(collector.subprocess, "run") as run:
                        self.assertEqual(125, collector.execute(fixture.context, "test", fixture.entry))
                        run.assert_not_called()
                    self.assertEqual({"before": False, "after": False}, fixture.context["configuration_checks"]["test"])
                    self.assertEqual("BLOCKED", fixture.collect()["status"])
                finally:
                    config.unlink()
        self.assertTrue(collector.configuration_absent(fixture.context))

    def test_each_stage_blocks_on_config_and_dangling_config_symlinks(self):
        for stage in collector.STAGES:
            with self.subTest(stage=stage):
                fixture = self.fixture()
                config = fixture.work / ".cargo/config.toml"
                config.parent.mkdir(parents=True)
                config.symlink_to(self.root / "nonexistent-config-target")
                with patch.object(collector.subprocess, "run") as run:
                    self.assertEqual(125, collector.execute(fixture.context, stage, fixture.entry))
                    run.assert_not_called()
                self.assertEqual({"before": False, "after": False}, fixture.context["configuration_checks"][stage])

    def test_symlinked_cargo_configuration_parent_is_blocked_even_without_file(self):
        for parent_kind in ("cwd-cargo", "ancestor-cargo", "cargo-home"):
            with self.subTest(parent_kind=parent_kind):
                fixture = self.fixture()
                if parent_kind == "cwd-cargo":
                    parent = fixture.work / ".cargo"
                elif parent_kind == "ancestor-cargo":
                    parent = fixture.work.parents[1] / ".cargo"
                else:
                    parent = Path(fixture.context["environment"]["CARGO_HOME"])
                parent.parent.mkdir(parents=True, exist_ok=True)
                target = self.root / (parent_kind + "-empty-target")
                target.mkdir()
                parent.symlink_to(target, target_is_directory=True)
                self.assertFalse(collector.configuration_absent(fixture.context))
                with patch.object(collector.subprocess, "run") as run:
                    self.assertEqual(125, collector.execute(fixture.context, "test", fixture.entry))
                    run.assert_not_called()

    def test_config_appearing_during_stage_blocks_receipt_and_next_command(self):
        fixture = self.fixture()
        config = fixture.work / ".cargo/config.toml"

        def inject_config(*_args, **_kwargs):
            config.parent.mkdir(parents=True)
            config.write_text('[build]\nrustflags = ["--cfg", "forged"]\n', encoding="utf-8")
            return types.SimpleNamespace(returncode=0)

        with patch.object(collector.subprocess, "run", side_effect=inject_config) as run:
            self.assertEqual(0, collector.execute(fixture.context, "test", fixture.entry))
            self.assertEqual(1, run.call_count)
        self.assertEqual({"before": True, "after": False}, fixture.context["configuration_checks"]["test"])
        result = fixture.collect()
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("configuration isolation" in problem for problem in result["problems"]))
        with patch.object(collector.subprocess, "run") as run:
            self.assertEqual(125, collector.execute(fixture.context, "hostile", fixture.entry))
            run.assert_not_called()


class SourceSnapshotTests(FixtureTests):
    def git_fixture(self):
        repo = self.root / "source-repository"
        probe = repo / collector.PROBE
        probe.mkdir(parents=True)
        manifest, lock = probe / "Cargo.toml", probe / "Cargo.lock"
        manifest_bytes = b'[package]\nname = "synthetic-source-test"\nversion = "0.0.0"\n'
        lock_bytes = b"# synthetic unit-test dependency graph\nversion = 4\n"
        manifest.write_bytes(manifest_bytes)
        lock.write_bytes(lock_bytes)
        git_env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_AUTHOR_NAME": "Synthetic Unit Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
                   "GIT_COMMITTER_NAME": "Synthetic Unit Test", "GIT_COMMITTER_EMAIL": "test@example.invalid"}

        def git(*args):
            return subprocess.run(
                ["git", "-C", str(repo), "-c", "core.hooksPath=" + os.devnull,
                 "-c", "commit.gpgsign=false", *args],
                check=True, capture_output=True, env=git_env,
            ).stdout.decode().strip()

        git("init", "--quiet")
        git("add", collector.PROBE + "/Cargo.toml", collector.PROBE + "/Cargo.lock")
        git("commit", "--quiet", "-m", "Synthetic source binding fixture")
        return repo, probe, git, manifest_bytes, lock_bytes

    def test_actual_git_commit_tree_cleanliness_and_committed_hashes(self):
        """A tiny disposable git repository; no Rust build, fetch, or publication."""
        repo, probe, git, manifest_bytes, lock_bytes = self.git_fixture()
        manifest, lock = probe / "Cargo.toml", probe / "Cargo.lock"
        clean = collector.source_snapshot(repo)
        self.assertEqual(git("rev-parse", "HEAD"), clean["commit"])
        self.assertEqual(git("rev-parse", "HEAD^{tree}"), clean["tree"])
        self.assertIs(clean["clean_tree"], True)
        self.assertEqual(collector.sha(manifest_bytes), clean["manifest_sha256"])
        self.assertEqual(collector.sha(lock_bytes), clean["cargo_lock_sha256"])

        for tracked in (manifest, lock):
            with self.subTest(tracked=tracked.name):
                original = tracked.read_bytes()
                tracked.write_bytes(original + b"\n# working-tree-only mutation\n")
                changed = collector.source_snapshot(repo)
                self.assertIs(changed["clean_tree"], False)
                self.assertEqual({**clean, "clean_tree": False}, changed)
                tracked.write_bytes(original)
        untracked = repo / "untracked-input.txt"
        untracked.write_text("untracked mutation\n", encoding="utf-8")
        self.assertEqual({**clean, "clean_tree": False}, collector.source_snapshot(repo))
        untracked.unlink()
        self.assertEqual(clean, collector.source_snapshot(repo))

    def test_committed_probe_copy_excludes_ignored_inputs_and_preserves_executable_mode(self):
        repo, probe, git, _, _ = self.git_fixture()
        (probe / "src").mkdir()
        source = probe / "src/main.rs"
        source.write_bytes(b"// committed synthetic source only\n")
        executable = probe / "fixture-helper.sh"
        executable.write_bytes(b"#!/bin/sh\n# synthetic committed fixture; never executed\n")
        executable.chmod(0o755)
        (repo / ".gitignore").write_text(
            f"/{collector.PROBE}/build.rs\n/{collector.PROBE}/src/ignored-sentinel.rs\n",
            encoding="utf-8",
        )
        ignored_build = probe / "build.rs"
        ignored_source = probe / "src/ignored-sentinel.rs"
        ignored_build.write_text("// ignored build script must never copy\n", encoding="utf-8")
        ignored_source.write_text("// ignored source must never copy\n", encoding="utf-8")
        git("add", ".")
        git("commit", "--quiet", "-m", "Add committed copy fixture and ignored inputs")
        commit = git("rev-parse", "HEAD")
        self.assertIs(collector.source_snapshot(repo)["clean_tree"], True)
        source.write_bytes(b"// uncommitted working bytes must not replace the pinned blob\n")
        work = self.root / "committed-work"
        collector.copy_committed_probe(repo, work, commit)
        self.assertEqual(b"// committed synthetic source only\n", (work / "src/main.rs").read_bytes())
        self.assertEqual(0o755, (work / executable.name).stat().st_mode & 0o777)
        self.assertFalse((work / "build.rs").exists())
        self.assertFalse((work / "src/ignored-sentinel.rs").exists())
        self.assertEqual({"Cargo.toml", "Cargo.lock", "src/main.rs", "fixture-helper.sh"},
                         {str(path.relative_to(work)) for path in work.rglob("*") if path.is_file()})

    def test_unchanged_ignored_root_cargo_config_review_repro_cannot_affect_isolated_command(self):
        repo, _, git, _, _ = self.git_fixture()
        before = collector.source_snapshot(repo)
        exclude = repo / ".git/info/exclude"
        exclude.write_bytes(exclude.read_bytes() + b"\n/.cargo/\n")
        ignored = repo / ".cargo/config.toml"
        ignored.parent.mkdir()
        ignored.write_text('[build]\nrustc-wrapper = "/synthetic/ignored-wrapper"\n', encoding="utf-8")
        # This is the independent review's unchanged source-snapshot repro.
        self.assertEqual(before, collector.source_snapshot(repo))
        self.assertIs(before["clean_tree"], True)
        self.assertEqual("", git("status", "--porcelain", "--untracked-files=all"))

        execution = self.root / "isolated-execution"
        name = collector.entry_name(collector.TOOLCHAINS[0], collector.SEEDS[0])
        work = execution / name / "probe"
        entry = self.root / "isolated-evidence" / name
        entry.mkdir(parents=True)
        collector.copy_committed_probe(repo, work, before["commit"])
        context = collector.new_context(
            collector.TOOLCHAINS[0], collector.SEEDS[0], work, entry, before,
            RUN_ID, RUN_ATTEMPT, RUNNER, source_root=repo,
            runtime_environment={"PATH": "/trusted/bin:/usr/bin", "RUSTUP_HOME": "/trusted/rustup"},
        )
        self.assertEqual(str(work), context["cwd"])
        self.assertNotIn(repo, work.parents)
        self.assertNotIn(str(ignored), context["configuration_paths"])
        self.assertTrue(collector.configuration_absent(context))
        with patch.dict(os.environ, {"RUSTC_WRAPPER": "/synthetic/ambient-wrapper", "CARGO_HOME": str(repo / ".cargo")}), \
                patch.object(collector.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertEqual(0, collector.execute(context, "test", entry))
        self.assertEqual(str(work), run.call_args.kwargs["cwd"])
        self.assertEqual(str(execution / "cargo-home"), run.call_args.kwargs["env"]["CARGO_HOME"])
        self.assertNotIn("RUSTC_WRAPPER", run.call_args.kwargs["env"])
        self.assertNotIn(str(repo / ".cargo"), run.call_args.kwargs["env"].values())

    def test_committed_copy_rejects_malformed_paths_and_nonregular_git_objects(self):
        prefix = collector.PROBE.encode()
        oid = b"a" * 40
        records = (
            b"100644 blob invalid-oid\t" + prefix + b"/invalid-oid.rs\0",
            b"120000 blob " + oid + b"\t" + prefix + b"/symlink\0",
            b"160000 commit " + oid + b"\t" + prefix + b"/submodule\0",
            b"040000 tree " + oid + b"\t" + prefix + b"/tree\0",
            b"100666 blob " + oid + b"\t" + prefix + b"/bad-mode.rs\0",
            b"100644 blob " + oid + b"\t" + prefix + b"/../escape.rs\0",
            b"100644 blob " + oid + b"\t/outside/probe.rs\0",
            b"100644 blob " + oid + b"\tprobes/h02/another-probe.rs\0",
            b"malformed metadata without path separator\0",
            b"100644 blob " + oid + b"\t" + prefix + b"/\xff.rs\0",
        )
        for index, record in enumerate(records):
            with self.subTest(record=record):
                destination = self.root / f"invalid-copy-{index}"
                with patch.object(collector.subprocess, "check_output", return_value=record) as git:
                    with self.assertRaises((ValueError, OSError)):
                        collector.copy_committed_probe(self.root, destination, COMMIT)
                self.assertEqual(1, git.call_count, "invalid tree entry must be rejected before reading a blob")
                self.assertEqual([], [path for path in destination.rglob("*") if path.is_file()])

    def test_committed_copy_rejects_blob_bytes_that_do_not_match_the_pinned_object(self):
        original = b"committed expected blob\n"
        oid = hashlib.sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest().encode()
        path = (collector.PROBE + "/src/main.rs").encode()
        tree = b"100644 blob " + oid + b"\t" + path + b"\0"
        destination = self.root / "wrong-blob-copy"
        with patch.object(collector.subprocess, "check_output", side_effect=[tree, b"substituted blob\n"]) as git:
            with self.assertRaisesRegex(ValueError, "blob content mismatch"):
                collector.copy_committed_probe(self.root, destination, COMMIT)
        self.assertEqual(2, git.call_count)
        self.assertEqual([], [file for file in destination.rglob("*") if file.is_file()])


if __name__ == "__main__":
    unittest.main()
