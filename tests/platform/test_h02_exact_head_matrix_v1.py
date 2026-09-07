from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "h02_exact_head_matrix_v1",
        ROOT / "scripts/h02_exact_head_matrix_v1.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


runner = load_module()
SEED = runner.SEEDS[0]


def closed_authority() -> dict:
    return {
        "qualification": False,
        "selection_effect": "NONE",
        "authority_effect": "NONE",
    }


def inmemory_stdout(status: str = "PASS") -> str:
    values = [
        {
            "kind": "meta",
            "candidate_id": runner.CANDIDATE_ID,
            "version": runner.CANDIDATE_VERSION,
            "seed": SEED,
            "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
            **closed_authority(),
        }
    ]
    values.extend(
        {
            "kind": "case",
            "case_id": case_id,
            "status": status,
        }
        for case_id in sorted(runner.EXPECTED_INMEMORY_CASES)
    )
    return "\n".join(json.dumps(value) for value in values) + "\n"


def hostile_stdout(status: str = "EXECUTED_PASS") -> str:
    return json.dumps(
        {
            "schema": "heptabao.h02-openraft-hostile-snapshot-result.v1",
            "candidate_id": runner.CANDIDATE_ID,
            "version": runner.CANDIDATE_VERSION,
            "seed": SEED,
            "status": status,
            "phase_reached": True,
            "outcome": (
                "REJECTED_OR_ABORTED_AFTER_INJECTION"
                if status == "EXECUTED_PASS"
                else "SETUP_OR_EXECUTION_BLOCKED"
                if status == "BLOCKED"
                else "ACCEPTED"
            ),
            **closed_authority(),
        }
    )


def blocker_stdout(status: str = "EXECUTED_PASS") -> str:
    component = {"status": status, **closed_authority()}
    return json.dumps(
        {
            "schema": "heptabao.h02-blocker-closure-result.v1",
            "candidate_id": runner.CANDIDATE_ID,
            "version": runner.CANDIDATE_VERSION,
            "seed": SEED,
            "status": status,
            "components": {
                "os_suspend": component,
                "durable_faults": component,
                "clock_faults": component,
            },
            **closed_authority(),
        }
    )


def durable_stdout(status: str = "EXECUTED_PASS") -> str:
    return json.dumps(
        {
            "schema": "heptabao.h02-openraft-durable-store-result.v1",
            "candidate_id": runner.CANDIDATE_ID,
            "version": runner.CANDIDATE_VERSION,
            "seed": SEED,
            "status": status,
            "cases": [
                {"case_id": case_id, "status": "PASS"}
                for case_id in sorted(runner.EXPECTED_DURABLE_CASES)
            ],
            "scope": {
                "real_openraft_nodes": 3,
                "raft_log_storage_implemented": True,
                "raft_state_machine_implemented": True,
                "state_machine_persisted_before_responder": True,
                "snapshot_state_atomic_bundle_publish": True,
                "state_publish_after_durable_write": True,
                "full_cluster_disk_restart": True,
                "read_index_after_restart": True,
                "corruption_rejected": True,
                "kernel_power_loss": False,
                "production_selected": False,
            },
            **closed_authority(),
        }
    )


def make_entry(probe, toolchain: str, seed: str) -> dict:
    identifier = runner.entry_id(probe, toolchain, seed)
    command = runner.canonical_command(
        probe,
        toolchain,
        seed,
        manifest=runner.EXPECTED_MANIFEST,
    )
    return {
        "entry_id": identifier,
        "kind": probe.kind,
        "binary": probe.binary,
        "toolchain": toolchain,
        "seed": seed,
        "command": command,
        "command_digest": runner.canonical_json_digest(command),
        "started_at": "2026-08-30T00:00:00Z",
        "completed_at": "2026-08-30T00:00:01Z",
        "duration_ms": 1000,
        "process_started": True,
        "exit_code": 0,
        "timed_out": False,
        "conclusion": "PASS",
        "application_status": "EXECUTED_PASS",
        "stdout_path": f"{identifier}.stdout",
        "stderr_path": f"{identifier}.stderr",
        "exit_path": f"{identifier}.exit",
        "stdout_digest": runner.sha256_bytes(b"ok"),
        "stderr_digest": runner.sha256_bytes(b""),
        "exit_digest": runner.sha256_bytes(b"0\n"),
        "validation_errors": [],
    }


def complete_entries() -> list[dict]:
    return [
        make_entry(probe, toolchain, seed)
        for toolchain in runner.TOOLCHAINS
        for seed in runner.SEEDS
        for probe in runner.PROBES
    ]


def write_entry_evidence(root: Path, entries: list[dict]) -> None:
    """Materialize the sidecars represented by a synthetic summary."""

    for entry in entries:
        (root / entry["stdout_path"]).write_bytes(b"ok")
        (root / entry["stderr_path"]).write_bytes(b"")
        (root / entry["exit_path"]).write_bytes(b"0\n")


class ExactHeadMatrixTests(unittest.TestCase):
    def test_all_application_contracts_accept_valid_results(self):
        self.assertEqual(runner.validate_inmemory(inmemory_stdout(), SEED), "EXECUTED_PASS")
        self.assertEqual(runner.validate_hostile(hostile_stdout(), SEED), "EXECUTED_PASS")
        self.assertEqual(runner.validate_blocker(blocker_stdout(), SEED), "EXECUTED_PASS")
        self.assertEqual(runner.validate_durable(durable_stdout(), SEED), "EXECUTED_PASS")

    def test_canonical_relative_manifest_is_portable_across_checkout_roots(self):
        """The digest-bound argv must survive source-checkout rematerialization."""

        probe = runner.PROBES[0]
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            first_manifest = first_root / runner.CANONICAL_MANIFEST_RELATIVE
            second_manifest = second_root / runner.CANONICAL_MANIFEST_RELATIVE
            first_manifest.parent.mkdir(parents=True)
            second_manifest.parent.mkdir(parents=True)
            first_manifest.write_text("[package]\nname='lane-a'\nversion='0.0.0'\n", encoding="utf-8")
            second_manifest.write_text("[package]\nname='lane-b'\nversion='0.0.0'\n", encoding="utf-8")

            # Build the command in one checkout, then validate the same argv
            # after the receipt validator is materialized under another root.
            with (
                mock.patch.object(runner, "REPOSITORY_ROOT", first_root),
                mock.patch.object(runner, "EXPECTED_MANIFEST", first_manifest),
            ):
                command = runner.canonical_command(
                    probe,
                    runner.TOOLCHAINS[0],
                    SEED,
                    manifest=first_manifest,
                )
            self.assertEqual(
                command[command.index("--manifest-path") + 1],
                runner.CANONICAL_MANIFEST_RELATIVE,
            )

            with (
                mock.patch.object(runner, "REPOSITORY_ROOT", second_root),
                mock.patch.object(runner, "EXPECTED_MANIFEST", second_manifest),
            ):
                runner.validate_command_tuple(
                    command,
                    probe,
                    runner.TOOLCHAINS[0],
                    SEED,
                    expected_manifest=second_manifest,
                    require_runner_flags=True,
                )

    def test_hostile_application_failure_is_failure_even_with_exit_zero(self):
        probe = next(item for item in runner.PROBES if item.kind == "hostile")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            hostile_stdout("EXECUTED_FAIL"),
            0,
        )
        self.assertEqual(conclusion, "FAIL")
        self.assertEqual(application_status, "EXECUTED_FAIL")
        self.assertTrue(any("EXECUTED_FAIL" in error for error in errors))

    def test_explicit_blocked_application_remains_blocked(self):
        probe = next(item for item in runner.PROBES if item.kind == "hostile")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            hostile_stdout("BLOCKED"),
            2,
        )
        self.assertEqual(conclusion, "BLOCKED")
        self.assertEqual(application_status, "BLOCKED")
        self.assertTrue(errors)

    def test_inmemory_unknown_remains_unknown(self):
        probe = next(item for item in runner.PROBES if item.kind == "inmemory")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            inmemory_stdout("UNKNOWN"),
            3,
        )
        self.assertEqual(conclusion, "UNKNOWN")
        self.assertEqual(application_status, "UNKNOWN")
        self.assertTrue(errors)

    def test_spawn_failure_is_unexecuted(self):
        probe = next(item for item in runner.PROBES if item.kind == "durable")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            "",
            None,
            process_started=False,
            spawn_error="cargo missing",
        )
        self.assertEqual(conclusion, "UNEXECUTED")
        self.assertIsNone(application_status)
        self.assertIn("cargo missing", errors[0])

    def test_timeout_is_blocked_even_with_partial_pass_json(self):
        probe = next(item for item in runner.PROBES if item.kind == "durable")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            durable_stdout(),
            -9,
            timed_out=True,
        )
        self.assertEqual(conclusion, "BLOCKED")
        self.assertEqual(application_status, "EXECUTED_PASS")
        self.assertTrue(any("timeout" in error for error in errors))

    def test_nonzero_exit_cannot_be_hidden_by_pass_json(self):
        probe = next(item for item in runner.PROBES if item.kind == "durable")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            durable_stdout(),
            9,
        )
        self.assertEqual(conclusion, "FAIL")
        self.assertEqual(application_status, "EXECUTED_PASS")
        self.assertIn("process exit code was 9", errors)

    def test_boolean_exit_code_cannot_be_treated_as_zero(self):
        probe = next(item for item in runner.PROBES if item.kind == "durable")
        conclusion, application_status, errors = runner.validate_captured_result(
            probe,
            SEED,
            durable_stdout(),
            False,
        )
        self.assertEqual(conclusion, "FAIL")
        self.assertEqual(application_status, "EXECUTED_PASS")
        self.assertTrue(any("JSON integer" in error for error in errors))

    def test_invalid_jsonl_line_is_rejected(self):
        with self.assertRaises(runner.ValidationError):
            runner.validate_inmemory(inmemory_stdout() + "not-json\n", SEED)

    def test_ambiguous_json_and_unknown_records_are_rejected(self):
        with self.assertRaises(runner.ValidationError):
            runner.validate_inmemory('{"kind":"meta","kind":"case"}\n', SEED)
        with self.assertRaises(runner.ValidationError):
            runner.validate_inmemory(inmemory_stdout() + '{"kind":"future-extension"}\n', SEED)
        with self.assertRaises(runner.ValidationError):
            runner.validate_hostile('{"schema":"x","value":NaN}', SEED)

    def test_summary_preserves_missing_entries_as_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            lock.write_text("version = 4\n", encoding="utf-8")
            summary = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=[],
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
            )
        self.assertEqual(summary["result"], "FAIL")
        self.assertEqual(summary["matrix"]["required_entry_count"], 24)
        self.assertEqual(len(summary["matrix"]["missing_entry_ids"]), 24)
        self.assertEqual(summary["counts"]["unexecuted"], 0)
        self.assertFalse(summary["qualification"])
        self.assertEqual(summary["authority_effect"], "NONE")

    def test_duplicate_entry_id_forces_failure(self):
        entries = complete_entries()
        entries[-1]["entry_id"] = entries[0]["entry_id"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            lock.write_text("version = 4\n", encoding="utf-8")
            summary = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=entries,
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
            )
        self.assertEqual(summary["result"], "FAIL")
        self.assertEqual(summary["matrix"]["duplicate_entry_ids"], [entries[0]["entry_id"]])
        self.assertEqual(len(summary["matrix"]["missing_entry_ids"]), 1)

    def test_entry_tuple_fields_are_bound_to_canonical_matrix(self):
        mutations = (
            ("entry_id", "inmemory-1.88.0-deadbeefdeadbeef"),
            ("kind", "hostile"),
            ("toolchain", "1.98.0"),
            ("seed", runner.SEEDS[1]),
            ("binary", "heptabao-h02-openraft-fault-lab"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                entries = complete_entries()
                entries[0][field] = replacement
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = root / "Cargo.toml"
                    lock = root / "Cargo.lock"
                    manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
                    lock.write_text("version = 4\n", encoding="utf-8")
                    summary = runner.build_summary(
                        repository="TrillionniumFoundation/HeptaBao",
                        ref="codex/test",
                        commit="1" * 40,
                        tree="2" * 40,
                        manifest=manifest,
                        lock=lock,
                        entries=entries,
                        started_at="2026-08-30T00:00:00Z",
                        completed_at="2026-08-30T00:01:00Z",
                    )
                self.assertEqual(summary["result"], "FAIL")
                self.assertTrue(any("tuple invalid" in error for error in summary["runner_errors"]))

    def test_command_digest_and_argv_are_bound_to_canonical_tuple(self):
        for mutate_command in (False, True):
            with self.subTest(mutate_command=mutate_command):
                entries = complete_entries()
                if mutate_command:
                    entries[0]["command"][-1] = runner.SEEDS[1]
                    entries[0]["command_digest"] = runner.canonical_json_digest(entries[0]["command"])
                else:
                    entries[0]["command_digest"] = "sha256:" + "f" * 64
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = root / "Cargo.toml"
                    lock = root / "Cargo.lock"
                    manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
                    lock.write_text("version = 4\n", encoding="utf-8")
                    summary = runner.build_summary(
                        repository="TrillionniumFoundation/HeptaBao",
                        ref="codex/test",
                        commit="1" * 40,
                        tree="2" * 40,
                        manifest=manifest,
                        lock=lock,
                        entries=entries,
                        started_at="2026-08-30T00:00:00Z",
                        completed_at="2026-08-30T00:01:00Z",
                    )
                self.assertEqual(summary["result"], "FAIL")
                self.assertTrue(any("tuple invalid" in error for error in summary["runner_errors"]))

    def test_canonical_manifest_argument_is_portable_and_traversal_free(self):
        probe = runner.PROBES[0]
        command = runner.canonical_command(
            probe,
            runner.TOOLCHAINS[0],
            runner.SEEDS[0],
            manifest=runner.EXPECTED_MANIFEST,
        )
        self.assertEqual(
            command[command.index("--manifest-path") + 1],
            runner.CANONICAL_MANIFEST_RELATIVE,
        )
        self.assertTrue(
            runner._manifest_argument_is_canonical(
                runner.CANONICAL_MANIFEST_RELATIVE,
                runner.EXPECTED_MANIFEST,
            )
        )
        self.assertFalse(
            runner._manifest_argument_is_canonical(
                "../probes/h02/openraft-tokio/Cargo.toml",
                runner.EXPECTED_MANIFEST,
            )
        )

    def test_complete_pass_summary_matches_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            lock.write_text("version = 4\n", encoding="utf-8")
            summary = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=complete_entries(),
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
            )
        schema = json.loads(
            (ROOT / "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        errors = list(Draft202012Validator(schema).iter_errors(summary))
        self.assertEqual(errors, [])
        self.assertEqual(summary["result"], "PASS")
        self.assertEqual(summary["counts"]["pass"], 24)
        self.assertEqual(summary["runner_errors"], [])

    def test_production_summary_requires_and_recomputes_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            lock.write_text("version = 4\n", encoding="utf-8")
            entries = complete_entries()
            # No evidence root must never yield a production PASS.
            missing = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=entries,
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
                require_artifacts=True,
            )
            self.assertEqual(missing["result"], "FAIL")
            self.assertTrue(any("evidence" in error for error in missing["runner_errors"]))

            write_entry_evidence(root, entries)
            valid = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=entries,
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
                evidence_dir=root,
                require_artifacts=True,
            )
            self.assertEqual(valid["result"], "PASS")
            (root / entries[0]["stdout_path"]).write_bytes(b"tampered")
            tampered = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=entries,
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
                evidence_dir=root,
                require_artifacts=True,
            )
            self.assertEqual(tampered["result"], "FAIL")
            self.assertTrue(any("digest" in error for error in tampered["runner_errors"]))

    def test_artifact_path_traversal_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            lock.write_text("version = 4\n", encoding="utf-8")
            entries = complete_entries()
            write_entry_evidence(root, entries)
            entries[0]["stdout_path"] = "../escape.stdout"
            summary = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=entries,
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
                evidence_dir=root,
                require_artifacts=True,
            )
            self.assertEqual(summary["result"], "FAIL")
            self.assertTrue(any("path" in error for error in summary["runner_errors"]))

    def test_runner_error_forces_schema_valid_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "Cargo.toml"
            lock = root / "Cargo.lock"
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            lock.write_text("version = 4\n", encoding="utf-8")
            summary = runner.build_summary(
                repository="TrillionniumFoundation/HeptaBao",
                ref="codex/test",
                commit="1" * 40,
                tree="2" * 40,
                manifest=manifest,
                lock=lock,
                entries=complete_entries(),
                started_at="2026-08-30T00:00:00Z",
                completed_at="2026-08-30T00:01:00Z",
                runner_errors=["repository became dirty"],
                clean_tree=False,
            )
        schema = json.loads(
            (ROOT / "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(summary)), [])
        self.assertEqual(summary["result"], "FAIL")
        self.assertFalse(summary["source_binding"]["clean_tree"])

    def test_source_binding_rejects_historical_repository_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "probes/h02/openraft-tokio/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            manifest.with_name("Cargo.lock").write_text("version=4\n", encoding="utf-8")
            outside = root.parent / "outside-evidence"
            with (
                mock.patch.object(runner, "REPOSITORY_ROOT", root),
                mock.patch.object(runner, "EXPECTED_MANIFEST", manifest),
                self.assertRaises(runner.ValidationError),
            ):
                runner.verify_source_binding(
                    repository="ProfHepta/HeptaBao",
                    commit="a" * 40,
                    tree="b" * 40,
                    manifest=manifest,
                    output_dir=outside,
                    target_root=outside / "target",
                )

    def test_source_binding_rejects_declared_head_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "probes/h02/openraft-tokio/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            manifest.with_name("Cargo.lock").write_text("version=4\n", encoding="utf-8")
            outside = root.parent / "outside-evidence"
            values = iter([str(root), "a" * 40])
            with (
                mock.patch.object(runner, "REPOSITORY_ROOT", root),
                mock.patch.object(runner, "EXPECTED_MANIFEST", manifest),
                mock.patch.object(runner, "git_text", side_effect=lambda *args: next(values)),
                self.assertRaises(runner.ValidationError),
            ):
                runner.verify_source_binding(
                    repository="TrillionniumFoundation/HeptaBao",
                    commit="b" * 40,
                    tree="c" * 40,
                    manifest=manifest,
                    output_dir=outside,
                    target_root=outside / "target",
                )

    def test_output_inside_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "probes/h02/openraft-tokio/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("[package]\nname='x'\nversion='0.0.0'\n", encoding="utf-8")
            manifest.with_name("Cargo.lock").write_text("version=4\n", encoding="utf-8")
            responses = {
                ("rev-parse", "--show-toplevel"): str(root),
                ("rev-parse", "HEAD"): "a" * 40,
                ("rev-parse", "HEAD^{tree}"): "b" * 40,
                ("status", "--porcelain=v1", "--untracked-files=all"): "",
            }
            with (
                mock.patch.object(runner, "REPOSITORY_ROOT", root),
                mock.patch.object(runner, "EXPECTED_MANIFEST", manifest),
                mock.patch.object(runner, "git_text", side_effect=lambda *args: responses[args]),
                self.assertRaises(runner.ValidationError),
            ):
                runner.verify_source_binding(
                    repository="TrillionniumFoundation/HeptaBao",
                    commit="a" * 40,
                    tree="b" * 40,
                    manifest=manifest,
                    output_dir=root / "evidence",
                    target_root=root.parent / "target",
                )

    def test_expected_entry_ids_are_unique_and_complete(self):
        identifiers = runner.expected_entry_ids()
        self.assertEqual(len(identifiers), 24)
        self.assertEqual(
            identifiers,
            {
                runner.entry_id(probe, toolchain, seed)
                for toolchain in runner.TOOLCHAINS
                for seed in runner.SEEDS
                for probe in runner.PROBES
            },
        )


if __name__ == "__main__":
    unittest.main()
