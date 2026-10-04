from __future__ import annotations

import copy
import hashlib
import fnmatch
import importlib.util
import importlib._bootstrap_external
import json
import shutil
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch, Mock

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = load("_historical_inmemory_tests", ROOT / "tests/platform/test_h02_openraft_inmemory_cluster_v1.py")
current = load("_current_inmemory_tests", ROOT / "scripts/h02_openraft_inmemory_cluster_evidence_v2.py")
guard = load("_current_inmemory_guard", ROOT / "scripts/validate_h02_openraft_inmemory_cluster_v2.py")
SCHEMA = json.loads(guard.SCHEMA.read_text())
COMMIT, TREE = "1" * 40, "2" * 40
RUN_ID, RUN_ATTEMPT, RUNNER = "123456", "1", "synthetic-runner"
EXECUTION_ROOT = Path("/synthetic-run-root")


def write_entry(root, toolchain, seed, *, exit_code=0):
    root.mkdir(parents=True, exist_ok=True)
    raw = legacy.output(seed)
    for filename in ("cluster-output.jsonl", "cluster-replay.jsonl"):
        (root / filename).write_text(raw)
    shutil.copyfile(ROOT / "probes/h02/openraft-tokio/Cargo.toml", root / "Cargo.toml")
    (root / "Cargo.lock").write_text("version = 4\n")
    (root / "execution-exit-code.txt").write_text(f"{exit_code}\n")
    (root / "rustc-version.txt").write_text(f"rustc {toolchain} (synthetic-test-only)\nrelease: {toolchain}\n")
    context = current.new_context(toolchain, seed, str(EXECUTION_ROOT / toolchain / "Cargo.toml"), RUN_ID, RUN_ATTEMPT, RUNNER)
    context["return_codes"] = {stage: (0 if exit_code == 0 else exit_code if stage == "rustc" else None) for stage in current.STAGES}
    (root / "execution-context.json").write_text(json.dumps(context, sort_keys=True))
    args = Namespace(
        adapter_output=str(root / "cluster-output.jsonl"), replay_output=str(root / "cluster-replay.jsonl"),
        manifest=str(root / "Cargo.toml"), cargo_lock=str(root / "Cargo.lock"), rustc_version=str(root / "rustc-version.txt"), execution_context=str(root / "execution-context.json"),
        execution_exit_code=exit_code, toolchain=toolchain, seed=seed, source_commit=COMMIT, source_tree=TREE,
        branch="test-synthetic-only", clean_tree=True, environment_id=current.environment_id(RUN_ID, RUN_ATTEMPT, RUNNER, toolchain, seed),
        executor_kind="github-hosted", runner_id=current.RUNNER_ID, runner_name=RUNNER,
    )
    value = current.collect(args)
    (root / "cluster-evidence.json").write_text(json.dumps(value))
    return args, value


class CurrentEvidenceTests(legacy.EvidenceTests):
    """Run every unchanged V1 semantic assertion against freshly emitted V2 data."""
    def collect(self, first, second=None, exit_code=0, toolchain="1.99.0"):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        args, _ = write_entry(root, toolchain, current.SEEDS[0], exit_code=exit_code)
        Path(args.adapter_output).write_text(first)
        Path(args.replay_output).write_text(first if second is None else second)
        return td, current.collect(args)

    def assert_schema(self, value):
        self.assertEqual([], [e.message for e in Draft202012Validator(SCHEMA).iter_errors(value)])

    def assert_current_mutation_rejected(self, mutate):
        td, value = self.collect(legacy.output(current.SEEDS[0]))
        self.addCleanup(td.cleanup)
        self.assert_schema(value)
        mutate(value)
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(value)))

    def test_false_pass_with_unknown_is_rejected_by_schema(self):
        self.assert_current_mutation_rejected(lambda v: v["summary"].update(unknown=1))

    def test_false_authority_is_rejected_by_schema(self):
        self.assert_current_mutation_rejected(lambda v: v.update(authority_effect="PRODUCTION"))

    def test_snapshot_pass_requires_full_snapshot_rpc(self):
        self.assert_current_mutation_rejected(lambda v: v["scope"].update(real_full_snapshot_rpc=False))

    def test_effective_floor_is_188_and_185_is_only_a_boundary_probe(self):
        td, value = self.collect(legacy.output(current.SEEDS[0]), toolchain="1.88.0")
        self.addCleanup(td.cleanup)
        self.assert_schema(value)
        value["environment"]["rust_toolchain"] = "1.85.0"
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(value)))

    def test_v1_engine_import_has_no_mutation_or_artifact_leak(self):
        before = hashlib.sha256(current.ENGINE.read_bytes()).hexdigest()
        td, old = legacy.EvidenceTests.collect(self, legacy.output(current.SEEDS[0]))
        self.addCleanup(td.cleanup)
        self.assertEqual("1.98.0", old["environment"]["rust_toolchain"])
        self.assertEqual("heptabao.h02-openraft-cluster-evidence.v1", old["schema"])
        self.assertEqual(("1.88.0", "1.98.0"), legacy.mod.EFFECTIVE_TOOLCHAINS)
        self.assertIsNot(legacy.mod, current.engine)
        self.assertIsNot(legacy.mod.parse_jsonl, current.engine.parse_jsonl)
        self.assertFalse(list(Draft202012Validator(legacy.SCHEMA).iter_errors(old)))
        self.assertEqual(before, hashlib.sha256(current.ENGINE.read_bytes()).hexdigest())
        self.assertEqual(current.ENGINE_SHA256, before)

    def test_v1_receipt_is_not_an_upgrade_input(self):
        td, old = legacy.EvidenceTests.collect(self, legacy.output(current.SEEDS[0]))
        self.addCleanup(td.cleanup)
        td2, result = self.collect(json.dumps(old) + "\n")
        self.addCleanup(td2.cleanup)
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual(6, result["summary"]["blocked"])

    def test_stale_requested_current_compiler_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "toolchain"):
                write_entry(Path(temp), "1.98.0", current.SEEDS[0])

    def test_stale_observed_compiler_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _ = write_entry(Path(temp), "1.99.0", current.SEEDS[0])
            Path(args.rustc_version).write_text("rustc 1.98.0 (synthetic)\nrelease: 1.98.0\n")
            with self.assertRaisesRegex(ValueError, "observed rustc"):
                current.collect(args)

    def test_missing_compiler_observation_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            args, _ = write_entry(Path(temp), "1.99.0", current.SEEDS[0])
            Path(args.rustc_version).unlink()
            value = current.collect(args)
            self.assert_schema(value)
            self.assertEqual("BLOCKED", value["status"])

    def test_duplicate_or_nonobject_raw_records_block(self):
        raw = legacy.output(current.SEEDS[0])
        for tail in (raw.splitlines()[1], "[]", "null", "not json"):
            with self.subTest(tail=tail[:25]):
                td, value = self.collect(raw + tail + "\n")
                self.addCleanup(td.cleanup)
                self.assertEqual("BLOCKED", value["status"])

    def test_v1_and_v2_receipt_schemas_are_not_interchangeable(self):
        td, value = self.collect(legacy.output(current.SEEDS[0]))
        self.addCleanup(td.cleanup)
        self.assert_schema(value)
        self.assertTrue(list(Draft202012Validator(legacy.SCHEMA).iter_errors(value)))
        value["environment"]["rust_toolchain"] = "1.98.0"
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(value)))

    def test_modified_historical_engine_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            scripts = Path(temp) / "scripts"
            scripts.mkdir()
            wrapper = scripts / "h02_openraft_inmemory_cluster_evidence_v2.py"
            shutil.copyfile(ROOT / "scripts" / wrapper.name, wrapper)
            (scripts / current.ENGINE.name).write_bytes(current.ENGINE.read_bytes() + b"\n# drift\n")
            with self.assertRaisesRegex(RuntimeError, "engine bytes changed"):
                load("_altered_engine_guard", wrapper)


class ExactByteLoaderTests(unittest.TestCase):
    def exercise(self, target, mode):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            scripts = root / "scripts"
            scripts.mkdir()
            engine_name = "h02_openraft_inmemory_cluster_evidence_v1.py"
            validator_name = "validate_h02_openraft_inmemory_cluster_v1.py"
            filename = engine_name if target == "engine" else validator_name
            helper = scripts / filename
            original = (ROOT / "scripts" / filename).read_bytes()
            helper.write_bytes(original)
            expected = hashlib.sha256(original).hexdigest()
            if target == "engine":
                wrapper = scripts / "h02_openraft_inmemory_cluster_evidence_v2.py"
                shutil.copyfile(ROOT / "scripts" / wrapper.name, wrapper)

            if mode == "foreign-pyc":
                # A valid timestamp/size header makes this foreign code acceptable
                # to a conventional source loader even though source hashes match.
                cached = Path(importlib.util.cache_from_source(str(helper)))
                cached.parent.mkdir()
                stat = helper.stat()
                foreign = compile("raise RuntimeError('foreign bytecode executed')", str(helper), "exec")
                cached.write_bytes(importlib._bootstrap_external._code_to_timestamp_pyc(
                    foreign, int(stat.st_mtime), stat.st_size
                ))

            read_bytes = Path.read_bytes
            captures = []
            def capture_then_replace(path):
                value = read_bytes(path)
                if path == helper:
                    captures.append(value)
                    if mode == "path-replacement":
                        path.write_bytes(b"raise RuntimeError('replacement path executed')\n")
                return value

            with patch.object(Path, "read_bytes", capture_then_replace):
                if target == "engine":
                    value = load("_exact_byte_engine_wrapper", wrapper)
                    self.assertEqual(6, len(value.engine.CASES))
                else:
                    with patch.object(guard, "ROOT", root):
                        value = guard.load_module("_exact_byte_validator", filename, expected)
                    self.assertEqual(6, len(value.REQUIRED_CASES))
            self.assertEqual([original], captures, "verified helper must be read exactly once")

    def test_engine_ignores_valid_header_foreign_pyc(self):
        self.exercise("engine", "foreign-pyc")

    def test_validator_ignores_valid_header_foreign_pyc(self):
        self.exercise("validator", "foreign-pyc")

    def test_engine_executes_captured_bytes_after_path_replacement(self):
        self.exercise("engine", "path-replacement")

    def test_validator_executes_captured_bytes_after_path_replacement(self):
        self.exercise("validator", "path-replacement")


class CurrentMatrixTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        for toolchain in current.EFFECTIVE_TOOLCHAINS:
            for seed in current.SEEDS:
                write_entry(self.root / f"{toolchain}-{seed[2:]}", toolchain, seed)
        self.entry = self.root / f"1.99.0-{current.SEEDS[0][2:]}"

    def validate(self, require_pass=True):
        guard.validate_evidence_directory(self.root, COMMIT, TREE, run_id=RUN_ID, run_attempt=RUN_ATTEMPT, runner_name=RUNNER, execution_root=EXECUTION_ROOT, require_pass=require_pass)

    def change_evidence(self, edit):
        path = self.entry / "cluster-evidence.json"
        value = json.loads(path.read_text())
        edit(value)
        path.write_text(json.dumps(value))

    def test_complete_exact_six_entries_pass(self):
        self.validate()

    def test_missing_entry_rejected(self):
        shutil.rmtree(self.entry)
        with self.assertRaisesRegex(guard.Failure, "missing, extra"):
            self.validate()

    def test_six_entries_with_stale_compiler_not_counted_as_current(self):
        self.entry.rename(self.root / self.entry.name.replace("1.99.0", "1.98.0"))
        with self.assertRaisesRegex(guard.Failure, "stale compiler"):
            self.validate()

    def test_wrong_raw_replay_lock_compiler_or_manifest_digest_rejected(self):
        for filename in ("cluster-output.jsonl", "cluster-replay.jsonl", "Cargo.lock", "rustc-version.txt", "Cargo.toml"):
            with self.subTest(filename=filename):
                path = self.entry / filename
                before = path.read_bytes()
                path.write_bytes(before + b"\n")
                try:
                    with self.assertRaisesRegex(guard.Failure, "digest|manifest"):
                        self.validate()
                finally:
                    path.write_bytes(before)

    def test_wrong_evidence_detail_digest_rejected(self):
        self.change_evidence(lambda v: v["cases"][0].update(details_sha256="0" * 64))
        with self.assertRaisesRegex(guard.Failure, "digest"):
            self.validate()

    def test_missing_case_cannot_be_hidden_by_pass_counts(self):
        self.change_evidence(lambda v: v["cases"].__setitem__(0, copy.deepcopy(v["cases"][1])))
        with self.assertRaisesRegex(guard.Failure, "semantic mismatch"):
            self.validate()

    def test_wrong_source_commit_or_tree_rejected(self):
        for field in ("commit_sha", "tree_sha"):
            with self.subTest(field=field):
                original = COMMIT if field == "commit_sha" else TREE
                self.change_evidence(lambda v: v["source"].update({field: "3" * 40}))
                with self.assertRaisesRegex(guard.Failure, "stale source"):
                    self.validate()
                self.change_evidence(lambda v: v["source"].update({field: original}))

    def rebind_context(self, edit, entry=None):
        entry = entry or self.entry
        path = entry / "execution-context.json"
        value = json.loads(path.read_text())
        edit(value)
        path.write_text(json.dumps(value, sort_keys=True))
        evidence_path = entry / "cluster-evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["execution"].update(context=value, context_sha256=current.sha256_file(path))
        evidence["environment"].update(
            runner_name=value["runner_name"],
            environment_id=current.environment_id(value["run_id"], value["run_attempt"], value["runner_name"], value["toolchain"], value["seed"]),
        )
        evidence_path.write_text(json.dumps(evidence))

    def test_other_run_labels_rebound_consistently_still_rejected(self):
        for entry in self.root.iterdir():
            self.rebind_context(lambda v: v.update(run_id="999999"), entry)
        with self.assertRaisesRegex(ValueError, "run/attempt/runner"):
            self.validate()

    def test_mixed_attempt_with_matching_context_digests_rejected(self):
        self.rebind_context(lambda v: v.update(run_attempt="2"))
        with self.assertRaisesRegex(ValueError, "run/attempt/runner"):
            self.validate()

    def test_wrong_runner_with_matching_context_digests_rejected(self):
        self.rebind_context(lambda v: v.update(runner_name="OTHER-RUNNER"))
        with self.assertRaisesRegex(ValueError, "run/attempt/runner"):
            self.validate()

    def test_changed_command_even_with_recomputed_digest_rejected(self):
        def edit(value):
            value["argv"]["probe"].append("--different-command")
            value["argv_sha256"] = current.engine.sha256_bytes(current.engine.canonical(value["argv"]))
        self.rebind_context(edit)
        with self.assertRaisesRegex(ValueError, "canonical command"):
            self.validate()

    def test_changed_manifest_target_and_canonical_argv_rejected(self):
        def edit(value):
            value["manifest"] = "/other-run/Cargo.toml"
            value["argv"] = current.command_profile(value["toolchain"], value["seed"], value["manifest"])
            value["argv_sha256"] = current.engine.sha256_bytes(current.engine.canonical(value["argv"]))
        self.rebind_context(edit)
        with self.assertRaisesRegex(ValueError, "canonical command"):
            self.validate()

    def test_missing_stage_cannot_support_pass(self):
        self.rebind_context(lambda v: v["return_codes"].update(test=None))
        with self.assertRaisesRegex(ValueError, "prerequisite"):
            self.validate()

    def test_context_digest_mutation_rejected(self):
        self.change_evidence(lambda v: v["execution"].update(context_sha256="0" * 64))
        with self.assertRaisesRegex(guard.Failure, "digest"):
            self.validate()

    def test_wrong_seed_rejected(self):
        self.change_evidence(lambda v: v["seed"].update(hex=current.SEEDS[1], decimal=int(current.SEEDS[1], 16)))
        with self.assertRaisesRegex(guard.Failure, "seed does not match"):
            self.validate()

    def test_authority_promotion_rejected(self):
        self.change_evidence(lambda v: v.update(authority_effect="PRODUCTION"))
        with self.assertRaisesRegex(guard.Failure, "invalid V2 evidence"):
            self.validate()

    def test_blocked_results_preserved_but_final_gate_fails(self):
        write_entry(self.entry, "1.99.0", current.SEEDS[0], exit_code=101)
        self.validate(require_pass=False)
        with self.assertRaisesRegex(guard.Failure, "did not execute and pass"):
            self.validate()

    def test_empty_lock_cannot_support_executed_pass(self):
        args, _ = write_entry(self.entry, "1.99.0", current.SEEDS[0])
        Path(args.cargo_lock).write_bytes(b"")
        (self.entry / "cluster-evidence.json").write_text(json.dumps(current.collect(args)))
        with self.assertRaisesRegex(guard.Failure, "empty execution lock"):
            self.validate()


class CommandRecorderTests(unittest.TestCase):
    def test_context_cli_copies_only_shared_build_and_rebinds_seed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = str(EXECUTION_ROOT / "1.99.0/Cargo.toml")
            build = current.new_context("1.99.0", current.SEEDS[0], manifest, RUN_ID, RUN_ATTEMPT, RUNNER)
            build["return_codes"].update({stage: 0 for stage in current.COMMON_STAGES})
            source, output = root / "build.json", root / "entry.json"
            source.write_text(json.dumps(build))
            argv = ["collector", "context", "--toolchain", "1.99.0", "--seed", current.SEEDS[1],
                    "--manifest", manifest, "--run-id", RUN_ID, "--run-attempt", RUN_ATTEMPT,
                    "--runner-name", RUNNER, "--build-context", str(source), "--output", str(output)]
            with patch("sys.argv", argv):
                self.assertEqual(0, current.main())
            value = json.loads(output.read_text())
            current.validate_context(value, "1.99.0", current.SEEDS[1], manifest, RUN_ID, RUN_ATTEMPT, RUNNER)
            self.assertEqual(current.SEEDS[1], value["argv"]["probe"][-1])
            self.assertIsNone(value["return_codes"]["probe"])
            self.assertIsNone(value["return_codes"]["replay"])
            build["run_attempt"] = "2"
            source.write_text(json.dumps(build))
            with patch("sys.argv", argv), self.assertRaisesRegex(ValueError, "run/attempt"):
                current.main()

    def test_validation_cli_requires_independent_run_expectations(self):
        with patch("sys.argv", ["validator", "--evidence-root", "/unused", "--source-commit", COMMIT, "--source-tree", TREE, "--require-pass"]):
            with self.assertRaises(SystemExit) as error:
                guard.main()
        self.assertEqual(2, error.exception.code)

    def test_recorder_executes_exact_recorded_argv_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            context = current.new_context("1.99.0", current.SEEDS[0], str(EXECUTION_ROOT / "1.99.0/Cargo.toml"), RUN_ID, RUN_ATTEMPT, RUNNER)
            path = root / "context.json"
            path.write_text(json.dumps(context))
            with patch.object(current.subprocess, "run", return_value=Mock(returncode=0)) as run:
                self.assertEqual(0, current.execute_stage(path, "rustc", root / "stdout", root / "stderr"))
                self.assertEqual(context["argv"]["rustc"], run.call_args.args[0])
                self.assertFalse(run.call_args.kwargs["check"])
                with self.assertRaisesRegex(ValueError, "already recorded"):
                    current.execute_stage(path, "rustc", root / "stdout", root / "stderr")
                run.assert_called_once()
            self.assertEqual(0, json.loads(path.read_text())["return_codes"]["rustc"])

    def test_recorder_rejects_changed_argv_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            context = current.new_context("1.99.0", current.SEEDS[0], str(EXECUTION_ROOT / "1.99.0/Cargo.toml"), RUN_ID, RUN_ATTEMPT, RUNNER)
            context["argv"]["rustc"].append("--other")
            context["argv_sha256"] = current.engine.sha256_bytes(current.engine.canonical(context["argv"]))
            path = root / "context.json"
            path.write_text(json.dumps(context))
            with patch.object(current.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "canonical command"):
                    current.execute_stage(path, "rustc", root / "stdout", root / "stderr")
                run.assert_not_called()

    def test_recorder_failure_is_retained_and_blocks_later_stages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            context = current.new_context("1.99.0", current.SEEDS[0], str(EXECUTION_ROOT / "1.99.0/Cargo.toml"), RUN_ID, RUN_ATTEMPT, RUNNER)
            path = root / "context.json"
            path.write_text(json.dumps(context))
            with patch.object(current.subprocess, "run", return_value=Mock(returncode=101)) as run:
                self.assertEqual(101, current.execute_stage(path, "rustc", root / "stdout", root / "stderr"))
                with self.assertRaisesRegex(ValueError, "prerequisite"):
                    current.execute_stage(path, "lock", root / "stdout", root / "stderr")
                run.assert_called_once()
            self.assertEqual(101, current.context_status(json.loads(path.read_text())))


class ScopedTriggerTests(unittest.TestCase):
    def setUp(self):
        self.parser = guard.load_module("_trigger_test_parser", "validate_workflow_trust_v1.py")
        self.workflow = self.parser.parse_workflow(guard.WORKFLOW.read_text())

    def test_exact_manual_and_scoped_pr_triggers_pass(self):
        guard.validate_workflow_triggers(self.workflow)
        self.assertEqual(list(guard.TRIGGER_PATHS), self.workflow["on"]["pull_request"]["paths"])

    def test_missing_required_path_rejected(self):
        for path in guard.TRIGGER_PATHS:
            with self.subTest(path=path):
                value = copy.deepcopy(self.workflow)
                value["on"]["pull_request"]["paths"].remove(path)
                with self.assertRaisesRegex(guard.Failure, "path scope"):
                    guard.validate_workflow_triggers(value)

    def test_broad_or_negated_path_rejected(self):
        for path in ("**", "probes/**", "scripts/**", "tests/**", "!docs/**"):
            with self.subTest(path=path):
                value = copy.deepcopy(self.workflow)
                value["on"]["pull_request"]["paths"].append(path)
                with self.assertRaisesRegex(guard.Failure, "path scope"):
                    guard.validate_workflow_triggers(value)

    def test_unrelated_path_rejected(self):
        for path in ("docs/**", "docs/CURRENT_DOCUMENTATION.md", "Cargo.toml", "crates/heptabao-p0-server/**"):
            with self.subTest(path=path):
                value = copy.deepcopy(self.workflow)
                value["on"]["pull_request"]["paths"].append(path)
                with self.assertRaisesRegex(guard.Failure, "path scope"):
                    guard.validate_workflow_triggers(value)

    def test_push_schedule_and_other_event_expansion_rejected(self):
        for event in ("push", "schedule", "pull_request_target", "workflow_run"):
            with self.subTest(event=event):
                value = copy.deepcopy(self.workflow)
                value["on"][event] = None
                with self.assertRaisesRegex(guard.Failure, "only manual"):
                    guard.validate_workflow_triggers(value)

    def test_missing_manual_or_pr_trigger_rejected(self):
        for event in ("workflow_dispatch", "pull_request"):
            value = copy.deepcopy(self.workflow)
            del value["on"][event]
            with self.assertRaisesRegex(guard.Failure, "only manual"):
                guard.validate_workflow_triggers(value)

    def test_unfiltered_pr_or_extra_trigger_options_rejected(self):
        for options in (None, {}, {"paths-ignore": ["docs/**"]},
                        {"paths": list(guard.TRIGGER_PATHS), "types": ["edited"]}):
            value = copy.deepcopy(self.workflow)
            value["on"]["pull_request"] = options
            with self.assertRaisesRegex(guard.Failure, "path scope"):
                guard.validate_workflow_triggers(value)
        self.workflow["on"]["workflow_dispatch"] = {"inputs": {"command": {"type": "string"}}}
        with self.assertRaisesRegex(guard.Failure, "manual trigger"):
            guard.validate_workflow_triggers(self.workflow)

    def test_duplicate_on_cannot_hide_unfiltered_pr(self):
        text = guard.WORKFLOW.read_text() + "\non: {pull_request: null}\n"
        with self.assertRaises(self.parser.PolicyError):
            self.parser.parse_workflow(text)

    def test_native_and_shared_inputs_match_without_unrelated_sources(self):
        # Cargo --all-targets compiles the sibling binaries, including their
        # dynamically discovered targets; no Rust include escapes this package.
        required = (
            "probes/h02/openraft-tokio/src/bin/inmemory_cluster.rs",
            "probes/h02/openraft-tokio/src/bin/openraft_fault_lab/cluster.rs",
            "probes/h02/openraft-tokio/src/bin/blocker_closure_lab.rs",
            "probes/h02/openraft-tokio/src/bin/durable_store_lab/store.rs",
            "probes/h02/openraft-tokio/tests/new_integration.rs",
            "probes/h02/openraft-tokio/examples/new_example.rs",
            "probes/h02/openraft-tokio/benches/new_bench.rs",
            "probes/h02/openraft-tokio/build.rs",
            "requirements-plan.txt", ".cargo/config.toml",
            "scripts/validate_workflow_trust_v1.py",
            "scripts/validate_acceptance_immutability.py",
        )
        for path in required:
            self.assertTrue(any(fnmatch.fnmatchcase(path, pattern) for pattern in guard.TRIGGER_PATHS), path)
        for path in ("docs/CURRENT_DOCUMENTATION.md", "probes/h02/other/Cargo.toml", "crates/heptabao-p0-server/src/lib.rs"):
            self.assertFalse(any(fnmatch.fnmatchcase(path, pattern) for pattern in guard.TRIGGER_PATHS), path)


class CurrentProfileTests(unittest.TestCase):
    def test_current_source_contract(self):
        guard.validate_source_contract()

    def test_stale_current_workflow_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "workflow.yml"
            p.write_text(guard.WORKFLOW.read_text().replace("1.88.0 1.99.0", "1.88.0 1.98.0"))
            with patch.object(guard, "WORKFLOW", p):
                with self.assertRaisesRegex(guard.Failure, "current compiler"):
                    guard.validate_source_contract()

    def test_probe_binary_and_replays_are_unchanged(self):
        text = guard.WORKFLOW.read_text()
        argv = current.command_profile("1.99.0", current.SEEDS[0], str(EXECUTION_ROOT / "1.99.0/Cargo.toml"))
        self.assertEqual(argv["probe"], argv["replay"])
        self.assertEqual(["--bin", "heptabao-h02-openraft-inmemory-cluster", "--", "--seed", current.SEEDS[0]], argv["probe"][-5:])
        self.assertIn("--stage probe", text)
        self.assertIn("--stage replay", text)
        self.assertIn("--rustc-version", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("pull_request:", text)

    def test_exact_upload_allowlist_and_hostile_path(self):
        policy = load("_inmemory_workflow_policy", ROOT / "scripts/validate_workflow_trust.py")
        text = guard.WORKFLOW.read_text()
        policy.validate_text(text, guard.WORKFLOW.name)
        with self.assertRaises(policy.PolicyError):
            policy.validate_text(text.replace("path: evidence/h02-openraft-inmemory-v2/", "path: evidence/"), guard.WORKFLOW.name)
        with self.assertRaises(policy.PolicyError):
            policy.validate_text(text, "unreviewed-inmemory-lane.yml")


if __name__ == "__main__":
    unittest.main()
