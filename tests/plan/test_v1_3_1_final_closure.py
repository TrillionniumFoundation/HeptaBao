from __future__ import annotations

import importlib.util
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "validate_v1_3_1_final_closure_v1.py"
SPEC = importlib.util.spec_from_file_location("validate_v1_3_1_final_closure_v1", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SURFACE = [
    "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
    "planning/HEPTABAO_V1_3_1_GAP_CLOSURE_STATUS.yaml",
    "planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml",
    "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml",
    "schemas/heptabao_normative_document_manifest_v1_3_1.schema.json",
    "docs/plan/HEPTABAO_PLAN_V1_3_1_REPOSITORY_GAP_CLOSURE.md",
    "docs/execution/HEPTABAO_V1_3_1_FINAL_CLOSURE_PROTOCOL.md",
    "scripts/classify_p0_transport_evidence_v1.py",
    "scripts/p0_transport_exact_v1.py",
    "scripts/validate_p0_transport_evidence_v2.py",
    "scripts/h02_exact_head_matrix_v1.py",
    "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json",
    "tests/platform/test_h02_exact_head_matrix_v1.py",
    "scripts/validate_plan_v1_3_1.py",
    "scripts/validate_v1_3_1_final_closure_v1.py",
    "tests/plan/test_v1_3_1_final_closure.py",
    "tests/plan/test_p0_transport_evidence_classification_v2.py",
    "schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json",
    "scripts/validate_v1_3_1_technical_completion_receipt_v1.py",
    "tests/plan/test_v1_3_1_technical_completion_receipt.py",
    "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json",
    "scripts/arbitrate_v1_3_1_lanes_v1.py",
    "tests/plan/test_v1_3_1_lane_arbitration.py",
    "scripts/render_canonical_project_state_v1.py",
    "probes/h02/openraft-tokio/src/bin/durable_store_lab.rs",
    ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml",
]


def copy_surface(target: Path) -> None:
    for relative in SURFACE:
        source = ROOT / relative
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def replace(target: Path, relative: str, old: str, new: str) -> None:
    path = target / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"missing mutation marker {old!r} in {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


class V131FinalClosureTests(unittest.TestCase):
    def test_checked_in_final_closure_contract_passes(self) -> None:
        MODULE.validate(ROOT)

    def test_current_pointers_override_historical_manifest_without_rewriting_it(self) -> None:
        manifest = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            manifest["current_plan"],
            "docs/plan/HEPTABAO_PLAN_V1_3_1_REPOSITORY_GAP_CLOSURE.md",
        )
        self.assertEqual(
            manifest["current_state"],
            "planning/HEPTABAO_V1_3_1_GAP_CLOSURE_STATUS.yaml",
        )
        self.assertEqual(
            manifest["current_state_input"],
            "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
        )
        historical = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            historical["current_plan"],
            "docs/plan/HEPTABAO_MASTER_DEVELOPMENT_PLAN_V1_2.md",
        )
        self.assertEqual(
            historical["current_state_input"],
            "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml",
        )

    def test_active_manifest_document_contract_and_legacy_workflow_classification(self) -> None:
        manifest = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml").read_text(
                encoding="utf-8"
            )
        )
        MODULE.validate_active_manifest_schema(ROOT, manifest)
        legacy = [
            entry
            for entry in manifest["documents"]
            if entry["path"] == ".github/workflows/plan-v1.3-gap-closure.yml"
        ]
        self.assertEqual(len(legacy), 1)
        self.assertEqual(legacy[0]["kind"], "HISTORICAL")
        self.assertEqual(legacy[0]["authority_effect"], "NONE")

        missing_field = copy.deepcopy(manifest)
        del missing_field["documents"][0]["owner_role"]
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_active_manifest_schema(ROOT, missing_field)

        forged_legacy = copy.deepcopy(manifest)
        forged_legacy["documents"][-1]["authority_effect"] = "GRANT"
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_active_manifest_schema(ROOT, forged_legacy)

    def test_final_closure_path_reads_reject_traversal_and_symlink_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.read_text(target, "../outside.txt")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.read_text(target, "scripts/bad\x00name.py")

            scripts = target / "scripts"
            moved = target / "scripts-real"
            scripts.rename(moved)
            try:
                scripts.symlink_to(moved, target_is_directory=True)
            except OSError as error:
                moved.rename(scripts)
                self.skipTest(f"symlink support unavailable: {error}")
            try:
                with self.assertRaises(MODULE.FinalClosureValidationError):
                    MODULE.read_text(target, "scripts/validate_v1_3_1_final_closure_v1.py")
            finally:
                scripts.unlink()
                moved.rename(scripts)

            root_alias = target.parent / f"{target.name}-alias"
            try:
                root_alias.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlink support unavailable: {error}")
            try:
                with self.assertRaisesRegex(
                    MODULE.FinalClosureValidationError, "symlink"
                ):
                    MODULE.validate(root_alias)
            finally:
                root_alias.unlink(missing_ok=True)

    def test_final_closure_schema_identity_and_mapping_guards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            workflow = (target / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml").read_text(
                encoding="utf-8"
            )

            active_schema_path = target / MODULE.ACTIVE_MANIFEST_SCHEMA_PATH
            active_schema = json.loads(active_schema_path.read_text(encoding="utf-8"))
            active_schema["properties"] = []
            active_schema_path.write_text(json.dumps(active_schema), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate_active_manifest_schema(
                    target,
                    yaml.safe_load(
                        (target / MODULE.CURRENT_MANIFEST).read_text(encoding="utf-8")
                    ),
                )

            # Restore the active schema and mutate the auxiliary schema URI;
            # closure validation must bind the loader to the canonical file.
            shutil.copyfile(ROOT / MODULE.ACTIVE_MANIFEST_SCHEMA_PATH, active_schema_path)
            job_schema_path = target / MODULE.JOB_IDENTITY_SCHEMA_PATH
            job_schema_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / MODULE.JOB_IDENTITY_SCHEMA_PATH, job_schema_path)
            job_schema = json.loads(job_schema_path.read_text(encoding="utf-8"))
            job_schema["$id"] = "https://example.invalid/forged-job.json"
            job_schema_path.write_text(json.dumps(job_schema), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate_job_identity_contract(target, workflow)

    def test_ratification_static_identity_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["ratification_authenticity"]["author"] = "forged-owner"
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_repository_transfer_ratifier_policy_drift_is_rejected(self) -> None:
        mutations = (
            ("designated_ratifier_login", "TrillionniumFoundation"),
            ("designated_ratifier_account_id", 262513357),
            ("repository_owner_may_differ_from_ratifier", False),
        )
        for key, replacement in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                target = Path(temporary)
                copy_surface(target)
                path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
                value = yaml.safe_load(path.read_text(encoding="utf-8"))
                value["ratification_authenticity"][key] = replacement
                path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
                with self.assertRaises(MODULE.FinalClosureValidationError):
                    MODULE.validate(target)

    def test_ratification_subject_or_parent_policy_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["ratification_authenticity"]["required_parent_count"] = 2
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_active_manifest_pointer_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["normative_manifest"] = "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml"
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_workflow_duplicate_arbitration_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["workflow_coverage"]["duplicate_arbitration"]["duplicate_entry_ids"] = "IGNORE"
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_workflow_cancelled_predecessor_policy_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            mutations = (
                ("workflow_concurrency_epoch", "v1"),
                ("matrix_max_parallel", 2),
                ("cancelled_predecessor_aggregate", "RUN"),
            )
            for key, replacement in mutations:
                with self.subTest(key=key):
                    mutated = yaml.safe_load(path.read_text(encoding="utf-8"))
                    mutated["workflow_coverage"]["duplicate_arbitration"][key] = replacement
                    path.write_text(yaml.safe_dump(mutated, sort_keys=False), encoding="utf-8")
                    with self.assertRaises(MODULE.FinalClosureValidationError):
                        MODULE.validate(target)
                    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    def test_workflow_cancel_handoff_is_fail_closed(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        mutations = (
            workflow.replace(
                "plan-v1.3.1-head-and-merge-closure-v2-",
                "plan-v1.3.1-head-and-merge-closure-",
                1,
            ),
            workflow.replace("      max-parallel: 1\n", "      max-parallel: 2\n", 1),
            workflow.replace(
                "    if: ${{ !cancelled() }}\n",
                "    if: ${{ always() }}\n",
                1,
            ),
        )
        for forged in mutations:
            self.assertNotEqual(forged, workflow)
            with self.subTest(mutation=forged[:120]):
                with self.assertRaises(MODULE.FinalClosureValidationError):
                    MODULE.validate_workflow_semantics(forged)

    def test_source_bound_case_cannot_be_declared_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            replace(
                target,
                "planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml",
                "evidence_class: EXACT_HEAD_COMPILED_SOURCE_BOUND",
                "evidence_class: RUNTIME_SOCKET_OBSERVED",
            )
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_merge_lane_cannot_checkout_the_head_again(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            replace(
                target,
                ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml",
                "matrix.source_kind == 'merge' && github.sha",
                "matrix.source_kind == 'merge' && github.event.pull_request.head.sha",
            )
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_workflow_evidence_order_is_required(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        value = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        steps = value["jobs"]["full-technical-matrix"]["steps"]
        names = [step["name"] for step in steps]
        first = names.index("Upload complete diagnostics before final H02 gate")
        second = names.index("Require complete H02 24-entry PASS")
        steps[first], steps[second] = steps[second], steps[first]
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(yaml.safe_dump(value, sort_keys=False))

    def test_workflow_gate_a_yaml_scanner_requires_merge_key_expansion(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        forged = workflow.replace("              loader.flatten_mapping(node)\n", "", 1)
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(forged)

    def test_workflow_gate_a_must_execute_each_validator(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        forged = workflow.replace(
            'python3 "$script" | tee -a "$evidence/validators.log"',
            'echo "$script" | tee -a "$evidence/validators.log"',
            1,
        )
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(forged)

    def test_workflow_trigger_set_is_exact_and_fail_closed(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        mutations = (
            # Removing either covered event leaves the source-lane contract
            # untriggerable or dispatch-only.
            workflow.replace("  workflow_dispatch:\n", "", 1),
            workflow.replace("  pull_request:\n", "  push:\n", 1),
            # An extra event creates an unsupported evidence lane.
            workflow.replace(
                "  workflow_dispatch:\n",
                "  workflow_dispatch:\n  push:\n",
                1,
            ),
            # PyYAML otherwise normalizes this boolean key to the same value
            # as the YAML 1.1 ``on`` key; the validator must still reject it.
            workflow.replace("\non:\n", "\ntrue:\n", 1),
        )
        for forged in mutations:
            with self.subTest(mutation=forged[:80]):
                with self.assertRaises(MODULE.FinalClosureValidationError):
                    MODULE.validate_workflow_semantics(forged)

    def test_workflow_permissions_reject_every_write_capability(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        mutations = (
            # Workflow-level write grant.
            workflow.replace(
                "permissions:\n  contents: read",
                "permissions:\n  contents: write",
                1,
            ),
            # Matrix job write grant.
            workflow.replace("      actions: read", "      actions: write", 1),
            # Aggregate job write grant.
            workflow.replace("      pull-requests: read", "      pull-requests: write", 1),
            # GitHub's shorthand must not bypass the mapping/value check.
            workflow.replace("permissions:\n  contents: read", "permissions: write-all", 1),
            # OIDC has no read grant in GitHub's permission model.
            workflow.replace(
                "permissions:\n  contents: read",
                "permissions:\n  id-token: read",
                1,
            ),
        )
        for forged in mutations:
            with self.subTest(mutation=forged[:80]):
                with self.assertRaises(MODULE.FinalClosureValidationError):
                    MODULE.validate_workflow_semantics(forged)

    def test_workflow_h02_always_path_initializes_diagnostics(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        forged = workflow.replace(
            '          mkdir -p "$evidence" "$evidence/matrix"\n',
            "",
            1,
        )
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(forged)

    def test_workflow_p0_path_initializes_diagnostics(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        forged = workflow.replace(
            '          mkdir -p "$evidence"\n',
            "",
            1,
        )
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(forged)

    def test_workflow_p0_runs_after_prior_gate_failure(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        forged = workflow.replace(
            "      - name: Execute and classify P0 socket and audit evidence\n        if: ${{ always() }}\n",
            "      - name: Execute and classify P0 socket and audit evidence\n",
            1,
        )
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(forged)

    def test_workflow_matrix_disables_fail_fast(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        forged = workflow.replace("      fail-fast: false\n", "      fail-fast: true\n", 1)
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(forged)

    def test_workflow_malformed_nested_mappings_fail_closed(self) -> None:
        workflow_path = ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        value = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        checkout = value["jobs"]["full-technical-matrix"]["steps"]
        checkout_step = next(
            step
            for step in checkout
            if step.get("name") == "Checkout exact head or GitHub synthetic merge"
        )
        checkout_step["with"] = []
        with self.assertRaises(MODULE.FinalClosureValidationError):
            MODULE.validate_workflow_semantics(yaml.safe_dump(value, sort_keys=False))

        # The P0 matrix requirements are consumed as a mapping; a sequence
        # must not trigger an unhandled ``.get``/TypeError path.
        matrix = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml").read_text(
                encoding="utf-8"
            )
        )
        matrix["exact_head_requirements"] = []
        # Invoke the public validator against a temporary source surface so
        # the malformed mapping reaches the same fail-closed boundary.
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            (target / "planning/HEPTABAO_P0_TRANSPORT_TEST_MATRIX_V2.yaml").write_text(
                yaml.safe_dump(matrix, sort_keys=False), encoding="utf-8"
            )
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_workflow_aggregate_schema_check_enforces_formats(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            replace(
                target,
                ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml",
                "Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value)",
                "Draft202012Validator(schema).iter_errors(value)",
            )
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_legacy_vote_equivalence_guard_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            replace(
                target,
                "probes/h02/openraft-tokio/src/bin/durable_store_lab.rs",
                "let legacy_log_vote_matches = semantic_field_matches(",
                "let legacy_log_vote_check_removed = semantic_field_matches(",
            )
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_external_blockers_cannot_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["external_open"] = value["external_open"][:-1]
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_authority_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            value["claims"]["production_authority"] = True
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
            with self.assertRaises(MODULE.FinalClosureValidationError):
                MODULE.validate(target)

    def test_duplicate_yaml_keys_are_rejected_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            copy_surface(target)
            path = target / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml"
            original = path.read_text(encoding="utf-8")
            path.write_text("schema: forged\nschema: ambiguous\n" + original, encoding="utf-8")
            with self.assertRaises(yaml.YAMLError):
                MODULE.validate(target)


if __name__ == "__main__":
    unittest.main()
