from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import tomllib
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


validator = load_module("plan_v12", "scripts/validate_plan_v1_2.py")
renderer = load_module("state_renderer", "scripts/render_canonical_project_state_v1.py")


class PlanV12Tests(unittest.TestCase):
    def test_checked_in_v12_contract_passes(self):
        result = validator.run_all()
        self.assertEqual(result["work_packages"], 301)
        self.assertFalse(result["qualification"])
        self.assertEqual(result["authority_effect"], "NONE")

    def test_duplicate_manifest_path_fails_closed(self):
        value = validator.load_yaml("planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1.yaml")
        value = copy.deepcopy(value)
        value["documents"][1]["path"] = value["documents"][0]["path"]
        with self.assertRaises(validator.ValidationFailure):
            validator.validate_manifest(value)

    def test_authority_drift_fails_closed(self):
        value = validator.load_yaml("planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml")
        value = copy.deepcopy(value)
        value["authority_flags"]["production_authority"] = True
        with self.assertRaises(validator.ValidationFailure):
            validator.validate_canonical_state(value)

    def test_external_blocker_cannot_be_preclosed(self):
        value = validator.load_yaml("planning/HEPTABAO_BLOCKER_REGISTER_V1.yaml")
        value = copy.deepcopy(value)
        external = next(item for item in value["blockers"] if item["class"] != "REPOSITORY_CONTROLLED")
        external["state"] = "CLOSED"
        external["evidence"] = ["forged"]
        with self.assertRaises(validator.ValidationFailure):
            validator.validate_blockers(value)

    def test_self_modifying_workflow_is_rejected(self):
        workflows = {
            ".github/workflows/plan-integrity-v4.yml": (
                ROOT / ".github/workflows/plan-integrity-v4.yml"
            ).read_text(encoding="utf-8"),
            ".github/workflows/forged.yml": "permissions:\n  contents: write\nsteps:\n  - run: git push\n",
        }
        with self.assertRaises(validator.ValidationFailure):
            validator.validate_workflow_policy(workflows)

    def test_lock_source_drift_fails_closed(self):
        lock = tomllib.loads(
            (ROOT / "probes/h02/openraft-tokio/Cargo.lock").read_text(encoding="utf-8")
        )
        lock = copy.deepcopy(lock)
        validit = next(item for item in lock["package"] if item["name"] == "validit")
        validit["source"] = "registry+https://github.com/rust-lang/crates.io-index"
        with self.assertRaises(validator.ValidationFailure):
            validator.validate_exact_openraft_lock(lock)

    def test_renderer_binds_exact_source_without_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "state.json"
            args = Namespace(
                root=str(ROOT),
                repository="ProfHepta/HeptaBao",
                ref="test/ref",
                commit=renderer.git(ROOT, "rev-parse", "HEAD"),
                tree=renderer.git(ROOT, "rev-parse", "HEAD^{tree}"),
                environment_id="test-environment",
                runner_id="runner-1",
                runner_name="test-runner",
                job_id="job-1",
                run_id="run-1",
                require_clean=False,
                output=str(output),
            )
            value = renderer.resolve(args)
            output.write_text(json.dumps(value), encoding="utf-8")
            self.assertEqual(value["binding"]["commit"], args.commit)
            self.assertEqual(value["binding"]["tree"], args.tree)
            self.assertFalse(value["qualification"])
            self.assertFalse(value["compatibility_claim"])
            self.assertEqual(value["authority_effect"], "NONE")
            self.assertGreaterEqual(len(value["resolved_documents"]), 20)

    def test_renderer_can_resolve_active_v131_state_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "state.json"
            args = Namespace(
                root=str(ROOT),
                repository="TrillionniumFoundation/HeptaBao",
                state_input="planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
                manifest="planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml",
                ref="test/v131",
                commit=renderer.git(ROOT, "rev-parse", "HEAD"),
                tree=renderer.git(ROOT, "rev-parse", "HEAD^{tree}"),
                environment_id="test-environment-v131",
                runner_id="runner-v131",
                runner_name="test-runner-v131",
                job_id="job-v131",
                run_id="run-v131",
                require_clean=False,
                output=str(output),
            )
            value = renderer.resolve(args)
            self.assertEqual(
                value["resolution_inputs"]["state_input"],
                "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
            )
            self.assertEqual(
                value["resolution_inputs"]["manifest"],
                "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml",
            )
            self.assertIn(
                "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
                {entry["path"] for entry in value["resolved_documents"]},
            )
            self.assertFalse(value["qualification"])
            self.assertEqual(value["authority_effect"], "NONE")

    def test_renderer_rejects_input_paths_that_escape_repository(self):
        with self.assertRaises(renderer.Failure):
            renderer.repository_file(
                ROOT,
                "../outside.yaml",
                renderer.DEFAULT_STATE_INPUT,
                "state input",
            )

    def test_renderer_rejects_repository_identity_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "state.json"
            args = Namespace(
                root=str(ROOT),
                repository="attacker/other",
                ref="test/ref",
                commit="1" * 40,
                tree="2" * 40,
                environment_id="test-environment",
                runner_id="runner-1",
                runner_name="test-runner",
                job_id="job-1",
                run_id="run-1",
                require_clean=False,
                output=str(output),
            )
            with self.assertRaises(renderer.Failure):
                renderer.resolve(args)

    def test_renderer_rejects_declared_source_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "state.json"
            args = Namespace(
                root=str(ROOT),
                repository="ProfHepta/HeptaBao",
                ref="test/ref",
                commit="1" * 40,
                tree="2" * 40,
                environment_id="test-environment",
                runner_id="runner-1",
                runner_name="test-runner",
                job_id="job-1",
                run_id="run-1",
                require_clean=False,
                output=str(output),
            )
            with self.assertRaises(renderer.Failure):
                renderer.resolve(args)

    def test_renderer_yaml_loader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.yaml"
            path.write_text("one: 1\none: 2\n", encoding="utf-8")
            with self.assertRaises(renderer.Failure):
                renderer.read_mapping(path, "duplicate fixture")

    def test_renderer_rejects_active_pointer_drift(self):
        state = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml").read_text(
                encoding="utf-8"
            )
        )
        manifest = yaml.safe_load(
            (ROOT / "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml").read_text(
                encoding="utf-8"
            )
        )
        manifest["current_state_input"] = "planning/HEPTABAO_CANONICAL_PROJECT_STATE_V1.yaml"
        with self.assertRaises(renderer.Failure):
            renderer.validate_inputs(
                ROOT,
                state,
                "planning/HEPTABAO_V1_3_1_FINAL_CLOSURE_INPUT.yaml",
                manifest,
                "planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_3_1.yaml",
            )

    def test_work_package_removal_fails_closed(self):
        value = validator.load_yaml("planning/HEPTABAO_WORK_PACKAGE_CATALOG_V1_2.yaml")
        value = copy.deepcopy(value)
        value["gates"]["H00"]["packages"].pop()
        value["package_count"] -= 1
        with self.assertRaises(validator.ValidationFailure):
            validator.validate_work_packages(value)


if __name__ == "__main__":
    unittest.main()
