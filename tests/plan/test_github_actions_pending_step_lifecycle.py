from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_PATH = ROOT / "scripts/collect_github_job_identity_v1.py"
VALIDATOR_PATH = ROOT / "scripts/validate_v1_3_1_technical_completion_receipt_v1.py"
ARBITRATOR_PATH = ROOT / "scripts/arbitrate_v1_3_1_lanes_v1.py"
JOB_SCHEMA_PATH = ROOT / "schemas/heptabao_github_actions_job_identity_v1.schema.json"

COMMIT = "a" * 40


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load_module(COLLECTOR_PATH, "pending_step_collector")
validator = load_module(VALIDATOR_PATH, "pending_step_receipt_validator")
arbitrator = load_module(ARBITRATOR_PATH, "pending_step_lane_arbitrator")


def completed_step(number: int, name: str) -> dict[str, Any]:
    return {
        "number": number,
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-08-31T11:40:00Z",
        "completed_at": "2026-08-31T11:40:01Z",
    }


def actions_api() -> dict[str, Any]:
    steps = [
        completed_step(number, name)
        for number, name in enumerate(collector.CANONICAL_REQUIRED_STEP_NAMES, start=1)
    ]
    steps.extend(
        [
            {
                "number": len(steps) + 1,
                "name": "Capture numeric GitHub job/runner identity and step outcomes",
                "status": "in_progress",
                "conclusion": None,
                "started_at": "2026-08-31T11:40:02Z",
                "completed_at": None,
            },
            {
                "number": len(steps) + 2,
                "name": "Emit exact-source technical completion receipt",
                "status": "pending",
                "conclusion": None,
                "started_at": None,
                "completed_at": None,
            },
            {
                "number": len(steps) + 3,
                "name": "Validate digest-bound technical completion receipt",
                "status": "pending",
                "conclusion": None,
                "started_at": None,
                "completed_at": None,
            },
        ]
    )
    return {
        "total_count": 1,
        "jobs": [
            {
                "id": 987654321,
                "run_id": 123456,
                "run_attempt": 1,
                "name": "full-technical-matrix (head)",
                "workflow_name": "plan-v1.3.1-head-and-merge-closure",
                "head_sha": COMMIT,
                "status": "in_progress",
                "conclusion": None,
                "started_at": "2026-08-31T11:39:59Z",
                "completed_at": None,
                "runner_id": 123456789,
                "runner_name": "GitHub Actions 1",
                "runner_group_id": 0,
                "runner_group_name": "GitHub Actions",
                "labels": ["ubuntu-24.04"],
                "steps": steps,
            }
        ],
    }


def collect(api: dict[str, Any], evidence: Path) -> dict[str, Any]:
    raw = (json.dumps(api, sort_keys=True) + "\n").encode("utf-8")
    return collector.collect(
        raw,
        expected_run_id="123456",
        expected_run_attempt="1",
        expected_job="full-technical-matrix",
        expected_job_name="full-technical-matrix (head)",
        expected_source_kind="head",
        expected_head_sha=COMMIT,
        expected_workflow_name="plan-v1.3.1-head-and-merge-closure",
        expected_runner_name="GitHub Actions 1",
        expected_runner_os="Linux",
        expected_runner_arch="X64",
        log_root=evidence,
        log_manifest=evidence / "raw-log-manifest.json",
        output_path=evidence / "job-identity.json",
    )


class GitHubActionsPendingStepLifecycleTests(unittest.TestCase):
    def test_provider_pending_future_steps_normalize_to_queued(self) -> None:
        """Future steps are retained as non-passing canonical queued entries."""

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            (evidence / "technical.log").write_text(
                "all required technical gates passed\n", encoding="utf-8"
            )
            raw_api = actions_api()
            value = collect(raw_api, evidence)

            self.assertTrue(
                all(step["status"] == "pending" for step in raw_api["jobs"][0]["steps"][-2:])
            )
            normalized = value["steps"][-2:]
            self.assertTrue(all(step["status"] == "queued" for step in normalized))
            self.assertTrue(all(step["outcome"] == "QUEUED" for step in normalized))
            self.assertEqual("QUEUED", validator._step_outcome("queued", None))

            schema = json.loads(JOB_SCHEMA_PATH.read_text(encoding="utf-8"))
            self.assertEqual([], list(Draft202012Validator(schema).iter_errors(value)))

    def test_pending_step_contradictions_fail_closed(self) -> None:
        """Provider pending steps cannot claim execution or completion facts."""

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            (evidence / "technical.log").write_text("evidence\n", encoding="utf-8")
            for label, mutation in (
                ("conclusion", {"conclusion": "success"}),
                ("started_at", {"started_at": "2026-08-31T11:40:03Z"}),
                ("completed_at", {"completed_at": "2026-08-31T11:40:04Z"}),
            ):
                api = actions_api()
                api["jobs"][0]["steps"][-1].update(mutation)
                with self.subTest(label=label), self.assertRaises(collector.CollectionError):
                    collect(api, evidence)


    def test_receipt_validator_rebuilds_pending_steps_as_canonical_queued(self) -> None:
        """Raw pending and normalized queued bind to one exact API digest."""

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            root = evidence / "root"
            root.mkdir(parents=True)
            (evidence / "p0").mkdir()
            (evidence / "h02/matrix").mkdir(parents=True)
            (evidence / "technical.log").write_text("evidence\n", encoding="utf-8")
            (evidence / "p0/classified-result.json").write_text("{}\n", encoding="utf-8")
            (evidence / "h02/matrix/matrix-summary.json").write_text("{}\n", encoding="utf-8")
            # Exercise the real prefix collision: POSIX lexical order requires
            # the sibling file before entries under the ``matrix`` directory.
            (evidence / "h02/matrix-runner.log").write_text("runner\n", encoding="utf-8")
            (root / "github-identity-verification.json").write_text("{}\n", encoding="utf-8")
            api = actions_api()
            api_raw = (json.dumps(api, sort_keys=True) + "\n").encode("utf-8")
            (root / "github-job-api.json").write_bytes(api_raw)
            artifact = collector.collect(
                api_raw,
                expected_run_id="123456",
                expected_run_attempt="1",
                expected_job="full-technical-matrix",
                expected_job_name="full-technical-matrix (head)",
                expected_source_kind="head",
                expected_head_sha=COMMIT,
                expected_workflow_name="plan-v1.3.1-head-and-merge-closure",
                expected_runner_name="GitHub Actions 1",
                expected_runner_os="Linux",
                expected_runner_arch="X64",
                log_root=evidence,
                log_manifest=root / "raw-log-manifest.json",
                output_path=root / "github-job-identity.json",
            )
            artifact_raw = (
                json.dumps(artifact, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            (root / "github-job-identity.json").write_bytes(artifact_raw)

            runner: dict[str, Any] = {}
            for field in validator.RUNNER_FIELDS:
                if field == "name":
                    runner[field] = artifact["runner_name"]
                elif field == "artifact_digest":
                    runner[field] = validator.sha256_digest(artifact_raw)
                else:
                    runner[field] = artifact[field]
            receipt = {"runner": runner}
            source = {"kind": "head", "head": COMMIT}

            validator._validate_job_identity_artifact(
                artifact,
                artifact_raw,
                api_raw,
                receipt,
                source,
                root / "raw-log-manifest.json",
            )

    def test_workflow_maps_receipt_name_to_provider_runner_name(self) -> None:
        """The inline non-authority check uses the declared field rename."""

        workflow = (
            ROOT / ".github/workflows/plan-v1.3.1-head-and-merge-closure.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'assert runner["name"] == job_identity["runner_name"], "runner_name"',
            workflow,
        )
        self.assertNotIn(
            '"runner_labels",\n              "name", "os",',
            workflow,
        )

    def test_arbitration_materializes_provider_lifecycle_core(self) -> None:
        """Immutable receipt validation includes every dynamic dependency."""

        core = "scripts/validate_v1_3_1_technical_completion_receipt_v1_core.py"
        self.assertIn(core, arbitrator._SOURCE_VALIDATOR_SURFACE)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            for relative in arbitrator._SOURCE_VALIDATOR_SURFACE:
                source = ROOT / relative
                destination = repository / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            subprocess.run(
                ["git", "config", "user.name", "HeptaBao Test"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "test@heptabao.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(["git", "add", "--all"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "test validator surface"],
                cwd=repository,
                check=True,
            )
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository, text=True
            ).strip()
            temporary_surface, source_root = arbitrator._materialize_validator_surface(
                repository, commit
            )
            try:
                materialized = arbitrator._load_receipt_validator_at(source_root, commit)
                self.assertEqual("QUEUED", materialized._step_outcome("pending", None))
            finally:
                temporary_surface.cleanup()

    def test_pending_required_gate_is_never_normalized_to_pass(self) -> None:
        """Only steps after the canonical required prefix may remain pending."""

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            (evidence / "technical.log").write_text("evidence\n", encoding="utf-8")
            api = actions_api()
            required = api["jobs"][0]["steps"][
                len(collector.CANONICAL_REQUIRED_STEP_NAMES) - 1
            ]
            required.update(
                status="pending",
                conclusion=None,
                started_at=None,
                completed_at=None,
            )
            with self.assertRaises(collector.CollectionError):
                collect(api, evidence)


if __name__ == "__main__":
    unittest.main()
