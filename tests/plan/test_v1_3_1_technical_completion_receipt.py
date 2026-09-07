from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts/validate_v1_3_1_technical_completion_receipt_v1.py"
SCHEMA_PATH = ROOT / "schemas/heptabao_v1_3_1_technical_completion_receipt_v1.schema.json"
JOB_IDENTITY_SCHEMA_PATH = ROOT / "schemas/heptabao_github_actions_job_identity_v1.schema.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_module(VALIDATOR_PATH, "technical_completion_receipt_validator")
matrix_runner = load_module(ROOT / "scripts/h02_exact_head_matrix_v1.py", "h02_matrix_runner_for_receipt_tests")
classifier = load_module(ROOT / "scripts/classify_p0_transport_evidence_v1.py", "p0_classifier_for_receipt_tests")
collector = load_module(ROOT / "scripts/collect_github_job_identity_v1.py", "github_job_identity_collector_for_receipt_tests")

COMMIT = "a" * 40
TREE = "b" * 40
HEAD_OWNER = "TrillionniumFoundation"
RATIFIER_LOGIN = "ProfHepta"
REPOSITORY_ID = 1349115072
ACCOUNT_ID = 102159240


def synthetic_steps(*, offset: bool = False) -> list[dict[str, Any]]:
    """Build the provider step table used by the bound fixture.

    GitHub's documented job response permits either ``Z`` or an explicit
    numeric UTC offset for step timestamps.  Keep the default fixture compact
    while allowing one end-to-end regression case to exercise the latter.
    """

    if offset:
        required_started = "2026-08-29T16:00:00.000-08:00"
        required_completed = "2026-08-29T16:00:01.000-08:00"
        collector_started = "2026-08-29T16:00:02.000-08:00"
    else:
        required_started = "2026-08-30T00:00:00Z"
        required_completed = "2026-08-30T00:00:01Z"
        collector_started = "2026-08-30T00:00:02Z"

    steps: list[dict[str, Any]] = []
    for number, name in enumerate(collector.CANONICAL_REQUIRED_STEP_NAMES, start=1):
        steps.append(
            {
                "number": number,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": required_started,
                "completed_at": required_completed,
                "outcome": "PASS",
            }
        )
    steps.append(
        {
            "number": len(steps) + 1,
            "name": "Capture numeric GitHub job/runner identity and step outcomes",
            "status": "in_progress",
            "conclusion": None,
            "started_at": collector_started,
            "completed_at": None,
            "outcome": "IN_PROGRESS",
        }
    )
    return steps


def synthetic_runner() -> dict[str, Any]:
    steps = synthetic_steps()
    return {
        "run_id": "123456",
        "run_attempt": "1",
        "job": "full-technical-matrix",
        "job_id": "987654321",
        "job_name": "full-technical-matrix (head)",
        "workflow_name": "plan-v1.3.1-head-and-merge-closure",
        "job_status": "in_progress",
        "job_conclusion": None,
        "name": "GitHub Actions 1",
        "runner_labels": ["ubuntu-24.04"],
        "runner_id": "123456789",
        "runner_group_id": "0",
        "runner_group": "GitHub Actions",
        "os": "Linux",
        "arch": "X64",
        "head_sha": COMMIT,
        "source_kind": "head",
        "job_started_at": "2026-08-30T00:00:00Z",
        "job_completed_at": None,
        "required_step_names": list(collector.CANONICAL_REQUIRED_STEP_NAMES),
        "steps": steps,
        "step_outcomes_digest": collector.canonical_digest(steps),
        "api_response_digest": "sha256:" + "0" * 64,
        "raw_log_manifest_digest": "sha256:" + "0" * 64,
        "artifact_digest": "sha256:" + "0" * 64,
    }


def receipt(kind: str = "head", arbitration_pr: str | None = None) -> dict[str, Any]:
    arbitration_pr = arbitration_pr or ("workflow_dispatch" if kind == "head" else "45")
    arbitration_head = COMMIT
    arbitration_key = f"{arbitration_pr}:{arbitration_head}:{kind}"
    return {
        "schema": validator.SCHEMA_ID,
        "source": {
            "repository": validator.REPOSITORY,
            "kind": kind,
            "commit": COMMIT if kind == "head" else TREE,
            "tree": TREE,
            "head": COMMIT,
            "base": "" if kind == "head" else "c" * 40,
            "event_merge": COMMIT if kind == "head" else TREE,
        },
        "runner": {
            **synthetic_runner(),
        },
        "arbitration": {
            "key": arbitration_key,
            "pull_request_number": arbitration_pr,
            "head_sha": arbitration_head,
            "source_kind": kind,
            "required_lanes": ["head"] if arbitration_pr == "workflow_dispatch" else ["head", "merge"],
        },
        "gates": {
            "plan_python": "PASS",
            "root_rust_1_98": "PASS",
            "p0": {
                "runtime_socket_observed": 11,
                "exact_head_compiled_source_bound": 2,
                "best_effort_source_bound": 1,
                "artifact_digest": "sha256:" + "0" * 64,
            },
            "h02": {
                "executed_entries": 24,
                "pass": 24,
                "artifact_digest": "sha256:" + "0" * 64,
            },
        },
        "github_identity": {
            "artifact_digest": "sha256:" + "0" * 64,
            "source_sha": COMMIT,
            "repository_id": REPOSITORY_ID,
            "repository_full_name": validator.REPOSITORY,
            "expected_head_owner": HEAD_OWNER,
            "head_owner": HEAD_OWNER,
            "expected_ratifier_login": RATIFIER_LOGIN,
            "expected_ratifier_id": ACCOUNT_ID,
            "author_login": RATIFIER_LOGIN,
            "committer_login": RATIFIER_LOGIN,
            "author_id": ACCOUNT_ID,
            "committer_id": ACCOUNT_ID,
            "verification": {"verified": False, "reason": "unsigned"},
            "identity_verified": True,
            "signature_required": False,
        },
        "independent_review": False,
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }


def p0_artifact() -> dict[str, Any]:
    raw = {
        "schema": "heptabao.p0-transport-exact-result.v1",
        "source": {
            "repository": validator.REPOSITORY,
            "commit": COMMIT,
            "tree": TREE,
            "clean_tree": True,
        },
        "result": "PASS",
        "counts": {"pass": 14, "fail": 0, "blocked": 0, "unexecuted": 0},
        "qualification": False,
        "compatibility_claim": False,
        "authority_effect": "NONE",
        "cases": [
            {"case_id": case_id, "status": "PASS"}
            for case_id in sorted(classifier.EXPECTED_CASES)
        ],
    }
    return classifier.classify(raw)


def h02_artifact() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for toolchain in matrix_runner.TOOLCHAINS:
        for seed in matrix_runner.SEEDS:
            for probe in matrix_runner.PROBES:
                entry_id = matrix_runner.entry_id(probe, toolchain, seed)
                command = [
                    "cargo",
                    f"+{toolchain}",
                    "run",
                    "--quiet",
                    "--locked",
                    "--manifest-path",
                    "probes/h02/openraft-tokio/Cargo.toml",
                    "--bin",
                    probe.binary,
                    "--",
                    *probe.arguments,
                    "--seed",
                    seed,
                ]
                entries.append(
                    {
                        "entry_id": entry_id,
                        "kind": probe.kind,
                        "binary": probe.binary,
                        "toolchain": toolchain,
                        "seed": seed,
                        "command": command,
                        "command_digest": matrix_runner.canonical_json_digest(command),
                        "started_at": "2026-08-30T00:00:00Z",
                        "completed_at": "2026-08-30T00:00:01Z",
                        "duration_ms": 1000,
                        "process_started": True,
                        "exit_code": 0,
                        "timed_out": False,
                        "conclusion": "PASS",
                        "application_status": "EXECUTED_PASS",
                        "stdout_path": f"{entry_id}.stdout",
                        "stderr_path": f"{entry_id}.stderr",
                        "exit_path": f"{entry_id}.exit",
                        "stdout_digest": matrix_runner.sha256_bytes(b"ok"),
                        "stderr_digest": matrix_runner.sha256_bytes(b""),
                        "exit_digest": matrix_runner.sha256_bytes(b"0\n"),
                        "validation_errors": [],
                    }
                )
    return matrix_runner.build_summary(
        repository=validator.REPOSITORY,
        ref="receipt-test-head",
        commit=COMMIT,
        tree=TREE,
        manifest=ROOT / "probes/h02/openraft-tokio/Cargo.toml",
        lock=ROOT / "probes/h02/openraft-tokio/Cargo.lock",
        entries=entries,
        started_at="2026-08-30T00:00:00Z",
        completed_at="2026-08-30T00:01:00Z",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def github_identity_artifact() -> dict[str, Any]:
    return {
        "source_sha": COMMIT,
        "repository_id": REPOSITORY_ID,
        "repository_full_name": validator.REPOSITORY,
        "expected_head_owner": HEAD_OWNER,
        "head_owner": HEAD_OWNER,
        "expected_ratifier_login": RATIFIER_LOGIN,
        "expected_ratifier_id": ACCOUNT_ID,
        "author_login": RATIFIER_LOGIN,
        "committer_login": RATIFIER_LOGIN,
        "author_id": ACCOUNT_ID,
        "committer_id": ACCOUNT_ID,
        "verification": {"verified": False, "reason": "unsigned"},
        "identity_verified": True,
        "signature_required": False,
    }


def synthetic_actions_api(*, offset: bool = False) -> dict[str, Any]:
    """Return a provider-shaped Actions jobs response for one matrix lane.

    The collector consumes numeric API values and normalizes them to decimal
    strings in the identity artifact. Keep the raw response close to
    GitHub's wire shape (numeric IDs and provider runner fields) so the
    receipt validator exercises the API-to-artifact binding.
    """

    raw_steps = [
        {key: value for key, value in step.items() if key != "outcome"}
        for step in synthetic_steps(offset=offset)
    ]
    job_started_at = (
        "2026-08-29T16:00:00.000-08:00"
        if offset
        else "2026-08-30T00:00:00Z"
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
                "started_at": job_started_at,
                "completed_at": None,
                "runner_id": 123456789,
                "runner_name": "GitHub Actions 1",
                "runner_group_id": 0,
                "runner_group_name": "GitHub Actions",
                "labels": ["ubuntu-24.04"],
                "steps": raw_steps,
            }
        ],
    }


def bound_fixture(
    *, offset: bool = False
) -> tuple[dict[str, Any], Path, Path, Path, tempfile.TemporaryDirectory[str]]:
    temporary = tempfile.TemporaryDirectory()
    evidence = Path(temporary.name)
    p0_path = evidence / "p0/classified-result.json"
    h02_path = evidence / "h02/matrix/matrix-summary.json"
    identity_path = evidence / "root/github-identity-verification.json"
    job_api_path = evidence / "root/github-job-api.json"
    job_identity_path = evidence / "root/github-job-identity.json"
    log_manifest_path = evidence / "root/raw-log-manifest.json"
    for path in (p0_path, h02_path, identity_path, job_api_path):
        path.parent.mkdir(parents=True, exist_ok=True)
    write_json(p0_path, p0_artifact())
    h02 = h02_artifact()
    # The technical receipt validator intentionally re-reads every H02
    # sidecar.  Materialize the same layout emitted by the matrix runner next
    # to the synthetic summary so the fixture exercises the real binding.
    for entry in h02["entries"]:
        (h02_path.parent / entry["stdout_path"]).write_bytes(b"ok")
        (h02_path.parent / entry["stderr_path"]).write_bytes(b"")
        (h02_path.parent / entry["exit_path"]).write_bytes(b"0\n")
    write_json(h02_path, h02)
    write_json(identity_path, github_identity_artifact())

    # Capture the raw provider response and let the production collector build
    # the normalized job artifact plus digest-only log inventory. The output
    # artifact is excluded from that inventory, matching the workflow's
    # ordering (manifest first, receipt/job artifact immediately afterwards).
    api_raw = (
        json.dumps(synthetic_actions_api(offset=offset), indent=2, sort_keys=True) + "\n"
    ).encode(
        "utf-8"
    )
    job_api_path.write_bytes(api_raw)
    job_identity = collector.collect(
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
        log_manifest=log_manifest_path,
        output_path=job_identity_path,
    )
    write_json(job_identity_path, job_identity)

    value = receipt()
    # The receipt uses ``name`` for compatibility, while the normalized
    # provider artifact calls the same field ``runner_name``. Copy every
    # collector value into the receipt so expected-runner checks cover nulls,
    # lists and timestamps as well as scalar identity fields.
    for field in validator.RUNNER_FIELDS:
        if field == "name":
            value["runner"][field] = job_identity["runner_name"]
        elif field == "artifact_digest":
            value["runner"][field] = validator.sha256_digest(job_identity_path.read_bytes())
        else:
            value["runner"][field] = job_identity[field]
    value["gates"]["p0"]["artifact_digest"] = validator.sha256_digest(p0_path.read_bytes())
    value["gates"]["h02"]["artifact_digest"] = validator.sha256_digest(h02_path.read_bytes())
    value["github_identity"]["artifact_digest"] = validator.sha256_digest(identity_path.read_bytes())
    return value, p0_path, h02_path, identity_path, temporary


def validate_bound(value: Mapping[str, Any], **kwargs: Any) -> None:
    """Validate a complete fixture, including all numeric-job artifacts."""

    # Only augment a complete P0/H02/identity set. Calls intentionally testing
    # a partial artifact pair must still reach the production validator and be
    # rejected there, rather than being silently completed by this helper.
    if {
        "p0_artifact",
        "h02_artifact",
        "github_identity_artifact",
    } <= set(kwargs):
        p0_path = Path(kwargs["p0_artifact"])
        h02_path = Path(kwargs["h02_artifact"])
        evidence = p0_path.parents[1]
        kwargs.setdefault("h02_evidence_dir", h02_path.parent)
        kwargs.setdefault("github_job_artifact", evidence / "root/github-job-identity.json")
        kwargs.setdefault("github_job_api", evidence / "root/github-job-api.json")
        kwargs.setdefault("raw_log_manifest", evidence / "root/raw-log-manifest.json")
    validator.validate(value, **kwargs)


def complete_artifact_paths(p0_path: Path) -> dict[str, Path]:
    """Return sibling job/API/manifest paths for a bound evidence root."""

    evidence = p0_path.parents[1]
    return {
        "github_job_artifact": evidence / "root/github-job-identity.json",
        "github_job_api": evidence / "root/github-job-api.json",
        "raw_log_manifest": evidence / "root/raw-log-manifest.json",
    }


class TechnicalCompletionReceiptTests(unittest.TestCase):
    def test_schema_is_valid_and_matches_inline_workflow_shape(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["$schema"], validator.DRAFT202012_SCHEMA_URI)
        self.assertEqual(schema["$id"], validator.SCHEMA_URI)
        value = receipt()
        self.assertEqual([], list(Draft202012Validator(schema).iter_errors(value)))

    def test_artifact_reads_reject_traversal_and_symlink_components(self) -> None:
        """A regular leaf below an alias must not escape the evidence root."""

        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        del value, h02_path, identity_path
        try:
            evidence = p0_path.parents[1]
            outside = Path(tempfile.mkdtemp(prefix="receipt-outside-"))
            try:
                outside_file = outside / "classified-result.json"
                outside_file.write_bytes(p0_path.read_bytes())
                alias = evidence / "alias"
                try:
                    alias.symlink_to(outside, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"symlink support unavailable: {error}")
                with self.assertRaises(validator.ValidationError):
                    validator._read_artifact(alias / "classified-result.json", "P0")

                with self.assertRaises(validator.ValidationError):
                    validator._read_bytes(
                        evidence / "root" / ".." / "root" / "github-job-api.json",
                        "GitHub Actions API response",
                    )
            finally:
                # ``TemporaryDirectory`` owns the evidence tree; remove only
                # this independent outside directory created for the alias.
                for child in outside.iterdir():
                    child.unlink()
                outside.rmdir()
        finally:
            temporary.cleanup()

    def test_schema_loaders_reject_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "schema.json"
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            schema["$id"] = "https://example.invalid/forged.json"
            target.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaises(validator.ValidationError):
                validator.load_schema(target)

            job_target = Path(temporary) / "job-identity-schema.json"
            job_schema = json.loads(
                validator.JOB_IDENTITY_SCHEMA_PATH.read_text(encoding="utf-8")
            )
            job_schema["$id"] = "https://example.invalid/job-identity.json"
            job_target.write_text(json.dumps(job_schema), encoding="utf-8")
            with self.assertRaises(validator.ValidationError):
                validator.load_artifact_schema(
                    job_target,
                    validator.JOB_IDENTITY_SCHEMA_ID,
                    expected_uri=validator.JOB_IDENTITY_SCHEMA_URI,
                )

            h02_target = Path(temporary) / "h02-schema.json"
            h02_schema = json.loads(
                (ROOT / "schemas/heptabao_h02_exact_head_matrix_summary_v1.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            h02_schema["$schema"] = "https://json-schema.org/draft/07/schema#"
            h02_target.write_text(json.dumps(h02_schema), encoding="utf-8")
            with self.assertRaises(validator.ValidationError):
                validator.load_schema(
                    h02_target,
                    expected_id=validator.H02_SCHEMA_ID,
                    expected_uri=validator.H02_SCHEMA_URI,
                )
            with self.assertRaises(validator.ValidationError):
                validator.validate(receipt(), require_artifacts=False, schema=schema)

            schema["$id"] = validator.SCHEMA_URI
            schema["$schema"] = "https://json-schema.org/draft/07/schema#"
            target.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaises(validator.ValidationError):
                validator.load_schema(target)

    def test_manifest_inventory_rejects_non_regular_entries(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            fifo = p0_path.parents[1] / "unexpected.fifo"
            try:
                os.mkfifo(fifo)
            except (AttributeError, OSError) as error:
                self.skipTest(f"FIFO support unavailable: {error}")
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
            fifo.unlink()
        finally:
            temporary.cleanup()

    def test_schema_binds_runner_step_status_conclusion_and_outcome(self) -> None:
        """A permissive status enum must not admit contradictory step state."""

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        checker = Draft202012Validator(schema)
        mutations: list[tuple[str, dict[str, Any]]] = []

        value = receipt()
        value["runner"]["steps"][0]["conclusion"] = None
        mutations.append(("completed-without-conclusion", value))

        value = receipt()
        value["runner"]["steps"][0]["outcome"] = "FAIL"
        mutations.append(("completed-success-with-fail-outcome", value))

        value = receipt()
        value["runner"]["steps"][0]["completed_at"] = None
        mutations.append(("completed-without-completion-time", value))

        value = receipt()
        value["runner"]["steps"][-1]["conclusion"] = "success"
        mutations.append(("in-progress-with-conclusion", value))

        value = receipt()
        value["runner"]["steps"][-1]["outcome"] = "PASS"
        mutations.append(("in-progress-with-pass-outcome", value))

        value = receipt()
        value["runner"]["steps"][-1]["started_at"] = None
        mutations.append(("in-progress-without-start-time", value))

        value = receipt()
        queued = value["runner"]["steps"][-1]
        queued.update(
            status="queued",
            conclusion=None,
            started_at=None,
            completed_at=None,
            outcome="PASS",
        )
        mutations.append(("queued-with-pass-outcome", value))

        value = receipt()
        queued = value["runner"]["steps"][-1]
        queued.update(status="queued", conclusion=None, started_at="2026-08-30T00:00:02Z")
        mutations.append(("queued-with-start-time", value))

        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assertTrue(
                    list(checker.iter_errors(mutated)),
                    f"schema accepted contradictory {label} step state",
                )

        # Job lifecycle fields are checked independently of the step table.
        for label, changes in (
            (
                "completed-job-without-success-conclusion",
                {"job_status": "completed", "job_conclusion": None, "job_completed_at": "2026-08-30T00:00:03Z"},
            ),
            (
                "completed-job-without-completion-time",
                {"job_status": "completed", "job_conclusion": "success", "job_completed_at": None},
            ),
            (
                "active-job-with-conclusion",
                {"job_status": "in_progress", "job_conclusion": "success"},
            ),
            (
                "active-job-without-start-time",
                {"job_status": "in_progress", "job_conclusion": None, "job_started_at": None},
            ),
        ):
            mutated = receipt()
            mutated["runner"].update(changes)
            with self.subTest(label=label):
                self.assertTrue(
                    list(checker.iter_errors(mutated)),
                    f"schema accepted contradictory {label} runner state",
                )

    def test_job_identity_schema_binds_status_conclusion_and_outcome(self) -> None:
        """The normalized Actions identity shares the same state contract."""

        schema = json.loads(JOB_IDENTITY_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        value, p0_path, _h02_path, _identity_path, temporary = bound_fixture()
        try:
            job_path = complete_artifact_paths(p0_path)["github_job_artifact"]
            base = json.loads(job_path.read_text(encoding="utf-8"))
            checker = Draft202012Validator(schema)
            self.assertEqual([], list(checker.iter_errors(base)))
            mutations: list[tuple[str, dict[str, Any]]] = []
            for label, changes in (
                (
                    "completed-job-without-success-conclusion",
                    {"job_status": "completed", "job_conclusion": None, "job_completed_at": "2026-08-30T00:00:03Z"},
                ),
                (
                    "active-job-with-conclusion",
                    {"job_status": "in_progress", "job_conclusion": "success"},
                ),
                (
                    "active-job-without-start-time",
                    {"job_status": "in_progress", "job_conclusion": None, "job_started_at": None},
                ),
            ):
                mutated = json.loads(json.dumps(base))
                mutated.update(changes)
                mutations.append((label, mutated))
            for label, changes in (
                ("completed-success-with-fail-outcome", {"outcome": "FAIL"}),
                ("in-progress-with-conclusion", {"conclusion": "success"}),
                ("in-progress-with-pass-outcome", {"outcome": "PASS"}),
                ("in-progress-without-start-time", {"started_at": None}),
            ):
                mutated = json.loads(json.dumps(base))
                mutated["steps"][-1].update(changes)
                mutations.append((label, mutated))
            for label, mutated in mutations:
                with self.subTest(label=label):
                    self.assertTrue(
                        list(checker.iter_errors(mutated)),
                        f"job identity schema accepted contradictory {label}",
                    )
        finally:
            temporary.cleanup()

    def test_job_identity_collector_rejects_queued_provider_job(self) -> None:
        """Queued API state is infrastructure evidence, never a receipt."""

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            api = synthetic_actions_api()
            api["jobs"][0]["status"] = "queued"
            raw = (json.dumps(api, sort_keys=True) + "\n").encode("utf-8")
            with self.assertRaises(collector.CollectionError):
                collector.collect(
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

    def test_bound_receipt_and_all_artifacts_pass(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            validate_bound(
                value,
                expected_source_kind="head",
                expected_commit=COMMIT,
                expected_tree=TREE,
                expected_head=COMMIT,
                expected_base="",
                expected_event_merge=COMMIT,
                expected_runner=value["runner"],
                p0_artifact=p0_path,
                h02_artifact=h02_path,
                github_identity_artifact=identity_path,
            )
        finally:
            temporary.cleanup()

    def test_provider_numeric_offset_timestamps_bind_end_to_end(self) -> None:
        """GitHub step offsets (for example ``-08:00``) remain valid evidence."""

        value, p0_path, h02_path, identity_path, temporary = bound_fixture(offset=True)
        try:
            validate_bound(
                value,
                expected_source_kind="head",
                expected_commit=COMMIT,
                expected_tree=TREE,
                expected_head=COMMIT,
                expected_base="",
                expected_event_merge=COMMIT,
                expected_runner=value["runner"],
                p0_artifact=p0_path,
                h02_artifact=h02_path,
                github_identity_artifact=identity_path,
            )
            self.assertTrue(value["runner"]["job_started_at"].endswith("-08:00"))
            self.assertTrue(value["runner"]["steps"][0]["started_at"].endswith("-08:00"))
        finally:
            temporary.cleanup()

    def test_artifact_paths_are_required_for_completion_validation(self) -> None:
        with self.assertRaises(validator.ValidationError):
            validator.validate(receipt())

    def test_authority_and_gate_drift_fail_closed(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            for field, replacement in (
                ("qualification", True),
                ("compatibility_claim", True),
                ("production_authority", True),
                ("authority_effect", "GRANT"),
            ):
                mutated = json.loads(json.dumps(value))
                mutated[field] = replacement
                with self.subTest(field=field):
                    with self.assertRaises(validator.ValidationError):
                        validate_bound(
                            mutated,
                            p0_artifact=p0_path,
                            h02_artifact=h02_path,
                            github_identity_artifact=identity_path,
                        )

            mutated = json.loads(json.dumps(value))
            mutated["gates"]["p0"]["runtime_socket_observed"] = 14
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    mutated,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
        finally:
            temporary.cleanup()

    def test_expected_source_and_runner_bindings_are_checked(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    expected_source_kind="merge",
                    expected_commit=COMMIT,
                    expected_tree=TREE,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    expected_head_owner="different-owner",
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    expected_runner={"run_id": "999"},
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
        finally:
            temporary.cleanup()

    def test_arbitration_key_and_lane_components_fail_closed(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            for field, replacement in (
                ("key", "45:" + COMMIT + ":head"),
                ("head_sha", "f" * 40),
                ("source_kind", "merge"),
                ("required_lanes", ["head", "merge"]),
            ):
                mutated = json.loads(json.dumps(value))
                mutated["arbitration"][field] = replacement
                with self.subTest(field=field):
                    with self.assertRaises(validator.ValidationError):
                        validate_bound(
                            mutated,
                            p0_artifact=p0_path,
                            h02_artifact=h02_path,
                            github_identity_artifact=identity_path,
                        )

            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    expected_arbitration_key="45:" + COMMIT + ":head",
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
        finally:
            temporary.cleanup()

    def test_pull_request_receipt_requires_both_lanes_in_arbitration(self) -> None:
        value = receipt("head", "45")
        self.assertEqual(value["arbitration"]["required_lanes"], ["head", "merge"])
        with self.assertRaises(validator.ValidationError):
            mutated = json.loads(json.dumps(value))
            mutated["arbitration"]["required_lanes"] = ["head"]
            validator.validate(mutated, require_artifacts=False)

    def test_repository_transfer_identity_cannot_masquerade_as_ratifier(self) -> None:
        value = receipt()
        mutations = []

        repository_id_drift = json.loads(json.dumps(value))
        repository_id_drift["github_identity"]["repository_id"] = REPOSITORY_ID + 1
        mutations.append(repository_id_drift)

        historical_full_name = json.loads(json.dumps(value))
        historical_full_name["github_identity"]["repository_full_name"] = "ProfHepta/HeptaBao"
        mutations.append(historical_full_name)

        owner_as_ratifier = json.loads(json.dumps(value))
        owner_as_ratifier["github_identity"]["expected_ratifier_login"] = HEAD_OWNER
        owner_as_ratifier["github_identity"]["author_login"] = HEAD_OWNER
        owner_as_ratifier["github_identity"]["committer_login"] = HEAD_OWNER
        mutations.append(owner_as_ratifier)

        for mutated in mutations:
            with self.subTest(identity=mutated["github_identity"]):
                with self.assertRaises(validator.ValidationError):
                    validator.validate(mutated, require_artifacts=False)

    def test_digest_mutation_and_partial_artifact_pair_fail_closed(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            mutated = json.loads(json.dumps(value))
            mutated["gates"]["h02"]["artifact_digest"] = "sha256:" + "f" * 64
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    mutated,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
            with self.assertRaises(validator.ValidationError):
                validator.validate(value, p0_artifact=p0_path)
            mutated = json.loads(json.dumps(value))
            mutated["github_identity"]["artifact_digest"] = "sha256:" + "f" * 64
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    mutated,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            identity_mutated = json.loads(json.dumps(github_identity_artifact()))
            identity_mutated["author_login"] = "other-owner"
            write_json(identity_path, identity_mutated)
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            # Even if an attacker rewrites the receipt digest after changing
            # an API field, the parsed artifact payload must still match every
            # identity field copied into the receipt.
            value["github_identity"]["artifact_digest"] = validator.sha256_digest(
                identity_path.read_bytes()
            )
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            identity_mutated = json.loads(json.dumps(github_identity_artifact()))
            identity_mutated["unexpected"] = True
            write_json(identity_path, identity_mutated)
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

        finally:
            temporary.cleanup()

    def test_numeric_job_api_and_log_manifest_bindings_fail_closed(self) -> None:
        """Provider/API and every manifest-listed sidecar are authenticated."""

        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        paths = complete_artifact_paths(p0_path)
        try:
            # A self-consistent response that omits the provider pagination
            # witness must not be accepted just because the selected job is
            # still present.
            original_api = paths["github_job_api"].read_bytes()
            truncated = json.loads(original_api.decode("utf-8"))
            del truncated["total_count"]
            paths["github_job_api"].write_text(
                json.dumps(truncated, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
            paths["github_job_api"].write_bytes(original_api)

            # A changed raw API response cannot be paired with the normalized
            # identity artifact, even when the JSON remains well formed.
            api_value = json.loads(paths["github_job_api"].read_text(encoding="utf-8"))
            api_value["jobs"][0]["runner_id"] = 123456790
            paths["github_job_api"].write_text(
                json.dumps(api_value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            # Restore the API and exercise the second binding layer: changing
            # a captured H02 sidecar without changing its manifest entry must
            # be detected by the validator's directory re-read.
            api_raw = (json.dumps(synthetic_actions_api(), indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
            paths["github_job_api"].write_bytes(api_raw)
            sidecar = h02_path.parent / "durable-1.88.0-5eed20260828cafe.stdout"
            sidecar.write_bytes(b"tampered")
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            # Restore the sidecar, then alter only the manifest's declared
            # byte count. Rebind the manifest and job-artifact digests so this
            # assertion specifically exercises size-vs-bytes validation rather
            # than stopping at an outer digest mismatch.
            sidecar.write_bytes(b"ok")
            manifest_path = paths["raw_log_manifest"]
            manifest_value = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_value["files"][0]["size"] += 1
            write_json(manifest_path, manifest_value)
            manifest_digest = validator.sha256_digest(manifest_path.read_bytes())
            job_path = paths["github_job_artifact"]
            job_value = json.loads(job_path.read_text(encoding="utf-8"))
            job_value["raw_log_manifest_digest"] = manifest_digest
            write_json(job_path, job_value)
            value["runner"]["raw_log_manifest_digest"] = manifest_digest
            value["runner"]["artifact_digest"] = validator.sha256_digest(job_path.read_bytes())
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )
        finally:
            temporary.cleanup()

    def test_provider_boolean_numeric_fields_fail_closed(self) -> None:
        """Raw Actions JSON booleans cannot masquerade as numeric IDs."""

        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        paths = complete_artifact_paths(p0_path)
        try:
            original_api = paths["github_job_api"].read_bytes()
            original_identity = paths["github_job_artifact"].read_bytes()
            original_api_digest = value["runner"]["api_response_digest"]
            original_artifact_digest = value["runner"]["artifact_digest"]
            for field, replacement in (("run_attempt", True), ("runner_group_id", False)):
                with self.subTest(field=field):
                    api_value = json.loads(original_api.decode("utf-8"))
                    api_value["jobs"][0][field] = replacement
                    mutated_api = (
                        json.dumps(api_value, indent=2, sort_keys=True) + "\n"
                    ).encode("utf-8")
                    paths["github_job_api"].write_bytes(mutated_api)

                    job_identity = json.loads(original_identity.decode("utf-8"))
                    job_identity["api_response_digest"] = validator.sha256_digest(mutated_api)
                    write_json(paths["github_job_artifact"], job_identity)
                    value["runner"]["api_response_digest"] = validator.sha256_digest(mutated_api)
                    value["runner"]["artifact_digest"] = validator.sha256_digest(
                        paths["github_job_artifact"].read_bytes()
                    )
                    with self.assertRaises(validator.ValidationError):
                        validate_bound(
                            value,
                            p0_artifact=p0_path,
                            h02_artifact=h02_path,
                            github_identity_artifact=identity_path,
                        )

            # Restore the complete digest chain so this regression remains
            # isolated if more assertions are appended to the fixture later.
            paths["github_job_api"].write_bytes(original_api)
            paths["github_job_artifact"].write_bytes(original_identity)
            value["runner"]["api_response_digest"] = original_api_digest
            value["runner"]["artifact_digest"] = original_artifact_digest
        finally:
            temporary.cleanup()

    def test_raw_log_manifest_rejects_unlisted_evidence_file(self) -> None:
        """Every pre-receipt evidence file must appear in the inventory."""

        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        try:
            evidence = p0_path.parents[1]
            (evidence / "unlisted-evidence.log").write_bytes(b"not in manifest\n")
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            # These files are intentionally emitted after the manifest
            # snapshot by the production workflow and are therefore exempt
            # from the pre-receipt inventory boundary.
            (evidence / "technical-completion-receipt.json").write_text(
                "{}\n", encoding="utf-8"
            )
            (evidence / "root/technical-receipt-validation.log").write_text(
                "validation output\n", encoding="utf-8"
            )
            (evidence / "unlisted-evidence.log").unlink()
            validate_bound(
                value,
                p0_artifact=p0_path,
                h02_artifact=h02_path,
                github_identity_artifact=identity_path,
            )
        finally:
            temporary.cleanup()

    def test_runner_labels_and_job_artifact_set_are_required(self) -> None:
        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        paths = complete_artifact_paths(p0_path)
        try:
            mutated = json.loads(json.dumps(value))
            mutated["runner"]["runner_labels"] = ["ubuntu-slim"]
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    mutated,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                )

            # Supplying only two of the three provider artifacts is not a
            # completion record; the production validator must reject the
            # partial set before accepting any digest-bound evidence.
            paths["github_job_api"].unlink()
            with self.assertRaises(validator.ValidationError):
                validator.validate(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    h02_evidence_dir=h02_path.parent,
                    github_identity_artifact=identity_path,
                    github_job_artifact=paths["github_job_artifact"],
                    raw_log_manifest=paths["raw_log_manifest"],
                )
        finally:
            temporary.cleanup()

    def test_h02_entry_tuple_fields_are_bound_fail_closed(self) -> None:
        mutations = (
            ("entry_id", "inmemory-1.88.0-deadbeefdeadbeef"),
            ("kind", "hostile"),
            ("toolchain", "1.98.0"),
            ("seed", matrix_runner.SEEDS[1]),
            ("binary", "heptabao-h02-openraft-fault-lab"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                value, p0_path, h02_path, identity_path, temporary = bound_fixture()
                try:
                    artifact = json.loads(h02_path.read_text(encoding="utf-8"))
                    artifact["entries"][0][field] = replacement
                    write_json(h02_path, artifact)
                    value["gates"]["h02"]["artifact_digest"] = validator.sha256_digest(
                        h02_path.read_bytes()
                    )
                    with self.assertRaises(validator.ValidationError):
                        validate_bound(
                            value,
                            p0_artifact=p0_path,
                            h02_artifact=h02_path,
                            github_identity_artifact=identity_path,
                        )
                finally:
                    temporary.cleanup()

    def test_h02_command_digest_and_argv_are_bound_fail_closed(self) -> None:
        for mutate_command in (False, True):
            with self.subTest(mutate_command=mutate_command):
                value, p0_path, h02_path, identity_path, temporary = bound_fixture()
                try:
                    artifact = json.loads(h02_path.read_text(encoding="utf-8"))
                    if mutate_command:
                        artifact["entries"][0]["command"][-1] = matrix_runner.SEEDS[1]
                        artifact["entries"][0]["command_digest"] = matrix_runner.canonical_json_digest(
                            artifact["entries"][0]["command"]
                        )
                    else:
                        artifact["entries"][0]["command_digest"] = "sha256:" + "f" * 64
                    write_json(h02_path, artifact)
                    value["gates"]["h02"]["artifact_digest"] = validator.sha256_digest(
                        h02_path.read_bytes()
                    )
                    with self.assertRaises(validator.ValidationError):
                        validate_bound(
                            value,
                            p0_artifact=p0_path,
                            h02_artifact=h02_path,
                            github_identity_artifact=identity_path,
                        )
                finally:
                    temporary.cleanup()

    def test_h02_dependency_binding_uses_supplied_lane_files(self) -> None:
        """A lane's dependency digest must be checked against that lane's files.

        The head and synthetic-merge receipts are validated from one aggregate
        checkout, but their Cargo.toml/Cargo.lock bytes can legitimately
        differ.  Supplying lane-specific files must therefore be sufficient
        for a PASS; silently falling back to the validator checkout would
        reject the valid receipt (or bind it to the wrong source tree).
        """

        value, p0_path, h02_path, identity_path, temporary = bound_fixture()
        lane_source_temporary = tempfile.TemporaryDirectory()
        try:
            # Lane-specific Cargo bytes are materialized by the aggregate in a
            # separate temporary root, not beneath the runner evidence root.
            # Keeping this fixture outside the evidence tree lets the strict
            # raw-log inventory check distinguish executable inputs from
            # uploaded evidence files.
            lane_root = Path(lane_source_temporary.name)
            manifest_path = lane_root / "probes/h02/openraft-tokio/Cargo.toml"
            lock_path = lane_root / "probes/h02/openraft-tokio/Cargo.lock"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_bytes(
                (ROOT / "probes/h02/openraft-tokio/Cargo.toml").read_bytes()
                + b"\n# lane-specific manifest bytes\n"
            )
            lock_path.write_bytes(
                (ROOT / "probes/h02/openraft-tokio/Cargo.lock").read_bytes()
                + b"\n# lane-specific lock bytes\n"
            )

            artifact = json.loads(h02_path.read_text(encoding="utf-8"))
            dependency = artifact["dependency_binding"]
            dependency["manifest_digest"] = validator.sha256_digest(
                manifest_path.read_bytes()
            )
            dependency["lock_digest"] = validator.sha256_digest(lock_path.read_bytes())
            write_json(h02_path, artifact)
            value["gates"]["h02"]["artifact_digest"] = validator.sha256_digest(
                h02_path.read_bytes()
            )

            # The summary is itself one of the manifest-listed evidence files;
            # refresh that chain exactly as a post-run artifact rewrite would
            # require, so the test isolates dependency-file selection rather
            # than failing on an intentionally stale manifest.
            paths = complete_artifact_paths(p0_path)
            manifest_value = json.loads(
                paths["raw_log_manifest"].read_text(encoding="utf-8")
            )
            for listed in manifest_value["files"]:
                if listed["path"] == "h02/matrix/matrix-summary.json":
                    listed["size"] = len(h02_path.read_bytes())
                    listed["digest"] = validator.sha256_digest(h02_path.read_bytes())
                    break
            write_json(paths["raw_log_manifest"], manifest_value)
            value["runner"]["raw_log_manifest_digest"] = validator.sha256_digest(
                paths["raw_log_manifest"].read_bytes()
            )
            job_identity_path = paths["github_job_artifact"]
            job_identity = json.loads(job_identity_path.read_text(encoding="utf-8"))
            job_identity["raw_log_manifest_digest"] = value["runner"][
                "raw_log_manifest_digest"
            ]
            write_json(job_identity_path, job_identity)
            value["runner"]["artifact_digest"] = validator.sha256_digest(
                job_identity_path.read_bytes()
            )

            # The differing lane bytes are accepted when explicitly supplied.
            validate_bound(
                value,
                p0_artifact=p0_path,
                h02_artifact=h02_path,
                github_identity_artifact=identity_path,
                h02_manifest_path=manifest_path,
                h02_lock_path=lock_path,
            )

            # Pointing at the ordinary validator checkout must now fail: its
            # bytes do not match the lane-bound digests above.
            with self.assertRaises(validator.ValidationError):
                validate_bound(
                    value,
                    p0_artifact=p0_path,
                    h02_artifact=h02_path,
                    github_identity_artifact=identity_path,
                    h02_manifest_path=ROOT / "probes/h02/openraft-tokio/Cargo.toml",
                    h02_lock_path=ROOT / "probes/h02/openraft-tokio/Cargo.lock",
                )
        finally:
            lane_source_temporary.cleanup()
            temporary.cleanup()

    def test_duplicate_json_members_are_rejected_instead_of_last_wins(self) -> None:
        with self.assertRaises(validator.ValidationError):
            validator._strict_json('{"schema":"first","schema":"second"}', "fixture")
        with self.assertRaises(validator.ValidationError):
            validator._strict_json('{"value":NaN}', "fixture")

    def test_merge_lane_requires_distinct_synthetic_merge_binding(self) -> None:
        value = receipt("merge")
        value["source"]["commit"] = COMMIT
        with self.assertRaises(validator.ValidationError):
            validator.validate(value, require_artifacts=False)


if __name__ == "__main__":
    unittest.main()
