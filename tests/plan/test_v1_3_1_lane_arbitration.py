from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/arbitrate_v1_3_1_lanes_v1.py"
SCHEMA = ROOT / "schemas/heptabao_v1_3_1_lane_arbitration_v1.schema.json"
SPEC = importlib.util.spec_from_file_location("v131_lane_arbitration", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# Keep the aggregate fixture tied to the same canonical step contract used by
# the receipt validator.  Calling through the loaded module avoids a second,
# silently drifting copy of the required workflow names in this test.
RECEIPT_VALIDATOR = MODULE.receipt_validator()
CANONICAL_REQUIRED_STEP_NAMES = tuple(RECEIPT_VALIDATOR.CANONICAL_REQUIRED_STEP_NAMES)

HEAD = "a" * 40
HEAD_TREE = "b" * 40
MERGE_TREE = "c" * 40
BASE = "d" * 40
MERGE = "e" * 40


def runner(kind: str, job_id: str) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    for number, name in enumerate(CANONICAL_REQUIRED_STEP_NAMES, start=1):
        steps.append(
            {
                "number": number,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-08-30T00:00:00Z",
                "completed_at": "2026-08-30T00:00:01Z",
                "outcome": "PASS",
            }
        )
    # The collector/receipt snapshot runs while the matrix job is still
    # active.  Keep that provider-visible step in the table while excluding it
    # from ``required_step_names`` exactly as production does.
    steps.append(
        {
            "number": len(steps) + 1,
            "name": "Capture numeric GitHub job/runner identity and step outcomes",
            "status": "in_progress",
            "conclusion": None,
            "started_at": "2026-08-30T00:00:02Z",
            "completed_at": None,
            "outcome": "IN_PROGRESS",
        }
    )
    step_digest = "sha256:" + hashlib.sha256(
        json.dumps(steps, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()
    return {
        "run_id": "12345",
        "run_attempt": "1",
        "job": "full-technical-matrix",
        "job_id": job_id,
        "job_name": "full-technical-matrix (" + kind + ")",
        "workflow_name": "plan-v1.3.1-head-and-merge-closure",
        "job_status": "in_progress",
        "job_conclusion": None,
        "name": "GitHub Actions 1",
        "runner_labels": ["ubuntu-24.04"],
        "runner_id": "900" + job_id[-1],
        "runner_group_id": "0",
        "runner_group": "GitHub Actions",
        "os": "Linux",
        "arch": "X64",
        "head_sha": HEAD,
        "source_kind": kind,
        "job_started_at": "2026-08-30T00:00:00Z",
        "job_completed_at": None,
        "required_step_names": list(CANONICAL_REQUIRED_STEP_NAMES),
        "steps": steps,
        "step_outcomes_digest": step_digest,
        "api_response_digest": "sha256:" + "2" * 64,
        "raw_log_manifest_digest": "sha256:" + "3" * 64,
        "artifact_digest": "sha256:" + "4" * 64,
    }


def record(kind: str, commit: str, tree: str, job_id: str) -> dict[str, Any]:
    return {
        "lane": kind,
        "receipt_path": f"{kind}/technical-completion-receipt.json",
        "receipt_digest": "sha256:" + ("a" if kind == "head" else "b") * 64,
        "arbitration_key": f"45:{HEAD}:{kind}",
        "source_commit": commit,
        "source_tree": tree,
        "source_head": HEAD,
        "source_base": BASE,
        "event_merge": MERGE,
        "runner": runner(kind, job_id),
        "technical_status": "PASS",
        "qualification": False,
        "compatibility_claim": False,
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }


def final_jobs_api_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the post-run Actions response expected by the arbiter.

    The receipt snapshot intentionally contains an in-progress collector step.
    The final API snapshot must show the same numeric job/runner identity after
    the job completed successfully, with every step completed and successful.
    """

    jobs: list[dict[str, Any]] = []
    for item in records:
        runner_value = item["runner"]
        final_steps = [
            {
                "number": step["number"],
                "name": step["name"],
                "status": "completed",
                "conclusion": "success",
                "started_at": step["started_at"],
                "completed_at": "2026-08-30T00:00:03Z",
            }
            for step in runner_value["steps"]
        ]
        jobs.append(
            {
                "id": int(runner_value["job_id"]),
                "run_id": int(runner_value["run_id"]),
                "run_attempt": int(runner_value["run_attempt"]),
                "name": runner_value["job_name"],
                "workflow_name": runner_value["workflow_name"],
                "head_sha": runner_value["head_sha"],
                "status": "completed",
                "conclusion": "success",
                "started_at": runner_value["job_started_at"],
                "completed_at": "2026-08-30T00:00:03Z",
                "runner_id": int(runner_value["runner_id"]),
                "runner_name": runner_value["name"],
                "runner_group_id": int(runner_value["runner_group_id"]),
                "runner_group_name": runner_value["runner_group"],
                "labels": list(runner_value["runner_labels"]),
                "steps": final_steps,
            }
        )
    return {"total_count": len(jobs), "jobs": jobs}


def aggregate_fixture() -> dict[str, Any]:
    """Build a schema-valid PASS aggregate without invoking the arbiter."""

    return {
        "schema": "heptabao.v1-3-1-lane-arbitration.v1",
        "repository": MODULE.REPOSITORY,
        "pull_request_number": "45",
        "head_sha": HEAD,
        "head_tree": HEAD_TREE,
        "merge_tree": MERGE_TREE,
        "base_sha": BASE,
        "synthetic_merge_sha": MERGE,
        "required_lanes": ["head", "merge"],
        "status": "PASS",
        "failure_class": "NONE",
        "receipts": [
            record("head", HEAD, HEAD_TREE, "101"),
            record("merge", MERGE, MERGE_TREE, "102"),
        ],
        "failure_reasons": [],
        "supersession": {
            "policy": "CANCEL_OLDER_RUN_AND_RETAIN_HISTORY",
            "duplicate_keys": [],
            "superseded_receipts": [],
            "ancestor_only_rejected": True,
            "selection_basis": "EXACT_HEAD_AND_SYNTHETIC_MERGE_ONLY",
        },
        "qualification": False,
        "compatibility_claim": False,
        "selected_candidates": [],
        "selection_effect": "NONE",
        "production_authority": False,
        "migration_authority": False,
        "release_authority": False,
        "authority_effect": "NONE",
    }


class LaneArbitrationTests(unittest.TestCase):
    def test_schema_is_valid_draft_2020_12(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "heptabao.v1-3-1-lane-arbitration.v1",
        )
        self.assertEqual(
            schema["$defs"]["runner_step"]["properties"]["outcome"]["enum"],
            ["PASS", "FAIL", "BLOCKED", "SKIPPED", "IN_PROGRESS", "QUEUED"],
        )

    def test_schema_loader_pins_repository_schema_identity(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "arbitration-schema.json"
            for field, replacement in (
                ("$schema", "https://json-schema.org/draft/07/schema#"),
                ("$id", "https://example.invalid/arbitration.json"),
            ):
                mutated = json.loads(json.dumps(schema))
                mutated[field] = replacement
                path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.subTest(field=field):
                    with self.assertRaises(MODULE.ArbitrationError):
                        MODULE._load_schema(path)

            mutated = json.loads(json.dumps(schema))
            mutated["properties"]["schema"]["const"] = "forged.schema"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaises(MODULE.ArbitrationError):
                MODULE._load_schema(path)

            # A valid schema reached through a symlink is still outside the
            # repository-controlled trust root.  The loader must reject the
            # alias before opening it (rather than relying on URI/contents).
            alias = Path(temporary) / "schema-alias.json"
            try:
                alias.symlink_to(SCHEMA)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink creation unavailable: {error}")
            with self.assertRaises(MODULE.ArbitrationError):
                MODULE._load_schema(alias)

    def test_schema_binds_nested_runner_step_lifecycle(self) -> None:
        """Aggregate schemas must preserve provider status semantics too."""

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        checker = Draft202012Validator(schema)
        base = aggregate_fixture()
        self.assertEqual([], list(checker.iter_errors(base)))

        mutations: list[tuple[str, dict[str, Any]]] = []
        value = json.loads(json.dumps(base))
        value["receipts"][0]["runner"]["steps"][0]["outcome"] = "FAIL"
        mutations.append(("completed-success-with-fail-outcome", value))

        value = json.loads(json.dumps(base))
        value["receipts"][0]["runner"]["steps"][-1]["conclusion"] = "success"
        mutations.append(("in-progress-with-conclusion", value))

        value = json.loads(json.dumps(base))
        value["receipts"][0]["runner"]["steps"][-1].update(
            status="queued", conclusion=None, started_at=None, completed_at=None, outcome="IN_PROGRESS"
        )
        mutations.append(("queued-with-in-progress-outcome", value))

        value = json.loads(json.dumps(base))
        value["receipts"][0]["runner"].update(job_status="completed", job_conclusion=None)
        mutations.append(("completed-job-without-success-conclusion", value))

        value = json.loads(json.dumps(base))
        value["receipts"][0]["runner"].update(job_status="in_progress", job_conclusion="success")
        mutations.append(("active-job-with-conclusion", value))

        for label, mutated in mutations:
            with self.subTest(label=label):
                self.assertTrue(
                    list(checker.iter_errors(mutated)),
                    f"schema accepted contradictory {label}",
                )

    def test_pull_request_pass_requires_exact_head_and_distinct_merge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "head").mkdir()
            (root / "merge").mkdir()
            head_path = root / "head/technical-completion-receipt.json"
            merge_path = root / "merge/technical-completion-receipt.json"
            head_path.write_text("{}\n", encoding="utf-8")
            merge_path.write_text("{}\n", encoding="utf-8")
            by_path = {
                head_path: record("head", HEAD, HEAD_TREE, "101"),
                merge_path: record("merge", MERGE, MERGE_TREE, "102"),
            }
            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ):
                result = MODULE.arbitrate(
                    root,
                    repository=MODULE.REPOSITORY,
                    pull_request_number="45",
                    head_sha=HEAD,
                    base_sha=BASE,
                    synthetic_merge_sha=MERGE,
                    expected_run_id="12345",
                    expected_run_attempt="1",
                    expected_head_tree=HEAD_TREE,
                )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["failure_class"], "NONE")
            self.assertEqual(result["required_lanes"], ["head", "merge"])
            self.assertEqual(result["head_tree"], HEAD_TREE)
            self.assertEqual({item["lane"] for item in result["receipts"]}, {"head", "merge"})

    def test_final_jobs_api_binds_completed_success_for_each_lane(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "head").mkdir()
            (root / "merge").mkdir()
            head_path = root / "head/technical-completion-receipt.json"
            merge_path = root / "merge/technical-completion-receipt.json"
            head_path.write_text("{}\n", encoding="utf-8")
            merge_path.write_text("{}\n", encoding="utf-8")
            records = [
                record("head", HEAD, HEAD_TREE, "101"),
                record("merge", MERGE, MERGE_TREE, "102"),
            ]
            by_path = {head_path: records[0], merge_path: records[1]}
            api_path = root / "final-jobs-api.json"
            api_raw = (
                json.dumps(final_jobs_api_payload(records), indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            api_path.write_bytes(api_raw)
            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ), mock.patch.object(
                MODULE,
                "_git_tree",
                side_effect=lambda _root, commit: {HEAD: HEAD_TREE, MERGE: MERGE_TREE}[commit],
            ):
                result = MODULE.arbitrate(
                    root,
                    repository=MODULE.REPOSITORY,
                    pull_request_number="45",
                    head_sha=HEAD,
                    base_sha=BASE,
                    synthetic_merge_sha=MERGE,
                    expected_run_id="12345",
                    expected_run_attempt="1",
                    expected_head_tree=HEAD_TREE,
                    expected_merge_tree=MERGE_TREE,
                    git_root=root,
                    require_git_tree_binding=True,
                    final_jobs_api=api_path,
                )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["head_tree"], HEAD_TREE)
            self.assertEqual(result["merge_tree"], MERGE_TREE)
            self.assertEqual(result["final_jobs_api_digest"], MODULE.sha256_digest(api_raw))
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            self.assertEqual([], list(Draft202012Validator(schema).iter_errors(result)))

            # A stale/in-progress final response cannot be promoted, even when
            # the initial receipt snapshot and all lane fields are otherwise
            # valid.
            tampered = final_jobs_api_payload(records)
            tampered["jobs"][0]["status"] = "in_progress"
            tampered["jobs"][0]["conclusion"] = None
            api_path.write_text(json.dumps(tampered, sort_keys=True) + "\n", encoding="utf-8")
            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ), mock.patch.object(
                MODULE,
                "_git_tree",
                side_effect=lambda _root, commit: {HEAD: HEAD_TREE, MERGE: MERGE_TREE}[commit],
            ):
                with self.assertRaises(MODULE.ArbitrationError):
                    MODULE.arbitrate(
                        root,
                        repository=MODULE.REPOSITORY,
                        pull_request_number="45",
                        head_sha=HEAD,
                        base_sha=BASE,
                        synthetic_merge_sha=MERGE,
                        expected_run_id="12345",
                        expected_run_attempt="1",
                        expected_head_tree=HEAD_TREE,
                        expected_merge_tree=MERGE_TREE,
                        git_root=root,
                        require_git_tree_binding=True,
                        final_jobs_api=api_path,
                    )

            # Keep all required names and PASS outcomes intact while changing
            # only the collector-step name. The final API must still match the
            # receipt's step prefix, not merely satisfy a set-of-names check.
            prefix_tampered = final_jobs_api_payload(records)
            collector_index = len(CANONICAL_REQUIRED_STEP_NAMES)
            prefix_tampered["jobs"][0]["steps"][collector_index]["name"] = (
                "forged collector step"
            )
            api_path.write_text(
                json.dumps(prefix_tampered, sort_keys=True) + "\n", encoding="utf-8"
            )
            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ), mock.patch.object(
                MODULE,
                "_git_tree",
                side_effect=lambda _root, commit: {HEAD: HEAD_TREE, MERGE: MERGE_TREE}[commit],
            ):
                with self.assertRaises(MODULE.ArbitrationError):
                    MODULE.arbitrate(
                        root,
                        repository=MODULE.REPOSITORY,
                        pull_request_number="45",
                        head_sha=HEAD,
                        base_sha=BASE,
                        synthetic_merge_sha=MERGE,
                        expected_run_id="12345",
                        expected_run_attempt="1",
                        expected_head_tree=HEAD_TREE,
                        expected_merge_tree=MERGE_TREE,
                        git_root=root,
                        require_git_tree_binding=True,
                        final_jobs_api=api_path,
                    )

    def test_post_run_mode_requires_final_jobs_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "head").mkdir()
            (root / "merge").mkdir()
            head_path = root / "head/technical-completion-receipt.json"
            merge_path = root / "merge/technical-completion-receipt.json"
            head_path.write_text("{}\n", encoding="utf-8")
            merge_path.write_text("{}\n", encoding="utf-8")
            by_path = {
                head_path: record("head", HEAD, HEAD_TREE, "101"),
                merge_path: record("merge", MERGE, MERGE_TREE, "102"),
            }
            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ):
                with self.assertRaises(MODULE.ArbitrationError):
                    MODULE.arbitrate(
                        root,
                        repository=MODULE.REPOSITORY,
                        pull_request_number="45",
                        head_sha=HEAD,
                        base_sha=BASE,
                        synthetic_merge_sha=MERGE,
                        expected_head_tree=HEAD_TREE,
                        expected_merge_tree=MERGE_TREE,
                        git_root=root,
                        require_git_tree_binding=True,
                        require_final_jobs_api=True,
                    )


    def test_final_jobs_api_rejects_boolean_numeric_fields(self) -> None:
        """JSON booleans must never compare equal to provider integer IDs."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = [
                record("head", HEAD, HEAD_TREE, "101"),
                record("merge", MERGE, MERGE_TREE, "102"),
            ]
            api_path = root / "final-jobs-api.json"
            mutations = (
                ("run_attempt", True),
                ("runner_group_id", False),
            )
            for field, replacement in mutations:
                with self.subTest(field=field):
                    payload = final_jobs_api_payload(records)
                    payload["jobs"][0][field] = replacement
                    api_path.write_text(
                        json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
                    )
                    with self.assertRaises(MODULE.ArbitrationError):
                        MODULE._validate_final_jobs_api(
                            api_path,
                            records,
                            expected_run_id="12345",
                            expected_run_attempt="1",
                        )

    def test_final_jobs_api_binds_run_identity_without_expected_arguments(self) -> None:
        """Provider run IDs must remain bound to each receipt lane locally."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = [
                record("head", HEAD, HEAD_TREE, "101"),
                record("merge", MERGE, MERGE_TREE, "102"),
            ]
            api_path = root / "final-jobs-api.json"
            for field in ("run_id", "run_attempt"):
                with self.subTest(field=field):
                    payload = final_jobs_api_payload(records)
                    payload["jobs"][0][field] += 1
                    api_path.write_text(
                        json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
                    )
                    with self.assertRaises(MODULE.ArbitrationError):
                        MODULE._validate_final_jobs_api(
                            api_path,
                            records,
                        )

    def test_git_tree_binding_checks_head_and_merge_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "head").mkdir()
            (root / "merge").mkdir()
            head_path = root / "head/technical-completion-receipt.json"
            merge_path = root / "merge/technical-completion-receipt.json"
            head_path.write_text("{}\n", encoding="utf-8")
            merge_path.write_text("{}\n", encoding="utf-8")
            by_path = {
                head_path: record("head", HEAD, HEAD_TREE, "101"),
                merge_path: record("merge", MERGE, MERGE_TREE, "102"),
            }

            def resolve_tree(_git_root: Path, commit: str) -> str:
                return {HEAD: HEAD_TREE, MERGE: MERGE_TREE}[commit]

            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ), mock.patch.object(MODULE, "_git_tree", side_effect=resolve_tree) as resolver:
                result = MODULE.arbitrate(
                    root,
                    repository=MODULE.REPOSITORY,
                    pull_request_number="45",
                    head_sha=HEAD,
                    base_sha=BASE,
                    synthetic_merge_sha=MERGE,
                    expected_head_tree=HEAD_TREE,
                    expected_merge_tree=MERGE_TREE,
                    git_root=root,
                    require_git_tree_binding=True,
                )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["head_tree"], HEAD_TREE)
            self.assertEqual(result["merge_tree"], MERGE_TREE)
            self.assertEqual(
                [call.args[1] for call in resolver.call_args_list],
                [HEAD, MERGE],
            )

            # If either immutable commit resolves to a different tree, the
            # aggregate must reject the lane pair rather than trusting receipt
            # self-reporting.
            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ), mock.patch.object(
                MODULE,
                "_git_tree",
                side_effect=lambda _root, commit: HEAD_TREE if commit == HEAD else "f" * 40,
            ):
                with self.assertRaises(MODULE.ArbitrationError):
                    MODULE.arbitrate(
                        root,
                        repository=MODULE.REPOSITORY,
                        pull_request_number="45",
                        head_sha=HEAD,
                        base_sha=BASE,
                        synthetic_merge_sha=MERGE,
                        expected_head_tree=HEAD_TREE,
                        expected_merge_tree=MERGE_TREE,
                        git_root=root,
                        require_git_tree_binding=True,
                    )

    def test_merge_parent_binding_requires_exact_base_then_head(self) -> None:
        """The production flag rejects a relabeled non-merge commit."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "head").mkdir()
            (root / "merge").mkdir()
            head_path = root / "head/technical-completion-receipt.json"
            merge_path = root / "merge/technical-completion-receipt.json"
            head_path.write_text("{}\n", encoding="utf-8")
            merge_path.write_text("{}\n", encoding="utf-8")
            by_path = {
                head_path: record("head", HEAD, HEAD_TREE, "101"),
                merge_path: record("merge", MERGE, MERGE_TREE, "102"),
            }

            with mock.patch.object(
                MODULE,
                "_validate_one",
                side_effect=lambda path, **_: by_path[path],
            ), mock.patch.object(
                MODULE,
                "_git_tree",
                side_effect=lambda _root, commit: {HEAD: HEAD_TREE, MERGE: MERGE_TREE}[commit],
            ), mock.patch.object(
                MODULE,
                "_git_parents",
                return_value=(MERGE, BASE, HEAD),
            ) as parent_resolver:
                result = MODULE.arbitrate(
                    root,
                    repository=MODULE.REPOSITORY,
                    pull_request_number="45",
                    head_sha=HEAD,
                    base_sha=BASE,
                    synthetic_merge_sha=MERGE,
                    expected_head_tree=HEAD_TREE,
                    expected_merge_tree=MERGE_TREE,
                    git_root=root,
                    require_git_tree_binding=True,
                    require_merge_parent_binding=True,
                )
            self.assertEqual(result["status"], "PASS")
            parent_resolver.assert_called_once_with(root, MERGE)

            # A first-parent/head swap and a three-parent object are both
            # invalid synthetic merge identities, even when their trees match.
            for malformed in ((MERGE, HEAD, BASE), (MERGE, BASE, HEAD, "f" * 40)):
                with self.subTest(parents=malformed):
                    with mock.patch.object(
                        MODULE,
                        "_validate_one",
                        side_effect=lambda path, **_: by_path[path],
                    ), mock.patch.object(
                        MODULE,
                        "_git_tree",
                        side_effect=lambda _root, commit: {HEAD: HEAD_TREE, MERGE: MERGE_TREE}[commit],
                    ), mock.patch.object(MODULE, "_git_parents", return_value=malformed):
                        with self.assertRaises(MODULE.ArbitrationError):
                            MODULE.arbitrate(
                                root,
                                repository=MODULE.REPOSITORY,
                                pull_request_number="45",
                                head_sha=HEAD,
                                base_sha=BASE,
                                synthetic_merge_sha=MERGE,
                                expected_head_tree=HEAD_TREE,
                                expected_merge_tree=MERGE_TREE,
                                git_root=root,
                                require_git_tree_binding=True,
                                require_merge_parent_binding=True,
                            )

    def test_failure_class_prioritizes_duplicate_evidence(self) -> None:
        self.assertEqual(MODULE._failure_class("expected exactly 2 receipts: duplicate key"), "DUPLICATE")
        self.assertEqual(MODULE._failure_class("expected exactly 2 lane receipts, found 3"), "UNEXECUTED")

    def test_companion_lookup_does_not_duplicate_immediate_parent(self) -> None:
        """A normal downloaded lane layout resolves one companion exactly once."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lane = root / "head"
            lane.mkdir()
            receipt_path = lane / "technical-completion-receipt.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            companion = lane / "p0/classified-result.json"
            companion.parent.mkdir()
            companion.write_text("{}\n", encoding="utf-8")
            self.assertEqual(MODULE._companion_path(receipt_path, "p0/classified-result.json"), companion)

    def test_companion_lookup_stops_at_own_downloaded_artifact_boundary(self) -> None:
        """A lane may not search sibling artifacts, the host root, or /root."""

        with tempfile.TemporaryDirectory() as temporary:
            input_root = Path(temporary) / "receipts"
            lane = input_root / "v1.3.1-head-technical-receipt"
            nested = lane / "nested"
            nested.mkdir(parents=True)
            receipt_path = nested / "technical-completion-receipt.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            companion = lane / "root/github-identity-verification.json"
            companion.parent.mkdir()
            companion.write_text("{}\n", encoding="utf-8")

            self.assertEqual(
                MODULE._companion_path(
                    receipt_path,
                    "root/github-identity-verification.json",
                    input_root=input_root,
                ),
                companion,
            )

            # A look-alike companion outside the lane artifact must not become
            # a second candidate and must never cause traversal toward /root.
            sibling = input_root / "root/github-identity-verification.json"
            sibling.parent.mkdir()
            sibling.write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                MODULE._companion_path(
                    receipt_path,
                    "root/github-identity-verification.json",
                    input_root=input_root,
                ),
                companion,
            )

    def test_flattened_companion_lookup_is_bounded_by_input_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            input_root = Path(temporary)
            receipt_path = input_root / "technical-completion-receipt.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            companion = input_root / "root/github-identity-verification.json"
            companion.parent.mkdir()
            companion.write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                MODULE._companion_path(
                    receipt_path,
                    "root/github-identity-verification.json",
                    input_root=input_root,
                ),
                companion,
            )

    def test_artifact_path_components_reject_symlink_and_traversal_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            lane = real / "head"
            lane.mkdir(parents=True)
            receipt_path = lane / "technical-completion-receipt.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            companion = lane / "p0/classified-result.json"
            companion.parent.mkdir()
            companion.write_text("{}\n", encoding="utf-8")
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink support unavailable: {error}")
            with self.assertRaises(MODULE.ArbitrationError):
                MODULE.discover_receipts(alias)
            with self.assertRaises(MODULE.ArbitrationError):
                MODULE._companion_path(receipt_path, "../outside.json")

    def test_missing_receipts_write_schema_valid_fail_and_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "aggregate.json"
            completed = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--input-root",
                    str(root),
                    "--output",
                    str(output),
                    "--repository",
                    MODULE.REPOSITORY,
                    "--pull-request-number",
                    "45",
                    "--head-sha",
                    HEAD,
                    "--base-sha",
                    BASE,
                    "--synthetic-merge-sha",
                    MERGE,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertTrue(output.is_file())
            value = json.loads(output.read_text(encoding="utf-8"))
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            self.assertEqual([], list(Draft202012Validator(schema).iter_errors(value)))
            self.assertEqual(value["status"], "FAIL")
            self.assertEqual(value["failure_class"], "UNEXECUTED")
            self.assertEqual(value["receipts"], [])

    def test_duplicate_lane_or_runner_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a").mkdir()
            (root / "b").mkdir()
            p1 = root / "a/technical-completion-receipt.json"
            p2 = root / "b/technical-completion-receipt.json"
            p1.write_text("{}\n", encoding="utf-8")
            p2.write_text("{}\n", encoding="utf-8")
            duplicate = record("head", HEAD, HEAD_TREE, "101")
            with mock.patch.object(MODULE, "_validate_one", return_value=duplicate):
                with self.assertRaises(MODULE.ArbitrationError):
                    MODULE.arbitrate(
                        root,
                        repository=MODULE.REPOSITORY,
                        pull_request_number="45",
                        head_sha=HEAD,
                        base_sha=BASE,
                        synthetic_merge_sha=MERGE,
                    )

    def test_merge_ancestor_or_wrong_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "head").mkdir()
            (root / "merge").mkdir()
            p1 = root / "head/technical-completion-receipt.json"
            p2 = root / "merge/technical-completion-receipt.json"
            p1.write_text("{}\n", encoding="utf-8")
            p2.write_text("{}\n", encoding="utf-8")
            values = {
                p1: record("head", HEAD, HEAD_TREE, "101"),
                p2: record("merge", HEAD, MERGE_TREE, "102"),
            }
            with mock.patch.object(MODULE, "_validate_one", side_effect=lambda path, **_: values[path]):
                with self.assertRaises(MODULE.ArbitrationError):
                    MODULE.arbitrate(
                        root,
                        repository=MODULE.REPOSITORY,
                        pull_request_number="45",
                        head_sha=HEAD,
                        base_sha=BASE,
                        synthetic_merge_sha=MERGE,
                    )

    def test_duplicate_json_members_are_rejected(self) -> None:
        with self.assertRaises(MODULE.ArbitrationError):
            MODULE.strict_json('{"status":"PASS","status":"FAIL"}', "fixture")


if __name__ == "__main__":
    unittest.main()
