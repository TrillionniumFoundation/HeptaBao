from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("workflow_trust", ROOT / "scripts/validate_workflow_trust.py")
assert spec and spec.loader
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

SAFE = """name: readonly
on:
  pull_request:
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: python -m unittest discover
"""


class WorkflowTrustTests(unittest.TestCase):
    def rejected(self, text, filename="test.yml"):
        with self.assertRaises(policy.PolicyError):
            policy.validate_text(text, filename)

    def test_safe_exact_head_is_readonly(self):
        policy.validate_text(SAFE)

    def test_on_key_is_not_yaml_11_boolean(self):
        self.assertIn("on", policy.parse_workflow(SAFE))
        self.assertNotIn(True, policy.parse_workflow(SAFE))

    def test_global_loader_not_modified(self):
        self.assertIn(True, policy.yaml.safe_load("on: pull_request"))

    def test_root_write_rejected(self):
        self.rejected(SAFE.replace("contents: read", "contents: write"))

    def test_job_write_rejected(self):
        self.rejected(SAFE.replace("    runs-on:", "    permissions: {contents: write}\n    runs-on:"))

    def test_skipped_job_write_is_not_exempt(self):
        self.rejected(SAFE.replace("    runs-on:", "    if: false\n    permissions: {contents: write}\n    runs-on:"))

    def test_missing_permissions_rejected(self):
        self.rejected(SAFE.replace("permissions:\n  contents: read\n", ""))

    def test_write_all_rejected(self):
        self.rejected(SAFE.replace("permissions:\n  contents: read", "permissions: write-all"))

    def test_expression_permissions_rejected(self):
        self.rejected(SAFE.replace("contents: read", "contents: ${{ inputs.permission }}"))

    def test_oidc_permission_rejected(self):
        self.rejected(SAFE.replace("contents: read", "contents: read\n  id-token: write"))

    def test_persisted_credentials_rejected(self):
        self.rejected(SAFE.replace("persist-credentials: false", "persist-credentials: true"))

    def test_default_persistence_rejected(self):
        self.rejected(SAFE.replace("          persist-credentials: false\n", ""))

    def test_quoted_false_is_not_boolean_false(self):
        self.rejected(SAFE.replace("persist-credentials: false", "persist-credentials: 'false'"))

    def test_alternate_checkout_token_rejected(self):
        self.rejected(SAFE.replace("          ref:", "          token: ${{ inputs.token }}\n          ref:"))

    def test_ssh_key_rejected(self):
        self.rejected(SAFE.replace("          ref:", "          ssh-key: private\n          ref:"))

    def test_secret_dot_reference_rejected(self):
        self.rejected(SAFE.replace("python -m unittest discover", "echo ${{ secrets.PUBLISH_TOKEN }}"))

    def test_secret_bracket_reference_rejected(self):
        self.rejected(SAFE.replace("python -m unittest discover", "echo ${{ secrets['TOKEN'] }}"))

    def test_whole_secret_context_rejected(self):
        self.rejected(SAFE.replace("python -m unittest discover", "echo ${{ toJSON(secrets) }}"))

    def test_retired_relay_cannot_be_renamed_to_run_controller(self):
        self.rejected(SAFE.replace("python -m unittest discover", "bash .exec/run_v1_9.sh"))

    def test_retired_controller_branch_advance_cannot_select_code(self):
        self.rejected(SAFE.replace("${{ github.event.pull_request.head.sha }}",
                                   "exec/v1.9.0-full-repository-convergence-v1"))

    def test_all_three_retired_relay_names_rejected(self):
        for name in policy.RETIRED_RELAYS:
            with self.subTest(name=name):
                self.rejected(SAFE, name)

    def test_same_repository_predicate_does_not_exempt_write(self):
        text = SAFE.replace("    runs-on:", "    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on:")
        self.rejected(text.replace("contents: read", "contents: write"))

    def test_pull_request_target_rejected(self):
        self.rejected(SAFE.replace("  pull_request:", "  pull_request_target:"))

    def test_workflow_run_rejected(self):
        self.rejected(SAFE.replace("  pull_request:", "  workflow_run:"))

    def test_reusable_workflow_cannot_hide_publisher(self):
        self.rejected(SAFE.replace("    runs-on:", "    uses: owner/repo/.github/workflows/publish.yml@main\n    runs-on:"))

    def test_duplicate_permissions_rejected(self):
        self.rejected(SAFE + "\npermissions: {contents: write}\n")

    def test_nested_duplicate_permissions_rejected(self):
        self.rejected(SAFE.replace("contents: read", "contents: read\n  contents: write"))

    def test_aliases_rejected(self):
        self.rejected(SAFE.replace("contents: read", "contents: &p read") + "other: *p\n")

    def test_merge_keys_rejected(self):
        self.rejected(SAFE.replace("contents: read", "'<<': {contents: write}"))

    def test_empty_directory_not_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(policy.PolicyError):
                policy.validate_directory(Path(temp))

    def test_all_workflows_scanned_even_yaml_extension(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.yml").write_text(SAFE)
            (root / "manual.yaml").write_text(SAFE.replace("contents: read", "contents: write"))
            result = policy.validate_directory(root)
            self.assertEqual(result["result"], "FAIL")
            self.assertEqual(len(result["failures"]), 1)
            self.assertFalse(result["production_authority"])

    def test_symlinked_workflow_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.txt").write_text(SAFE)
            (root / "linked.yml").symlink_to("target.txt")
            self.assertEqual(policy.validate_directory(root)["result"], "FAIL")

    def test_size_bound_rejected(self):
        self.rejected("#" * (policy.MAX_WORKFLOW_BYTES + 1))

    def test_no_qualification_or_authority_from_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.yml").write_text(SAFE)
            result = policy.validate_directory(root)
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["authority_effect"], "NONE")
            self.assertFalse(result["production_authority"])


if __name__ == "__main__":
    unittest.main()
