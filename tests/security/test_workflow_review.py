"""Regression cases from PR68 review; parsing only, no candidate execution."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from test_workflow_trust import SAFE, ROOT, policy


class WorkflowReviewTests(unittest.TestCase):
    def reject(self, text, filename="fixture.yml"):
        with self.assertRaises(policy.PolicyError):
            policy.validate_text(text, filename)

    def job_field(self, field):
        return SAFE.replace("    runs-on:", field + "\n    runs-on:")

    def test_self_hosted_scalar_is_rejected(self):
        self.reject(SAFE.replace("ubuntu-24.04", "self-hosted"))

    def test_runner_lists_are_not_a_hosted_proof(self):
        for value in ["[self-hosted, production]", "[ubuntu-24.04]", "[]"]:
            with self.subTest(value=value):
                self.reject(SAFE.replace("ubuntu-24.04", value))

    def test_runner_group_mapping_is_rejected(self):
        self.reject(SAFE.replace("ubuntu-24.04", "{group: production, labels: linux}"))

    def test_dynamic_runner_is_rejected(self):
        self.reject(SAFE.replace("ubuntu-24.04", "${{ inputs.runner }}"))

    def test_unknown_runner_label_is_rejected(self):
        self.reject(SAFE.replace("ubuntu-24.04", "production-runner"))

    def test_environment_delegation_scalar_or_object_is_rejected(self):
        for value in ["production", "{name: production}", "${{ inputs.environment }}"]:
            with self.subTest(value=value):
                self.reject(self.job_field(f"    environment: {value}"))

    def test_job_container_delegation_is_rejected(self):
        self.reject(self.job_field("    container: ubuntu:24.04"))

    def test_service_containers_are_rejected(self):
        self.reject(self.job_field("    services: {db: {image: postgres:latest}}"))

    def test_dynamic_defaults_are_rejected(self):
        self.reject(self.job_field("    defaults: ${{ inputs.defaults }}"))

    def test_default_shell_indirection_is_rejected(self):
        self.reject(self.job_field("    defaults: {run: {shell: '${{ inputs.shell }}'}}"))

    def test_static_bash_defaults_are_accepted(self):
        policy.validate_text(self.job_field("    defaults: {run: {shell: bash}}"))

    def test_step_shell_is_closed(self):
        self.reject(SAFE.replace("      - run:", "      - shell: ${{ inputs.shell }}\n        run:"))

    def test_working_directory_cannot_escape_or_be_dynamic(self):
        for value in ["/root", "../other", "${{ inputs.path }}", "a/../../other"]:
            with self.subTest(value=value):
                self.reject(SAFE.replace("      - run:", f"      - working-directory: {value}\n        run:"))

    def test_github_token_dot_reference_is_rejected(self):
        self.reject(SAFE.replace("python -m unittest discover", "echo ${{ github.token }}"))

    def test_github_token_bracket_reference_is_rejected(self):
        self.reject(SAFE + "\nenv:\n  X: ${{ github['token'] }}\n")

    def test_event_token_reference_is_rejected(self):
        self.reject(SAFE + "\nenv:\n  X: ${{ github.event.inputs.access_token }}\n")

    def test_whole_github_context_is_not_token_free(self):
        for value in ["${{ github }}", "${{ toJSON(github) }}"]:
            with self.subTest(value=value):
                self.reject(SAFE + f"\nenv:\n  X: {value}\n")

    def test_literal_credential_bearing_keys_are_rejected(self):
        for key in ["TOKEN", "GH_TOKEN", "password", "username", "registry", "credentials", "ssh-key", "private-key", "api-key"]:
            with self.subTest(key=key):
                self.reject(SAFE + f"\nenv:\n  {key}: disposable-fixture\n")

    def test_dynamic_environment_map_cannot_hide_credential_keys(self):
        self.reject(self.job_field("    env: ${{ fromJSON(inputs.env) }}"))
        self.reject(SAFE.replace("      - run:", "      - env: ${{ fromJSON(inputs.env) }}\n        run:"))

    def test_mutable_checkout_action_is_rejected(self):
        self.reject(SAFE.replace("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7"))

    def test_arbitrary_pinned_action_is_not_implicitly_reviewed(self):
        self.reject(SAFE.replace("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "example/fixture@" + "a" * 40))

    def test_local_docker_mutable_and_dynamic_actions_are_rejected(self):
        for value in ["./.github/actions/hidden", "docker://ubuntu:latest", "docker://ubuntu@sha256:" + "1" * 64,
                      "actions/setup-python@main", "${{ inputs.action }}"]:
            with self.subTest(value=value):
                self.reject(SAFE.replace("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", value))

    def test_movable_or_short_checkout_refs_are_rejected(self):
        for value in ["main", "deadbeef", "${{ inputs.ref }}"]:
            with self.subTest(value=value):
                self.reject(SAFE.replace("${{ github.event.pull_request.head.sha }}", value))

    def test_fixed_sha_ref_is_accepted(self):
        policy.validate_text(SAFE.replace("${{ github.event.pull_request.head.sha }}", "a" * 40))

    def test_env_sha_alias_must_resolve_to_exact_source(self):
        text = SAFE.replace("${{ github.event.pull_request.head.sha }}", "${{ env.SOURCE_SHA }}")
        self.reject(text)
        self.reject(text + "\nenv: {SOURCE_SHA: main}\n")
        policy.validate_text(text + "\nenv: {SOURCE_SHA: '${{ github.sha }}'}\n")

    def test_step_env_cannot_shadow_a_safe_source_ref_with_branch(self):
        text = SAFE.replace("${{ github.event.pull_request.head.sha }}", "${{ env.SOURCE_SHA }}")
        text += "\nenv: {SOURCE_SHA: '${{ github.sha }}'}\n"
        self.reject(text.replace("        with:", "        env: {SOURCE_SHA: main}\n        with:"))

    def test_checkout_repository_and_path_are_constrained(self):
        self.reject(SAFE.replace("          ref:", "          repository: example/other\n          ref:"))
        self.reject(SAFE.replace("          ref:", "          path: ../other\n          ref:"))

    def test_pull_request_title_cannot_be_interpolated_into_shell(self):
        self.reject(SAFE.replace("python -m unittest discover", "echo '${{ github.event.pull_request.title }}'"))

    def test_static_matrix_argument_is_bounded(self):
        text = self.job_field("    strategy: {matrix: {variant: [safe-one, safe-two]}}")
        policy.validate_text(text.replace("python -m unittest discover", "echo '${{ matrix.variant }}'"))

    def test_matrix_expression_or_shell_metacharacters_are_rejected(self):
        for value in ["\"bad;exit 0\"", "'${{ inputs.variant }}'", "../outside"]:
            with self.subTest(value=value):
                text = self.job_field(f"    strategy: {{matrix: {{variant: [{value}]}}}}")
                self.reject(text.replace("python -m unittest discover", "echo '${{ matrix.variant }}'"))

    def test_dynamic_first_command_selector_is_rejected(self):
        self.reject(SAFE.replace("python -m unittest discover", '"$COMMAND"'))

    def test_exact_frozen_historical_read_token_observer_is_explicit(self):
        path = ROOT / ".github/workflows" / policy.HISTORICAL_READ_TOKEN_FILE
        policy.validate_text(path.read_text(), path.name)

    def test_changed_or_renamed_observer_does_not_inherit_token_exception(self):
        path = ROOT / ".github/workflows" / policy.HISTORICAL_READ_TOKEN_FILE
        text = path.read_text()
        self.reject(text + "\n# changed\n", path.name)
        self.reject(text, "renamed.yml")

    def test_a_step_cannot_claim_run_and_action_at_once(self):
        self.reject(SAFE.replace("      - run:", "      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97\n        run:"))

    def test_pass_is_neither_independent_admission_nor_credential_free(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / "safe.yml").write_text(SAFE)
            result = policy.validate_directory(path)
            self.assertEqual("PASS", result["result"])
            self.assertFalse(result["independent_admission"])
            self.assertFalse(result["transitive_script_sandbox"])
            self.assertIn("not credential-free", result["credential_model"])
            self.assertTrue(result["requires_live_runner_environment_and_independent_policy_controls"])

    def test_external_expression_sources_cannot_enter_environment(self):
        sources = [
            "${{ inputs.payload }}",
            "${{ vars.PAYLOAD }}",
            "${{ github.event.client_payload.payload }}",
            "${{ github.event.inputs.payload }}",
        ]
        sinks = [
            'bash -c "$X"',
            'eval "$X"',
            'curl "https://example.invalid/$X"',
            'python tool.py "$X"',
            'source "$X"',
        ]
        for source in sources:
            for sink in sinks:
                with self.subTest(source=source, sink=sink):
                    text = SAFE.replace(
                        "      - run: python -m unittest discover",
                        f"      - env: {{X: '{source}'}}\n        run: {sink}",
                    )
                    self.reject(text)

    def test_review_counterexample_with_dispatch_input_is_rejected(self):
        text = SAFE.replace(
            "  pull_request:\n",
            "  workflow_dispatch:\n    inputs:\n      payload:\n        required: true\n",
        ).replace(
            "      - run: python -m unittest discover",
            "      - env: {X: '${{ inputs.payload }}'}\n        run: bash -c \"$X\"",
        )
        self.reject(text)

    def test_allowed_environment_value_still_cannot_select_shell_program(self):
        text = SAFE.replace(
            "      - run: python -m unittest discover",
            "      - env: {SOURCE_SHA: '${{ github.sha }}'}\n        run: bash -c \"$SOURCE_SHA\"",
        )
        self.reject(text)

    def test_artifact_path_grammar_rejects_broad_or_escaping_exports(self):
        rejected = [
            "/home/runner",
            "/tmp",
            "${{ runner.temp }}/",
            "../workspace",
            "evidence/*",
            "${{ inputs.path }}/results",
            "~/secrets",
        ]
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(policy.PolicyError):
                policy.check_upload_path(value, {}, "fixture.path", lambda *_: False, {})

    def test_artifact_path_grammar_accepts_only_bounded_roots(self):
        for value in [
            "evidence/result.json",
            "${{ runner.temp }}/reviewed/result.json",
        ]:
            with self.subTest(value=value):
                policy.check_upload_path(value, {}, "fixture.path", lambda *_: False, {})

    def test_upload_registry_is_closed_and_contains_no_unsafe_paths(self):
        self.assertEqual(27, len(policy.APPROVED_UPLOAD_PATHS))
        for key, value in policy.APPROVED_UPLOAD_PATHS.items():
            with self.subTest(invocation=key):
                self.assertNotIn("*", value)
                self.assertNotIn("?", value)
                self.assertNotIn("..", value.split("/"))
                self.assertNotIn("/home/runner", value)
                self.assertNotEqual("/tmp", value.rstrip("/"))

    def test_action_inputs_are_checked_beyond_action_sha(self):
        setup = SAFE.replace(
            "      - run: python -m unittest discover",
            "      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97\n"
            "        with:\n"
            "          python-version: 3.13\n"
            "          token: disposable",
        )
        self.reject(setup)
        dynamic = setup.replace("          token: disposable\n", "").replace(
            "python-version: 3.13", "python-version: '${{ inputs.python }}'"
        )
        self.reject(dynamic)
        self.reject(SAFE.replace("          ref:", "          clean: true\n          ref:"))

    def test_validation_result_discloses_closed_artifact_model(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / "safe.yml").write_text(SAFE)
            result = policy.validate_directory(path)
            self.assertEqual(
                "EXACT_PER_INVOCATION_PATH_AND_ACTION_INPUT_SCHEMA",
                result["artifact_export_model"],
            )
            self.assertEqual("heptabao.workflow-trust-check.v2", result["schema"])

    def test_current_installed_workflows_pass_without_running_them(self):
        directory = ROOT / ".github/workflows"
        result = policy.validate_directory(directory)
        self.assertEqual("PASS", result["result"], result["failures"])
        expected = sorted(
            path.name
            for path in directory.iterdir()
            if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
        )
        self.assertEqual(expected, result["checked"])


if __name__ == "__main__":
    unittest.main()
