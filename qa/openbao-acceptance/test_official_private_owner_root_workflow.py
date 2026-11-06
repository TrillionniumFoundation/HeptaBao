"""Source-bound negative regression for three official differential CI owner roots.

This checks only the workflow/owner admission contract, not official OpenBao
compatibility, three-process HA, external Oracle identity or production readiness.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/codex-openbao-replacement-ci.yml"
OWNER = ROOT / "qa/openbao-acceptance/owned_process.py"
STEPS = {
    "Compare strict OpenBao 2.7.0 runtime and ACL error contracts": "official-270",
    "Compare KV metadata CAS and enumeration with official OpenBao 2.6.2": "kv-cas",
    "Execute all bounded official-binary differential profiles": "official-bounded",
}


def section(workflow: str, step_name: str) -> str:
    heading = "      - name: " + step_name + "\n"
    if workflow.count(heading) != 1:
        raise AssertionError(f"expected one exact native step: {step_name}")
    start = workflow.index(heading)
    end = workflow.find("\n      - name: ", start + len(heading))
    return workflow[start:] if end < 0 else workflow[start:end]


class OfficialOwnerRootSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.owner = OWNER.read_text(encoding="utf-8")

    def test_all_three_native_profiles_create_a_distinct_new_private_parent(self):
        for name, suffix in STEPS.items():
            with self.subTest(profile=name):
                body = section(self.workflow, name)
                self.assertIn(
                    'qa_owner_parent="$(mktemp -d "$RUNNER_TEMP/heptabao-owned-'
                    + suffix + '.XXXXXXXX")"', body)
                self.assertIn('test -d "$qa_owner_parent" && test ! -L "$qa_owner_parent"', body)
                self.assertIn('test "$(stat -c %a "$qa_owner_parent")" = 700', body)
                self.assertIn('test "$(stat -c %u "$qa_owner_parent")" = "$(id -u)"', body)
                self.assertIn('export HB_QA_PROCESS_WORK_ROOT="$qa_owner_parent"', body)

    def test_owner_scope_is_not_weakened_or_globalized(self):
        self.assertEqual(self.workflow.count('export HB_QA_PROCESS_WORK_ROOT='), 3)
        self.assertNotIn('chmod -R 777', self.workflow)
        self.assertNotIn('umask 000', self.workflow)
        self.assertIn('raise OwnedFailure("owned_private_work_root_required")', self.owner)
        self.assertIn('raise OwnedFailure("owned_work_parent_not_private")', self.owner)
        self.assertIn('stat.S_IMODE(info.st_mode) != 0o700', self.owner)

    def test_exact_original_acceptance_calls_and_oracle_guards_remain(self):
        version27 = section(self.workflow, "Compare strict OpenBao 2.7.0 runtime and ACL error contracts")
        self.assertIn("--oracle-version 2.7.0", version27)
        self.assertIn("steps.oracle270_ready.outcome == 'success'", version27)
        kv = section(self.workflow, "Compare KV metadata CAS and enumeration with official OpenBao 2.6.2")
        self.assertIn("kv_metadata_cas_live.py", kv)
        self.assertIn("kv_enumeration_live.py", kv)
        bounded = section(self.workflow, "Execute all bounded official-binary differential profiles")
        self.assertIn("remote_jwks_compare", bounded)
        self.assertIn("steps.oracle_ready.outcome == 'success'", kv)
        self.assertIn("steps.oracle_ready.outcome == 'success'", bounded)

    def test_no_success_from_ignored_child_or_refused_profile(self):
        for name in STEPS:
            with self.subTest(profile=name):
                body = section(self.workflow, name)
                self.assertIn("set -euo pipefail", body)
                self.assertNotIn("|| true", body)
                self.assertNotRegex(body, r"\b(?:continue-on-error|exit 0)\b")
                self.assertIn("HB_QA_PROCESS_WORK_ROOT", body)


if __name__ == "__main__":
    unittest.main()
