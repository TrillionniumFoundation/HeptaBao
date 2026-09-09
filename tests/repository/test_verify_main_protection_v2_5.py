from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_main_protection_v2_5.py"
SPEC = importlib.util.spec_from_file_location("verify_main_protection_v2_5", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class MainProtectionVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.required_checks = {
            "exact-head / full repository qualification",
            "prospective main merge / repository qualification",
            "CodeQL",
        }
        self.protection = {
            "required_status_checks": {
                "strict": True,
                "contexts": sorted(self.required_checks),
                "checks": [],
            },
            "enforce_admins": {"enabled": True},
            "required_pull_request_reviews": {
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True,
                "require_last_push_approval": True,
                "required_approving_review_count": 2,
                "bypass_pull_request_allowances": {
                    "users": [],
                    "teams": [],
                    "apps": [],
                },
            },
            "required_conversation_resolution": {"enabled": True},
            "required_linear_history": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "lock_branch": {"enabled": False},
        }
        self.rulesets = [
            {
                "id": 101,
                "target": "branch",
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": {
                    "ref_name": {
                        "include": ["refs/heads/main"],
                        "exclude": [],
                    }
                },
            }
        ]

    def test_complete_configuration_passes_but_still_requires_hostile_evidence(self) -> None:
        result = verifier.verify(self.protection, self.rulesets, self.required_checks)
        self.assertTrue(result["configuration_pass"])
        self.assertTrue(result["hostile_enforcement_required"])
        self.assertEqual(result["authority_effect"], "NONE")

    def test_missing_exact_head_check_fails(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["required_status_checks"]["contexts"].remove(
            "exact-head / full repository qualification"
        )
        with self.assertRaisesRegex(verifier.ProtectionError, "missing required checks"):
            verifier.verify(protection, self.rulesets, self.required_checks)

    def test_admin_bypass_fails(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["enforce_admins"]["enabled"] = False
        with self.assertRaisesRegex(verifier.ProtectionError, "administrators"):
            verifier.verify(protection, self.rulesets, self.required_checks)

    def test_one_approval_fails(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["required_pull_request_reviews"]["required_approving_review_count"] = 1
        with self.assertRaisesRegex(verifier.ProtectionError, "two approvals"):
            verifier.verify(protection, self.rulesets, self.required_checks)

    def test_stale_review_acceptance_fails(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["required_pull_request_reviews"]["dismiss_stale_reviews"] = False
        with self.assertRaisesRegex(verifier.ProtectionError, "Stale|stale"):
            verifier.verify(protection, self.rulesets, self.required_checks)

    def test_last_pusher_self_approval_fails(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["required_pull_request_reviews"]["require_last_push_approval"] = False
        with self.assertRaisesRegex(verifier.ProtectionError, "last-push"):
            verifier.verify(protection, self.rulesets, self.required_checks)

    def test_pull_request_bypass_actor_fails(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["required_pull_request_reviews"]["bypass_pull_request_allowances"][
            "apps"
        ] = [{"slug": "automation"}]
        with self.assertRaisesRegex(verifier.ProtectionError, "bypass allowance"):
            verifier.verify(protection, self.rulesets, self.required_checks)

    def test_ruleset_bypass_actor_fails(self) -> None:
        rulesets = copy.deepcopy(self.rulesets)
        rulesets[0]["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
        with self.assertRaisesRegex(verifier.ProtectionError, "bypass actors"):
            verifier.verify(self.protection, rulesets, self.required_checks)

    def test_force_push_or_delete_fails(self) -> None:
        for field, fragment in (
            ("allow_force_pushes", "force pushes"),
            ("allow_deletions", "deletion"),
        ):
            with self.subTest(field=field):
                protection = copy.deepcopy(self.protection)
                protection[field]["enabled"] = True
                with self.assertRaisesRegex(verifier.ProtectionError, fragment):
                    verifier.verify(protection, self.rulesets, self.required_checks)

    def test_unresolved_conversations_or_nonlinear_history_fails(self) -> None:
        for field, fragment in (
            ("required_conversation_resolution", "conversations"),
            ("required_linear_history", "linear history"),
        ):
            with self.subTest(field=field):
                protection = copy.deepcopy(self.protection)
                protection[field]["enabled"] = False
                with self.assertRaisesRegex(verifier.ProtectionError, fragment):
                    verifier.verify(protection, self.rulesets, self.required_checks)


if __name__ == "__main__":
    unittest.main()
