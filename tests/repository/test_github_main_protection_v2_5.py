from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import validate_github_main_protection_v2_5 as protection

REPOSITORY_URL = "https://api.github.com/repos/TrillionniumFoundation/HeptaBao"
REQUIRED = {
    "heptabao-required-exact-head",
    "heptabao-required-prospective-main",
}


def branch_snapshot() -> dict:
    return {
        "name": "main",
        "protected": True,
        "protection_url": REPOSITORY_URL + "/branches/main/protection",
    }


def protection_snapshot() -> dict:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": sorted(REQUIRED),
        },
        "enforce_admins": {"enabled": True},
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "required_approving_review_count": 2,
            "require_last_push_approval": True,
            "bypass_pull_request_allowances": {
                "users": [],
                "teams": [],
                "apps": [],
            },
            "dismissal_restrictions": {
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


def validate(branch: dict | None = None, state: dict | None = None):
    return protection.validate_snapshot(
        branch or branch_snapshot(),
        state or protection_snapshot(),
        expected_repository_url=REPOSITORY_URL,
        required_contexts=REQUIRED,
    )


class GitHubMainProtectionV25Tests(unittest.TestCase):
    def test_complete_policy_is_observable_but_not_authority(self) -> None:
        result = validate()
        self.assertEqual(
            result["status"],
            "GITHUB_MAIN_PROTECTION_POLICY_SATISFIED_NOT_AUTHORITY",
        )
        self.assertEqual(result["authority_effect"], "NONE")
        self.assertEqual(result["approval_count"], 2)

    def test_unprotected_wrong_branch_or_wrong_repository_is_rejected(self) -> None:
        branch = branch_snapshot()
        branch["protected"] = False
        with self.assertRaisesRegex(protection.ProtectionError, "not marked"):
            validate(branch=branch)

        branch = branch_snapshot()
        branch["name"] = "develop"
        with self.assertRaisesRegex(protection.ProtectionError, "not for main"):
            validate(branch=branch)

        with self.assertRaisesRegex(protection.ProtectionError, "URL binding"):
            protection.validate_snapshot(
                branch_snapshot(),
                protection_snapshot(),
                expected_repository_url="https://api.github.com/repos/other/repo",
                required_contexts=REQUIRED,
            )

    def test_strict_and_complete_status_contexts_are_required(self) -> None:
        state = protection_snapshot()
        state["required_status_checks"]["strict"] = False
        with self.assertRaisesRegex(protection.ProtectionError, "must be strict"):
            validate(state=state)

        state = protection_snapshot()
        state["required_status_checks"]["contexts"].pop()
        with self.assertRaisesRegex(protection.ProtectionError, "are missing"):
            validate(state=state)

        with self.assertRaisesRegex(protection.ProtectionError, "at least one"):
            protection.validate_snapshot(
                branch_snapshot(),
                protection_snapshot(),
                expected_repository_url=REPOSITORY_URL,
                required_contexts=set(),
            )

    def test_admin_review_and_last_push_separation_are_required(self) -> None:
        mutations = [
            ("enforce_admins", "enabled", False, "enforce_admins"),
            (
                "required_pull_request_reviews",
                "dismiss_stale_reviews",
                False,
                "stale reviews",
            ),
            (
                "required_pull_request_reviews",
                "require_code_owner_reviews",
                False,
                "Code Owner",
            ),
            (
                "required_pull_request_reviews",
                "required_approving_review_count",
                1,
                "two approving",
            ),
            (
                "required_pull_request_reviews",
                "require_last_push_approval",
                False,
                "last-push",
            ),
        ]
        for section, key, value, message in mutations:
            with self.subTest(key=key):
                state = protection_snapshot()
                state[section][key] = value
                with self.assertRaisesRegex(
                    protection.ProtectionError, message
                ):
                    validate(state=state)

    def test_bypass_actors_are_rejected(self) -> None:
        for field in (
            "bypass_pull_request_allowances",
            "dismissal_restrictions",
        ):
            state = protection_snapshot()
            state["required_pull_request_reviews"][field]["users"] = [
                {"login": "administrator"}
            ]
            with self.assertRaisesRegex(
                protection.ProtectionError, "must not grant bypass"
            ):
                validate(state=state)

    def test_force_push_delete_unresolved_and_nonlinear_policies_fail(self) -> None:
        mutations = [
            ("allow_force_pushes", True, "must be false"),
            ("allow_deletions", True, "must be false"),
            ("required_conversation_resolution", False, "must be true"),
            ("required_linear_history", False, "must be true"),
            ("lock_branch", True, "permanently locked"),
        ]
        for field, value, message in mutations:
            with self.subTest(field=field):
                state = protection_snapshot()
                state[field]["enabled"] = value
                with self.assertRaisesRegex(
                    protection.ProtectionError, message
                ):
                    validate(state=state)


if __name__ == "__main__":
    unittest.main()
