#!/usr/bin/env python3
"""Exact UID=-2 cases observed on macOS, without importing a QA manager."""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import sys
import unittest

if "mac_uid_patch_under_test" in sys.modules:
    patch = sys.modules["mac_uid_patch_under_test"]
else:
    source = Path(__file__).resolve().parents[1] / "prepare_macos_launchctl_uid_patch.py"
    spec = importlib.util.spec_from_file_location("mac_uid_patch_under_test", source)
    patch = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(patch)


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def rows_function(source):
    tree = ast.parse("class OwnedLaunchd:\n" + source)
    method = tree.body[0].body[0]
    module = ast.Module(body=[method], type_ignores=[])
    namespace = {"need": need}
    exec(compile(ast.fix_missing_locations(module), "<exact-manager-rows>", "exec"), namespace)
    return namespace["_rows"]


class Owner:
    def __init__(self, data, exit_code=0, error=b""):
        self.data = data
        self.exit_code = exit_code
        self.error = error
        self.calls = []

    def _call(self, label, argv, **kwargs):
        self.calls.append((label, argv, kwargs))
        return {"exitCode": self.exit_code}, self.data, self.error


class MacLaunchctlUidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = staticmethod(rows_function(patch.OBSERVED_ROWS))
        cls.fixed = staticmethod(rows_function(patch.OBSERVED_ROWS.replace(patch.OLD_CHECK, patch.NEW_CHECK, 1)))

    def test_observed_original_rejects_uid_minus_two(self):
        with self.assertRaisesRegex(Refused, "^typed_process_row$"):
            self.old(Owner(b"97472 1 97472 -2 Ss\n32527 1 32527 501 S\n"), {32527})

    def test_observed_unrelated_uid_minus_two_does_not_block_owned_group(self):
        actual = self.fixed(Owner(b"97472 1 97472 -2 Ss\n32527 1 32527 501 S\n"), {32527})
        self.assertEqual(actual, [{"pid": 32527, "ppid": 1, "pgid": 32527, "uid": 501, "state": "S"}])

    def test_related_uid_minus_two_is_visible_and_never_promoted_to_owner(self):
        actual = self.fixed(Owner(b"97472 1 97472 -2 Ss\n"), {97472})
        self.assertEqual(actual, [{"pid": 97472, "ppid": 1, "pgid": 97472, "uid": -2, "state": "Ss"}])

    def test_uid_minus_two_is_the_only_additional_signed_literal(self):
        for value in ("-0", "-1", "-3", "-02", "-002", "+2", "--2", "2.0", "nobody"):
            with self.subTest(value=value), self.assertRaisesRegex(Refused, "^typed_process_row$"):
                self.fixed(Owner(("101 1 101 " + value + " S\n").encode("ascii")), {101})

    def test_pid_ppid_and_pgid_do_not_accept_minus_two(self):
        for index in range(3):
            fields = ["101", "1", "101", "501", "S"]
            fields[index] = "-2"
            with self.subTest(column=index), self.assertRaisesRegex(Refused, "^typed_process_row$"):
                self.fixed(Owner((" ".join(fields) + "\n").encode("ascii")), {101})

    def test_all_four_numeric_columns_keep_rejecting_plus_prefix(self):
        for index in range(4):
            fields = ["101", "1", "101", "501", "S"]
            fields[index] = "+" + fields[index]
            with self.subTest(column=index), self.assertRaisesRegex(Refused, "^typed_process_row$"):
                self.fixed(Owner((" ".join(fields) + "\n").encode("ascii")), {101})

    def test_unsigned_uid_behavior_is_preserved(self):
        for value in ("0", "501", "4294967294", "0501"):
            with self.subTest(value=value):
                result = self.fixed(Owner(("101 1 101 " + value + " S\n").encode("ascii")), {101})
                self.assertEqual(result[0]["uid"], int(value))

    def test_missing_extra_or_blank_fields_still_refuse(self):
        for raw in (b"101 1 101 501\n", b"101 1 101 501 S extra\n", b"\n"):
            with self.subTest(raw=raw), self.assertRaisesRegex(Refused, "^typed_process_row$"):
                self.fixed(Owner(raw), {101})

    def test_strict_ascii_decoding_is_preserved(self):
        with self.assertRaises(UnicodeDecodeError):
            self.fixed(Owner("101 1 101 ٥٠١ S\n".encode("utf-8")), {101})

    def test_nonzero_command_exit_still_refuses(self):
        with self.assertRaisesRegex(Refused, "^complete_group_observation$"):
            self.fixed(Owner(b"", exit_code=1), set())

    def test_command_stderr_still_refuses(self):
        with self.assertRaisesRegex(Refused, "^complete_group_observation$"):
            self.fixed(Owner(b"", error=b"failure"), set())

    def test_exact_command_and_original_budget_are_preserved(self):
        owner = Owner(b"101 1 101 501 S\n")
        self.fixed(owner, {101}, until=123.25, cleanup=True)
        self.assertEqual(owner.calls, [("owned-launchd-group-observation",
                         ["/bin/ps", "-axo", "pid=,ppid=,pgid=,uid=,stat="],
                         {"until": 123.25, "cleanup": True, "ps": True})])

    def test_empty_output_and_group_filter_are_preserved(self):
        self.assertEqual(self.fixed(Owner(b""), {101}), [])
        self.assertEqual(self.fixed(Owner(b"101 1 101 501 S\n"), set()), [])

    def test_state_column_is_preserved_without_new_grammar(self):
        for value in ("S", "Ss", "R+", "S<", "S<s", "Z", "custom"):
            with self.subTest(value=value):
                result = self.fixed(Owner(("101 1 101 501 " + value + "\n").encode("ascii")), {101})
                self.assertEqual(result[0]["state"], value)

    def test_changed_source_refuses_before_parser_application(self):
        with self.assertRaisesRegex(patch.PatchRefused, "^source_hash_changed$"):
            patch.build_patch(b"class OwnedLaunchd: pass\n", patch.EXPECTED_MANAGER_SHA256)

    def test_pre_sentinel_manager_is_not_admitted(self):
        with self.assertRaisesRegex(patch.PatchRefused, "^never_exited_fixed_r2_source_required$"):
            patch.build_patch(b"x", "8feb3f9db05fa59986409c6c1306b48213102c7deaae6035219afa959add5ae4")

    def test_bounded_complete_input_is_required(self):
        for raw in (b"", b"x" * (1024 * 1024 + 1), "x"):
            with self.subTest(size=len(raw)), self.assertRaisesRegex(patch.PatchRefused, "^bounded_complete_manager_source$"):
                patch.build_patch(raw, patch.EXPECTED_MANAGER_SHA256)

    def test_expected_source_hash_is_typed(self):
        for value in ("", "g" * 64, None, "0" * 63):
            with self.subTest(value=value), self.assertRaisesRegex(patch.PatchRefused, "^typed_expected_source_hash$"):
                patch.build_patch(b"x", value)


if __name__ == "__main__":
    unittest.main()
