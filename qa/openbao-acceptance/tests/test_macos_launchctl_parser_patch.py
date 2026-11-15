"""Source-bound launchd parser regression; no Mac process or credentials needed."""
from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prepare_macos_launchctl_parser_patch as repair

FIXTURES = json.loads((Path(__file__).parent / "fixtures/macos_launchctl_observed_parsers.json").read_text())
TARGET = "gui/501/org.heptabao.qa.parser-regression.server"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parser_function(source):
    def need(ok, code):
        if not ok:
            raise RuntimeError(code)
    tree = ast.parse(source)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "parse_print")
    namespace = {"need": need, "re": re}
    # Compile only the captured pure function. Never import a launchd manager.
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<observed-parser>", "exec"), namespace)
    return namespace["parse_print"]


def record(exit_value="(never exited)", *, pid="4321", runs="1", extra=""):
    fields = [f"{TARGET} = {{", "\tpath = /tmp/source-only.plist", "\tprogram = /usr/bin/true",
              "\targuments = {", "\t\t/usr/bin/true", "\t}", "\tstate = running"]
    if pid is not None:
        fields.append(f"\tpid = {pid}")
    if runs is not None:
        fields.append(f"\truns = {runs}")
    if exit_value is not None:
        fields.append(f"\tlast exit code = {exit_value}")
    if extra:
        fields.append(extra)
    fields.append("}")
    return ("\n".join(fields) + "\n").encode()


def patched_parser(row):
    raw = row["parser_source"].encode()
    return parser_function(repair.build_patch(raw, digest(raw)))


class MacLaunchctlParserRepairTests(unittest.TestCase):
    def test_exact_observed_source_fixtures(self):
        self.assertEqual({row["parser_sha256"] for row in FIXTURES.values()}, repair.OBSERVED_PARSER_SHA256)
        for row in FIXTURES.values():
            with self.subTest(source=row["full_source_sha256"]):
                self.assertEqual(digest(row["parser_source"].encode()), row["parser_sha256"])
                self.assertRegex(row["full_source_sha256"], r"^[0-9a-f]{64}$")
                self.assertGreater(row["full_source_bytes"], len(row["parser_source"]))

    def test_both_observed_parsers_reject_never_exited_before_repair(self):
        for name, row in FIXTURES.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "typed_launchctl_integer"):
                parser_function(row["parser_source"])(record(), TARGET)

    def test_r2_already_recognizes_annotated_config_failure(self):
        parse = parser_function(FIXTURES["home_launch_r2"]["parser_source"])
        state = parse(record("78: EX_CONFIG", pid=None), TARGET)
        self.assertEqual(state["last exit code"], 78)
        self.assertFalse(state.get("last exit code") == 0)

    def test_no_exit_is_not_success(self):
        for name, row in FIXTURES.items():
            parse = patched_parser(row)
            for pid, runs in ((None, "0"), ("4321", "1")):
                with self.subTest(name=name, pid=pid):
                    state = parse(record(pid=pid, runs=runs), TARGET)
                    self.assertIsNone(state["last exit code"])
                    # Exactly the existing phase-completion predicate.
                    self.assertFalse(state.get("last exit code") == 0)

    def test_observed_exit_status_semantics_are_preserved(self):
        for name, row in FIXTURES.items():
            parse = patched_parser(row)
            for raw, expected in (("0", 0), ("1", 1), ("-9", -9), ("78", 78), ("78: EX_CONFIG", 78)):
                with self.subTest(name=name, exit=raw):
                    state = parse(record(raw, pid=None), TARGET)
                    self.assertEqual(state["last exit code"], expected)
                    self.assertEqual(state.get("last exit code") == 0, expected == 0)

    def test_missing_exit_and_termination_signal_do_not_mint_success(self):
        for row in FIXTURES.values():
            state = patched_parser(row)(record(None, pid=None, extra="\tlast terminating signal = 9"), TARGET)
            self.assertNotIn("last exit code", state)
            self.assertFalse(state.get("last exit code") == 0)
            self.assertEqual(state["last terminating signal"], "9")

    def test_unknown_exit_literals_are_still_refused(self):
        bad = ["never exited", "(Never exited)", "(never exited) trailing", "0: EX_CONFIG", "78: EX_USAGE",
               "0: SUCCESS", "75: EX_TEMPFAIL", "unknown", "None", "+0", "0.0", "１２", "1" * 11]
        for name, row in FIXTURES.items():
            for value in bad:
                with self.subTest(name=name, value=value), self.assertRaises(RuntimeError):
                    patched_parser(row)(record(value), TARGET)

    def test_empty_exit_field_cannot_pass_completion(self):
        # Existing record parsing treats a stripped empty field as absent.
        # This narrow repair preserves that behavior, which cannot equal zero.
        for row in FIXTURES.values():
            state = patched_parser(row)(record("", pid=None), TARGET)
            self.assertFalse(state.get("last exit code") == 0)

    def test_no_exit_sentinel_is_only_for_last_exit(self):
        for row in FIXTURES.values():
            parse = patched_parser(row)
            for field in ("pid", "runs"):
                with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "typed_launchctl_integer"):
                    parse(record("0", **{field: "(never exited)"}), TARGET)

    def test_invalid_pid_never_becomes_identity(self):
        for row in FIXTURES.values():
            parse = patched_parser(row)
            for pid in ("0", "1", "-1", "78: EX_CONFIG", "4321 extra"):
                with self.subTest(pid=pid), self.assertRaises(RuntimeError):
                    parse(record("0", pid=pid), TARGET)

    def test_original_record_guards_are_preserved(self):
        for row in FIXTURES.values():
            parse = patched_parser(row)
            bad = [record().replace(TARGET.encode(), b"gui/501/other", 1),
                   record(extra="\truns = 1"), record(extra="\tlast exit code = 0"),
                   record().replace(b"\targuments = {\n\t\t/usr/bin/true\n\t}\n", b""),
                   record() + b"unexpected trailer\n", b"x" * 262145]
            for index, raw in enumerate(bad):
                with self.subTest(index=index), self.assertRaises(RuntimeError):
                    parse(raw, TARGET)

    def test_nested_fields_cannot_replace_actual_parent_status(self):
        for row in FIXTURES.values():
            state = patched_parser(row)(record(extra="\tchild = {\n\t\tpid = 9999\n\t\tlast exit code = 0\n\t}"), TARGET)
            self.assertEqual(state["pid"], 4321)
            self.assertIsNone(state["last exit code"])

    def test_source_hash_mismatch_refuses_before_patch(self):
        raw = FIXTURES["home_launch_r2"]["parser_source"].encode()
        with self.assertRaisesRegex(repair.PatchRefused, "source_hash_changed"):
            repair.build_patch(raw, "0" * 64)

    def test_unobserved_parser_and_duplicate_definitions_are_refused(self):
        raw = FIXTURES["home_launch_r2"]["parser_source"].encode()
        for source in (raw.replace(b"len(raw)<=262144", b"len(raw)<=524288"), raw + b"\n" + raw):
            with self.assertRaises(repair.PatchRefused):
                repair.build_patch(source, digest(source))

    def test_every_byte_outside_integer_block_is_unchanged(self):
        for row in FIXTURES.values():
            # Marker text includes manager deadline/unknown-effect predicates;
            # the patcher must preserve all non-parser bytes exactly.
            prefix = b"NEW_MANAGER_SECONDS=600.0\nNEW_CLEANUP_SECONDS=60.0\n"
            suffix = b"\ndef no_business_after_unknown(self):\n    need(not self.unknown,'no_business_after_unknown')\n"
            raw = prefix + row["parser_source"].encode() + suffix
            result = repair.build_patch(raw, digest(raw))
            old = repair.R2_INTEGERS if repair.R2_INTEGERS.encode() in raw else repair.PLAIN_INTEGERS
            self.assertEqual(result, raw.replace(old.encode(), repair.FIXED_INTEGERS.encode(), 1))

    def test_cli_oversized_source_refuses_without_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "oversized.py"
            output = Path(directory) / "candidate.py"
            raw = b"#" * (1024 * 1024 + 2)
            source.write_bytes(raw)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = repair.main(["--source", str(source), "--source-sha256", digest(raw), "--output", str(output)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(stderr.getvalue())["errorCode"], "bounded_complete_manager_source")
            self.assertFalse(output.exists())
            self.assertEqual(source.stat().st_size, len(raw))

    def test_cli_is_create_only_and_does_not_change_source(self):
        raw = FIXTURES["home_launch_r2"]["parser_source"].encode()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.py"
            output = Path(directory) / "candidate.py"
            source.write_bytes(raw)
            argv = ["--source", str(source), "--source-sha256", digest(raw), "--output", str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(repair.main(argv), 0)
            first = output.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(repair.main(argv), 1)
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(output.read_bytes(), first)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(repair.main([*argv[:-1], str(source)]), 1)
            self.assertEqual(source.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
