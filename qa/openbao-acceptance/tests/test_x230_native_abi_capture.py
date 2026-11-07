#!/usr/bin/env python3
"""Local guard fixtures only; no HeptaBao, compiler, provider or remote execution."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("x230_native_abi_capture.py"))
CAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAP)


def terminal():
    return {"job_id": "actual-projection-job", "state": "succeeded", "exit_code": 0,
            "output_complete": True, "output_durable": True, "terminal_publication_confirmed": True,
            "timed_out": False, "cancelled": False, "automatic_retry": False,
            "log_bytes": {key: {"seen": 1, "stored": 1} for key in ("stdout", "stderr")},
            "log_synced": {key: True for key in ("stdout", "stderr")},
            "log_truncated": {key: False for key in ("stdout", "stderr")},
            "log_errors": {key: None for key in ("stdout", "stderr")}}


def projection():
    pins = {name: {"path": "/owned/artifacts/" + name, "bytes": 123, "sha256": "a" * 64,
                   "mode": 0o700} for name in CAP.NAMES}
    return {"schema": "heptabao.native-build.v1", "source_commit": CAP.PRODUCT, "source_tree": CAP.TREE,
            "build_exit_code": 0, "source_freeze_verified": True, "native_abi": "x86_64-unknown-linux-gnu",
            "binary_sha256": "a" * 64, "provenance": {"original_job_id": "normal107-job",
                "passed_cases": 107, "original_receipt_status": "passed", "projection_compiler_invocations": 0,
                "projection_binary_executions": 0, "actual_artifacts": pins}}


class TerminalAndProjection(unittest.TestCase):
    def test_complete_terminal_accepted(self):
        CAP.require_terminal(terminal(), "actual-projection-job")

    def test_failed_running_unknown_or_wrong_job_refused(self):
        for key, value in (("state", "running"), ("state", "failed"), ("state", "unknown"),
                           ("exit_code", 1), ("exit_code", False), ("job_id", "other")):
            with self.subTest(key=key, value=value):
                row = terminal(); row[key] = value
                with self.assertRaises(CAP.Refused): CAP.require_terminal(row, "actual-projection-job")

    def test_incomplete_timed_out_cancelled_or_retried_refused(self):
        for key in ("output_complete", "output_durable", "terminal_publication_confirmed",
                    "timed_out", "cancelled", "automatic_retry"):
            with self.subTest(key=key):
                row = terminal(); row[key] = not row[key]
                with self.assertRaises(CAP.Refused): CAP.require_terminal(row, "actual-projection-job")

    def test_log_loss_and_boolean_counts_refused(self):
        for mutation in (lambda t: t["log_bytes"]["stdout"].update(stored=0),
                         lambda t: t["log_bytes"]["stderr"].update(stored=True),
                         lambda t: t["log_truncated"].update(stdout=True),
                         lambda t: t["log_errors"].update(stderr="publication_error"),
                         lambda t: t["log_synced"].update(stderr=False)):
            row = terminal(); mutation(row)
            with self.assertRaises(CAP.Refused): CAP.require_terminal(row, "actual-projection-job")

    def test_exact_native_projection_accepted(self):
        self.assertEqual(set(CAP.projection_artifacts(projection(), "normal107-job")), CAP.NAMES)

    def test_wrong_source_failed_build_and_wrong_abi_refused(self):
        for key, value in (("source_commit", "0" * 40), ("source_tree", "0" * 40),
                           ("build_exit_code", 101), ("build_exit_code", False),
                           ("source_freeze_verified", False), ("native_abi", "aarch64-apple-darwin")):
            with self.subTest(key=key):
                row = projection(); row[key] = value
                with self.assertRaises(CAP.Refused): CAP.projection_artifacts(row, "normal107-job")

    def test_incomplete_cohort_and_other_job_refused(self):
        for key, value in (("passed_cases", 106), ("passed_cases", 61), ("original_job_id", "other"),
                           ("original_receipt_status", "running"), ("projection_binary_executions", 1)):
            row = projection(); row["provenance"][key] = value
            with self.assertRaises(CAP.Refused): CAP.projection_artifacts(row, "normal107-job")

    def test_missing_extra_or_nonprivate_artifact_refused(self):
        for mutation in (lambda p: p.pop("heptabao-seed"),
                         lambda p: p.update(extra=dict(p["heptabao-server"])),
                         lambda p: p["heptabao-seed"].update(mode=0o755),
                         lambda p: p["heptabao-seed"].update(path="relative")):
            row = projection(); mutation(row["provenance"]["actual_artifacts"])
            with self.assertRaises(CAP.Refused): CAP.projection_artifacts(row, "normal107-job")

    def test_producer_requires_actual_bound_normal107_terminal_before_readelf(self):
        for outcome in ("succeeded", "running", "failed", "mismatched_projection_terminal_pin"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                native, normal, projected = projection(), terminal(), terminal()
                normal["job_id"] = "normal107-job"
                if outcome in ("running", "failed"):
                    normal.update(state=outcome, exit_code=None if outcome == "running" else 1)
                def save(name, value):
                    path = root / name; path.write_bytes(CAP.encode(value)); path.chmod(0o600)
                    return CAP.file_pin(path, time.monotonic() + 5)[0]
                normal_pin = save("normal-terminal.json", normal)
                native["provenance"]["original_inputs"] = {"terminal": dict(normal_pin)}
                if outcome == "mismatched_projection_terminal_pin":
                    native["provenance"]["original_inputs"]["terminal"]["sha256"] = "0" * 64
                manifest = {"native_projection": save("native.json", native),
                            "normal107_terminal": normal_pin,
                            "projection_terminal": save("projection-terminal.json", projected),
                            "normal107_job_id": "normal107-job", "projection_job_id": "actual-projection-job",
                            "expected_artifacts": native["provenance"]["actual_artifacts"]}
                capture = CAP.Capture(manifest, root, time.monotonic() + 5, {})
                with patch.object(capture, "elf", return_value={}) as readelf:
                    if outcome == "succeeded":
                        result = capture.producer()
                        self.assertEqual(readelf.call_count, 2)
                        self.assertFalse(result["static_receiver_compatibility_qualified"])
                    else:
                        with self.assertRaises(CAP.Refused): capture.producer()
                        readelf.assert_not_called()


class LoaderCache(unittest.TestCase):
    def cache(self):
        return ("3 libs found in cache `/etc/ld.so.cache'\n"
                "\tlibc.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libc.so.6\n"
                "\tlibc.so.6 (libc6) => /lib/i386-linux-gnu/libc.so.6\n"
                "\tlibm.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libm.so.6\n"
                "Cache generated by: ldconfig (Ubuntu GLIBC 2.39-0ubuntu8) stable release version 2.39\n")

    def test_complete_cache_filters_only_actual_x86_64_entries(self):
        self.assertEqual(CAP.parse_cache(self.cache()), {
            "libc.so.6": ["/lib/x86_64-linux-gnu/libc.so.6"],
            "libm.so.6": ["/lib/x86_64-linux-gnu/libm.so.6"]})

    def test_truncated_extra_and_unknown_cache_rows_refused(self):
        variants = [self.cache().replace("3 libs", "4 libs"), self.cache() + "unparsed row\n",
                    self.cache().replace("/lib/x86_64-linux-gnu/libm.so.6", "/lib/../unsafe.so")]
        for text in variants:
            with self.assertRaises(CAP.Refused): CAP.parse_cache(text)

    def test_duplicate_cache_entries_refused(self):
        text = self.cache().replace("3 libs", "4 libs").replace("Cache generated", (
            "\tlibm.so.6 (libc6,x86-64) => /lib/x86_64-linux-gnu/libm.so.6\nCache generated"))
        with self.assertRaises(CAP.Refused): CAP.parse_cache(text)

    def test_aliases_resolve_to_same_actual_provider(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root / "provider"; target.write_bytes(b"public fixture")
            alias = root / "alias"; alias.symlink_to(target)
            actual, candidates = CAP.choose_provider("libc.so.6", {"libc.so.6": [str(alias), str(target)]},
                                                    "/lib64/ld-linux-x86-64.so.2")
            self.assertEqual(actual, str(target)); self.assertEqual(len(candidates), 2)

    def test_missing_or_ambiguous_provider_refused(self):
        with self.assertRaises(CAP.Refused):
            CAP.choose_provider("libc.so.6", {}, "/lib64/ld-linux-x86-64.so.2")
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / name for name in ("one", "two")]
            for p in paths: p.write_bytes(b"public fixture")
            with self.assertRaises(CAP.Refused):
                CAP.choose_provider("libc.so.6", {"libc.so.6": list(map(str, paths))},
                                    "/lib64/ld-linux-x86-64.so.2")

    def test_lookup_alias_retarget_refused_when_old_provider_and_cache_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); old, new, alias, cache = [root / name for name in ("old", "new", "alias", "cache")]
            old.write_bytes(b"unchanged old provider"); new.write_bytes(b"new provider")
            cache.write_bytes(b"unchanged loader cache mapping alias")
            alias.symlink_to(old)
            original = CAP.alias_binding(alias, time.monotonic() + 5)
            old_bytes, cache_bytes = old.read_bytes(), cache.read_bytes()
            CAP.recheck_alias_bindings({str(alias): original}, time.monotonic() + 5)
            alias.unlink(); alias.symlink_to(new)
            self.assertEqual(old.read_bytes(), old_bytes); self.assertEqual(cache.read_bytes(), cache_bytes)
            with self.assertRaisesRegex(CAP.Refused, "actual_loader_lookup_alias_changed"):
                CAP.recheck_alias_bindings({str(alias): original}, time.monotonic() + 5)


class FileAndToolCapture(unittest.TestCase):
    def test_private_regular_file_pin_uses_real_bytes_and_header(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"; path.write_bytes(bytes(range(100))); path.chmod(0o600)
            pin, header = CAP.file_pin(path, time.monotonic() + 5)
            self.assertEqual(pin["sha256"], hashlib.sha256(bytes(range(100))).hexdigest())
            self.assertEqual(header, bytes(range(64))); self.assertEqual(pin["bytes"], 100)

    def test_symlink_world_readable_and_hardlink_private_inputs_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"; path.write_bytes(b"public fixture"); path.chmod(0o600)
            alias = Path(folder) / "alias"; alias.symlink_to(path)
            with self.assertRaises(CAP.Refused): CAP.file_pin(alias, time.monotonic() + 5)
            path.chmod(0o644)
            with self.assertRaises(CAP.Refused): CAP.file_pin(path, time.monotonic() + 5)
            path.chmod(0o600); os.link(path, Path(folder) / "hardlink")
            with self.assertRaises(CAP.Refused): CAP.file_pin(path, time.monotonic() + 5)

    def test_changed_and_expired_input_pins_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"; path.write_bytes(b"public fixture"); path.chmod(0o600)
            pin, _ = CAP.file_pin(path, time.monotonic() + 5)
            changed = dict(pin, sha256="0" * 64)
            with self.assertRaises(CAP.Refused): CAP.require_pin(pin, changed)
            with self.assertRaises(CAP.Refused): CAP.file_pin(path, time.monotonic() - 1)

    def test_growing_stream_refused_before_accumulating_past_original_size(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"; path.write_bytes(b"original"); path.chmod(0o600)
            class GrowingStream:
                calls = 0
                def __init__(self, stream): self.stream = stream
                def __enter__(self): return self
                def __exit__(self, *args): self.stream.close()
                def fileno(self): return self.stream.fileno()
                def read(self, maximum):
                    self.calls += 1
                    return b"original+growth" if self.calls == 1 else b""
            growing = GrowingStream(path.open("rb"))
            with patch("builtins.open", return_value=growing), self.assertRaisesRegex(
                    CAP.Refused, "input_grew_beyond_original_bound"):
                CAP.file_pin(path, time.monotonic() + 5, contents=True)
            self.assertEqual(growing.calls, 1)

    def test_tool_environment_deadline_and_complete_output_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            capture = CAP.Capture({}, Path(folder), time.monotonic() + 5, {})
            def invoke(argv, **kwargs):
                self.assertEqual(argv, ["/reviewed/readelf", "--version"])
                self.assertEqual(kwargs["env"], CAP.ENV)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertGreater(kwargs["timeout"], 0); self.assertLessEqual(kwargs["timeout"], 5)
                kwargs["stdout"].write(b"bounded public output\n")
                return types.SimpleNamespace(returncode=0)
            with patch.object(CAP.subprocess, "run", side_effect=invoke):
                text, row = capture.command("readelf-version", ["/reviewed/readelf", "--version"])
            self.assertEqual(text, "bounded public output\n"); self.assertEqual(row["exit_code"], 0)
            self.assertEqual(row["stderr_bytes"], 0); self.assertFalse(row["timed_out"])

    def test_tool_failure_stderr_and_timeout_never_complete(self):
        for failure in ("exit", "stderr", "timeout"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                capture = CAP.Capture({}, Path(folder), time.monotonic() + 5, {})
                def invoke(argv, **kwargs):
                    if failure == "timeout": raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                    if failure == "stderr": kwargs["stderr"].write(b"diagnostic")
                    return types.SimpleNamespace(returncode=1 if failure == "exit" else 0)
                with patch.object(CAP.subprocess, "run", side_effect=invoke), self.assertRaises(CAP.Refused):
                    capture.command("readelf", ["/reviewed/readelf"])
                self.assertEqual(len(capture.commands), 1)

    def test_capture_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "readelf.stdout").write_bytes(b"previous original")
            capture = CAP.Capture({}, root, time.monotonic() + 5, {})
            with patch.object(CAP.subprocess, "run") as mocked, self.assertRaises(FileExistsError):
                capture.command("readelf", ["/reviewed/readelf"])
            mocked.assert_not_called()
            self.assertEqual((root / "readelf.stdout").read_bytes(), b"previous original")


if __name__ == "__main__":
    unittest.main(verbosity=2)
