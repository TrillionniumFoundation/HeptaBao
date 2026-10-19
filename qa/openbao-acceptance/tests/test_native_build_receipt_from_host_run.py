"""Synthetic metadata custody regressions; no compiler, server or LAN evidence."""
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "native_build_receipt_from_host_run.py"
spec = importlib.util.spec_from_file_location("receipt_projector_tested", SCRIPT)
projector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(projector)
COMMIT, TREE, RUNNER = "1" * 40, "2" * 40, "3" * 64


def put(path, value):
    path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value) + "\n").encode())
    path.chmod(0o600)
    return projector.digest(path.read_bytes())


def fixture(root):
    """Explicit invented unit fixture; never accepted as an actual build receipt."""
    manifest = root / "manifest.json"
    manifest_sha = put(manifest, {"commit": COMMIT, "tree": TREE, "files": [{"synthetic_unit_test": True}]})
    binary = root / "heptabao-server"
    binary_sha = put(binary, b"synthetic unit bytes; never executable or an actual Mach-O binary")
    commands = []
    for label, argv, output in (
        ("build-server", ["/synthetic/cargo", "build", "--locked", "--offline", "-p", "heptabao-server",
                          "--bin", "heptabao-server", "--features",
                          "experimental-native-v6-ha,private-ha-forward-diagnostic"], "synthetic build record\n"),
        ("rustc-version", ["/synthetic/rustc", "--version", "--verbose"],
         "synthetic compiler record\nhost: aarch64-apple-darwin\n"),
        ("built-binary-format", ["/usr/bin/file", str(binary)],
         "synthetic format record: Mach-O 64-bit executable arm64\n"),
    ):
        logfile = root / (label + ".log")
        log_sha = put(logfile, (json.dumps({"argv": argv}) + "\n" + output).encode())
        row = {"label": label, "argv": argv, "status": "passed", "exit_code": 0,
               "log": logfile.name, "log_sha256": log_sha}
        if label == "build-server":
            row.update(binary=str(binary), binary_sha256=binary_sha, binary_bytes=binary.stat().st_size)
        commands.append(row)
    observed = {"commit": COMMIT, "tree": TREE, "verified_files": 1}
    summary = {"runner_completed": True, "source_unchanged": True,
               "source_commit": COMMIT, "source_tree": TREE, "runner_sha256": RUNNER,
               "status": "failed_or_blocked", "finished_utc": "synthetic-unit-time",
               "manifest_sha256": manifest_sha, "source_before": dict(observed),
               "source_after": dict(observed), "machine": "arm64", "commands": commands}
    path = root / "summary.json"
    put(path, summary)
    return path, manifest, summary


class ProjectionRegression(unittest.TestCase):
    def apply(self, path, manifest):
        return projector.project(path, projector.digest(path.read_bytes()), manifest, COMMIT, TREE, RUNNER)

    def test_exact_retained_records_project_build_but_preserve_failed_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, manifest, _ = fixture(Path(tmp))
            value = self.apply(path, manifest)
            self.assertEqual(value["schema"], "heptabao.native-build.v1")
            self.assertEqual(value["native_abi"], "aarch64-apple-darwin")
            self.assertFalse(value["provenance"]["original_scoped_host_passed"])
            self.assertEqual(value["provenance"]["original_scoped_host_status"], "failed_or_blocked")
            self.assertFalse(value["provenance"]["lan98_executed_by_projection"])

    def test_actual_artifact_or_compiler_log_change_refuses(self):
        for changed in ("heptabao-server", "rustc-version.log", "built-binary-format.log", "build-server.log"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                path, manifest, _ = fixture(Path(tmp))
                with (path.parent / changed).open("ab") as output:
                    output.write(b"changed after recorded digest")
                with self.assertRaises(projector.Refusal):
                    self.apply(path, manifest)

    def test_source_and_build_claims_cannot_be_upgraded(self):
        for field, value in (("runner_completed", False), ("source_unchanged", False),
                             ("source_commit", "4" * 40), ("source_tree", "5" * 40),
                             ("runner_sha256", "6" * 64), ("status", "running")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                path, manifest, summary = fixture(Path(tmp))
                summary[field] = value
                put(path, summary)
                with self.assertRaises(projector.Refusal):
                    self.apply(path, manifest)
        for side in ("source_before", "source_after"):
            with self.subTest(side=side), tempfile.TemporaryDirectory() as tmp:
                path, manifest, summary = fixture(Path(tmp))
                summary[side]["tree"] = "7" * 40
                put(path, summary)
                with self.assertRaises(projector.Refusal):
                    self.apply(path, manifest)
        for code in (False, True, 1, -1):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                path, manifest, summary = fixture(Path(tmp))
                summary["commands"][0]["exit_code"] = code
                put(path, summary)
                with self.assertRaises(projector.Refusal):
                    self.apply(path, manifest)

    def test_duplicate_command_wrong_native_abi_and_manifest_refuse(self):
        for mode in ("duplicate", "machine", "manifest"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                path, manifest, summary = fixture(Path(tmp))
                if mode == "duplicate":
                    summary["commands"].append(summary["commands"][0].copy())
                elif mode == "machine":
                    summary["machine"] = "x86_64"
                else:
                    put(manifest, {"commit": COMMIT, "tree": "8" * 40, "files": []})
                put(path, summary)
                with self.assertRaises(projector.Refusal):
                    self.apply(path, manifest)

    def test_symlink_binary_and_existing_receipt_are_never_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, manifest, _ = fixture(Path(tmp))
            value = self.apply(path, manifest)
            output = path.parent / "receipt.json"
            projector.write_new(output, value)
            before = output.read_bytes()
            with self.assertRaises(FileExistsError):
                projector.write_new(output, {"unexpected": "replacement"})
            self.assertEqual(output.read_bytes(), before)
            binary = path.parent / "heptabao-server"
            saved = binary.with_name("retained-test-bytes")
            binary.rename(saved)
            binary.symlink_to(saved)
            with self.assertRaises(projector.Refusal):
                self.apply(path, manifest)


    def test_binary_stream_has_exact_digest_and_rejects_oversize_without_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "public-synthetic-stream-bytes"
            raw = b"public-artifact-stream-unit-vector" * 100000
            put(binary, raw)
            actual_read = os.read
            read_sizes = []
            def watched_read(descriptor, size):
                read_sizes.append(size)
                return actual_read(descriptor, size)
            with mock.patch.object(projector.os, "read", side_effect=watched_read):
                digest, size = projector.owned_binary_digest(binary)
            self.assertEqual((digest, size), (hashlib.sha256(raw).hexdigest(), len(raw)))
            self.assertGreater(len(read_sizes), 2)
            self.assertLessEqual(max(read_sizes), 1024 ** 2)
            with binary.open("r+b") as stream:
                stream.truncate(projector.BINARY_ARTIFACT_LIMIT + 1)
            with mock.patch.object(projector.os, "read", side_effect=AssertionError("oversize must refuse before read")):
                with self.assertRaises(projector.Refusal):
                    projector.owned_binary_digest(binary)

    def test_stream_custody_detects_same_size_replacement_and_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "synthetic-binary"
            put(binary, b"first vector")
            actual_read = os.read
            changed = False
            def changed_name(descriptor, size):
                nonlocal changed
                value = actual_read(descriptor, size)
                if not changed:
                    changed = True
                    replacement = binary.with_name("replacement")
                    put(replacement, b"other vector")
                    os.replace(replacement, binary)
                return value
            with mock.patch.object(projector.os, "read", side_effect=changed_name):
                with self.assertRaises(projector.Refusal):
                    projector.owned_binary_digest(binary)
            os.link(binary, binary.with_name("second-link"))
            with self.assertRaises(projector.Refusal):
                projector.owned_binary_digest(binary)


if __name__ == "__main__":
    unittest.main()
