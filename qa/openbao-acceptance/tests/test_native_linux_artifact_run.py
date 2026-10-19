"""Artifact custody negatives, not an actual HeptaBao build or X230 run."""
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "native_linux_artifact_run.py"
spec = importlib.util.spec_from_file_location("tested_native_artifact_lane", SCRIPT)
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)


def put(path, raw):
    path.write_bytes(raw if isinstance(raw, bytes) else (json.dumps(raw) + "\n").encode())
    path.chmod(0o600)
    return lane.sha(path.read_bytes())


def original_inventory(root):
    """Invented metadata solely for parser tests; no artifact is executable."""
    profile = SimpleNamespace(SERVER_FEATURES="synthetic-server", PEER_FEATURES="synthetic-peer")
    target = root / "target"
    groups = [["synthetic-server-group", "server", "synthetic_server_selector", 1],
              ["synthetic-peer-group", "peer", "synthetic_peer_selector", 1]]
    summary = {"commands": []}

    def add(label, argv, text, **extra):
        log = label + ".log"
        digest = put(root / log, (json.dumps({"argv": argv}) + "\n" + text).encode())
        row = {"label": label, "argv": argv, "log": log, "log_sha256": digest,
               "exit_code": 0, "status": "passed", "finished_utc": "synthetic-unit-only", **extra}
        summary["commands"].append(row)
        return row

    for owner, (_, prefix) in lane.ROLES.items():
        artifact = target / "debug/deps" / (prefix + "-" + "1" * 16)
        command = ["/synthetic/cargo", *lane.expected_cargo(profile, owner)]
        add("compile-" + owner + "-tests", command + ["--no-run"],
            "  Executable unittests src/lib.rs (" + str(artifact) + ")\n")
        label, _, selector, count = next(row for row in groups if row[1] == owner)
        names = ["synthetic_module::" + selector]
        running = "     Running unittests src/lib.rs (" + str(artifact) + ")\n"
        add(label + "-list", command + [selector, "--", "--list", "--color=never"],
            running + names[0] + ": test\n", selected_test_names=names, expected_count=count)
        add(label, command + [selector, "--", "--nocapture", "--test-threads=1", "--color=never"],
            running + "synthetic failed original test\n", status="failed", exit_code=101)
    add("build-server", ["/synthetic/cargo", "build", "--locked", "--offline", "-p", "heptabao-server",
                         "--bin", "heptabao-server", "--features", profile.SERVER_FEATURES],
        "synthetic build record only\n", binary=str(root / "heptabao-server"))
    return summary, target, profile, groups


class ArtifactCustodyRegression(unittest.TestCase):
    def test_compile_artifact_requires_one_exact_absolute_target_path(self):
        target = Path("/owned-synthetic/target")
        path = target / "debug/deps/heptabao_server-1234567890abcdef"
        text = "  Executable unittests src/lib.rs (" + str(path) + ")\n"
        self.assertEqual(lane.artifact_from_log(text, "heptabao_server", target, compiled=True), path)
        for bad in (text + text, text.replace("/owned-synthetic/target", "/another/target"),
                    text.replace(str(path), "target/debug/deps/" + path.name)):
            with self.subTest(bad=bad), self.assertRaises(lane.Refusal):
                lane.artifact_from_log(bad, "heptabao_server", target, compiled=True)

    def test_original_log_identity_and_selector_list_cannot_be_substituted(self):
        for mode in ("unchanged", "different-running-artifact", "changed-log", "duplicate-name", "changed-selector"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                summary, target, profile, groups = original_inventory(root)
                row = next(row for row in summary["commands"] if row["label"] == "synthetic-server-group-list")
                path = root / row["log"]
                raw = path.read_bytes()
                if mode == "different-running-artifact":
                    row["log_sha256"] = put(path, raw.replace(b"1" * 16, b"2" * 16))
                elif mode == "changed-log":
                    put(path, raw + b"changed after original receipt\n")
                elif mode == "duplicate-name":
                    row["log_sha256"] = put(path, raw + b"synthetic_module::synthetic_server_selector: test\n")
                elif mode == "changed-selector":
                    row["argv"] = [word.replace("synthetic_server_selector", "a_different_selector") for word in row["argv"]]
                if mode == "unchanged":
                    _, selections, _, _ = lane.producer_inventory(summary, root, target, profile, groups)
                    self.assertTrue(all(item["producer_test_status"] == "failed" for item in selections))
                    self.assertTrue(all(item["producer_test_exit_code"] == 101 for item in selections))
                else:
                    with self.assertRaises(lane.Refusal):
                        lane.producer_inventory(summary, root, target, profile, groups)

    def test_streamed_copy_preserves_bytes_and_rejects_links_or_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "large-unit-bytes", root / "copied-unit-bytes"
            raw = b"public-synthetic-unit-bytes" * 100000
            put(source, raw)
            before = lane.inspect_file(source, copy_to=target)
            after = lane.inspect_file(target)
            self.assertEqual(before["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual((after["bytes"], after["sha256"]), (len(raw), before["sha256"]))
            with self.assertRaises(FileExistsError):
                lane.inspect_file(source, copy_to=target)
            linked = root / "second-link"
            os.link(source, linked)
            with self.assertRaises(lane.Refusal):
                lane.inspect_file(source)
            linked.unlink()
            linked.symlink_to(source)
            with self.assertRaises(lane.Refusal):
                lane.inspect_file(linked)
            with source.open("r+b") as stream:
                stream.truncate(lane.ARTIFACT_LIMIT + 1)
            with mock.patch.object(lane.os, "read", side_effect=AssertionError("oversize must refuse before read")):
                with self.assertRaises(lane.Refusal):
                    lane.inspect_file(source)

    def test_duplicate_missing_or_wrong_selector_name_counts_refuse(self):
        for text, count in (("a: test\na: test\n", 2), ("a: test\n", 2), ("a: test\nb: test\n", 1)):
            with self.subTest(text=text), self.assertRaises(lane.Refusal):
                lane.listed_names(text, count)
        self.assertEqual(lane.listed_names("a: test\nb: test\n", 2), ["a", "b"])

    def test_partial_failure_retains_counts_and_incomplete_or_duplicate_results_refuse(self):
        failed = "test result: FAILED. 7 passed; 1 failed; 0 ignored; 0 measured; 23 filtered out; finished in 0.1s\n"
        self.assertEqual(lane.observed_test_result(failed, 8),
                         {"status": "FAILED", "passed": 7, "failed": 1, "ignored": 0})
        for value in (failed + failed, failed.replace("1 failed", "0 failed"),
                      failed.replace("FAILED", "ok"), "incomplete process output"):
            with self.subTest(value=value):
                self.assertIsNone(lane.observed_test_result(value, 8))

    def test_actual_local_system_elf_loader_observation_is_not_product_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path("/usr/bin/true").resolve(strict=True)
            result = lane.native_abi(path, Path(tmp), "synthetic-local-system-elf")
            self.assertEqual(result["native_abi"], "x86_64-unknown-linux-gnu")
            self.assertEqual(result["loader_resolution_exit_code"], 0)
            self.assertIn("libc.so.6", result["needed"])
            self.assertFalse(result["application_entry_point_executed"])
            self.assertTrue(all(lane.exact_hex(row["sha256"], 64) for row in result["dependencies"]))


if __name__ == "__main__":
    unittest.main()
