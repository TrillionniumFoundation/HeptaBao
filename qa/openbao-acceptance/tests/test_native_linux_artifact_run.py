"""Artifact custody negatives, not an actual HeptaBao build or X230 run."""
import ast
import copy
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


def current_groups():
    path = SCRIPT.with_name("native_candidate_host_run.py")
    for node in ast.parse(path.read_bytes()).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "GROUPS"
                                                for target in node.targets):
            return [list(row) for row in ast.literal_eval(node.value)]
    raise AssertionError("current host runner must declare its group inventory")


def synthetic_capsule(root, groups):
    """Small metadata-only capsule; none of these bytes is a native executable."""
    files, artifacts = [], {}
    for name in ("server", "peer", "server-bin", "producer-summary.json", "product-source-manifest.json"):
        path = root / name
        digest = put(path, ("synthetic capsule parser bytes for " + name).encode())
        mode = 0o700 if name in ("server", "peer", "server-bin") else 0o600
        path.chmod(mode)
        row = {"name": name, "sha256": digest, "bytes": path.stat().st_size, "mode": mode}
        files.append(row)
        if mode == 0o700:
            artifacts[name] = {key: row[key] for key in ("name", "sha256", "bytes")}
    return {"schema": "heptabao.native-linux-artifact-capsule.v1", "source_commit": "1" * 40,
            "source_tree": "2" * 40, "producer_runner_sha256": "3" * 64, "groups": groups,
            "required_test_count": sum(row[3] for row in groups),
            "original_command_deadline_seconds": 1800, "producer_role": "main",
            "producer_target_shared_lock_held": True, "production_authority": False,
            "files": files, "artifacts": artifacts,
            "producer_summary_sha256": lane.sha((root / "producer-summary.json").read_bytes()),
            "product_manifest_sha256": lane.sha((root / "product-source-manifest.json").read_bytes())}


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
    def test_current_source_profile_loads_58_and_retained_legacy_source_loads_55(self):
        groups = current_groups()
        self.assertEqual((len(groups), sum(row[3] for row in groups)), (18, 58))
        legacy = [row for row in groups if row[0] != "native-kv2-mount"]
        for count, profile in ((58, SCRIPT.with_name("native_candidate_host_run.py").read_bytes()),
                               (55, ("GROUPS = " + repr(legacy) + "\n").encode())):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / "source"
                source.mkdir(mode=0o700)
                runner = source / lane.PROFILE_PATH
                runner.parent.mkdir(parents=True)
                digest = put(runner, profile)
                manifest = root / "manifest.json"
                blob = hashlib.sha1(b"blob " + str(len(profile)).encode() + b"\0" + profile).hexdigest()
                put(manifest, {"commit": "1" * 40, "tree": "2" * 40,
                               "files": [{"path": lane.PROFILE_PATH, "sha": blob}]})
                _, _, _, actual = lane.load_profile(source, manifest, "1" * 40, "2" * 40, digest)
                self.assertEqual(lane.profile_test_count(actual), count)
                self.assertFalse(list(source.rglob("__pycache__")))

    def test_58_profile_cannot_replace_mount_cases_with_another_selector_or_count(self):
        for mode in ("selector", "owner", "count", "label", "duplicate", "malformed"):
            with self.subTest(mode=mode):
                groups = copy.deepcopy(current_groups())
                mount = next(row for row in groups if row[0] == "native-kv2-mount")
                if mode == "selector":
                    mount[2] = "unrelated_three_tests_"
                elif mode == "owner":
                    mount[1] = "peer"
                elif mode == "count":
                    mount[3] = 2
                    groups[0][3] += 1  # Keep 58 total while dropping one mount case.
                elif mode == "label":
                    mount[0] = "unrelated-three-cases"
                elif mode == "duplicate":
                    mount[0] = groups[0][0]
                else:
                    mount[1] = []
                with self.assertRaises(lane.Refusal):
                    lane.profile_test_count(groups)

    def test_capsule_denominator_cannot_relabel_55_as_58_or_omit_current_mount_cases(self):
        current = current_groups()
        legacy = [row for row in current if row[0] != "native-kv2-mount"]
        for groups in (legacy, current):
            with self.subTest(count=sum(row[3] for row in groups)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                capsule = synthetic_capsule(root, groups)
                digest = put(root / "capsule.json", capsule)
                actual, _ = lane.verify_capsule(root, digest, "1" * 40, "2" * 40, "3" * 64, groups)
                self.assertEqual(actual["required_test_count"], sum(row[3] for row in groups))
                other = current if groups == legacy else legacy
                with self.assertRaisesRegex(lane.Refusal, "transferred_capsule_profile_mismatch"):
                    lane.verify_capsule(root, digest, "1" * 40, "2" * 40, "3" * 64, other)
                capsule["required_test_count"] = sum(row[3] for row in other)
                digest = put(root / "capsule.json", capsule)
                with self.assertRaisesRegex(lane.Refusal, "transferred_capsule_profile_mismatch"):
                    lane.verify_capsule(root, digest, "1" * 40, "2" * 40, "3" * 64, groups)

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
