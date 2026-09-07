import importlib.util
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "candidate", ROOT / "scripts/h02_candidate_adapter_harness_v1.py"
)
mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(mod)

CANDIDATE_FEATURES = {
    "tokio": [
        "io-util",
        "macros",
        "net",
        "rt-multi-thread",
        "signal",
        "sync",
        "time",
    ],
    "rustls-ring": ["logging", "ring", "std", "tls12"],
    "rustls-aws-lc": [
        "aws_lc_rs",
        "logging",
        "prefer-post-quantum",
        "std",
        "tls12",
    ],
    "openraft": ["serde", "tokio-rt", "type-alias"],
}

SUPPORT_DEPENDENCY_SPECS = {
    "futures": 'futures = "=0.3.34"',
    "jobserver": 'jobserver = "=0.1.32"',
    "openraft-macros": 'openraft-macros = "=0.10.0-alpha.33"',
    "openraft-memstore": 'openraft-memstore = "=0.10.0-alpha.33"',
    "openraft-rt": 'openraft-rt = "=0.10.0-alpha.33"',
    "openraft-rt-tokio": 'openraft-rt-tokio = "=0.10.0-alpha.33"',
    "serde": 'serde = { version = "=1.0.229", features = ["derive"] }',
    "serde_json": 'serde_json = "=1.0.145"',
    "tokio": (
        'tokio = { version = "=1.53.1", default-features = false, '
        'features = ["macros", "process", "rt-multi-thread", "sync", "time"] }'
    ),
    "zeroize": 'zeroize = "=1.8.2"',
}


def make_repo(root: Path, profile_name: str) -> Path:
    profile = mod.PROFILES[profile_name]
    path = root / profile["manifest"]
    path.parent.mkdir(parents=True, exist_ok=True)
    package = profile["candidate_package"]
    feature_text = ", ".join(json.dumps(value) for value in CANDIDATE_FEATURES[profile_name])
    lines = [
        "[package]",
        'name = "probe"',
        'version = "0.0.0"',
        'edition = "2021"',
        "",
        "[dependencies]",
        (
            f'{package} = {{ version = "={profile["version"]}", '
            f'default-features = false, features = [{feature_text}] }}'
        ),
    ]
    for dependency in profile["support_dependencies"]:
        lines.append(SUPPORT_DEPENDENCY_SPECS[dependency])
    source_overrides = profile.get("source_overrides", {})
    if source_overrides:
        lines.extend(["", "[patch.crates-io]"])
        for dependency, spec in sorted(source_overrides.items()):
            lines.append(
                f'{dependency} = {{ git = {json.dumps(spec["git"])}, '
                f'rev = {json.dumps(spec["rev"])} }}'
            )
    lines.extend(["", "[workspace]", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def output_rows(profile_name: str, seed: int, status: str = "PASS") -> str:
    profile = mod.PROFILES[profile_name]
    rows = [
        {
            "kind": "meta",
            "candidate_id": profile["candidate_id"],
            "version": profile["version"],
            "profile_id": profile["profile_id"],
            "domain": profile["domain"],
            "seed": f"0x{seed:016x}",
        }
    ]
    rows.extend(
        {
            "kind": "case",
            "case_id": case,
            "status": status,
            "assertion_count": 1 if status == "PASS" else 0,
            "detail": "synthetic",
        }
        for case in profile["cases"]
    )
    return "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"


class CandidateTests(unittest.TestCase):
    def collect(
        self,
        profile_name: str = "tokio",
        status: str = "PASS",
        replay_same: bool = True,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        make_repo(root, profile_name)
        seed = 0x5EED20260828CAFE
        output = root / "out.jsonl"
        output.write_text(output_rows(profile_name, seed, status), encoding="utf-8")
        replay = root / "replay.jsonl"
        replay.write_text(
            output_rows(profile_name, seed, status if replay_same else "FAIL"),
            encoding="utf-8",
        )
        evidence = root / "evidence.json"
        binding = root / "binding.json"
        args = Namespace(
            profile=profile_name,
            adapter_output=str(output),
            replay_output=str(replay),
            execution_exit_code=0,
            seed=hex(seed),
            toolchain="1.98.0",
            target="x86_64-unknown-linux-gnu",
            source_commit="1" * 40,
            source_tree="2" * 40,
            branch="test",
            clean_tree=True,
            environment_id="environment-123",
            executor_kind="local-container",
            runner_id=None,
            runner_name="test",
            root=str(root),
            output=str(evidence),
            binding_output=str(binding),
        )
        value = mod.collect(args)
        return temporary, root, value, evidence

    def test_collect_pass_is_candidate_bound_and_authority_free(self):
        temporary, _root, value, _evidence = self.collect()
        self.assertEqual(value["status"], "EXECUTED_PASS")
        self.assertTrue(value["candidate"]["bound"])
        self.assertFalse(value["qualification"])
        self.assertEqual(value["authority_effect"], "NONE")
        temporary.cleanup()

    def test_blocked_case_blocks_evidence(self):
        temporary, _root, value, _evidence = self.collect(status="BLOCKED")
        self.assertEqual(value["status"], "BLOCKED")
        self.assertEqual(value["summary"]["blocked"], 6)
        temporary.cleanup()

    def test_replay_mismatch_rejected(self):
        with self.assertRaises(mod.Failure):
            self.collect(replay_same=False)

    def test_feature_digest_changes_with_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, "tokio")
            first = mod.manifest_binding(
                root,
                mod.PROFILES["tokio"],
                "1.71.0",
                "x86_64-unknown-linux-gnu",
            )
            second = mod.manifest_binding(
                root,
                mod.PROFILES["tokio"],
                "1.98.0",
                "x86_64-unknown-linux-gnu",
            )
            self.assertNotEqual(
                first["feature_profile_sha256"], second["feature_profile_sha256"]
            )

    def test_support_dependency_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = make_repo(root, "rustls-ring")
            text = manifest.read_text(encoding="utf-8")
            manifest.write_text(
                text.replace(
                    "\n[workspace]",
                    '\nunexpected = "=1.0.0"\n\n[workspace]',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(mod.Failure):
                mod.manifest_binding(
                    root,
                    mod.PROFILES["rustls-ring"],
                    "1.98.0",
                    "x86_64-unknown-linux-gnu",
                )

    def test_support_dependency_version_is_digest_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = make_repo(root, "rustls-ring")
            original = mod.manifest_binding(
                root,
                mod.PROFILES["rustls-ring"],
                "1.98.0",
                "x86_64-unknown-linux-gnu",
            )
            text = manifest.read_text(encoding="utf-8")
            manifest.write_text(text.replace("=1.8.2", "=1.8.1", 1), encoding="utf-8")
            changed = mod.manifest_binding(
                root,
                mod.PROFILES["rustls-ring"],
                "1.98.0",
                "x86_64-unknown-linux-gnu",
            )
            self.assertNotEqual(
                original["feature_profile_sha256"], changed["feature_profile_sha256"]
            )


    def test_source_override_is_separate_and_digest_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, "openraft")
            binding = mod.manifest_binding(
                root,
                mod.PROFILES["openraft"],
                "1.88.0",
                "x86_64-unknown-linux-gnu",
            )
            self.assertNotIn("validit", binding["direct_dependencies"])
            self.assertEqual(
                binding["source_overrides"]["validit"]["rev"],
                "7016fa5e072a86092928144b3a3040381e6964e9",
            )

    def test_source_override_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = make_repo(root, "openraft")
            expected = mod.PROFILES["openraft"]["source_overrides"]["validit"]["rev"]
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(expected, "0" * 40, 1),
                encoding="utf-8",
            )
            with self.assertRaises(mod.Failure):
                mod.manifest_binding(
                    root,
                    mod.PROFILES["openraft"],
                    "1.88.0",
                    "x86_64-unknown-linux-gnu",
                )

    def test_unbound_patch_table_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = make_repo(root, "tokio")
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "\n[workspace]",
                    '\n[patch.crates-io]\nserde = { git = "https://example.invalid/serde", rev = "' + "1" * 40 + '" }\n\n[workspace]',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(mod.Failure):
                mod.manifest_binding(
                    root,
                    mod.PROFILES["tokio"],
                    "1.98.0",
                    "x86_64-unknown-linux-gnu",
                )

    def test_meta_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, "tokio")
            seed = 1
            meta = json.loads(output_rows("tokio", seed).splitlines()[0])
            meta["candidate_id"] = "wrong"
            lines = [json.dumps(meta)] + output_rows("tokio", seed).splitlines()[1:]
            path = root / "bad"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(mod.Failure):
                mod.validate_rows(mod.parse_jsonl(path), mod.PROFILES["tokio"], seed)

    def test_secret_marker_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, "tokio")
            seed = 1
            rows = [json.loads(line) for line in output_rows("tokio", seed).splitlines()]
            rows[1]["detail"] = "BEGIN PRIVATE KEY"
            path = root / "bad"
            path.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(mod.Failure):
                mod.validate_rows(mod.parse_jsonl(path), mod.PROFILES["tokio"], seed)

    def test_compare_full_scope_equivalent(self):
        temporary, root, _candidate, candidate_path = self.collect()
        reference = json.loads(candidate_path.read_text(encoding="utf-8"))
        reference["execution_kind"] = "REFERENCE_MODEL"
        reference["candidate"] = {
            "bound": False,
            "candidate_id": None,
            "version": None,
            "feature_profile_sha256": None,
        }
        reference["profile_id"] = "HB-H02-BEHAVIOR-RUNTIME-REFERENCE"
        reference_path = root / "ref.json"
        reference_path.write_text(json.dumps(reference), encoding="utf-8")
        output = root / "comparison.json"
        value = mod.compare(
            Namespace(
                reference=str(reference_path),
                candidate=str(candidate_path),
                adapter_scope="FULL_REFERENCE_CASE_SET",
                output=str(output),
            )
        )
        self.assertEqual(value["result"], "INVARIANT_EQUIVALENT_UNREVIEWED")
        self.assertEqual(value["authority_effect"], "NONE")
        temporary.cleanup()

    def test_compare_partial_scope_blocks_promotion(self):
        temporary, root, _candidate, candidate_path = self.collect(
            profile_name="openraft"
        )
        reference = json.loads(candidate_path.read_text(encoding="utf-8"))
        reference["execution_kind"] = "REFERENCE_MODEL"
        reference["candidate"] = {
            "bound": False,
            "candidate_id": None,
            "version": None,
            "feature_profile_sha256": None,
        }
        reference["profile_id"] = "HB-H02-BEHAVIOR-RAFT-REFERENCE"
        reference_path = root / "ref.json"
        reference_path.write_text(json.dumps(reference), encoding="utf-8")
        output = root / "comparison.json"
        value = mod.compare(
            Namespace(
                reference=str(reference_path),
                candidate=str(candidate_path),
                adapter_scope="API_SEAM_AND_FAILURE_MODEL_PARTIAL",
                output=str(output),
            )
        )
        self.assertEqual(
            value["result"], "PARTIAL_ADAPTER_SCOPE_BLOCKS_PROMOTION"
        )
        temporary.cleanup()

    def test_compare_detects_failure(self):
        temporary, root, _candidate, candidate_path = self.collect(status="FAIL")
        reference = json.loads(candidate_path.read_text(encoding="utf-8"))
        for row in reference["cases"]:
            row["status"] = "PASS"
        reference["execution_kind"] = "REFERENCE_MODEL"
        reference["candidate"] = {
            "bound": False,
            "candidate_id": None,
            "version": None,
            "feature_profile_sha256": None,
        }
        reference["profile_id"] = "HB-H02-BEHAVIOR-RUNTIME-REFERENCE"
        reference_path = root / "ref.json"
        reference_path.write_text(json.dumps(reference), encoding="utf-8")
        value = mod.compare(
            Namespace(
                reference=str(reference_path),
                candidate=str(candidate_path),
                adapter_scope="FULL_REFERENCE_CASE_SET",
                output=str(root / "comparison.json"),
            )
        )
        self.assertEqual(value["result"], "DEVIATION_OR_DEFECT_REVIEW_REQUIRED")
        temporary.cleanup()

    def test_process_failure_preserved_as_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_repo(root, "tokio")
            output = root / "out"
            output.write_text("", encoding="utf-8")
            evidence = root / "evidence.json"
            args = Namespace(
                profile="tokio",
                adapter_output=str(output),
                replay_output=None,
                execution_exit_code=101,
                seed="1",
                toolchain="1.98.0",
                target="x86_64-unknown-linux-gnu",
                source_commit="1" * 40,
                source_tree="2" * 40,
                branch="test",
                clean_tree=True,
                environment_id="environment-123",
                executor_kind="local-container",
                runner_id=None,
                runner_name="test",
                root=str(root),
                output=str(evidence),
                binding_output=None,
            )
            value = mod.collect(args)
            self.assertEqual(value["status"], "BLOCKED")
            self.assertEqual(value["summary"]["blocked"], 6)


if __name__ == "__main__":
    unittest.main()
