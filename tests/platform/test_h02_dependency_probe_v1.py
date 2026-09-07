from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("h02_dependency_probe_v1", SCRIPTS / "h02_dependency_probe_v1.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

class ProbeTests(unittest.TestCase):
    def test_01_matrix_and_manifests(self):
        self.assertEqual(MODULE.validate_matrix(ROOT / "planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml", ROOT), 4)

    def test_02_digest_feature_order_independent(self):
        item = MODULE.profiles(MODULE.load_yaml(ROOT / "planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml"))["HB-H02-PROBE-TOKIO-MINIMAL-SERVER"]
        changed = dict(item); changed["features"] = list(reversed(item["features"]))
        self.assertEqual(MODULE.profile_digest(item), MODULE.profile_digest(changed))

    def test_03_source_scan_is_heuristic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "build.rs").write_text("fn main(){}\n"); (root / "lib.rs").write_text('unsafe fn x(){} extern "C" { fn y(); }\n')
            value = MODULE.scan_source_tree(root)
            self.assertEqual(value["heuristic_unsafe_files"], 1); self.assertEqual(value["heuristic_ffi_files"], 1)
            self.assertEqual(value["classification"], "HEURISTIC_UNREVIEWED"); self.assertFalse(value["qualification"]); self.assertEqual(value["authority_effect"], "NONE")

    def test_04_metadata_finds_build_native(self):
        metadata = {"packages":[{"name":"root","version":"0","links":None,"targets":[{"kind":["bin"]}]},{"name":"aws-lc-sys","version":"1","links":"aws_lc","targets":[{"kind":["custom-build"]}]}],"resolve":{"nodes":[{"deps":[{"dep_kinds":[{"kind":None},{"kind":"build"}]}]}]}}
        value = MODULE.summarize_metadata(metadata)
        self.assertEqual(value["package_count"], 2); self.assertEqual(value["normal_edge_count"], 1); self.assertEqual(value["build_edge_count"], 1)
        self.assertEqual(value["native_link_packages"], ["aws-lc-sys@1"]); self.assertEqual(value["native_tool_packages"], ["aws-lc-sys@1"])

    def _args(self, tmp: Path, profile: str, **updates):
        defaults = dict(matrix=str(ROOT / "planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml"), schema=str(ROOT / "schemas/heptabao_dependency_probe_evidence_v1.schema.json"), profile_id=profile, evidence_id="HB-H02-PROBE-EVIDENCE-SYNTHETIC01", artifact_root=str(tmp / "artifacts"), cargo_lock="Cargo.lock", metadata="cargo-metadata.json", dependency_tree="dependency-tree.txt", feature_tree="feature-tree.txt", build_log="build.log", test_log="test.log", source_root=None, case_results=None, execution_kind="LOCAL_UNATTESTED", environment_id="test", branch="codex/test", commit_sha="1"*40, tree_sha="2"*40, clean_tree=False, os="linux", arch="x86_64", target="x86_64-unknown-linux-gnu", toolchain="1.98.0", rustc=None, cargo=None, runner_name=None, runner_id=None, job_id=None, image_digest=None, lock_status="FAIL", metadata_status="BLOCKED", build_status="BLOCKED", test_status="BLOCKED", package_checksum_match=None, package_vcs_commit_match=None, output=str(tmp / "out.json"))
        defaults.update(updates); return argparse.Namespace(**defaults)

    def test_05_complete_local_pass_has_no_authority(self):
        matrix = MODULE.load_yaml(ROOT / "planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml"); item = MODULE.profiles(matrix)["HB-H02-PROBE-TOKIO-MINIMAL-SERVER"]
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary); artifacts = tmp / "artifacts"; artifacts.mkdir()
            (artifacts / "cargo-metadata.json").write_text(json.dumps({"packages":[{"name":"tokio","version":"1.53.1","links":None,"targets":[{"kind":["lib"]}]}],"resolve":{"nodes":[]}}))
            for name in ("Cargo.lock","dependency-tree.txt","feature-tree.txt","build.log","test.log"): (artifacts / name).write_text(name + "\n")
            source = tmp / "source"; source.mkdir(); (source / "lib.rs").write_text("pub fn safe(){}\n")
            cases = [{"case_id":case,"status":"PASS","evidence_ref":"case/"+case} for case in item["required_cases"]]; (tmp / "cases.json").write_text(json.dumps(cases))
            args = self._args(tmp, item["profile_id"], source_root=str(source), case_results=str(tmp / "cases.json"), clean_tree=True, lock_status="PASS", metadata_status="PASS", build_status="PASS", test_status="PASS", package_checksum_match=True, package_vcs_commit_match=True, rustc="rustc 1.98", cargo="cargo 1.98")
            value = MODULE.collect(args)
            self.assertEqual(value["status"], "EXECUTED_PASS"); self.assertFalse(value["qualification"]); self.assertEqual(value["authority_effect"], "NONE"); self.assertEqual(value["review_status"]["independent_reproduction_count"], 0)

    def test_06_failure_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary); (tmp / "artifacts").mkdir(); value = MODULE.collect(self._args(tmp, "HB-H02-PROBE-RUSTLS-RING"))
            self.assertEqual(value["status"], "EXECUTED_FAIL"); self.assertGreater(value["result"]["failed_steps"], 0); self.assertGreater(value["result"]["unknown_steps"], 0); self.assertFalse(value["qualification"])

    def test_07_false_pass_with_unknown_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary); artifacts = tmp / "artifacts"; artifacts.mkdir()
            value = MODULE.collect(self._args(tmp, "HB-H02-PROBE-RUSTLS-RING")); value["status"] = "EXECUTED_PASS"
            schema = json.loads((ROOT / "schemas/heptabao_dependency_probe_evidence_v1.schema.json").read_text())
            self.assertTrue(list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value)))

    def test_08_feature_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "root"; shutil.copytree(ROOT, copied)
            manifest = copied / "probes/h02/tokio-minimal/Cargo.toml"; manifest.write_text(manifest.read_text().replace('"signal", ', ""))
            with self.assertRaises(MODULE.ProbeError): MODULE.validate_matrix(copied / "planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml", copied)

if __name__ == "__main__":
    unittest.main()
