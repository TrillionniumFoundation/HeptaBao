#!/usr/bin/env python3
"""Archive the unexecuted live adapter and actual local control runs separately."""
from pathlib import Path
import ast
import gzip
import hashlib
import io
import json
import re
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCE = ROOT / "r6_readindex_verification_prepare"
files = {}
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def add(path, name):
    path = Path(path)
    assert path.is_file() and not path.is_symlink()
    raw = path.read_bytes()
    assert re.search(rb"(?m)^-----BEGIN (?:RSA )?PRIVATE KEY-----\r?$", raw) is None
    assert name not in files
    files[name] = raw


scripts = ["native_read_index_wire.py", "read_index_response_verifier.py", "read_index_log_verifier.py",
           "qa_native_read_index_wire.py", "qa_read_index_response_verifier.py", "qa_read_index_log_verifier.py",
           "native_read_index_history_extension.py", "qa_native_read_index_history_extension.py"]
for filename in scripts:
    add(SOURCE / filename, "current-controls/" + filename)
for folder in ("control-qa-r4", "log-control-qa-r2", "wire-control-qa-local-r2",
               "history-extension-control-r1", "history-extension-control-r2", "history-extension-control-r3"):
    add(SOURCE / folder / "result.public.json", "local-control-runs/" + folder + "/result.public.json")
for folder in ("history-extension-control-r1", "history-extension-control-r2"):
    for name in ("native_read_index_history_extension.py", "qa_native_read_index_history_extension.py"):
        add(SOURCE / folder / name, "local-control-runs/" + folder + "/" + name)
for folder in ("history-extension-pre-review-r1", "pre-byte-count-and-wrap-r1", "original-native-adapter"):
    for path in sorted((SOURCE / folder).iterdir()):
        if path.is_file():
            add(path, folder + "/" + path.name)
for path in sorted((ROOT / "r9_native128_readindex_prepare/parent-draft-r1").iterdir()):
    if path.is_file():
        add(path, "parent-draft-r1/" + path.name)
add(ROOT / "r7_readindex_client_evidence/original-root-tool-records.json", "mac-original-api/original-root-tool-records.json")
add(HERE / "build_checkpoint.py", "build_checkpoint.py")
add(HERE / "archive-preparation-failed-r1.public.json", "archive-preparation-failed-r1.public.json")
add(HERE / "build_checkpoint.before-key-scan-fix.py", "build_checkpoint.before-key-scan-fix.py")

drafts = []
for path in (SOURCE / "native_read_index_wire.py", SOURCE / "native_read_index_history_extension.py",
             ROOT / "r9_native128_readindex_prepare/parent-draft-r1/native_v6_ha_allhosts_owned_live.py",
             ROOT / "r9_native128_readindex_prepare/parent-draft-r1/native_v6_ha_official_history_live.py"):
    tree = ast.parse(path.read_bytes())
    values = [n.value.value for n in tree.body if isinstance(n, ast.Assign)
              and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
              and n.targets[0].id == "DRAFT_ONLY" and isinstance(n.value, ast.Constant)]
    assert values == [True]
    drafts.append({"filename": path.name, "sha256": sha(path.read_bytes()), "DRAFT_ONLY": True})

cases = []
for folder, required in (("control-qa-r4", 42), ("log-control-qa-r2", 35), ("wire-control-qa-local-r2", 11),
                         ("history-extension-control-r3", 13)):
    raw = (SOURCE / folder / "result.public.json").read_bytes()
    value = json.loads(raw)
    passed = value.get("passed", value.get("passed_count"))
    count = value.get("required", value.get("expected", value.get("required_count")))
    # Counted dictionaries are read according to each actual control schema.
    if count is None:
        count = len(value["cases"])
    assert passed == count == required, (folder, passed, count, required)
    cases.append({"local_directory": folder, "passed": passed, "required": count, "result_sha256": sha(raw),
                  "physical_product_evidence": False})

review = {"schema": "heptabao.readindex-control-checkpoint.v1",
    "status": "draft_live_entry_closed_actual_local_controls_only",
    "candidate_source_commit": "fa37c0fc6f28317d5f432bbbc2bbae062c4be064",
    "candidate_source_tree": "b1911f24c0b5c2c2ca67590b4e52c7d47dbf43af",
    "candidate_source_is_not_test_qualification": True,
    "actual_local_control_cohorts": cases, "closed_entries": drafts,
    "earlier_history_control_9_of_10_failure_retained": True,
    "earlier_history_control_failure_reason": "Removed model terminal was rejected first by the existing sequence-gap check; the test expected a later missing-terminal refusal.",
    "current_history_control_additions": "Both sequence-gap and contiguous-model missing-terminal refusals, twenty historical owners, one standalone OFF profile, strict owner binding, final fsync deadline, original request and stop ordering.",
    "native128_product_runs": 0, "new_actual_owner21_runs": 0,
    "actual_current_mac_control42_terminal_retrieved": False,
    "actual_current_mac_control42_original_job_id": "1a1abbfc587-fc05-504c",
    "actual_current_mac_control35_and11_started": False,
    "original_history_wire_runtime_sha256_required": "71a81748c07f22a2584993239b28e2e02babe97e5de8fc1f6911d7353fa3bc22",
    "github_history_wire_sha256_is_not_that_runtime_file": "15355994054c75d293a98f906b8762751b6edd59376a896267a9546ae8ceb080",
    "original_history_wire_runtime_bytes_still_pending": True,
    "original_product_denominators": {"direct": 98, "official_history": 30, "owner_checks": 6},
    "original_success_path_launches": 20,
    "launch_count_basis": {"standalone_seed": 1, "initial_native": 3, "first_leader_rejoin": 1,
        "quorum_peers_rejoin": 2, "full_cold_restart": 3, "missing_cipher_per_node_cold": 3,
        "missing_cipher_pair": 2, "missing_cipher_healthy_source": 1, "official_leader_rejoin": 1,
        "official_all_node_cold_restart": 3},
    "new_post_cleanup_evidence_pool_seconds": 360,
    "new_pool_fixed_before_first_product_run": True,
    "new_pool_covers": "All twenty original closed-log reads, local original-body/hash checks, correlations and final report fsync.",
    "per_closed_log_read_seconds": 15,
    "original_budget_credit": False,
    "original_budgets_unchanged_seconds": {"outer_fixture": 1800, "cleanup": 45, "live_stop": 5, "http": 15},
    "full_process_lifetime_completeness_proven": False,
    "executed_minority_readindex_failure_proven": False,
    "physical_ha_qualified": False, "production_credentials_tested": False,
    "production_changed": False, "traffic_cutover": False, "replacement_qualified": False,
    "synthetic_tls_private_keys_and_generated_model_artifacts_included": False,
}
assert sum(review["launch_count_basis"].values()) == 20
raw = (json.dumps(review, indent=2, sort_keys=True) + "\n").encode()
files["scope-and-independent-review.public.json"] = raw
(HERE / "scope-and-independent-review.public.json").write_bytes(raw)
manifest = {"schema": "heptabao.immutable-evidence-file-manifest.v1",
            "files": [{"path": name, "bytes": len(raw), "sha256": sha(raw)} for name, raw in sorted(files.items())]}
raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
files["manifest.public.json"] = raw
(HERE / "manifest.public.json").write_bytes(raw)
target = HERE / "readindex-control-checkpoint-r1.tar.gz"
with target.open("wb") as stream:
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, raw in sorted(files.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(raw), 0o600, 0
                item.uid = item.gid = 0
                archive.addfile(item, io.BytesIO(raw))
with tarfile.open(target, "r:gz") as archive:
    assert archive.getnames() == sorted(files)
    for name, raw in files.items():
        assert archive.extractfile(name).read() == raw
print(json.dumps({"status": "draft_control_archive_reopened_exactly", "files": len(files),
                  "bytes": target.stat().st_size, "sha256": sha(target.read_bytes()),
                  "product_runs": 0, "replacement_qualified": False}))
