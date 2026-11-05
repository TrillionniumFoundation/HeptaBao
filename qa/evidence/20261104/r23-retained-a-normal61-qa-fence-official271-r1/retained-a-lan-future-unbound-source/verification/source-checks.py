import ast
import difflib
import hashlib
import json
from pathlib import Path

root = Path("/tmp/heptabao_retained_a_lan_unbound_r1")
data = json.loads((root / "input.json").read_text())
checks = []
def check(name, value):
    checks.append({"name": name, "passed": bool(value)})
    if not value:
        raise AssertionError(name)
def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()
def definitions(source):
    tree = ast.parse(source)
    return [(type(n).__name__, getattr(n, "name", ""), ast.get_source_segment(source, n))
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
diffs, same, changed, definition_counts = {}, [], [], {}
inverse = {v: k for k, v in data["renames"].items()}
for name, source in data["after"].items():
    oldname = inverse.get(name, name)
    old = data["before"][oldname]
    compile(old, oldname, "exec")
    compile(source, name, "exec")
    check("AST_compile_only_" + name, True)
    check("all_function_class_source_same_" + name, definitions(old) == definitions(source))
    definition_counts[name] = len(definitions(source))
    if old == source:
        same.append(name)
    else:
        changed.append(name)
        diffs[name] = "".join(difflib.unified_diff(old.splitlines(True), source.splitlines(True),
                                                  fromfile="a/" + oldname, tofile="b/" + name))
check("six_sources_whole_unchanged", len(same) == 6)
check("only_three_binding_sources_changed", set(changed) == {
    "read_stopped_recovered_cipher_same_root_publication_r1.py",
    "native_v6_pocket_source_postrecovery_cold_4e808_r1.py",
    "launch_normal_same_root_publication_pocket_postrecovery_cold_r1.py"})
launcher = data["after"]["launch_normal_same_root_publication_pocket_postrecovery_cold_r1.py"]
lt = ast.parse(launcher)
values = {}
for n in lt.body:
    if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
        try:
            values[n.targets[0].id] = ast.literal_eval(n.value)
        except (ValueError, TypeError):
            pass
check("exact_canonical_commit_tree", values["COMMIT"] == data["canonical"]["commit"] and values["TREE"] == data["canonical"]["tree"])
check("runner_pin_exact", values["RUNNER_SHA256"] == sha(data["after"]["native_v6_pocket_source_postrecovery_cold_4e808_r1.py"]))
check("cipher_reader_pin_exact", values["CIPHER_HELPER_SHA256"] == sha(data["after"]["read_stopped_recovered_cipher_same_root_publication_r1.py"]))
build_maps = [(name, value) for name, value in values.items() if isinstance(value, dict)
              and set(value) == {"linux", "mac"} and all(isinstance(v, dict) and "files" in v for v in value.values())]
check("one_exact_two_host_build_table", len(build_maps) == 1)
build_name, builds = build_maps[0]
check("all_ten_artifact_pins_remain_none", sum(len(v["files"]) for v in builds.values()) == 10 and all(x is None for v in builds.values() for x in v["files"].values()))
check("exact_two_host_new_driver_pins", all(builds[k]["build_driver_sha256"] == data["normal_drivers"][k] for k in builds))
check("candidate_build_table_equals_unbound_manifest", builds == data["binding"]["all10_actual_artifact_pins"])
check("not_ready_not_authorized", data["binding"]["ready"] is False and data["binding"]["dispatch_authorized"] is False and data["binding"]["actual_stage_or_runtime_submitted"] is False)
check("both_qualifications_remain_incomplete", data["binding"]["qualified_normal61_both_platforms"] is False and all(v["normal_result_sha256"] is None and v["root_review_blob"] is None for v in data["binding"]["independent_normal61_required"].values()))
check("original60_plus_independent1_counts", data["binding"]["each_platform_original60"] == 60 and data["binding"]["each_platform_additional_same_root_regression"] == 1)
check("desktop_import_not_claimed", data["binding"]["desktop_source"]["actual_complete_import_sha256"] is None and data["binding"]["desktop_source"]["exists_claimed"] is False)
report = {"schema": "heptabao.retained-a-unbound-lan-source-checks.v1", "all_passed": all(x["passed"] for x in checks),
          "checks": checks, "unchanged_files": same, "changed_files": changed,
          "unchanged_function_class_count": sum(definition_counts.values()), "definition_counts": definition_counts,
          "build_table_name": build_name, "diffs": diffs, "source_modules_executed": 0, "remote_calls": 0,
          "host_or_runtime_qualification": False, "scope": "local public source parse/compile and exact source comparisons only"}
print(json.dumps(report, sort_keys=True))
