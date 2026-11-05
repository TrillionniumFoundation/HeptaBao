#!/usr/bin/env python3
"""Pure checks of actual Binding lexical path predicates; no module or filesystem admission."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
data = json.loads(Path(sys.argv[1]).read_text())
raw = data["source"]
tree = ast.parse(raw)
assert hashlib.sha256(raw.encode()).hexdigest() == "6bbaa72dcb899d359f14c6e442c824c46a8c52aa74aa0d6be8b1820596c34cf4"
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Binding")
init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
calls = {}
for n in ast.walk(init):
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "need" and len(n.args) == 2 and isinstance(n.args[1], ast.Constant):
        calls[n.args[1].value] = n.args[0]
base = Path("/home/qian-qi/heptabao-ha-closure-20261103-r1")
checks = []
def check(name, value):
    assert value, name
    checks.append(name)
def predicate(name, scope):
    return bool(eval(compile(ast.Expression(calls[name]), "<selected-actual-path-predicate>", "eval"), scope))
def evaluate(binding):
    self = SimpleNamespace(**{k: Path(v) for k,v in binding["layout"].items()})
    scope = {"self": self, "BASE": base, "re": re, "path": self.control / "binding.private.json",
             "str": str, "os": SimpleNamespace(getuid=lambda: 1000)}
    result = {}
    for label in ("owned_control_namespace", "owned_work_namespace", "canonical_source_namespace",
                  "prepare_namespace", "exact_binding_location"):
        result[label] = predicate(label, scope)
    for category, label in (("qa_files", "qa_owned_layout"), ("artifacts", "owned_artifact_layout"),
                            ("h2_client", "owned_h2_qa_layout")):
        for name,pin in binding[category].items():
            row = dict(scope, pin=pin, name=name, role=name)
            if category == "artifacts":
                stmt = next(n for n in init.body if isinstance(n, ast.Assign)
                            and any(isinstance(t, ast.Name) and t.id == "artifact_names" for t in n.targets))
                row["artifact_names"] = ast.literal_eval(stmt.value)
            if category == "h2_client":
                stmt = next(n for n in init.body if isinstance(n, ast.Assign)
                            and any(isinstance(t, ast.Name) and t.id == "names" for t in n.targets))
                row["names"] = ast.literal_eval(stmt.value)
            result[category + "/" + name] = predicate(label, row)
    return result
old_binding, new_binding = [json.loads(data[k]) for k in ("old_binding_raw", "new_binding_raw")]
old_dispatch, new_dispatch = [json.loads(data[k]) for k in ("old_dispatch_raw", "new_dispatch_raw")]
old_result, new_result = evaluate(old_binding), evaluate(new_binding)
check("old_template_actual_control_namespace_rejected", old_result["owned_control_namespace"] is False)
check("old_template_actual_work_namespace_rejected", old_result["owned_work_namespace"] is False)
for label,value in new_result.items():
    check("corrected_actual_path_predicate/" + label, value)
check("candidate_binding_source_unchanged", True)
check("fixed_parent_basename", new_binding["layout"]["control"] == str(base / "normal-native-h2-gate-control-r2")
      and new_binding["layout"]["work"] == str(base / "normal-native-h2-gate-live-r2")
      and new_binding["layout"]["prepare"] == str(base / "normal-native-h2-gate-control-r2/prepare-r1"))
check("canonical_source_unchanged", new_binding["layout"]["source"] == old_binding["layout"]["source"])
def leaves(value, prefix=()):
    if isinstance(value, dict):
        out = {}
        for k,v in value.items(): out.update(leaves(v, prefix + (k,)))
        return out
    if isinstance(value, list):
        out = {}
        for k,v in enumerate(value): out.update(leaves(v, prefix + (k,)))
        return out
    return {prefix: value}
before, after = leaves(old_binding), leaves(new_binding)
check("binding_leaf_set_unchanged", before.keys() == after.keys())
changes = []
for key in before:
    if before[key] != after[key]:
        check("only_declared_binding_path/" + "/".join(map(str,key)),
              key in (("layout","control"),("layout","work"),("layout","prepare"))
              or (key[0] in ("qa_files","artifacts","h2_client") and key[-1] == "path"))
        changes.append({"field": list(key), "before": before[key], "after": after[key]})
check("exact_25_binding_path_changes", len(changes) == 25)
before, after = leaves(old_dispatch), leaves(new_dispatch)
check("dispatch_leaf_set_unchanged", before.keys() == after.keys())
dispatch_changes = []
for key in before:
    if before[key] != after[key]:
        check("only_declared_dispatch_argv_path/" + "/".join(map(str,key)),
              len(key) == 4 and key[0] == "templates" and key[1] in ("prepare","live")
              and key[2] == "args" and key[3] in (3,5))
        dispatch_changes.append({"field": list(key), "before": before[key], "after": after[key]})
check("exact_four_dispatch_path_changes", len(dispatch_changes) == 4)
for name,request in new_dispatch["templates"].items():
    args = request["args"]
    check(name + "_exact_program_and_binding",
          args[3] == new_binding["layout"]["control"] + "/qa/native_h2_gate_r1.py"
          and args[4:6] == ["--binding", new_binding["layout"]["control"] + "/binding.private.json"]
          and request["cwd"] == str(base))
    check(name + "_unmodified_flags_caps_and_key", all(
        request[k] == old_dispatch["templates"][name][k] for k in
        ("host","executable","cwd","timeout_seconds","idempotency_key")))
check("binding_unready_preserved", new_binding["ready_for_readonly_prepare"] is False)
check("dispatch_unauthorized_preserved", new_dispatch["ready"] is False
      and new_dispatch["requests_authorized"] is False)
def strict_apply(before, patch):
    old_lines, diff = before.splitlines(keepends=True), patch.splitlines(keepends=True)
    assert diff[0].startswith("--- ") and diff[1].startswith("+++ ")
    out, position, index, hunks = [], 0, 2, 0
    while index < len(diff):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n", diff[index])
        assert match
        old_start, old_count, new_start, new_count = (int(match[1]), int(match[2] or 1),
                                                      int(match[3]), int(match[4] or 1))
        start = old_start - 1 if old_count else old_start
        assert start >= position
        out.extend(old_lines[position:start])
        position = start
        assert len(out) == (new_start - 1 if new_count else new_start)
        seen_old = seen_new = 0
        index += 1
        while index < len(diff) and not diff[index].startswith("@@ "):
            line = diff[index]
            assert line[0] in " +-"
            if line[0] != "+":
                assert old_lines[position] == line[1:]
                position += 1
                seen_old += 1
            if line[0] != "-":
                out.append(line[1:])
                seen_new += 1
            index += 1
        assert (seen_old, seen_new) == (old_count, new_count)
        hunks += 1
    out.extend(old_lines[position:])
    return "".join(out), hunks

diffs = {}
for name in ("binding","dispatch"):
    before,after = data["old_" + name + "_raw"], data["new_" + name + "_raw"]
    delta = "".join(difflib.unified_diff(before.splitlines(keepends=True),after.splitlines(keepends=True),
                                       fromfile="before/" + name + ".json",tofile="corrected/" + name + ".json"))
    rebuilt,hunks = strict_apply(before,delta)
    check(name + "_strict_whole_apply", rebuilt == after)
    reverse = "".join(difflib.unified_diff(after.splitlines(keepends=True),before.splitlines(keepends=True),
                                         fromfile="corrected/" + name + ".json",tofile="before/" + name + ".json"))
    recovered,back_hunks = strict_apply(after,reverse)
    check(name + "_strict_reverse_exact", recovered == before and back_hunks == hunks)
    diffs[name] = {"text":delta,"hunks":hunks,"bytes":len(delta.encode()),
                   "sha256":hashlib.sha256(delta.encode()).hexdigest()}
print(json.dumps({"schema":"heptabao.h2-template-path-correction.offline.v1","status":"passed",
                  "checks":checks,"check_count":len(checks),"old_actual_predicate_results":old_result,
                  "new_actual_predicate_results":new_result,"binding_path_changes":changes,
                  "dispatch_path_changes":dispatch_changes,"diffs":diffs,
                  "full_candidate_modules_executed":False,"target_host_calls":0,
                  "filesystem_calls_by_selected_predicates":0,"new_runtime_qualification":False},
                 indent=2,sort_keys=True))
