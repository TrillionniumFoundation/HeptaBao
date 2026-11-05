#!/usr/bin/env python3
"""Offline AST-selected checks for separate instrument/product identities. No target imports."""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from types import SimpleNamespace

source = json.loads(Path(sys.argv[1]).read_text())
checks = []
def check(label, value):
    assert value, label
    checks.append(label)
def digest(raw):
    return hashlib.sha256(raw.encode()).hexdigest()
def trees(raw):
    tree = ast.parse(raw)
    compile(tree, "<source-parse-only>", "exec")
    return tree
old_b, new_b = trees(source["before_binding"]), trees(source["after_binding"])
old_g, new_g = trees(source["before_gate"]), trees(source["after_gate"])
def constants(tree):
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return out
old, new = constants(old_b), constants(new_b)
check("four_full_sources_parse_compile_not_executed", True)
for key in ("BUDGETS", "API_PORTS", "FEATURES", "PROFILE", "REFERENCE_PINS",
            "PRODUCT_PINS", "H2_BUILD_CAPS", "H2_SOURCE_PINS", "H2_COMPONENT_TESTS",
            "INGRESS_OBSERVER_TESTS", "COLD_H2_TESTS", "CANONICAL_LOCK_SHA", "GROUPS_SHA"):
    check("unchanged_constant_" + key, old[key] == new[key])
check("product_exact_4e808", new["PRODUCT_COMMIT"] == "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"
      and new["PRODUCT_TREE"] == "eba5e650bd080b8ad41ea52a2bc68867f541d255")
check("instrument_exact_df026", new["H2_INSTRUMENT_BUILD_COMMIT"] == old["COMMIT"]
      and new["H2_INSTRUMENT_BUILD_TREE"] == old["TREE"])
check("normal61_exact_runner_sha", new["PRODUCT_NORMAL_RUNNER_SHA"] == digest(source["normal61_runner"]))
check("instrument_normal60_exact_result", new["H2_INSTRUMENT_NORMAL_RESULT"] ==
      (48188, "84d763e6ff948df27964f373e834f869d7b22eeb0d7efb929fbd5c299c528f1b"))
check("instrument_normal60_exact_runner", new["H2_INSTRUMENT_NORMAL_RUNNER_SHA"] ==
      "1a3fdc3a7cf6504447feb7d7dadf2f365b292512f6d0cf8cdfb4a2ea63d33d40")
runner = constants(trees(source["normal61_runner"]))
check("additional_one_exact_runner_name", new["SAME_ROOT_PUBLICATION_TESTS"] == runner["SAME_ROOT_PUBLICATION_TESTS"])

def definitions(tree, raw):
    out = {}
    def visit(body, prefix):
        for node in body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + node.name
                out[name] = ast.get_source_segment(raw, node)
                visit(node.body, name + ".")
    visit(tree.body, "")
    return out
definition_proof = {}
for label, before_tree, after_tree, before_raw, after_raw, allowed in (
    ("binding", old_b, new_b, source["before_binding"], source["after_binding"],
     {"Binding", "Binding.__init__", "Binding.verify_h2_qa", "Binding.verify"}),
    ("driver", old_g, new_g, source["before_gate"], source["after_gate"],
     {"make_fixture", "make_fixture.PhaseB", "make_fixture.PhaseB.h2_case",
      "make_fixture.PhaseB.finish", "prepare", "main"}),
):
    before_defs, after_defs = definitions(before_tree, before_raw), definitions(after_tree, after_raw)
    check(label + "_definition_names_equal", before_defs.keys() == after_defs.keys())
    changed = sorted(k for k in before_defs if before_defs[k] != after_defs[k])
    unchanged = sorted(k for k in before_defs if before_defs[k] == after_defs[k])
    check(label + "_only_declared_identity_and_qualification_definitions_changed", set(changed) == allowed)
    definition_proof[label] = {"changed": changed, "unchanged_count": len(unchanged), "unchanged": unchanged}

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
for label in ("binding", "gate"):
    before, after = source["before_" + label], source["after_" + label]
    delta = "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                      fromfile="before/" + label + ".py", tofile="candidate/" + label + ".py"))
    rebuilt, count = strict_apply(before, delta)
    check(label + "_strict_whole_diff_rebuild", rebuilt == after)
    reverse = "".join(difflib.unified_diff(after.splitlines(keepends=True), before.splitlines(keepends=True),
                                         fromfile="candidate/" + label + ".py", tofile="before/" + label + ".py"))
    inverse, inverse_count = strict_apply(after, reverse)
    check(label + "_strict_reverse_recovers_original", inverse == before and count == inverse_count)
    diffs[label] = {"text": delta, "hunks": count, "sha256": digest(delta), "bytes": len(delta.encode())}

def method(tree, name):
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Binding")
    return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
def selected_globals(tree):
    ns = {"json": json, "hashlib": hashlib, "re": re, "tomllib": tomllib}
    ns.update(constants(tree))
    nodes = [copy.deepcopy(n) for n in tree.body if
             (isinstance(n, ast.ClassDef) and n.name == "BindingError") or
             (isinstance(n, ast.FunctionDef) and n.name in
              ("need", "sha", "duplicate_free", "parse", "lock_subset"))]
    nodes.append(copy.deepcopy(method(tree, "verify_h2_qa")))
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 "<selected-pure-definitions>", "exec"), ns)
    ns["remaining"] = lambda until: 1.0
    return ns

original_instrument = source["instrument_raws"]
def instrument_case(tree, mutate=None):
    ns = selected_globals(tree)
    data = dict(original_instrument)
    pins = copy.deepcopy(source["fixture_template"]["h2_client"])
    if mutate is not None:
        mutate(data)
        for role, raw in data.items():
            pins[role]["sha256"], pins[role]["bytes"] = digest(raw), len(raw.encode())
    by_path = {pins[role]["path"]: raw.encode() for role, raw in data.items()}
    def fake_pin(pin, until, retain=False):
        raw = by_path[pin["path"]]
        assert hashlib.sha256(raw).hexdigest() == pin["sha256"] and len(raw) == pin["bytes"]
        return raw, {}
    ns["pin_file"] = fake_pin
    obj = SimpleNamespace(h2_client=pins, artifacts={"combined_tests": {"sha256": "f" * 64}})
    try:
        return {"ok": True, "proof": ns["verify_h2_qa"](obj, 1)}
    except ns["BindingError"] as error:
        return {"ok": False, "code": str(error)}
def change_build(key, value):
    def mutate(data):
        obj = json.loads(data["build_receipt"])
        obj[key] = value
        data["build_receipt"] = json.dumps(obj)
    return mutate
def change_original(path, value):
    def mutate(data):
        obj = json.loads(data["build_binding"])
        if len(path) == 1:
            obj[path[0]] = value
        else:
            obj[path[0]][path[1]] = value
        data["build_binding"] = json.dumps(obj)
        build = json.loads(data["build_receipt"])
        build["binding_sha256"] = digest(data["build_binding"])
        data["build_receipt"] = json.dumps(build)
    return mutate
outcomes = {}
outcomes["original_coupled_method_rejects_actual_instrument_when_current_product_receipt_differs"] = instrument_case(old_b)
check("old_coupling_counterexample", outcomes[next(iter(outcomes))] ==
      {"ok": False, "code": "actual_qa_build_provenance"})
outcomes["actual_df026_instrument_with_independent_current_product_slot"] = instrument_case(new_b)
check("actual_instrument_proof_passes_selected_new_method", outcomes["actual_df026_instrument_with_independent_current_product_slot"]["ok"])
proof = outcomes["actual_df026_instrument_with_independent_current_product_slot"]["proof"]
check("proof_explicit_instrument_identity", proof["instrument_build_commit"] == new["H2_INSTRUMENT_BUILD_COMMIT"]
      and proof["instrument_build_tree"] == new["H2_INSTRUMENT_BUILD_TREE"]
      and proof["http_or_product_qualification"] is False and proof["component_count"] == 6)
for label, mutation, code in (
    ("product_identity_cannot_impersonate_instrument", change_build("candidate_commit", new["PRODUCT_COMMIT"]), "actual_qa_build_provenance"),
    ("current_product_result_cannot_replace_instrument_normal60", change_build("normal_product_result_sha256", "f" * 64), "actual_qa_build_provenance"),
    ("original_binding_product_identity_rejected", change_original(["candidate_commit"], new["PRODUCT_COMMIT"]), "original_actual_qa_build_binding"),
    ("original_binding_wrong_normal60_rejected", change_original(["normal_product_result", "sha256"], "f" * 64), "original_actual_qa_build_binding"),
):
    outcomes[label] = instrument_case(new_b, mutation)
    check(label, outcomes[label] == {"ok": False, "code": code})

calls = [n for n in ast.walk(new_g) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
         and n.func.id == "require" and len(n.args) == 2 and isinstance(n.args[1], ast.Constant)
         and n.args[1].value == "h2_exact_bound_client_terminal"]
check("one_actual_client_identity_predicate", len(calls) == 1)
expression = compile(ast.fix_missing_locations(ast.Expression(calls[0].args[0])), "<actual-client-predicate>", "eval")
client = {"schema": "heptabao.h2-single-request-client.v1",
          "candidate_commit": new["H2_INSTRUMENT_BUILD_COMMIT"], "candidate_tree": new["H2_INSTRUMENT_BUILD_TREE"],
          "operation": 2, "deadline_monotonic_ns": "1234", "stage": "complete", "error_code": None}
scope = {"client": client, "bm": SimpleNamespace(**new), "operation": 2, "until": 1234}
check("actual_driver_predicate_accepts_instrument_report", eval(expression, scope))
client["candidate_commit"], client["candidate_tree"] = new["PRODUCT_COMMIT"], new["PRODUCT_TREE"]
check("actual_driver_predicate_refuses_product_as_instrument_report", not eval(expression, scope))

verify = method(new_b, "verify")
start = next(i for i,n in enumerate(verify.body) if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "publication" for t in n.targets))
end = next(i for i in range(start, len(verify.body)) if isinstance(verify.body[i], ast.Assign)
           and any(isinstance(t, ast.Name) and t.id == "cleanup" for t in verify.body[i].targets))
publication_code = compile(ast.fix_missing_locations(ast.Module(body=copy.deepcopy(verify.body[start:end]),
                                                                type_ignores=[])), "<selected-publication-predicates>", "exec")
ns = selected_globals(new_b)
name = new["SAME_ROOT_PUBLICATION_TESTS"][0]
synthetic_product = {
    "same_root_publication_regression": {
        "schema": "heptabao.normal-same-root-publication-regression.v1", "status": "passed", "test_count": 1,
        "original_44_7_9_denominators_unchanged": True, "new_total_group_cap_seconds": 600,
        "clamped_to_original_outer_deadline": True, "actual_test_names": [name],
        "tests": [{"name": name, "tests": {"exit_code": 0, "timed_out": False,
                                          "direct_child_reaped": True, "remaining": []}}],
    },
    "original_60_status": "passed", "original_60_test_total": 60, "selected_test_total": 61,
    "additional_test_counts": {"ingress_observer": 7, "cold_h2": 9, "same_root_publication": 1},
    "controller_sha256": new["PRODUCT_NORMAL_RUNNER_SHA"],
}
def publication_case(mutate=None):
    obj = copy.deepcopy(synthetic_product)
    if mutate is not None:
        mutate(obj)
    scope = dict(ns, combined=obj)
    try:
        exec(publication_code, scope)
        return {"ok": True}
    except ns["BindingError"] as error:
        return {"ok": False, "code": str(error)}
product_outcomes = {"synthetic_shape_only": publication_case()}
check("synthetic_new_one_shape_only", product_outcomes["synthetic_shape_only"]["ok"])
for label, mutate, code in (
    ("old_total60_refused", lambda x: x.update(selected_test_total=60), "current_product_61_with_separate_same_root_one"),
    ("missing_one_refused", lambda x: x.pop("same_root_publication_regression"), "current_product_61_with_separate_same_root_one"),
    ("failed_one_refused", lambda x: x["same_root_publication_regression"].update(status="failed"), "current_product_61_with_separate_same_root_one"),
    ("wrong_exact_name_refused", lambda x: x["same_root_publication_regression"].update(actual_test_names=["other"]), "current_product_61_with_separate_same_root_one"),
    ("surviving_child_refused", lambda x: x["same_root_publication_regression"]["tests"][0]["tests"].update(remaining=[7]), "same_root_publication_regression_terminal"),
    ("old_runner_refused", lambda x: x.update(controller_sha256=new["H2_INSTRUMENT_NORMAL_RUNNER_SHA"]), "exact_current_product_normal61_runner"),
):
    product_outcomes[label] = publication_case(mutate)
    check(label, product_outcomes[label] == {"ok": False, "code": code})
template = source["fixture_template"]
check("template_two_exact_identities", template["candidate_commit"] == new["PRODUCT_COMMIT"]
      and template["candidate_tree"] == new["PRODUCT_TREE"]
      and template["instrument_build_commit"] == new["H2_INSTRUMENT_BUILD_COMMIT"]
      and template["instrument_build_tree"] == new["H2_INSTRUMENT_BUILD_TREE"])
check("template_not_ready", template["ready_for_readonly_prepare"] is False)
check("four_current_product_slots_unresolved", all(template["artifacts"][name]["bytes"] is None
      and template["artifacts"][name]["sha256"] is None
      for name in ("server", "native_receipt", "release_receipt", "combined_tests")))
check("no_new_qa_build_dispatch", "qa_build" not in source["dispatch_template"]["templates"]
      and source["dispatch_template"]["ready"] is False
      and source["dispatch_template"]["requests_authorized"] is False)
check("template_original_budgets", template["budgets"] == new["BUDGETS"])
check("instrument_client_actual_compiletime_identity_unmodified",
      'const CANDIDATE: &str = "' + new["H2_INSTRUMENT_BUILD_COMMIT"] + '";' in original_instrument["rust_source"]
      and 'const TREE: &str = "' + new["H2_INSTRUMENT_BUILD_TREE"] + '";' in original_instrument["rust_source"])

print(json.dumps({
    "schema": "heptabao.h2-product4e808.instrument-df026.offline-source-checks.v1",
    "status": "passed", "check_count": len(checks), "checks": checks,
    "definition_proof": definition_proof, "diffs": diffs,
    "instrument_selected_method_outcomes": outcomes,
    "synthetic_product_predicate_outcomes": product_outcomes,
    "candidate_full_modules_executed": False, "real_files_or_processes_opened_by_selected_code": 0,
    "rust_compiled_or_executed": False, "remote_host_calls": 0,
    "actual_product61_or_http_qualification": False,
}, indent=2, sort_keys=True))
