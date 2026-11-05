#!/usr/bin/env python3
"""Pure source/serialization checks for actual-bound QA publication and build requests."""
import argparse
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--input")
    choice.add_argument("--packet-dir")
    parser.add_argument("--output", required=True)
    parser.add_argument("--diff-output", required=True)
    parser.add_argument("--binding-diff-output", required=True)
    args = parser.parse_args()
    if args.input:
        value = json.loads(Path(args.input).read_text())
    else:
        root = Path(args.packet_dir)
        read = lambda name: (root / name).read_text(encoding="utf-8")
        carrier = read("carrier/qa-build-inputs.json")
        names = json.loads(carrier)["files"]
        value = {
            "before_source": read("reference/qa_inert.unbound.py"),
            "after_source": read("source/publish_h2_qa_inputs_r1.py"),
            "edits": json.loads(read("analysis/publisher-binding-edits.json")),
            "before_carrier": read("reference/qa-build-inputs.partial.json"),
            "after_carrier": carrier,
            "file_texts": {name: read("source/" + name) for name in names},
            "binding_raw": read("source/build-binding.private.json"),
            "partial_binding": json.loads(read("reference/build-binding.partial.json")),
            "inert_request": json.loads(read("requests/inert.exact.json")),
            "build_request": json.loads(read("requests/build.exact.json")),
            "builder_source": read("source/build_native_h2_client_r1.py")
        }
    checks = []
    def require(condition, label):
        if not condition:
            raise AssertionError(label)
        checks.append(label)
    before, after = value["before_source"], value["after_source"]
    reproduced = before
    for old, new in value["edits"]:
        require(reproduced.count(old) == 1, "unique literal binding edit")
        reproduced = reproduced.replace(old, new, 1)
    require(reproduced == after, "two edits reproduce complete source")
    inverse = after
    for old, new in reversed(value["edits"]):
        require(inverse.count(new) == 1, "unique inverse binding edit")
        inverse = inverse.replace(new, old, 1)
    require(inverse == before, "inverse reconstructs unbound publisher")
    old_tree, new_tree = ast.parse(before), ast.parse(after)
    def functions(tree, source):
        return {node.name: ast.get_source_segment(source, node) for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    old_functions, new_functions = functions(old_tree, before), functions(new_tree, after)
    require(len(old_functions) == 5 and old_functions == new_functions, "all five publisher definitions byte-identical")
    constants = {}
    for node in new_tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {"PINS", "ACTUAL_INPUTS_READY"}:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
    require(constants["ACTUAL_INPUTS_READY"] is True, "actual inputs ready")
    pins = constants["PINS"]
    payload = json.loads(value["after_carrier"])
    require(set(payload) == {"schema", "files"} and payload["schema"] == "heptabao.native-h2-qa-build-inputs.v1", "exact carrier schema")
    require(set(payload["files"]) == set(pins) == set(value["file_texts"]) and len(pins) == 8, "exact eight named files")
    require(len(value["after_carrier"].encode()) <= 524288, "original new publisher transfer cap")
    compiled = []
    for name, encoded in payload["files"].items():
        raw = base64.b64decode(encoded, validate=True)
        require(raw == value["file_texts"][name].encode(), name + " exact source bytes")
        require(pins[name] == [len(raw), sha(raw)], name + " exact pin")
        if name.endswith(".py"):
            compile(raw, name, "exec")
            compiled.append(name)
    require(len(compiled) == 3, "three Python sources compile only")
    compile(after, "qa-inert-publisher.py", "exec")
    old_payload = json.loads(value["before_carrier"])
    for name in payload["files"]:
        if name != "build-binding.private.json":
            require(payload["files"][name] == old_payload["files"][name], name + " original carrier encoding unchanged")
    old_encoded = old_payload["files"]["build-binding.private.json"]
    new_encoded = payload["files"]["build-binding.private.json"]
    require(value["before_carrier"].count(old_encoded) == 1 and value["before_carrier"].replace(old_encoded, new_encoded, 1) == value["after_carrier"], "only binding encoding changes carrier")
    binding_raw = value["binding_raw"].encode()
    require(len(binding_raw) == 4039 and sha(binding_raw) == "8807a51468c42c09d68058e9ba63313676e69f99b8d922dca11083b920581b1d", "actual-derived binding exact")
    spec = json.loads(binding_raw)
    require(spec["ready"] is True and spec["candidate_commit"] == "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c" and spec["candidate_tree"] == "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825", "exact qualified normal candidate")
    restored = json.loads(binding_raw)
    partial = value["partial_binding"]
    for name in ("ready", "target_identity", "host", "tools"):
        restored[name] = partial[name]
    require(restored == partial, "only actual ready/target/host/tools binding fields changed")
    inert = value["inert_request"]
    require(set(inert) == {"host", "executable", "args", "cwd", "stdin", "timeout_seconds", "idempotency_key"}, "exact inert request fields")
    require(inert["host"] == "rog" and inert["executable"] == "/usr/bin/python3" and inert["cwd"] == "/home/qian-qi", "fixed inert entry")
    require(inert["args"] == ["-I", "-S", "-B", "-c", after] and inert["stdin"] == value["after_carrier"], "exact inert argv and stdin")
    require(inert["timeout_seconds"] == 60 and inert["idempotency_key"] == "heptabao-df026-native-h2-qa-inert-cf7460ca-20261105-r1", "fixed unique inert key and outer cap")
    build = value["build_request"]
    require(build["host"] == "rog" and build["executable"] == "/usr/bin/python3.12" and build["cwd"] == "/home/qian-qi", "fixed build entry")
    require(build["timeout_seconds"] == 660 and build["idempotency_key"] == "heptabao-df026-native-h2-qa-build-2e2ea6ed-8807a514-20261105-r1", "build unique key and accepted outer cap")
    require(build["args"][:4] == ["-I", "-S", "-B", spec["control"] + "/build_native_h2_client_r1.py"], "build isolation flags and exact source file")
    builder = value["builder_source"]
    require(len(builder.encode()) == 35155 and sha(builder.encode()) == "2e2ea6edd029b3d7164fbe6a85826ef3523a0ec60586d330b539761d870c0a35", "reviewed builder unchanged")
    builder_tree = ast.parse(builder)
    body = next(node.body for node in builder_tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    # Only the actual ArgumentParser constructor and three add_argument calls.
    # No main, clock, imports, filesystem, child, Cargo, or reference module is executed.
    selected = []
    for node in body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "parser" for target in node.targets):
            selected.append(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "parser" and node.value.func.attr == "add_argument":
            selected.append(node)
    require(len(selected) == 4, "actual four pure argparse statements selected")
    namespace = {"argparse": argparse, "Path": Path}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "selected-actual-argparse-only", "exec"), namespace)
    parsed = namespace["parser"].parse_args(build["args"][4:])
    require(str(parsed.binding) == spec["control"] + "/build-binding.private.json" and parsed.binding_sha256 == sha(binding_raw) and parsed.self_sha256 == sha(builder.encode()), "actual builder parser accepts complete exact request")
    required = {action.option_strings[0] for action in namespace["parser"]._actions if action.required}
    require(required == {"--binding", "--binding-sha256", "--self-sha256"}, "all actual required arguments supplied")
    require(spec["caps"] == partial["caps"] and spec["caps"]["total_seconds"] == 600, "all reviewed inner caps preserved")
    report = {
        "schema": "heptabao.native-h2-qa.df026.bound-inert-offline-review.v1",
        "status": "passed_source_and_serialization_only", "check_count": len(checks), "checks": checks,
        "publisher_bytes": len(after.encode()), "publisher_sha256": sha(after.encode()),
        "carrier_bytes": len(value["after_carrier"].encode()), "carrier_sha256": sha(value["after_carrier"].encode()),
        "binding_bytes": len(binding_raw), "binding_sha256": sha(binding_raw),
        "publisher_definitions_unchanged": 5, "retained_source_files_unchanged": 7,
        "python_compile_only": compiled, "actual_argparse_statements_executed": 4,
        "target_main_or_top_level_executed": False,
        "host_publication_or_build_executed": False, "cargo_or_http_executed": False,
        "historical_target_five_fields_only": True, "builder_current_recheck_required": True,
        "inert_outer_seconds": 60, "inert_internal_new_deadline": False,
        "build_inner_seconds": 600, "build_outer_seconds": 660
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    Path(args.diff_output).write_text("".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile="reference/qa_inert.unbound.py", tofile="source/qa_inert.actual.py")))
    old_binding = base64.b64decode(old_encoded).decode()
    Path(args.binding_diff_output).write_text("".join(difflib.unified_diff(old_binding.splitlines(keepends=True), value["binding_raw"].splitlines(keepends=True), fromfile="reference/build-binding.partial.json", tofile="source/build-binding.private.json")))
    print(json.dumps({key: val for key, val in report.items() if key not in {"checks", "python_compile_only"}}))

if __name__ == "__main__":
    main()
