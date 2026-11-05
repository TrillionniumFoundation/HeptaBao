import ast
import base64
import difflib
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path("/workspace/scratch/f86faac821c4/source4e808_carrier_import_r1")
data = json.loads((ROOT / "input.json").read_text())
files = data["files"]
checks = []
def check(name, value):
    assert isinstance(value, bool)
    checks.append({"name": name, "passed": value})
    assert value, name
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
def assigned(tree, name):
    nodes = [node for node in tree.body if isinstance(node, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)]
    assert len(nodes) == 1, name
    return nodes[0].value
def literal(tree, name):
    return ast.literal_eval(assigned(tree, name))
def path_value(tree, name):
    def evaluate(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return pathlib.PurePosixPath(node.value)
        if isinstance(node, ast.Name):
            return evaluate(assigned(tree, node.id))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path":
            assert len(node.args) == 1 and not node.keywords
            return evaluate(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return evaluate(node.left) / evaluate(node.right)
        raise AssertionError("unexpected path expression")
    return str(evaluate(assigned(tree, name)))
def definitions(source, tree):
    return [(type(node).__name__, node.name, ast.get_source_segment(source, node))
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
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


before, after = data["before"], data["after"]
expected_original = {
    "sender.py": ("ac7a5e9f6a8f82faef76a1a5676fdae9f8e0ced4", 6257),
    "receiver.py": ("668989b43054dc48bc0ffe611eaae91544a5ea59", 8656),
    "relay.py": ("dcde23cb53feb13627d6309ba9f4a4df37a6cd83", 15333),
    "inert.py": ("05b379d914897ebfec9f32920904f27d74ccf31d", 5025),
    "importer.py": ("7019ca391f5832cb04a7703ddcb4365558661f81", 32923),
}
trees, old_trees, definition_details, diff_info = {}, {}, {}, {}
for name in before:
    old, new = before[name], after[name]
    trees[name], old_trees[name] = ast.parse(new, name), ast.parse(old, name)
    compile(trees[name], name, "exec", dont_inherit=True)
    compile(old_trees[name], "reference/" + name, "exec", dont_inherit=True)
    check(name + " original exact actual source", (
        blob(old.encode()), len(old.encode())) == expected_original[name])
    label = name.removesuffix(".py")
    edits = [row for row in data["edits"] if row["source"] == label]
    candidate = old
    for row in edits:
        check(name + " original literal occurrences " + row["before"][:55],
              candidate.count(row["before"]) == row["occurrences"])
        candidate = candidate.replace(row["before"], row["after"])
    check(name + " whole exact literal replay", candidate == new)
    for row in reversed(edits):
        check(name + " inverse literal occurrences " + row["after"][:55],
              candidate.count(row["after"]) == row["occurrences"])
        candidate = candidate.replace(row["after"], row["before"])
    check(name + " whole original restored by inverse", candidate == old)
    diff = "".join(difflib.unified_diff(old.splitlines(keepends=True),
                                       new.splitlines(keepends=True),
                                       fromfile="reference/" + name,
                                       tofile="candidate/" + name))
    applied, hunks = strict_apply(old, diff)
    check(name + " strict unified diff reconstruction", applied == new)
    (ROOT / (name + ".diff")).write_text(diff)
    old_defs = {(kind, symbol): raw for kind, symbol, raw in definitions(old, old_trees[name])}
    new_defs = {(kind, symbol): raw for kind, symbol, raw in definitions(new, trees[name])}
    check(name + " original definition set retained", set(old_defs) == set(new_defs))
    changed = [symbol for (kind, symbol), raw in new_defs.items() if raw != old_defs[(kind, symbol)]]
    expected_changed = {"receiver.py": ["receive"], "importer.py": ["verify_receipts"]}.get(name, [])
    check(name + " only receipt identity predicate definition changes", changed == expected_changed)
    definition_details[name] = {
        "count": len(new_defs), "whole_unchanged_count": len(new_defs) - len(changed),
        "changed_definitions": changed,
    }
    diff_info[name] = {"hunks": hunks, "bytes": len(diff.encode()), "sha256": sha(diff.encode())}

head = "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"
tree = "eba5e650bd080b8ad41ea52a2bc68867f541d255"
source_files, received, transfer = data["source_files"], data["files"], data["transfer"]
base = "/home/qian-qi/heptabao-ha-closure-20261103-r1"
source_root = "/home/qian-qi/heptabao-same-root-publication-source-export-20261105-r1"
carrier_root = base + "/normal-same-root-publication-source-carrier-r1"
controls = base + "/normal-same-root-publication-source-carrier-controls-r1"
check("two ordered source roles names", [row["name"] for row in source_files] ==
      ["canonical-4e808-full.bundle", "source-export.result.public.json"])
check("source bytes hash version all unresolved",
      all(all(row[key] is None for key in ("bytes", "sha256", "version")) for row in source_files))
check("source fixed paths and separate modes",
      source_files[0]["path"] == source_root + "/canonical-4e808-full.bundle"
      and source_files[1]["path"] == source_root + "/result.public.json"
      and all(row["source_mode"] == 0o600 and row["target_mode"] == 0o400 for row in source_files))
check("received two identities unresolved distinct paths",
      [row["name"] for row in received] == [row["name"] for row in source_files]
      and all(row["path"] == carrier_root + "/incoming/" + row["name"]
              and row["mode"] == 0o400
              and all(row[key] is None for key in ("bytes", "sha256", "version"))
              for row in received))
check("transfer receipt unresolved",
      transfer["path"] == carrier_root + "/control/result.public.json"
      and transfer["mode"] == 0o600
      and all(transfer[key] is None for key in ("bytes", "sha256", "version")))
for name in ("sender.py", "receiver.py", "relay.py"):
    t = trees[name]
    check(name + " exact current identity and unbound table",
          literal(t, "HEAD") == head and literal(t, "TREE") == tree
          and literal(t, "FILES") == source_files
          and literal(t, "ACTUAL_INPUTS_READY") is False)
    idx = next(i for i, n in enumerate(t.body) if isinstance(n, ast.Assign)
               and any(isinstance(a, ast.Name) and a.id == "ACTUAL_INPUTS_READY" for a in n.targets))
    pair = t.body[idx:idx + 2]
    check(name + " early readiness guard precedes all operational statements",
          all(isinstance(n, (ast.Import, ast.ImportFrom)) or
              (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
               and isinstance(n.value.value, str))
              for n in t.body[:idx])
          and isinstance(pair[1], ast.If))
    namespace = {"__builtins__": {"RuntimeError": RuntimeError}}
    try:
        exec(compile(ast.Module(body=pair, type_ignores=[]), name + ":selected-ready", "exec"), namespace)
    except RuntimeError as error:
        denied = str(error) == "actual 4e808 source-export metadata unresolved"
    else:
        denied = False
    check(name + " selected actual false guard rejects before calls", denied)
check("relay strict SSH and trust are old exact literals",
      literal(trees["relay.py"], "SSH") == literal(old_trees["relay.py"], "SSH")
      and literal(trees["relay.py"], "TRUST") == literal(old_trees["relay.py"], "TRUST")
      and literal(trees["relay.py"], "ORIGINAL_SHA") == literal(old_trees["relay.py"], "ORIGINAL_SHA"))
check("transport helpers bind exact unbound source bytes",
      literal(trees["relay.py"], "HELPERS") ==
      {name: sha(after[name].encode()) for name in ("sender.py", "receiver.py")})
check("inert binds three exact unbound source bytes",
      literal(trees["inert.py"], "PINS") ==
      {name: [len(after[name].encode()), sha(after[name].encode())]
       for name in ("sender.py", "receiver.py", "relay.py")})
check("source carrier namespaces agree",
      path_value(trees["relay.py"], "BASE") == base
      and path_value(trees["relay.py"], "SOURCES") == controls
      and path_value(trees["relay.py"], "ROOT") == carrier_root
      and path_value(trees["inert.py"], "BASE") == controls
      and path_value(trees["receiver.py"], "ROOT") == carrier_root
      and path_value(trees["receiver.py"], "DESTINATION") == carrier_root + "/incoming")
for name in ("sender.py", "receiver.py"):
    check(name + " original endpoint absolute deadline",
          ast.dump(assigned(trees[name], "UNTIL")) ==
          ast.dump(assigned(old_trees[name], "UNTIL"))
          and assigned(trees[name], "UNTIL").right.value == 90)
check("relay original absolute deadline",
      ast.dump(assigned(trees["relay.py"], "UNTIL")) ==
      ast.dump(assigned(old_trees["relay.py"], "UNTIL"))
      and assigned(trees["relay.py"], "UNTIL").right.value == 300)
payload = json.loads(data["payload"])
check("inert payload exact schema and names",
      payload["schema"] == "heptabao.same-root-publication-4e808-source-carrier-inputs.v1"
      and set(payload["files"]) == {"sender.py", "receiver.py", "relay.py"})
for name in payload["files"]:
    check(name + " exact inert base64 full source",
          base64.b64decode(payload["files"][name], validate=True) == after[name].encode())
check("payload original size bound retained", len(data["payload"].encode()) <= 262144)

imp = trees["importer.py"]
check("importer exact current identity history and leaf count",
      literal(imp, "CANONICAL") == head and literal(imp, "TREE") == tree
      and literal(imp, "PARENT") == "1c66541993662f92cf717154e33717abedb2ea74"
      and literal(imp, "CANONICAL_COUNT") == 3763 and literal(imp, "TRACKED_FILES") == 3914)
check("importer exact source and destination contract",
      path_value(imp, "BASE") == base
      and path_value(imp, "SOURCE") == base + "/normal-same-root-publication-validation-source-r1"
      and path_value(imp, "ROOT") == base + "/normal-same-root-publication-source-import-r1"
      and path_value(imp, "CARRIER") == carrier_root
      and path_value(imp, "ART") == carrier_root + "/incoming")
check("importer exact unresolved tables and false ready",
      literal(imp, "ACTUAL_INPUTS_READY") is False
      and literal(imp, "SOURCE_FILES") == source_files
      and literal(imp, "FILES") == received and literal(imp, "TRANSFER") == transfer)
check("importer original total and only-file Git environment",
      ast.dump(assigned(imp, "UNTIL")) == ast.dump(assigned(old_trees["importer.py"], "UNTIL"))
      and literal(imp, "environment") == literal(old_trees["importer.py"], "environment"))
core = json.loads(data["source_core_raw"])
check("importer source facts match actual current source",
      (literal(imp, "CANONICAL"), literal(imp, "TREE"), literal(imp, "PARENT"),
       literal(imp, "CANONICAL_COUNT"), literal(imp, "TRACKED_FILES"))
      == (core["source_commit"], core["source_tree"], core["sole_parent"],
          core["canonical_history_count"], core["full_worktree"]["tracked_leaf_count"]))
exporter = data["exporter_raw"]
export_sha = sha(exporter.encode())
check("new receiver and importer pin exact reviewed new exporter",
      all("exported['controller']['bytes']==" + str(len(exporter.encode())) in after[name]
          and "exported['controller']['sha256']=='" + export_sha + "'" in after[name]
          for name in ("receiver.py", "importer.py")))
check("future final transport control four expected pins explicitly unresolved",
      all(line in after["importer.py"] for line in (
          "assert transported['controller']['bytes']==None",
          "assert transported['controller']['sha256']==None",
          "assert transported['helpers']['sender.py']['sha256']==None",
          "assert transported['helpers']['receiver.py']['sha256']==None")))

# Only the original argument-contract statements and the false readiness guard
# execute here. No imported candidate module, path I/O, clocks, signals or children.
old_import_req = json.loads(data["old_import_request_raw"])
check("old actual import request has required self SHA",
      old_import_req["args"] == ["-I", "-S", "-B", "-c", before["importer.py"], sha(before["importer.py"].encode())])
main = next(node for node in imp.body if isinstance(node, ast.Try))
old_main = next(node for node in old_trees["importer.py"].body if isinstance(node, ast.Try))
check("first six importer argument/readiness statements unchanged",
      [ast.dump(node) for node in main.body[:6]]
      == [ast.dump(node) for node in old_main.body[:6]])
class Args:
    pass
def run_selected_arguments(include_sha):
    self_sha = sha(after["importer.py"].encode())
    system = Args()
    system.argv = ["-c", self_sha] if include_sha else ["-c"]
    system.orig_argv = ["/usr/bin/python3", "-I", "-S", "-B", "-c", after["importer.py"]]
    if include_sha:
        system.orig_argv.append(self_sha)
    namespace = {
        "sys": system, "re": re, "digest": sha, "ACTUAL_INPUTS_READY": False,
        "__builtins__": {"len": len, "AssertionError": AssertionError},
    }
    try:
        exec(compile(ast.Module(body=main.body[:6], type_ignores=[]),
                     "importer-selected-argv", "exec"), namespace)
    except AssertionError as error:
        return str(error)
    raise AssertionError("unbound importer selected guard should refuse")
check("correct trailing self SHA passes argv then rejects unresolved inputs",
      run_selected_arguments(True) == "actual source-carrier metadata unresolved")
check("missing trailing self SHA rejects original first argument guard",
      run_selected_arguments(False) == "")

result = {
    "schema": "heptabao.same-root-publication-4e808-unbound-carrier-import-source-review.v1",
    "status": "passed_source_only",
    "checks_count": len(checks), "checks": checks,
    "definition_details": definition_details, "strict_diffs": diff_info,
    "compiled_modules": 10, "complete_candidate_modules_executed": 0,
    "selected_pure_ready_guards_executed": 3,
    "selected_original_import_arg_contract_cases": 2,
    "host_requests": 0, "cargo_or_product_or_transport_or_import_execution": False,
    "source_carrier_actual_ready": False, "source_import_actual_ready": False,
    "proposed_original_limits": {
        "endpoints": 90, "relay": 300, "relay_outer": 360, "inert_outer": 60,
        "import": 300, "git_leaf": 60, "clone": 90, "import_outer": 330,
        "term": 5, "kill": 5,
    },
}
raw = json.dumps(result, indent=2) + "\n"
(ROOT / "result.public.json").write_text(raw)
print(raw, end="")
