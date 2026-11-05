import ast
import base64
import difflib
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path("/workspace/scratch/f86faac821c4/source4e808_exporter_r1")
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

old_export = files["reference/source_export_df026_r1.py"]
old_inert = files["reference/exporter_inert_df026_r1.py"]
filename = "source_export_same_root_publication_4e808_r1.py"
export = files["candidate/" + filename]
inert = files["candidate/exporter_inert_4e808_r1.py"]
export_tree, inert_tree = ast.parse(export), ast.parse(inert)
old_export_tree, old_inert_tree = ast.parse(old_export), ast.parse(old_inert)
for name, tree in [("old_exporter", old_export_tree), ("old_inert", old_inert_tree),
                   ("exporter", export_tree), ("inert", inert_tree)]:
    compile(tree, name, "exec", dont_inherit=True)
check("original exporter whole actual source", len(old_export.encode()) == 15324 and
      blob(old_export.encode()) == "47c96d89591c71e43566da3e529fa49702a8f66b")
check("original inert whole actual source", len(old_inert.encode()) == 4813 and
      blob(old_inert.encode()) == "656db30aa62f86b84f0a8dd905486d24eeb574de")
old_req = json.loads(files["reference/df026-export-inert-request.original.json"])
old_payload = json.loads(old_req["stdin"])
check("source recovered exactly from prior actual inert request",
      old_req["args"] == ["-I", "-S", "-B", "-c", old_inert] and
      base64.b64decode(old_payload["files"]["source_export_cold_h2_df026_r1.py"], validate=True)
      == old_export.encode())
edits = json.loads(files["verification/literal-edits.public.json"])
for label, before, after in [("exporter", old_export, export), ("inert", old_inert, inert)]:
    raw = before
    selected = [edit for edit in edits if edit["source"] == label]
    for edit in selected:
        check(label + " literal count " + edit["before"][:64],
              raw.count(edit["before"]) == edit["occurrences"])
        raw = raw.replace(edit["before"], edit["after"])
    check(label + " literal replay whole equality", raw == after)
    for edit in reversed(selected):
        check(label + " inverse literal count " + edit["after"][:64],
              raw.count(edit["after"]) == edit["occurrences"])
        raw = raw.replace(edit["after"], edit["before"])
    check(label + " literal inverse restores whole original", raw == before)
    diff = "".join(difflib.unified_diff(before.splitlines(keepends=True),
                                       after.splitlines(keepends=True),
                                       fromfile="reference/" + label + ".py",
                                       tofile="candidate/" + label + ".py"))
    applied, hunks = strict_apply(before, diff)
    check(label + " strict diff whole reconstruction", applied == after)
    (ROOT / (label + ".diff")).write_text(diff)
check("all exporter twenty functions plus class byte identical",
      definitions(export, export_tree) == definitions(old_export, old_export_tree)
      and len(definitions(export, export_tree)) == 21)
check("all five inert functions byte identical",
      definitions(inert, inert_tree) == definitions(old_inert, old_inert_tree)
      and len(definitions(inert, inert_tree)) == 5)
core_raw = files["reference/actual4e808-source-stage-result.original.json"]
core = json.loads(core_raw)
check("actual source core whole pinned",
      len(core_raw.encode()) == 27181 and
      sha(core_raw.encode()) == "1bbe84d728f91058ecca7045483a231b993e1409577d2bc87191fa14af972bce" and
      blob(core_raw.encode()) == "079369dac398d8fab512bd52c00657af7357467c")
check("source constants match actual staged source", (
      path_value(export_tree, "SOURCE"), literal(export_tree, "CANONICAL"),
      literal(export_tree, "TREE"), literal(export_tree, "PARENT"),
      literal(export_tree, "CANONICAL_COUNT")) == (
      core["source"], core["source_commit"], core["source_tree"],
      core["sole_parent"], core["canonical_history_count"]))
check("actual source stage was prepared clean independent full proof",
      core["host"] == "rog" and core["status"] == "prepared"
      and core["source_clean"] is True and core["full_strict_fsck_passed"] is True
      and core["independent_git_directory"] is True and core["no_alternates"] is True
      and core["no_shared_object_links"] is True
      and core["within_new_stage_deadline"] is True
      and core["compiler_started"] is False and core["server_started"] is False)
check("actual source stage 56 children closed",
      len(core["cleanup"]) == 56
      and all(row["direct_child_reaped"] is True and row["remaining"] == []
              for row in core["cleanup"]))
check("actual source full tree facts exact", (
      core["full_worktree"]["tracked_leaf_count"], core["full_worktree"]["tracked_bytes"],
      core["full_worktree"]["full_leaf_index_sha256"]) == (
      3914, 62227757, "4bdd85122123e7c8ddfe7e82220688ba23fecd263bb245cfdfc176d08226e092"))
check("existing stage bundle is explicitly incremental not reusable standalone",
      core["canonical_bundle"]["header"]["prerequisites"] ==
      ["49503322c7f446e5eb41e7744f1fdbd7f1192ecc"])
check("new source exact head and tree",
      literal(export_tree, "CANONICAL") == "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec"
      and literal(export_tree, "TREE") == "eba5e650bd080b8ad41ea52a2bc68867f541d255"
      and literal(export_tree, "CANONICAL_COUNT") == 3763)
check("original root commit uid and host contract unchanged",
      literal(export_tree, "ROOT_COMMIT") == literal(old_export_tree, "ROOT_COMMIT")
      == "67d79b3b5442ed033d38929eab2010403463e56d"
      and literal(export_tree, "UID") == 1000
      and literal(export_tree, "SYSTEM") == ("Linux", "x86_64"))
check("new exporter fresh root outside source", (
      path_value(export_tree, "ROOT"), path_value(export_tree, "BUNDLE")) == (
      "/home/qian-qi/heptabao-same-root-publication-source-export-20261105-r1",
      "/home/qian-qi/heptabao-same-root-publication-source-export-20261105-r1/canonical-4e808-full.bundle")
      and not path_value(export_tree, "ROOT").startswith(path_value(export_tree, "SOURCE") + "/"))
check("new controls outside source and export root",
      path_value(inert_tree, "BASE") ==
      "/home/qian-qi/heptabao-same-root-publication-source-export-controls-20261105-r1"
      and not path_value(inert_tree, "BASE").startswith(path_value(export_tree, "SOURCE") + "/")
      and not path_value(inert_tree, "BASE").startswith(path_value(export_tree, "ROOT") + "/"))
check("original absolute 300 seconds unchanged",
      ast.dump(assigned(export_tree, "UNTIL")) == ast.dump(assigned(old_export_tree, "UNTIL"))
      and isinstance(assigned(export_tree, "UNTIL"), ast.BinOp)
      and assigned(export_tree, "UNTIL").right.value == 300)
check("original bundle maximum unchanged",
      ast.dump(assigned(export_tree, "MAX_BUNDLE")) == ast.dump(assigned(old_export_tree, "MAX_BUNDLE")))
check("original only file Git protocols unchanged",
      literal(export_tree, "environment") == literal(old_export_tree, "environment")
      and literal(export_tree, "environment")["GIT_ALLOW_PROTOCOL"] == "file")
payload_raw = files["payload/exporter.json"]
payload = json.loads(payload_raw)
check("new payload schema exact single name",
      set(payload) == {"schema", "files"}
      and payload["schema"] == "heptabao.same-root-publication-4e808-source-export-inputs.v1"
      and set(payload["files"]) == {filename})
check("new payload exact complete exporter",
      base64.b64decode(payload["files"][filename], validate=True) == export.encode())
check("inert exact source pin",
      literal(inert_tree, "PINS") == {filename: [len(export.encode()), sha(export.encode())]})
check("original inert transport cap preserved",
      len(payload_raw.encode()) <= 262144 and
      "incoming = sys.stdin.buffer.read(262145)" in inert)
inert_req = json.loads(files["dispatch/inert.request.json"])
export_req = json.loads(files["dispatch/export.request.json"])
check("inert exact seven fields",
      set(inert_req) == {"host", "executable", "args", "stdin", "cwd", "timeout_seconds", "idempotency_key"})
check("inert exact code flags stdin cwd deadline key",
      inert_req["host"] == "rog" and inert_req["executable"] == "/usr/bin/python3"
      and inert_req["args"] == ["-I", "-S", "-B", "-c", inert]
      and inert_req["stdin"] == payload_raw and inert_req["cwd"] == "/home/qian-qi"
      and inert_req["timeout_seconds"] == 60
      and inert_req["idempotency_key"] == "heptabao-4e808-standalone-source-export-inert-" + sha(inert.encode())[:8] + "-20261105-r1")
check("export exact six fields",
      set(export_req) == {"host", "executable", "args", "cwd", "timeout_seconds", "idempotency_key"})
check("export exact filepath flags cwd deadline key",
      export_req["host"] == "rog" and export_req["executable"] == "/usr/bin/python3"
      and export_req["args"] == ["-I", "-S", "-B", path_value(inert_tree, "BASE") + "/" + filename]
      and export_req["cwd"] == "/home/qian-qi" and export_req["timeout_seconds"] == 330
      and export_req["idempotency_key"] == "heptabao-4e808-standalone-source-export-" + sha(export.encode())[:8] + "-20261105-r1")
for label, tree in [("export", export_tree), ("inert", inert_tree)]:
    check(label + " has no hidden extra argv contract",
          not any(isinstance(node, ast.Attribute)
                  and isinstance(node.value, ast.Name) and node.value.id == "sys"
                  and node.attr in ("argv", "orig_argv")
                  for node in ast.walk(tree)))
result = {
    "schema": "heptabao.same-root-publication-4e808-source-export-static-review.v1",
    "status": "passed_source_only", "checks_count": len(checks), "checks": checks,
    "source_and_inert_functions_unchanged": True,
    "original_absolute_seconds": 300, "original_git_leaf_seconds": 90,
    "original_term_seconds": 5, "original_kill_seconds": 5,
    "proposed_inert_outer_seconds": 60, "proposed_export_outer_seconds": 330,
    "candidate_modules_executed": 0, "host_requests": 0,
    "source_export_or_transport_or_import_executed": False,
    "source_stage_core_read_losslessly": True,
    "new_bundle_actual_metadata": None,
    "product_or_runtime_qualification": False,
}
raw = json.dumps(result, indent=2) + "\n"
(ROOT / "result.public.json").write_text(raw)
print(raw, end="")
