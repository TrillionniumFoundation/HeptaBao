import ast
import base64
import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path("/workspace/scratch/f86faac821c4/qa12_binding_peer_r1")
data = json.loads((ROOT / "input.json").read_text())
files = data["files"]
checks = []
details = {}

def check(name, condition):
    if not isinstance(condition, bool):
        raise TypeError("nonboolean independent check")
    checks.append({"name": name, "passed": condition})
    if not condition:
        raise AssertionError(name)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def unique_assignment(tree, name):
    rows = [node for node in tree.body
            if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name
                for target in node.targets)]
    assert len(rows) == 1, name
    return rows[0]

def literal(tree, name):
    return ast.literal_eval(unique_assignment(tree, name).value)

def statement_text(source, node):
    lines = source.splitlines(keepends=True)
    assert node.col_offset == 0
    return "".join(lines[node.lineno - 1:node.end_lineno])

def definition_texts(source, tree):
    return [(type(node).__name__, node.name, ast.get_source_segment(source, node))
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]

def invert_diff(patch):
    lines = patch.splitlines(keepends=True)
    assert lines[0].startswith("--- ") and lines[1].startswith("+++ ")
    result = ["--- " + lines[1][4:], "+++ " + lines[0][4:]]
    for line in lines[2:]:
        if line.startswith("@@ "):
            match = re.fullmatch(r"@@ -(\d+(?:,\d+)?) \+(\d+(?:,\d+)?) @@(.*)\n", line)
            assert match
            result.append("@@ -" + match[2] + " +" + match[1] + " @@" + match[3] + "\n")
        elif line.startswith("+"):
            result.append("-" + line[1:])
        elif line.startswith("-"):
            result.append("+" + line[1:])
        else:
            assert line.startswith(" ")
            result.append(line)
    return "".join(result)

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

meta_by_path = {row["path"]: row for row in data["whole_metas"]}
for path, raw_text in files.items():
    raw = raw_text.encode()
    meta = meta_by_path[path]
    check("whole source " + path,
          len(raw) == meta["bytes"] and sha(raw) == meta["sha256"]
          and git_blob(raw) == meta["blob"])

allowed = {
    "sender.py": ("ACTUAL_INPUTS_READY", "FILES"),
    "receiver.py": ("ACTUAL_INPUTS_READY", "FILES"),
    "relay.py": ("ACTUAL_INPUTS_READY", "FILES", "HELPERS"),
    "inert_carrier.py": ("PINS",),
}
trees = {}
function_counts = {}
for name, names in allowed.items():
    old, new = files["before/" + name], files["candidate/" + name]
    before_tree, after_tree = ast.parse(old, name), ast.parse(new, name)
    compile(before_tree, "before/" + name, "exec", dont_inherit=True)
    compile(after_tree, "candidate/" + name, "exec", dont_inherit=True)
    trees[name] = after_tree
    forward, hunks = strict_apply(old, files["diffs/" + name + ".diff"])
    reverse, inverse_hunks = strict_apply(new, invert_diff(files["diffs/" + name + ".diff"]))
    check(name + " original diff strict forward", forward == new)
    check(name + " original diff strict reverse", reverse == old and inverse_hunks == hunks)
    check(name + " exact hunk count", hunks == (1 if name == "inert_carrier.py" else 2))
    old_definitions = definition_texts(old, before_tree)
    new_definitions = definition_texts(new, after_tree)
    check(name + " all definitions byte identical", old_definitions == new_definitions)
    function_counts[name] = len(new_definitions)
    lines = new.splitlines(keepends=True)
    replacements = []
    for assignment in names:
        old_node, new_node = unique_assignment(before_tree, assignment), unique_assignment(after_tree, assignment)
        replacements.append((new_node.lineno - 1, new_node.end_lineno,
                             statement_text(old, old_node)))
    for start, end, original in sorted(replacements, reverse=True):
        lines[start:end] = [original]
    check(name + " only specified top-level assignments changed", "".join(lines) == old)
    if name != "inert_carrier.py":
        check(name + " exact false to true ready literal",
              literal(before_tree, "ACTUAL_INPUTS_READY") is False
              and literal(after_tree, "ACTUAL_INPUTS_READY") is True)
        check(name + " actual bound table",
              literal(after_tree, "FILES") == json.loads(files["binding/files.actual.public.json"]))
        check(name + " instrument identity remains df026",
              literal(after_tree, "HEAD") == "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"
              and literal(after_tree, "TREE") == "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825")
        check(name + " no current product identity substituted",
              "4e808d0ecb1bcded22870a7ec960dfb2491cf6ec" not in new
              and "eba5e650bd080b8ad41ea52a2bc68867f541d255" not in new)
        old_rows, new_rows = literal(before_tree, "FILES"), literal(after_tree, "FILES")
        check(name + " only three per-file slots change",
              len(old_rows) == len(new_rows) == 12 and
              all({key: value for key, value in a.items() if key not in ("bytes", "sha256", "version")}
                  == {key: value for key, value in b.items() if key not in ("bytes", "sha256", "version")}
                  and all(a[key] is None for key in ("bytes", "sha256", "version"))
                  and all(b[key] is not None for key in ("bytes", "sha256", "version"))
                  for a, b in zip(old_rows, new_rows)))
    details[name] = {"strict_hunks": hunks, "unchanged_definition_count": len(new_definitions),
                     "only_changed_assignments": list(names)}

check("published complete provenance table equals my prior exact v2 table",
      files["references/qa12-complete-table.public.json"] == data["independent_prior_qa12_table_raw"])
provenance = json.loads(data["independent_prior_qa12_table_raw"])
rows = json.loads(files["binding/files.actual.public.json"])
roles = ["executable", "rust_source", "test_source", "cargo_manifest", "cargo_lock",
         "canonical_lock", "build_receipt", "build_controller", "build_binding",
         "component_stdout", "component_record", "component_list_stdout"]
check("12 roles exact original order", [row["role"] for row in rows] == roles)
check("12 destination names unique", len({row["name"] for row in rows}) == 12)
check("all source paths distinct", len({row["path"] for row in rows}) == 12)
check("v2 table historical observations not transport qualification",
      provenance["transport_ready"] is False
      and provenance["current_product_qualification"] is False
      and provenance["observations_are_prior_actual_not_current_stat"] is True)
source_roots = (
    "/home/qian-qi/heptabao-native-h2-qa-df026-20261105-r3/",
    "/home/qian-qi/heptabao-native-h2-qa-controls-df026-20261105-r3/",
)
for row, original in zip(rows, provenance["files"]):
    role = row["role"]
    info_raw = files["actual-source-metadata/" + role + ".original.json"]
    info = json.loads(info_raw)
    check(role + " 8 exact fields only",
          set(row) == {"role", "path", "name", "bytes", "sha256", "source_mode", "target_mode", "version"})
    check(role + " exact original table row",
          (row["role"], row["path"], row["name"], row["bytes"], row["sha256"], row["version"])
          == (original["role"], original["source_path"], original["destination_basename"],
              original["whole_bytes"], original["whole_sha256"], original["observed_version"]))
    check(role + " native full metadata source content exact",
          len(info_raw.encode()) == original["metadata_source"]["bytes"]
          and sha(info_raw.encode()) == original["metadata_source"]["sha256"]
          and git_blob(info_raw.encode()) == original["metadata_source"]["blob"])
    check(role + " native file_info path whole size sha and version exact",
          (row["path"], row["bytes"], row["sha256"], row["version"])
          == (info["path"], info["size"], info["sha256"], info["version"]))
    check(role + " source mode uid gid nlink exact observed",
          info["metadata"] == original["observed_metadata"]
          and (info["metadata"]["mode"], info["metadata"]["uid"], info["metadata"]["gid"],
               info["metadata"]["link_count"])
          == (row["source_mode"], 1000, 1000, 1))
    check(role + " destination mode explicitly separate",
          row["source_mode"] == (0o500 if role == "executable" else 0o600)
          and row["target_mode"] == (0o500 if role == "executable" else 0o400))
    check(role + " no unbound values and exact source root",
          isinstance(row["bytes"], int) and not isinstance(row["bytes"], bool)
          and row["bytes"] > 0
          and isinstance(row["sha256"], str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]) is not None
          and isinstance(row["version"], str) and re.fullmatch(r"\d+:\d+:\d+:\d+:\d+", row["version"]) is not None
          and row["path"].startswith(source_roots)
          and "/" not in row["name"] and row["name"] not in ("", ".", ".."))

new_sources = {name: files["candidate/" + name] for name in ("sender.py", "receiver.py", "relay.py")}
check("relay helpers exact bound source hashes",
      literal(trees["relay.py"], "HELPERS")
      == {name: sha(new_sources[name].encode()) for name in ("sender.py", "receiver.py")})
check("publisher pins exact three source bytes and hashes",
      literal(trees["inert_carrier.py"], "PINS")
      == {name: [len(raw.encode()), sha(raw.encode())] for name, raw in new_sources.items()})
carrier_raw = files["payload/three-controls.bound.json"]
carrier = json.loads(carrier_raw)
check("carrier exact schema and source names",
      set(carrier) == {"schema", "files"}
      and carrier["schema"] == "heptabao.df026-shared-h2qa12-inputs.v1"
      and set(carrier["files"]) == set(new_sources))
for name, source in new_sources.items():
    check(name + " base64 exact source bytes",
          base64.b64decode(carrier["files"][name], validate=True) == source.encode())
check("carrier stays in unchanged 262144 byte envelope", len(carrier_raw.encode()) <= 262144)
base = "/home/qian-qi/heptabao-ha-closure-20261103-r1"
controls = base + "/normal-native-h2-qa-shared-artifact-controls-r1"
destination = base + "/normal-native-h2-qa-shared-artifacts-r1"
inert = json.loads(files["dispatch/inert.request.json"])
relay = json.loads(files["dispatch/relay.request.json"])
check("exact inert keys no ambient override",
      set(inert) == {"host", "executable", "args", "cwd", "stdin", "timeout_seconds", "idempotency_key"})
check("exact inert argv code stdin and cwd",
      inert["host"] == "desktop" and inert["executable"] == "/usr/bin/python3"
      and inert["args"] == ["-I", "-S", "-B", "-c", files["candidate/inert_carrier.py"]]
      and inert["cwd"] == base and inert["stdin"] == carrier_raw
      and inert["timeout_seconds"] == 60
      and inert["idempotency_key"] == "heptabao-df026-h2qa12-controls-inert-r1-be0b0b53")
check("exact relay keys no new stdin or environment",
      set(relay) == {"host", "executable", "args", "cwd", "timeout_seconds", "idempotency_key"})
check("exact relay argv cwd timeout and stable key",
      relay["host"] == "desktop" and relay["executable"] == "/usr/bin/python3"
      and relay["args"] == ["-I", "-S", "-B", controls + "/relay.py"]
      and relay["cwd"] == base and relay["timeout_seconds"] == 360
      and relay["idempotency_key"] == "heptabao-df026-h2qa12-artifact-relay-r1-d34b6df5")
check("namespace contract retains original base",
      controls in files["candidate/inert_carrier.py"]
      and "'normal-native-h2-qa-shared-artifact-controls-r1'" in new_sources["relay.py"]
      and "'normal-native-h2-qa-shared-artifacts-r1'" in new_sources["relay.py"]
      and destination in new_sources["receiver.py"]
      and "assert Path(__file__).resolve(strict=True)==SOURCES/'relay.py'" in new_sources["relay.py"])
check("receiver explicitly instrument not product qualification",
      "'http_or_product_qualification':False" in new_sources["receiver.py"]
      or '"http_or_product_qualification":False' in new_sources["receiver.py"]
      or "'http_or_product_qualification': False" in new_sources["receiver.py"]
      or '"http_or_product_qualification": False' in new_sources["receiver.py"])

result = {
    "schema": "heptabao.qa12-final-binding-independent-narrow-peer.v1",
    "status": "passed",
    "reviewed_tree": data["package_tree"],
    "checks_count": len(checks),
    "checks": checks,
    "source_diff_details": details,
    "scope": "strict literal binding, actual historical metadata, unchanged definitions and full remaining bytes, carrier and exact dispatch",
    "compiled_sources": 8,
    "candidate_modules_executed": 0,
    "host_requests": 0,
    "cargo_or_product_or_transport_execution": False,
    "current_product_qualification": False,
    "actual_file_info_is_historical_observation": True,
    "unchanged_limits": {
        "endpoint_seconds": 90, "relay_seconds": 300, "relay_outer_seconds": 360,
        "inert_outer_seconds": 60, "term_seconds": 5, "kill_seconds": 5
    },
    "transport_ready_not_claimed": True,
}
raw = json.dumps(result, indent=2) + "\n"
(ROOT / "result.public.json").write_text(raw)
print(raw, end="")
