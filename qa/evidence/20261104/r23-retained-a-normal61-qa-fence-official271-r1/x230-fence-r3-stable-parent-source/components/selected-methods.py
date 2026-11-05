#!/usr/bin/env python3
"""Pure selected-method checks; no real filesystem, signal, child or network."""
import ast
import copy
import errno
import hashlib
import json
import stat
import sys
import types

data = json.load(sys.stdin)
old_source = data["historical_source"]
before = data["before"]
after = data["after"]
metadata = json.loads(data["metadata_raw"])
fields = ["dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"]
checks = []
def record(name, condition, **details):
    assert condition, name
    checks.append({"case": name, "passed": True, **details})

def constants(source):
    tree = ast.parse(source)
    env = {"os": types.SimpleNamespace(O_RDONLY=0, O_DIRECTORY=1, O_NOFOLLOW=2,
           O_CLOEXEC=4, O_NONBLOCK=8), "stat": stat}
    selected = [n for n in tree.body if isinstance(n, ast.Assign)]
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<selected-constants>", "exec"), env)
    return env

class Clock:
    def monotonic_ns(self):
        return 0

def s(row):
    return types.SimpleNamespace(**dict(zip(
        ["st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
         "st_size", "st_mtime_ns", "st_ctime_ns"], row)))

class FakeOS:
    O_RDONLY = 0
    O_DIRECTORY = 1
    O_NOFOLLOW = 2
    O_CLOEXEC = 4
    O_NONBLOCK = 8
    def __init__(self):
        self.stats = []
        self.fstats = []
        self.opens = []
        self.closes = []
        self.mkdirs = []
        self.fsyncs = []
        self.mkdir_error = None
    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        assert follow_symlinks is False
        value = self.stats.pop(0)
        if isinstance(value, BaseException):
            raise value
        return s(value)
    def fstat(self, fd):
        return s(self.fstats.pop(0))
    def open(self, name, flags, *, dir_fd=None):
        self.opens.append({"name": name, "flags": flags, "parent": dir_fd})
        return 91
    def close(self, fd):
        self.closes.append(fd)
    def mkdir(self, name, mode, *, dir_fd=None):
        self.mkdirs.append({"name": name, "mode": mode, "parent": dir_fd})
        if self.mkdir_error is not None:
            raise self.mkdir_error
    def fsync(self, fd):
        self.fsyncs.append(fd)

method_names = {"__init__", "handle_signal", "check", "observe", "open_fd",
                "bind", "current_identity", "verify_nodes", "reserve", "close_all"}
def selected(source):
    fake = FakeOS()
    env = constants(source)
    env.update({"os": fake, "stat": stat, "errno": errno, "time": Clock()})
    tree = ast.parse(source)
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Refused":
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in {"identity", "same_bound_identity"}:
            nodes.append(node)
        elif isinstance(node, ast.ClassDef) and node.name == "Fence":
            selected_class = copy.deepcopy(node)
            selected_class.body = [n for n in selected_class.body
                                   if isinstance(n, ast.FunctionDef) and n.name in method_names]
            nodes.append(selected_class)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<selected-fence>", "exec"), env)
    return env, fake, env["Fence"]()

def must_refuse(env, call, reason):
    try:
        call()
    except env["Refused"] as error:
        assert str(error) == reason
        return
    raise AssertionError("did not refuse " + reason)

def source_methods(source):
    tree = ast.parse(source)
    owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Fence")
    return {n.name: ast.get_source_segment(source, n)
            for n in owner.body if isinstance(n, ast.FunctionDef)}

old = constants(old_source)
base = constants(before)
new = constants(after)
record("both_candidates_ast_compile_only",
       isinstance(compile(before, "<before>", "exec"), types.CodeType)
       and isinstance(compile(after, "<after>", "exec"), types.CodeType))
for name in ["SOFT_SECONDS", "READ_CAP", "TOMBSTONE_CAP", "OUTPUT_CAP",
             "EXPECTED_DIRECTORIES", "EXPECTED_CONTROLS", "ROOT_NAME",
             "ORIGINAL_JOB", "ORIGINAL_KEY", "ORIGINAL_REQUEST_SHA256", "ORIGINAL_REQUEST_DIGEST"]:
    record("unchanged_" + name, base[name] == new[name])
bm, nm = source_methods(before), source_methods(after)
unchanged = [name for name in bm if bm[name] == nm[name]]
record("only_three_Fence_methods_changed",
       set(bm) == set(nm) and set(bm) - set(unchanged) == {"bind", "current_identity", "verify_nodes"},
       unchanged_methods=unchanged)
record("create_only_mutations_and_closure_source_unchanged",
       all(bm[n] == nm[n] for n in ("reserve", "publish", "read_source", "close_all")))
record("shared_parent_allowlist_exact",
       new["SHARED_PARENT_PATHS"] == ("/", "/home", "/home/qian-qi", new["BASE"])
       and new["CONTROLS"] not in new["SHARED_PARENT_PATHS"])

comparisons = []
for node in metadata["nodes"]:
    path = node["path"]
    if node["directory"]:
        old_expected = old["EXPECTED_DIRECTORIES"][path]
        bound_expected = base["EXPECTED_DIRECTORIES"][path]
    else:
        old_expected = old["EXPECTED_CONTROLS"][node["name"]]["identity"]
        bound_expected = base["EXPECTED_CONTROLS"][node["name"]]["identity"]
    observed = node["identity_before"]
    assert observed == node["identity_after"] == bound_expected
    changed = [{"field": fields[i], "historical_expected": str(old_expected[i]),
                "later_observed": str(observed[i])}
               for i in range(9) if old_expected[i] != observed[i]]
    comparisons.append({"path": path, "expected_r2_equals_saved_metadata": True,
                        "stable_object_first_five_equal": old_expected[:5] == observed[:5],
                        "historical_to_later_observed_changes": changed})
record("metadata_observation_exact_all_eight_nodes", len(comparisons) == 8)
record("historical_difference_only_two_shared_paths",
       [r["path"] for r in comparisons if r["historical_to_later_observed_changes"]]
       == ["/home/qian-qi", new["BASE"]])
record("historical_difference_only_nlink_mtime_ctime",
       all([d["field"] for d in r["historical_to_later_observed_changes"]]
           == ["nlink", "mtime_ns", "ctime_ns"]
           for r in comparisons if r["historical_to_later_observed_changes"]))

path = "/home/qian-qi"
expected = new["EXPECTED_DIRECTORIES"][path]
actual_metadata = next(n["identity_before"] for n in metadata["nodes"] if n["path"] == path)
oe, of, state = selected(old_source)
of.stats = [actual_metadata]
must_refuse(oe, lambda: state.bind(path, "qian-qi", 4, True,
                                  old["EXPECTED_DIRECTORIES"][path]), "fixed_identity_mismatch")
record("old_full9_rejects_saved_public_metadata_before_open", of.opens == [])

for i in (5, 6, 7, 8):
    env, fake, state = selected(after)
    before_id, held_id, named_id = [list(expected) for _ in range(3)]
    before_id[i] += 1
    held_id[i] += 2
    named_id[i] += 3
    fake.stats = [before_id, named_id]
    fake.fstats = [held_id]
    node = state.bind(path, "qian-qi", 4, True, expected)
    fake.stats = [named_id]
    fake.fstats = [held_id]
    state.verify_nodes()
    assert state.close_all()
    record("shared_" + fields[i] + "_variation_keeps_object_binding",
           node["identity_before"] == before_id
           and node["expected_fixed_identity"] == expected
           and node["identity_after"] == held_id
           and fake.opens[0]["flags"] == env["DIR_FLAGS"]
           and fake.closes == [91])

for i in range(5):
    env, fake, state = selected(after)
    changed = list(expected)
    changed[i] += 1
    fake.stats = [changed]
    must_refuse(env, lambda: state.bind(path, "qian-qi", 4, True, expected),
                "fixed_identity_mismatch")
    record("before_open_" + fields[i] + "_drift_refused", fake.opens == [])

env, fake, state = selected(after)
named_replacement = list(expected)
named_replacement[1] += 100
fake.stats = [expected, named_replacement]
fake.fstats = [expected]
must_refuse(env, lambda: state.bind(path, "qian-qi", 4, True, expected),
            "opened_named_held_identity_mismatch")
record("replacement_between_open_and_named_check_refused_and_closed",
       state.close_all() and fake.closes == [91] and len(state.nodes) == 0)

env, fake, state = selected(after)
fake.stats = [expected, expected]
fake.fstats = [expected]
node = state.bind(path, "qian-qi", 4, True, expected)
fake.stats = [named_replacement]
fake.fstats = [expected]
must_refuse(env, lambda: state.current_identity(node), "current_named_held_identity_mismatch")
record("late_named_replacement_refused_and_closed",
       state.close_all() and fake.closes == [91])

env, fake, state = selected(after)
same = env["same_bound_identity"]
for scope_path, directory in [(new["CONTROLS"], True),
                               (new["BASE"] + "/" + new["ROOT_NAME"], True),
                               (new["CONTROLS"] + "/relay.py", False),
                               (path, False)]:
    observed = list(expected)
    observed[7] += 1
    record("full9_scope_retained_" + scope_path + "_" + str(directory),
           same(scope_path, directory, observed, expected) is False)

for kind, mode in [("directory", stat.S_IFDIR | 0o700),
                   ("regular", stat.S_IFREG | 0o600),
                   ("symlink", stat.S_IFLNK | 0o777)]:
    env, fake, state = selected(after)
    present = list(expected)
    present[4] = mode
    fake.stats = [present]
    parent = {"fd": 7, "identity_before": new["EXPECTED_DIRECTORIES"][new["BASE"]]}
    must_refuse(env, lambda: state.reserve(parent), "existing_root_no_modification")
    record("existing_" + kind + "_root_never_mkdir",
           fake.mkdirs == [] and not state.mkdir_attempted
           and state.absence_observation == "present")

env, fake, state = selected(after)
fake.stats = [FileNotFoundError(errno.ENOENT, "synthetic-only")]
fake.mkdir_error = FileExistsError(errno.EEXIST, "synthetic-only")
try:
    state.reserve({"fd": 7, "identity_before": new["EXPECTED_DIRECTORIES"][new["BASE"]]})
except FileExistsError as error:
    assert error.errno == errno.EEXIST
else:
    raise AssertionError("mkdir race admitted")
record("absence_then_competing_mkdir_refused_no_retry",
       len(fake.mkdirs) == 1 and state.mkdir_attempted
       and not state.mkdir_returned_success and fake.fsyncs == [])

output = {
 "schema": "heptabao.shared-parent-fence-pure-components.v1",
 "checks": checks, "total": len(checks), "passed": len(checks),
 "metadata_comparison": comparisons,
 "limits": {"actual_host_calls": 0, "actual_file_descriptors": 0,
            "actual_directory_reads": 0, "actual_signals": 0,
            "actual_network": 0, "actual_children": 0, "actual_mkdirs": 0,
            "whole_controller_main_executed": False},
 "interpretation": {
   "old_failure_specific_field_proven": False,
   "latest_fence_failed_parent_full9_was_not_reported": True,
   "saved_metadata_is_separate_historical_observation": True,
   "original_relay_state": "UNKNOWN",
   "runtime_go": False
 }
}
sys.stdout.write(json.dumps(output, sort_keys=True) + "\n")
