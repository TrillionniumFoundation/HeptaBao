"""Local delegation/failure checks; no host, product or actual HTTP execution."""
import ast
import hashlib
import json
from pathlib import Path
import types
import urllib.error

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "ha128-r3-actual/native_v6_ha_multihost_live.af91.readonly.py"
ORIGINAL_SHA = "330cc6fe8eccb02711e897753ef70d9f3f46717f581f6e80a7b814f7603c638c"


def main():
    raw = ORIGINAL.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL_SHA
    original = ast.parse(raw)
    cls = next(n for n in original.body if isinstance(n, ast.ClassDef) and n.name == "NativeRun")
    execute = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "execute")
    scope = {}
    exec(compile(ast.Module(body=[execute], type_ignores=[]), str(ORIGINAL), "exec"), scope)
    original_checks = frozenset("original_case_%03d" % i for i in range(128))

    class OriginalDelegate:
        required_checks = original_checks
        execute = scope["execute"]

        def prepare(self): self.sequence.append("prepare")
        def bootstrap_v5(self): self.sequence.append("bootstrap"); return "original-leader"
        def activate_and_grow(self, leader):
            assert leader == "original-leader"
            self.sequence.extend("original-history-write-%02d" % i for i in range(1, 18))
            if self.failure is not None: raise self.failure
        def failover_and_quorum(self, leader):
            self.sequence.append("failover-and-quorum"); return "new-leader", "denied-write"
        def full_cold_restart(self, leader, denied):
            assert (leader, denied) == ("new-leader", "denied-write")
            self.sequence.append("full-cold-restart"); return leader
        def missing_cipher_leader(self, leader):
            self.sequence.append("missing-cipher-leader"); return leader
        def finish_application(self, leader):
            self.sequence.append("original-official-finish-application")
        def start(self, node, *, native=True):
            if self.start_failure is not None: raise self.start_failure
            self.next_pid += 1
            return self.next_pid

    original_api = object()
    base = types.SimpleNamespace(api=original_api)
    safe_error = lambda e: {"class": type(e).__name__, "reasonClass": type(getattr(e, "reason", e)).__name__}
    original_parser = lambda argv: ("parsed", argv)
    official = types.SimpleNamespace(OfficialHistoryRun=OriginalDelegate, parsed_arguments=original_parser)
    native = types.SimpleNamespace()
    fixture = {"official": official, "base": base, "native": native,
               "observer": types.SimpleNamespace(safe_error=safe_error), "urllib": urllib}
    source = ast.parse((ROOT / "ha128_transport_observed_r4.py").read_text())
    selected = [n for n in source.body if isinstance(n, (ast.ClassDef, ast.FunctionDef))
                and n.name in ("ObservedOfficialHistoryRun", "main")]
    exec(compile(ast.Module(body=selected, type_ignores=[]), "formal-observer-adapter", "exec"), fixture)
    new_type = fixture["ObservedOfficialHistoryRun"]
    assert all(name not in new_type.__dict__ for name in
               ("required_checks", "request", "exact_read", "activate_and_grow", "cleanup", "check"))
    assert new_type.required_checks is original_checks
    rows = ["original_required_checks_and_mutation_read_cleanup_check_methods_inherited_unchanged"]

    def fresh(error=None, node=1):
        run = object.__new__(new_type)
        run.sequence, run.report = [], {}
        run.failure = error
        run.nodes, run.started = ["original-x230"], {"original-x230"}
        run.transport_rows = [{"node": node, "error": safe_error(error)}] if error is not None else []
        run.snapshots = 0
        def snapshot(): run.snapshots += 1
        run.observe_owned_failure = snapshot
        return run

    run = fresh()
    run.execute()
    assert run.sequence == ["prepare", "bootstrap", *["original-history-write-%02d" % i for i in range(1, 18)],
                            "failover-and-quorum", "full-cold-restart", "missing-cipher-leader",
                            "original-official-finish-application"]
    assert run.snapshots == 0
    rows.append("entire_original_execute_ast_runs_seventeen_writes_and_all_later_stages_once")

    failure = urllib.error.URLError(TimeoutError("synthetic private reason"))
    run = fresh(failure)
    try: run.execute(); raise AssertionError("failure swallowed")
    except urllib.error.URLError as actual: assert actual is failure
    assert run.snapshots == 1 and "failover-and-quorum" not in run.sequence
    rows.append("same_x230_transport_error_gets_one_snapshot_then_same_exception")

    run = fresh(failure, node=2)
    try: run.execute(); raise AssertionError("failure swallowed")
    except urllib.error.URLError as actual: assert actual is failure
    assert run.snapshots == 0
    rows.append("other_node_failure_does_not_expand_x230_snapshot_scope")

    run = fresh(failure)
    run.started.clear()
    try: run.execute(); raise AssertionError("failure swallowed")
    except urllib.error.URLError as actual: assert actual is failure
    assert run.snapshots == 0
    rows.append("stopped_or_unowned_x230_never_snapshot_target")

    failure2 = RuntimeError("synthetic fixture contract failure")
    run = fresh(failure2)
    try: run.execute(); raise AssertionError("failure swallowed")
    except RuntimeError as actual: assert actual is failure2
    assert run.snapshots == 0
    rows.append("nontransport_failure_unchanged_without_snapshot")

    run = fresh(failure)
    def refused_snapshot(): raise RuntimeError("synthetic snapshot refused")
    run.observe_owned_failure = refused_snapshot
    try: run.execute(); raise AssertionError("failure swallowed")
    except urllib.error.URLError as actual: assert actual is failure
    assert run.report["optionalSnapshotReportingFailed"] is True
    rows.append("snapshot_refusal_cannot_replace_original_transport_failure")

    run = fresh()
    run.next_pid, run.start_failure, run.native_x230_pid = 1000, None, None
    node = types.SimpleNamespace(node_id=1)
    assert run.start(node) == 1001 and run.native_x230_pid == 1001
    assert run.start(node) == 1002 and run.native_x230_pid == 1002
    run.start_failure = RuntimeError("unknown original startup")
    try: run.start(node); raise AssertionError("unknown startup swallowed")
    except RuntimeError as actual: assert actual is run.start_failure
    assert run.native_x230_pid is None
    rows.append("original_restarts_keep_latest_known_pid_and_discard_pid_on_unknown_start")

    def original_driver(*args, run_type):
        assert args == ("parsed", ["original-argv"]) and run_type is new_type
        base.api = "temporary-bound-api"
        return 0
    native.execute_fixture = original_driver
    assert fixture["main"](["original-argv"]) == 0 and base.api is original_api
    rows.append("main_delegates_original_parser_driver_and_restores_api_after_success")
    def failed_driver(*_args, **_kwargs):
        base.api = "temporary-bound-api"
        raise failure2
    native.execute_fixture = failed_driver
    try: fixture["main"]([]); raise AssertionError("driver failure swallowed")
    except RuntimeError as actual: assert actual is failure2
    assert base.api is original_api
    rows.append("original_driver_failure_restores_api_without_replay")

    source_text = (ROOT / "ha_history10_transport_diagnostic_r1.py").read_text()
    old = next(n for n in ast.walk(ast.parse(source_text)) if isinstance(n, ast.FunctionDef)
               and n.name == "observe_owned_failure")
    new = next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef)
               and n.name == "observe_owned_failure")
    assert ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False)
    rows.append("single_snapshot_method_ast_exactly_matches_reviewed_history10")
    print(json.dumps({"schema": "heptabao.ha128-observed-adapter-local-tests.v1",
                      "passed": len(rows), "required": 11, "cases": rows,
                      "actualHaExecution": False, "networkCalls": 0, "productExecutions": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
