"""Local control-flow checks using the exact original 17-write method AST.

Network, seed setup and product reads are mocked. This is not a product/HA run.
The original payload generation, CAS construction, write checks and exact-read
call ordering are executed unchanged; only the new diagnostic stop is tested.
"""
import ast
import hashlib
import json
from pathlib import Path
import secrets
import time
import types

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "ha128-r3-actual/native_v6_ha_multihost_live.af91.readonly.py"
ORIGINAL_SHA = "330cc6fe8eccb02711e897753ef70d9f3f46717f581f6e80a7b814f7603c638c"


class FixtureError(Exception):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def classes():
    raw = ORIGINAL.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL_SHA
    original = ast.parse(raw)
    cls = next(n for n in original.body if isinstance(n, ast.ClassDef) and n.name == "NativeRun")
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "activate_and_grow")
    base = types.SimpleNamespace(FixtureError=FixtureError, capture_committed_frontier=lambda *_: 34)
    scope = {"base": base, "secrets": secrets, "time": time, "HISTORY_WRITES": 17,
             "PAYLOAD_BYTES": 2 * 1024 * 1024, "TARGET_BYTES": 34 * 1024 * 1024,
             "data_digest": digest}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(ORIGINAL), "exec"), scope)

    class OriginalDelegate:
        activate_and_grow = scope["activate_and_grow"]

        def prepare(self):
            self.prepared = True

        def bootstrap_v5(self):
            return self.leader

        def capacity(self, *_):
            return {"generation": 11}

        def history_reads(self, *_args, **_kwargs):
            pass

        def request(self, node, method, path, body=None):
            if method == "POST" and path == "secret/data/" + self.path:
                ordinal = body["data"]["ordinal"]
                assert body["options"]["cas"] == ordinal + 1
                assert len(body["data"]["payload"]) == 2 * 1024 * 1024
                self.mutations.append(ordinal)
                self.last_digest = digest(body["data"])
                return (400 if self.bad_write == ordinal else 200), {"data": {"version": ordinal + 2}}
            assert (method, path) in (
                ("POST", "sys/storage/native-v6/activate"), ("POST", "secret/config"),
                ("DELETE", "secret/metadata/native-ha-local/never-created"),
            )
            return 204, {}

        def check(self, name, condition, **_details):
            self.checked.append(name)
            if condition is not True:
                raise FixtureError(name)

        def exact_read(self, _node, _path, expected, *, version=None):
            self.reads.append(version)
            if version == self.bad_read:
                raise self.original_failure
            if version is not None and version >= 3:
                assert expected == self.last_digest
            return "original_exact_read_return"

    tree = ast.parse((ROOT / "ha_history10_transport_diagnostic_r1.py").read_text())
    selected = [n for n in tree.body if isinstance(n, ast.ClassDef)
                and n.name in ("PrefixComplete", "History10Run")]
    fixture = {"official": types.SimpleNamespace(OfficialHistoryRun=OriginalDelegate),
               "base": base, "X230_ROOT": "/home/qian/heptabao-ha-history10-transport-20261107-r1"}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "diagnostic-hooks", "exec"), fixture)
    assert "required_checks" not in fixture["History10Run"].__dict__
    assert "activate_and_grow" not in fixture["History10Run"].__dict__
    return fixture["History10Run"], fixture["PrefixComplete"], fixture["X230_ROOT"]


def fresh(cls, root):
    run = object.__new__(cls)
    run.leader = types.SimpleNamespace(node_id=1, alias="x230", root=root)
    run.nodes = [run.leader]
    run.path, run.run_id, run.stage = "synthetic/history", "local", "preflight"
    run.history = {1: "seed1", 2: "seed2"}
    run.prefix_completed, run.report = False, {}
    run.context = None
    run.mutations, run.reads, run.checked = [], [], []
    run.bad_write = run.bad_read = None
    run.original_failure = TimeoutError("private synthetic exception must propagate")
    return run


def main():
    cls, complete, root = classes()
    rows = []
    run = fresh(cls, root)
    run.execute()
    assert run.mutations == list(range(1, 11)) and run.reads == list(range(3, 13))
    assert run.prefix_completed and run.report["tenthExactReadReturned"] is True
    assert len(run.history) == 12 and "native_history_write_11" not in run.checked
    rows.append("original_17_iteration_method_stops_after_tenth_exact_read_before_eleventh_intent")

    run = fresh(cls, root)
    run.bad_read = 12
    try:
        run.execute()
        raise AssertionError("failure swallowed")
    except TimeoutError as error:
        assert error is run.original_failure
    assert run.mutations == list(range(1, 11)) and run.reads[-1] == 12
    assert not run.prefix_completed and not run.report.get("tenthExactReadReturned")
    rows.append("tenth_get_timeout_preserved_without_completion_or_retry")

    run = fresh(cls, root)
    run.bad_write = 10
    try:
        run.execute()
        raise AssertionError("rejected write accepted")
    except FixtureError as error:
        assert str(error) == "native_history_write_10"
    assert run.mutations == list(range(1, 11)) and run.reads == list(range(3, 12))
    assert not run.prefix_completed
    rows.append("tenth_write_rejection_stops_before_tenth_read")

    run = fresh(cls, root)
    run.bad_read = 11
    run.original_failure = FixtureError("actual_digest_mismatch")
    try:
        run.execute()
        raise AssertionError("read failure swallowed")
    except FixtureError as error:
        assert error is run.original_failure
    assert run.mutations == list(range(1, 10)) and not run.prefix_completed
    rows.append("ninth_exact_read_failure_never_dispatches_tenth_write")

    run = fresh(cls, root)
    run.leader.node_id = 2
    try:
        run.execute()
        raise AssertionError("different leader accepted")
    except FixtureError as error:
        assert str(error) == "diagnostic_original_target_not_elected"
    assert run.mutations == [] and run.reads == []
    rows.append("different_elected_target_refused_without_forced_election")

    run = fresh(cls, root)
    run.stage = "fresh_standalone_v5_seed"
    assert run.exact_read(run.leader, run.path, "seed2", version=2) == "original_exact_read_return"
    assert not run.prefix_completed
    rows.append("seed_exact_reads_do_not_trigger_prefix_stop")

    run = fresh(cls, root)
    run.stage = "seventeen_actual_native_history_writes"
    run.last_digest = "expected"
    run.history[12] = "expected"
    try:
        run.exact_read(run.leader, run.path, "expected", version=12)
        raise AssertionError("incomplete history accepted")
    except FixtureError as error:
        assert str(error) == "diagnostic_tenth_exact_read_binding"
    assert not run.prefix_completed
    rows.append("version12_without_all_twelve_original_history_entries_refused")

    assembled = ast.parse((ROOT / "launch_history10_transport_diagnostic_r1.py").read_text())
    entries = {n.targets[0].id: n.value for n in assembled.body if isinstance(n, ast.Assign)
               and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
    old = ast.parse((ROOT / "launch_ha128_current_r3.py").read_text())
    old_pins = next(ast.literal_eval(n.value) for n in old.body if isinstance(n, ast.Assign)
                    and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "PINS")
    assert ast.literal_eval(entries["PINS"]) == old_pins and len(old_pins) == 613
    diagnostic = ast.parse((ROOT / "ha_history10_transport_diagnostic_r1.py").read_text())
    prefix_node = next(n.value for n in diagnostic.body if isinstance(n, ast.Assign)
                       and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "PREFIX_CHECKS")
    prefix = eval(compile(ast.Expression(body=prefix_node), "fixed-prefix-expression", "eval"), {})
    actual_failed = json.loads((ROOT / "ha128-r3-actual/stdout.original.ndjson").read_text().splitlines()[2])
    assert prefix == {row["case"] for row in actual_failed["checks"]} and len(prefix) == 51
    assert actual_failed["fixture_recovery"]["mutation_intents"] == actual_failed["fixture_recovery"]["mutation_responses"] == 23
    import base64
    for name, entry in ast.literal_eval(entries["PAYLOADS"]).items():
        raw = base64.b64decode(entry["base64"], validate=True)
        assert raw == (ROOT / name).read_bytes()
        assert len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"]
    rows.append("all_613_original_pins_and_three_embedded_sources_exact")
    print(json.dumps({"schema": "heptabao.history10-local-prefix-fault-checks.v1",
                      "passed": len(rows), "required": 8, "cases": rows,
                      "networkCalls": 0, "productExecutions": 0,
                      "originalMethodSha256": hashlib.sha256(ast.unparse(
                          next(n for n in ast.walk(ast.parse(ORIGINAL.read_bytes()))
                               if isinstance(n, ast.FunctionDef) and n.name == "activate_and_grow")
                      ).encode()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
