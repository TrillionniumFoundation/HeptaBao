#!/usr/bin/env python3
"""Offline branch tests of actual R3 owner/action/restore methods.

Dependency objects here are synthetic. No product, socket, child, actual file
write or archive upload is executed. This does not qualify a live consumer.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace, FunctionType

def run(controller):
    checks = []
    def check(name, result):
        checks.append({"name": name, "passed": bool(result)})
        if not result:
            raise AssertionError(name)
    class FakeOwner:
        pass
    class FakeNative:
        def __init__(self, binary, root, prepared):
            self.binary, self.root, self.prepared = binary, root, prepared
            self.private = root / "private"
            self.procs, self.clients, self.observations = [], [], []
            self.seq, self.outcome_unknown = 0, False
    def parent_remaining(until):
        value = (until - time.monotonic_ns()) / 1e9
        if value <= 0:
            raise controller.Failure("component_parent_deadline")
        return value
    fake_cli = SimpleNamespace(Owner=FakeOwner)
    fake_native = SimpleNamespace(Fixture=FakeNative)
    fake_binding = SimpleNamespace(
        server=Path("/synthetic-component/server"), work=Path("/synthetic-component/work"),
        quick_fence=lambda _value: None,
    )
    bm = SimpleNamespace(remaining=parent_remaining)
    def fixture():
        instance = controller.make_fixture(fake_native, fake_cli, bm, None,
                                           fake_binding, {}, {})
        instance.initial_state = {"nodes": {"1": {"synthetic": "baseline"}}}
        return instance
    def action_failure(method, status, dispatched):
        item = fixture()
        try:
            with item.action("synthetic_malformed_reply"):
                item.last_exchange = {"method": method, "status": status, "sequence_before": 0}
                item.seq = 1 if dispatched else 0
                # Real JSON parser exception, outside request() and before check().
                json.loads("{")
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("component_exception_missing")
        return item
    item = action_failure("POST", 200, True)
    check("bad_2xx_mutation_json_unknown", item.outcome_unknown and not item.boundary_known)
    check("action_failure_record_retains_unknown", item.actions[-1]["outcome_unknown"] is True)
    try:
        item.mutation_allowed()
    except controller.Failure:
        check("new_mutation_denied_after_bad_reply", True)
    else:
        check("new_mutation_denied_after_bad_reply", False)
    for status in (400, 403):
        item = action_failure("POST", status, True)
        check("explicit_refusal_%d_stays_known" % status, item.outcome_unknown is False)
    check("not_dispatched_stays_known", action_failure("POST", None, False).outcome_unknown is False)
    check("plain_read_bad_json_not_a_new_mutation",
          action_failure("GET", 200, True).outcome_unknown is False)

    calls = []
    def stop_once(process, _captured=None):
        calls.append(process.pid)
        if process.pid == 11:
            raise OSError("synthetic_cleanup_unknown")
        return {"pid": process.pid, "owned_stopped": True, "remaining": []}
    cleanup_cli = SimpleNamespace(Owner=FakeOwner, stop_owned=stop_once, stop_provisional=stop_once)
    owner = controller.owner_class(cleanup_cli)(Path("/synthetic-component"))
    one = SimpleNamespace(pid=11, returncode=None)
    two = SimpleNamespace(pid=12, returncode=0)
    owner.children.append((one, {"start_ticks": 1}))
    first = owner.cleanup()
    second = owner.cleanup()
    check("cleanup_unknown_attempt_once", calls == [11])
    check("cleanup_unknown_result_not_upgraded", first[0]["owned_stopped"] is False
          and second[0]["owned_stopped"] is False
          and second[0]["prior_cleanup_result_retained"] is True)
    owner.children.append((two, {"start_ticks": 2}))
    third = owner.cleanup()
    check("new_after_fence_child_cleaned_separately", calls == [11, 12])
    check("old_cleanup_failure_preserved_with_new_child",
          any(x["pid"] == 11 and not x["owned_stopped"] for x in third)
          and any(x["pid"] == 12 and x["owned_stopped"] for x in third))

    # Real stop_once dispatch through the scoped setup globals adapter. The
    # synthetic reference contains only the same stop symbol; it does no I/O.
    seed_calls, fallback_calls = [], []
    def seed_stop(process, _capture):
        seed_calls.append(process.pid)
        raise OSError("synthetic_seed_stop_unknown")
    def fallback_stop(process, _capture=None):
        fallback_calls.append(process.pid)
        raise OSError("unexpected_new_cleanup_budget")
    def reference_setup(self):
        process, captured = self.component_seed, self.component_capture
        self.seed_owned = (process, captured)
        self.owner.children.append((process, captured))
        stop_owned(process, captured)
    namespace = dict(reference_setup.__globals__)
    namespace["stop_owned"] = seed_stop
    original_setup = FunctionType(reference_setup.__code__, namespace, "setup",
                                  reference_setup.__defaults__, reference_setup.__closure__)
    class FakeSeedNative(FakeNative):
        setup = original_setup
    seed_native = SimpleNamespace(Fixture=FakeSeedNative, stop_owned=seed_stop)
    seed_cli = SimpleNamespace(Owner=FakeOwner, stop_owned=fallback_stop,
                               stop_provisional=fallback_stop)
    value = controller.make_fixture(seed_native, seed_cli, bm, None, fake_binding, {}, {})
    value.component_seed = SimpleNamespace(pid=21, returncode=None)
    value.component_capture = {"start_ticks": 21}
    try:
        value.setup_phase()
    except OSError:
        check("reference_seed_stop_exception_propagates", True)
    else:
        check("reference_seed_stop_exception_propagates", False)
    first_cleanup = value.owner.cleanup()
    second_cleanup = value.owner.cleanup()
    check("reference_seed_unknown_not_retried_by_finish", seed_calls == [21] and fallback_calls == [])
    check("reference_seed_stop_is_unknown_and_not_cleared",
          value.outcome_unknown and not value.boundary_known
          and not first_cleanup[0]["owned_stopped"] and not second_cleanup[0]["owned_stopped"])
    check("reference_setup_global_symbol_not_modified",
          FakeSeedNative.setup is original_setup and original_setup.__globals__["stop_owned"] is seed_stop)

    cold_calls, cold_spawns = [], []
    def cold_stop(process, _capture):
        cold_calls.append(process.pid)
        raise OSError("synthetic_cold_stop_unknown")
    cold_cli = SimpleNamespace(Owner=FakeOwner, stop_owned=cold_stop, stop_provisional=cold_stop)
    cold_evidence = SimpleNamespace(capture_audits=lambda *_args: {})
    value = controller.make_fixture(fake_native, cold_cli, bm, cold_evidence, fake_binding, {}, {})
    value.action_until = time.monotonic_ns() + 300_000_000_000
    value.cli_cases = [{"case": "B02", "known_complete_business_terminal": True, "outcome_unknown": False}]
    process, captured = SimpleNamespace(pid=31, returncode=None), {"start_ticks": 31}
    value.nodes = {1: (process, captured)}
    value.owner.children.append((process, captured))
    value.node_fence = lambda: []
    value.spawn = lambda *_args, **_kwargs: cold_spawns.append(True)
    try:
        value.cold_restart("B02", {})
    except OSError:
        check("cold_stop_exception_propagates", True)
    else:
        check("cold_stop_exception_propagates", False)
    cold_cleanup = value.owner.cleanup()
    value.owner.cleanup()
    check("cold_unknown_not_retried_by_finish", cold_calls == [31])
    check("cold_stop_failure_never_respawns", not cold_spawns and value.outcome_unknown
          and not value.boundary_known and not cold_cleanup[0]["owned_stopped"])

    original_write = controller.write_json
    writes = []
    try:
        def exercise(label, state_mode, terminal, write_fails=False):
            value = fixture()
            value.action_until = time.monotonic_ns() + 300_000_000_000
            before = {"nodes": {"1": {"synthetic": "mutated"}}}
            cold = []
            def read_state(_label):
                if state_mode == "invalid_json":
                    return json.loads("{")
                if state_mode == "api_failure":
                    raise controller.Failure("synthetic_read_api_not_complete")
                if state_mode == "baseline":
                    return value.initial_state
                if state_mode == "unchanged":
                    return before
                return {"nodes": {"1": {"synthetic": "unaccounted"}}}
            value.state_view = read_state
            value.cold_restart = lambda case, actual: cold.append((case, actual))
            def write(_path, report):
                if write_fails:
                    raise OSError("synthetic_report_write_failure")
                writes.append(report)
            controller.write_json = write
            record = {
                "known_complete_business_terminal": True, "outcome_unknown": False,
                "cli_exit_zero": True, "server_terminal": {"terminal_status": terminal},
            }
            result, failed = None, False
            try:
                result = value.finish_restore_readback("B02", record, before)
            except (controller.Failure, ValueError, OSError):
                failed = True
            return value, result, failed, cold
        for label, mode, terminal, write_fails in (
            ("malformed_api_json", "invalid_json", 204, False),
            ("unavailable_api", "api_failure", 204, False),
            ("unaccounted_state", "other", 204, False),
            ("report_io_failure", "baseline", 204, True),
            ("rejected_but_changed_state", "baseline", 400, False),
        ):
            value, result, failed, cold = exercise(label, mode, terminal, write_fails)
            check(label + "_unknown_and_pending", failed and value.outcome_unknown
                  and value.operation_inflight is not None and not value.boundary_known)
            check(label + "_no_cold_restart", cold == [])
        value, result, failed, cold = exercise("success", "baseline", 204)
        check("exact_restoration_clears_pending_only_after_report",
              not failed and value.operation_inflight is None and value.boundary_known
              and not value.outcome_unknown and result["native_restore_qualified"])
        check("exact_restoration_permits_one_cold_call", len(cold) == 1)
        value, result, failed, cold = exercise("known_rejection", "unchanged", 400)
        check("known_rejection_does_not_claim_restore_success",
              not failed and result["known_rejection"] and not result["native_restore_qualified"])
        check("known_rejection_cold_checks_unchanged_state", len(cold) == 1 and not value.outcome_unknown)
    finally:
        controller.write_json = original_write

    report = {
        "schema": "heptabao.official271-native-cli-phaseb-r3.offline-controller-components.v1",
        "checks": checks, "passed": sum(item["passed"] for item in checks), "total": len(checks),
        "actual_controller_methods_exercised": ["owner_class.stop_once", "owner_class.cleanup",
                                               "PhaseB.action", "PhaseB.mutation_allowed",
                                               "PhaseB.setup_phase", "PhaseB.stop_fixture_owned_once",
                                               "PhaseB.cold_restart", "PhaseB.finish_restore_readback"],
        "synthetic_dependencies": True, "network_calls": 0, "children_spawned": 0,
        "actual_product_operations": 0, "actual_file_writes": 0,
        "runtime_qualification": False,
    }
    print(json.dumps(report, sort_keys=True))
    return 0

def main():
    if len(sys.argv) != 2:
        raise SystemExit("explicit controller source path required")
    spec = importlib.util.spec_from_file_location("new_phaseb_r3_controller_components", Path(sys.argv[1]))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return run(module)

if __name__ == "__main__":
    raise SystemExit(main())
