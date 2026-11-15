#!/usr/bin/env python3
"""Regression for mixed original guard interfaces and independent cleanup."""
import ast
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
TREE = ast.parse((HERE / "capture_current_database_inventory_r3.py").read_text())
NS = {}


def need(value, code):
    if not value:
        raise RuntimeError(code)


NS["need"] = need
exec(compile(ast.Module(body=[node for node in TREE.body if isinstance(node, ast.FunctionDef)
    and node.name in ("close_guard_resources", "public_database_kind_and_mode")], type_ignores=[]),
    "exact-r3-functions", "exec"), NS)
close_project = NS["close_guard_resources"]
project_mode = NS["public_database_kind_and_mode"]


class Guard:
    def __init__(self, log, ordinal, *, close_error=False, public_error=False, counts=False):
        self.log, self.ordinal = log, ordinal
        self.close_error, self.public_error, self.counts = close_error, public_error, counts
        self.calls = 0
        self.connect_attempts = [{}, {}]
        self.connections = [{}]
        self.cursors = [{}, {}, {}]
        self.queries = [{}, {}, {}, {}]
        self.closed = False
        self.errors = []
        self.closure_value = True

    def close(self):
        self.log.append(("close", self.ordinal))
        self.calls += 1
        if self.close_error:
            raise OSError("private content must not escape")
        self.closed = True

    def public(self):
        self.log.append(("public", self.ordinal))
        if self.public_error:
            raise KeyError("private content must not escape")
        value = {key: self.closed for key in (
            "allHeldDescriptorsClosed", "allReturnedConnectionsClosed", "allExplicitCursorsClosed",
            "allPublicCodeDescriptorsClosed")}
        value.update(allOwnedDescriptorsClosed=self.closure_value and self.closed, closeErrors=self.errors)
        if self.counts:
            value.update(connectionAttemptCount=2, returnedConnectionCount=1, cursorCount=3, queryCount=4)
        return value


class ResourceClosure(unittest.TestCase):
    def test_actual_mixed_count_interface_and_all_close_before_public(self):
        log = []
        guards = [Guard(log, 1, counts=True), Guard(log, 2, counts=False)]
        value = close_project(guards, {})
        self.assertEqual(log[:2], [("close", 1), ("close", 2)])
        self.assertTrue(all(row["projectionComplete"] and row["allOwnedDescriptorsClosed"] for row in value))
        for row in value:
            self.assertEqual([row[key] for key in ("connectionAttemptCount", "returnedConnectionCount",
                                                  "cursorCount", "queryCount")], [2, 1, 3, 4])

    def test_close_error_does_not_skip_later_or_repeat_unknown(self):
        guards = [Guard([], 1, close_error=True), Guard([], 2), Guard([], 3)]
        ledger = {}
        first = close_project(guards, ledger)
        second = close_project(guards, ledger)
        self.assertFalse(first[0]["closeCallReturned"])
        self.assertTrue(all(row["closeCallReturned"] for row in first[1:]))
        self.assertEqual([guard.calls for guard in guards], [1, 1, 1])
        self.assertNotIn("private content", json.dumps([first, second]))

    def test_public_error_does_not_skip_later_close_or_projection(self):
        log = []
        guards = [Guard(log, 1, public_error=True), Guard(log, 2)]
        value = close_project(guards, {})
        self.assertEqual(log[:2], [("close", 1), ("close", 2)])
        self.assertFalse(value[0]["projectionComplete"])
        self.assertTrue(value[1]["projectionComplete"])
        self.assertNotIn("private content", json.dumps(value))

    def test_missing_vector_refuses_without_default_zero(self):
        guard = Guard([], 1)
        del guard.queries
        row = close_project([guard], {})[0]
        self.assertTrue(guard.closed)
        self.assertFalse(row["projectionComplete"])
        self.assertNotIn("queryCount", row)

    def test_wrong_vector_container_refuses(self):
        guard = Guard([], 1)
        guard.queries = ()
        self.assertFalse(close_project([guard], {})[0]["projectionComplete"])

    def test_wrong_vector_item_refuses(self):
        guard = Guard([], 1)
        guard.queries = [True]
        self.assertFalse(close_project([guard], {})[0]["projectionComplete"])

    def test_unknown_error_name_is_fixed_public_category(self):
        guard = Guard([], 1)
        guard.errors = ["private-content", "OSError"]
        row = close_project([guard], {})[0]
        self.assertEqual(row["closeErrors"], ["OtherError", "OSError"])
        self.assertNotIn("private-content", json.dumps(row))

    def test_original_journal_modes_and_no_owner_claim(self):
        for mode in ("delete", "truncate", "persist", "memory", "wal", "off"):
            row = project_mode({"pragmas": {"journal_mode": mode}}, True, False)
            self.assertEqual(row["journalMode"], mode)
            self.assertTrue(row["configuredPrimaryAgentSlot"])
            self.assertFalse(row["credentialOwnerRevalidatedByThisInventory"])
        self.assertEqual(project_mode({"pragmas": {"journal_mode": "wal"}}, False, True)["databaseKind"],
                         "shared-state")

    def test_unknown_or_untyped_mode_refuses(self):
        for value in (True, 0, None, "private-content", "WAL"):
            with self.assertRaises(RuntimeError):
                project_mode({"pragmas": {"journal_mode": value}}, True, False)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ResourceClosure)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "heptabao.inventory-r3-resource-closure-local.r1",
              "testsRun": result.testsRun, "passed": result.wasSuccessful(),
              "macExecution": False, "productionInputsRead": False}
    (HERE / "resource-closure-local.original.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    raise SystemExit(0 if result.wasSuccessful() else 1)
