import copy
import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "kv2_271_numeric_raw_followup.py"
SPEC = importlib.util.spec_from_file_location("numeric_raw_followup_under_test", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def prior_fixture():
    requests = [{"method": method, "path": path, "status": status,
                 "outcome": "response_received", "retried": False,
                 "owned_wait_completed": True, "response_sha256": "0" * 64}
                for method, path, status in (("GET", "sys/health", 200),
                    ("GET", "secret/config", 200),
                    ("LIST", "secret/metadata/numeric-boundary-r1", 404))]
    cases = []
    for index, lexeme in enumerate(MODULE.CASES, 1):
        case = "case-" + str(index).zfill(2)
        key = "numeric-boundary-r1/" + case
        write, read = (200, 200) if index < 7 else (400, 404)
        cases.append({"case": case, "key": key, "request_number_lexeme": lexeme,
                      "write_status": write, "get_status": read,
                      "get_body_sha256": "0" * 64})
        for method, path, status in (("POST", "secret/data/" + key, write),
                                    ("GET", "secret/data/" + key + "?version=1", read)):
            requests.append({"method": method, "path": path, "status": status,
                             "outcome": "response_received", "retried": False,
                             "owned_wait_completed": True, "response_sha256": "0" * 64})
    return {"schema": "heptabao.openbao271-numeric-boundary-observation.v1",
            "script_sha256": MODULE.PRIOR_SCRIPT_SHA256, "diagnostic_complete": False,
            "error": "KeyError", "synthetic_only": True, "migration_qualified": False,
            "writes_retried": False, "mutation_outcome_unknown": False,
            "actual_official_version": "2.7.1", "actual_cluster_matches_fixture": True,
            "prefix": "numeric-boundary-r1", "cases": cases, "requests": requests}


class NumericRawFollowupTests(unittest.TestCase):
    def test_nested_config_root_replaces_unproven_top_level_salt_assumption(self):
        outer = "logical/test-uuid/"
        root = outer + "actual-kv-prefix/"
        records = {root + "config": b"config", root + "salt": b"synthetic-salt"}
        with self.assertRaises(KeyError):
            records[outer + "salt"]
        actual, salt, projection = MODULE.discover_storage_root(records, "test-uuid")
        self.assertEqual(actual, root)
        self.assertEqual(salt, b"synthetic-salt")
        self.assertFalse(projection["legacy_assumed_salt_present"])
        self.assertEqual(projection["config_root_relative_depth"], 1)

    def test_config_root_rejects_ambiguity_cross_mount_and_missing_salt(self):
        valid = {"logical/u/config": b"config", "logical/u/salt": b"salt"}
        for records in ({**valid, "logical/u/nested/config": b"bad"},
                        {"logical/another/config": b"config", "logical/another/salt": b"salt"},
                        {"logical/u/config": b"config"},
                        {**valid, "logical/outside/payload": b"bad"}):
            with self.subTest(paths=tuple(records)), self.assertRaises(MODULE.Failure):
                MODULE.discover_storage_root(records, "u")

    def test_network_gate_rejects_every_mutation_and_get_body(self):
        MODULE.allow_read("GET", "sys/health")
        MODULE.allow_read("LIST", "sys/raw/logical/u/")
        for method in ("POST", "PUT", "PATCH", "DELETE", "get"):
            with self.subTest(method=method), self.assertRaises(MODULE.Failure):
                MODULE.allow_read(method, "secret/data/existing")
        with self.assertRaises(MODULE.Failure):
            MODULE.allow_read("GET", "sys/health", b"body")

    def test_prior_requires_all_seven_known_outcomes_in_original_order(self):
        prior = prior_fixture()
        prefix, cases = MODULE.validate_prior(prior)
        self.assertEqual(prefix, "numeric-boundary-r1")
        self.assertEqual(len(cases), 7)
        for alter in (lambda value: value["requests"][3].update(outcome="unknown"),
                      lambda value: value["requests"][3].update(retried=True),
                      lambda value: value["cases"][6].update(write_status=200),
                      lambda value: value.update(mutation_outcome_unknown=True)):
            changed = copy.deepcopy(prior)
            alter(changed)
            with self.assertRaises(MODULE.Failure):
                MODULE.validate_prior(changed)

    def test_json_observer_preserves_all_seven_numeric_lexemes(self):
        for lexeme in MODULE.CASES:
            observed = MODULE.lexemes(('{"number":' + lexeme + '}').encode())["number"]
            self.assertIsInstance(observed, MODULE.NumberLexeme)
            self.assertEqual(str(observed), lexeme)

    def test_json_observer_rejects_duplicate_and_non_json_numbers(self):
        for body in (b'{"number":1,"number":2}', b'{"number":NaN}', b'{"number":Infinity}'):
            with self.subTest(body=body), self.assertRaises(MODULE.Failure):
                MODULE.lexemes(body)


if __name__ == "__main__":
    unittest.main()
