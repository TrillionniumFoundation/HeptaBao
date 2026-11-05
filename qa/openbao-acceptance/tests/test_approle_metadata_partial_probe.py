import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import approle_metadata_partial_probe as f

RECEIPT = Path(__file__).resolve().parents[1] / "evidence/approle-metadata-partial-official-b56954e.json"

class PartialMetadataTests(unittest.TestCase):
    def rows(self):
        return {row["case"]: row for row in json.loads(RECEIPT.read_text())["cases"]}

    def test_original_receipt_binds_runner_and_named_scenarios(self):
        value = json.loads(RECEIPT.read_text())
        self.assertEqual(f.file_hash(RECEIPT), "9f8d574fd8a25b2e7f62c136093db838adf0f86a61b056534d8e771caf36828c")
        self.assertEqual(f.file_hash(Path(f.__file__)), value["runner_sha256"])
        self.assertEqual(value["status"], "observed")
        for key in ("inputs_unchanged", "secrets_absent", "processes_stopped"):
            self.assertIs(value[key], True)
        self.assertFalse(value["candidate_executed"])
        self.assertFalse(value["source_qualified"])
        trace = SimpleNamespace(rows=value["cases"], finished=value["completed_scenarios"])
        self.assertTrue(f.complete(trace))
        for name, _ in f.INPUTS:
            self.assertIn("parser." + name + ".issue", self.rows())

    def test_type_errors_and_valid_controls_remain_distinct(self):
        rows = self.rows()
        for name in ("type_number", "type_nested", "type_array", "type_number_first",
                     "json_null_value", "csv_missing_equals"):
            row = rows["parser." + name + ".issue"]
            self.assertEqual(row["status"], 400)
            self.assertTrue(row["metadata_error"])
            self.assertFalse(row["auth"] or row["data"] or row["wrap"])
        for name in ("json_strings_control", "csv_control"):
            for suffix in ("issue", "login", "bearer", "lookup"):
                self.assertEqual(rows["parser." + name + "." + suffix]["status"], 200)

    def test_malformed_fallback_can_issue_but_fresh_alias_rejects_login(self):
        rows = self.rows()
        stem = "parser.malformed_json"
        self.assertEqual(rows[stem + ".issue"]["status"], 200)
        source = dict(f.INPUTS)["malformed_json"]
        fallback = dict(part.strip().split("=") for part in sorted(set(source.lower().split(","))))
        for suffix in ("stored.raw", "stored.accessor"):
            self.assertEqual(rows[stem + "." + suffix]["data_metadata"],
                             f.contract.metadata_projection(fallback))
        rejected = rows[stem + ".login"]
        self.assertEqual(rejected["status"], 500)
        self.assertTrue(rejected["metadata_error"])
        self.assertFalse(rejected["auth"] or rejected["data"] or rejected["wrap"])
        self.assertFalse(rows[stem + ".no_issued_bearer"]["credential_issued"])
        self.assertNotIn(stem + ".bearer", rows)
        order = list(rows)
        self.assertLess(order.index(stem + ".login"), order.index("parser.json_strings_control.login"))

    def test_rejected_login_never_uses_admin_bearer(self):
        trace = Mock()
        trace.call.return_value = (500, {"errors": ["synthetic metadata error"]})
        with (patch.object(f, "INPUTS", (("one", "{}"),)),
              patch.object(f.contract, "role", return_value=("path", "rid")),
              patch.object(f.contract, "issue_sid", return_value=("sid", "accessor")),
              patch.object(f.contract, "lookup_sid")):
            f.run(trace, Mock())
        self.assertEqual(trace.call.call_count, 1)
        trace.observe.assert_called_once_with("parser.one.no_issued_bearer", credential_issued=False)

    def test_completion_rejects_missing_scenario_or_repeated_observation(self):
        trace = SimpleNamespace(rows=[{"case": "one"}], finished=list(f.SCENARIOS))
        self.assertTrue(f.complete(trace))
        trace.finished.pop()
        self.assertFalse(f.complete(trace))
        trace.finished = list(f.SCENARIOS)
        trace.rows.append({"case": "one"})
        self.assertFalse(f.complete(trace))

if __name__ == "__main__":
    unittest.main()
