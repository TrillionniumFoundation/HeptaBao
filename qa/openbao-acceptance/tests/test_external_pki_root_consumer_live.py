import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[3]
RUNNER=ROOT/"qa/openbao-acceptance/external_pki_root_consumer_live.py"
sys.path.insert(0,str(RUNNER.parent))
SPEC=importlib.util.spec_from_file_location("external_pki_root_contract",RUNNER)
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)

class ExternalPkiRootContractTests(unittest.TestCase):
    def rows(self):
        rows=[{"case":case,"passed":True} for case in MODULE.EXPECTED_CASES]
        for row in rows:
            if row["case"].endswith("provider_sign_exact"):
                count=1 if ".csr." in row["case"] else 3
                row.update(observed_provider_sign_entries=count,expected_provider_sign_entries=count)
        return rows

    def test_fresh_complete_trace_is_required_and_original_failed_scope_is_retained(self):
        cases=MODULE.EXPECTED_CASES
        self.assertEqual(81,len(cases));self.assertEqual(len(cases),len(set(cases)))
        self.assertEqual(85,len(MODULE.pki.EXPECTED_CASES))
        self.assertNotIn("official.csr.spki_matches",cases)
        self.assertIn("official.csr.spki_matches",MODULE.pki.EXPECTED_CASES)
        rows=self.rows()
        self.assertTrue(MODULE.trace_complete(rows))
        for bad in (rows[:27],rows[:-1],list(reversed(rows)),rows+[rows[-1]]):
            self.assertFalse(MODULE.trace_complete(bad))

    def test_native_remote_binding_and_root_scope_each_fail_closed(self):
        self.assertEqual(71,len(MODULE.ROOT_COMPARISON_CASES));self.assertEqual(10,len(MODULE.NATIVE_CSR_CASES))
        rows=self.rows()
        self.assertEqual((True,True),MODULE.scope_results(rows))
        for required in ("candidate.csr.provider_sign_exact","candidate.csr.actual_signature","candidate.csr.spki_matches"):
            failed=[dict(row,passed=False) if row["case"]==required else row for row in rows]
            self.assertFalse(MODULE.trace_complete(failed));self.assertEqual((True,False),MODULE.scope_results(failed))
        missing=[row for row in rows if row["case"]!="owned_processes_cleared"]
        self.assertEqual((False,True),MODULE.scope_results(missing))

    def test_sign_count_metadata_is_required_without_a_native_official_union(self):
        rows=self.rows()
        for bad_count in (0,1,2,None):
            bad=[dict(row,observed_provider_sign_entries=bad_count) if row["case"]=="candidate.root.provider_sign_exact" else row for row in rows]
            self.assertFalse(MODULE.trace_complete(bad))

if __name__=="__main__":unittest.main()
