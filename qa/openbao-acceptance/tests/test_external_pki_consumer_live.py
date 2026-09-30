import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[3]
RUNNER=ROOT/"qa/openbao-acceptance/external_pki_consumer_live.py"
sys.path.insert(0,str(RUNNER.parent))
SPEC=importlib.util.spec_from_file_location("external_pki_contract",RUNNER)
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class ExternalPkiContractTests(unittest.TestCase):
    def test_complete_ordered_unique_denominator_is_required(self):
        cases=MODULE.EXPECTED_CASES
        self.assertEqual(85,len(cases))
        self.assertEqual(len(cases),len(set(cases)))
        rows=[{"case":case,"passed":True} for case in cases]
        self.assertTrue(MODULE.trace_complete(rows))
        for bad in ([],rows[:-1],list(reversed(rows)),rows+[rows[-1]],rows[:-1]+[{"case":cases[-1],"passed":False}]):
            self.assertFalse(MODULE.trace_complete(bad))

    def test_known_rejection_is_exact_and_cleanup_is_in_denominator(self):
        self.assertIn("owned_processes_cleared",MODULE.EXPECTED_CASES)
        rows=[]
        class Response:
            status=503
            body={}
        class Client:
            def request(self,*args,**kwargs):return Response()
        with self.assertRaises(MODULE.shared.Failure):
            MODULE.shared.Trace(rows).call("candidate.rotated.old_fixed_rejected",Client(),"POST","pki/root/generate/kms",400,{})
        self.assertEqual([{"case":"candidate.rotated.old_fixed_rejected","status":503,"passed":False}],rows)

if __name__=="__main__":unittest.main()
