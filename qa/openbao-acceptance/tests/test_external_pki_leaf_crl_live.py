import importlib.util
from datetime import datetime,timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
RUNNER=ROOT/"qa/openbao-acceptance/external_pki_leaf_crl_live.py"
sys.path.insert(0,str(RUNNER.parent))
SPEC=importlib.util.spec_from_file_location("external_pki_leaf_crl_contract",RUNNER)
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)

class ExternalPkiLeafCrlContractTests(unittest.TestCase):
    def test_successor_native_control_uses_explicit_two_second_transport(self):
        class Instance:
            def __init__(self,binary,root):
                self.root=Path(root);self.address="https://127.0.0.1:1234";self.token=""
        class Smoke:pass
        Smoke.Instance=Instance
        with patch.object(MODULE,"Client") as client:
            client.return_value.request.return_value.status=501
            client.return_value.request.return_value.body={"sealed":True}
            native=MODULE.bounded_native_instance(Smoke,Path("binary"),Path("private"))
            self.assertEqual((501,{"sealed":True}),native.call("GET","sys/health"))
            self.assertEqual(2,client.call_args.kwargs["timeout"])
            self.assertEqual("",client.return_value.request.call_args.kwargs["token"])
            native.token="synthetic-authenticated-token"
            native.call("POST","sys/unseal",{"key":"synthetic-unseal-input"})
            self.assertEqual(2,client.call_args.kwargs["timeout"])
            self.assertTrue(native.token==client.return_value.request.call_args.kwargs["token"])

    def rows(self):
        rows=[{"case":case,"passed":True} for case in MODULE.EXPECTED_CASES]
        for row in rows:
            if row["case"].endswith("sign_exact"):
                count=3 if row["case"].endswith("root_sign_exact") else 1 if row["case"].endswith("leaf_sign_exact") else 2
                row.update(observed_provider_sign_entries=count,expected_provider_sign_entries=count)
            if row["case"].endswith("leaf_lease"):
                row.update(lease_id_present=True,observed_renewable=False,observed_lease_duration=600,
                    request_before_unix=100.2,request_after_unix=100.3,certificate_not_after_unix=700,
                    certificate_not_before_unix=70,certificate_requested_ttl_matches=True,
                    lease_duration_expected_min=600,lease_duration_expected_max=600)
        return rows

    def test_complete_unique_ordered_trace_includes_both_crls_and_restart(self):
        cases=MODULE.EXPECTED_CASES
        self.assertEqual(164,len(cases))
        self.assertEqual(len(cases),len(set(cases)))
        self.assertTrue(MODULE.trace_complete(self.rows()))
        for side in ("candidate","official"):
            for suffix in ("root_sign_exact","leaf_private_binding","revoked_full_signature","revoked_delta_signature","restart_leaf_readback","restart_delta_number"):
                self.assertIn(side+"."+suffix,cases)
        self.assertIn("owned_processes_cleared",cases)
        rows=self.rows()
        for bad in (rows[:-1],rows[:17],list(reversed(rows)),rows+[rows[-1]],rows[:]):
            if bad==rows:bad[11]=dict(bad[11],passed=False)
            self.assertFalse(MODULE.trace_complete(bad))

    def test_effect_counts_are_exact_without_union_or_missing_metadata(self):
        rows=self.rows()
        for case in ("candidate.root_sign_exact","official.root_sign_exact","candidate.leaf_sign_exact","candidate.revoke_sign_exact"):
            for count in (0,1,2,3,None):
                expected=next(row["expected_provider_sign_entries"] for row in rows if row["case"]==case)
                if count==expected:continue
                bad=[dict(row,observed_provider_sign_entries=count) if row["case"]==case else row for row in rows]
                self.assertFalse(MODULE.trace_complete(bad))

    def test_known_consumer_grant_rejection_is_500(self):
        rows=[]
        class Response:status=503;body={}
        class Client:
            def request(self,*args,**kwargs):return Response()
        with self.assertRaises(MODULE.shared.Failure):
            MODULE.shared.Trace(rows).call("candidate.grant_denied_leaf",Client(),"POST","pki/issue/leaf",500,{})
        self.assertEqual([{"case":"candidate.grant_denied_leaf","status":503,"passed":False}],rows)

    def test_failed_lease_keeps_only_safe_diagnostics(self):
        rows=[]
        body={"lease_id":"owned-secret-id","lease_duration":599,"renewable":False,
            "data":{"private_key":"must-never-appear"}}
        with self.assertRaises(MODULE.shared.Failure):
            MODULE.check_leaf_lease(MODULE.shared.Trace(rows),"candidate.leaf_lease",body)
        self.assertEqual([{"case":"candidate.leaf_lease","passed":False,
            "lease_id_present":True,"observed_lease_duration":599,"observed_renewable":False}],rows)

    def test_lease_duration_is_uniquely_derived_from_certificate_and_request_clock(self):
        class Certificate:
            not_valid_after_utc=datetime.fromtimestamp(700,timezone.utc)
            not_valid_before_utc=datetime.fromtimestamp(70,timezone.utc)
        for before,after,expected in ((100.6221,100.6501,599),(100.3801,100.4484,600)):
            body={"lease_id":"must-not-record","lease_duration":expected,"renewable":False,
                "data":{"expiration":700,"not_before":70}}
            rows=[]
            MODULE.check_leaf_lease(MODULE.shared.Trace(rows),"candidate.leaf_lease",body,
                request_before=before,request_after=after,certificate=Certificate())
            self.assertTrue(rows[0]["passed"])
            self.assertEqual(expected,rows[0]["lease_duration_expected_min"])
            self.assertEqual(expected,rows[0]["lease_duration_expected_max"])
            for wrong in (598,599,600,601):
                if wrong==expected:continue
                with self.assertRaises(MODULE.shared.Failure):
                    MODULE.check_leaf_lease(MODULE.shared.Trace([]),"candidate.leaf_lease",dict(body,lease_duration=wrong),
                        request_before=before,request_after=after,certificate=Certificate())

    def test_complete_trace_requires_exact_lease_time_evidence(self):
        rows=self.rows()
        for mutation in ({"observed_lease_duration":599},{"observed_lease_duration":True},
                {"request_after_unix":float("nan")},{"certificate_not_after_unix":701},
                {"lease_duration_expected_min":599},{"lease_id_present":False},
                {"certificate_requested_ttl_matches":False}):
            changed=[dict(row,**mutation) if row["case"]=="candidate.leaf_lease" else row for row in rows]
            self.assertFalse(MODULE.trace_complete(changed))
        missing=[dict(row) for row in rows]
        next(row for row in missing if row["case"]=="candidate.leaf_lease").pop("request_before_unix")
        self.assertFalse(MODULE.trace_complete(missing))

if __name__=="__main__":unittest.main()
