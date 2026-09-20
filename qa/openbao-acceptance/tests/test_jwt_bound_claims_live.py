import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bao_http import Response
from jwt_bound_claims_live import (ACCEPTED, ROLE_REJECTED, EVENTS, Failure, Trace, matrix,
                                  numeric_payload, partial_steps, required_comparison, valid_gate, valid_rows)


class JwtBoundClaimsGuards(unittest.TestCase):
    def test_matrix_has_unique_cases_and_expected_outcomes_cover_signed_number_and_pointer_edges(self):
        cases = {row[0]: row for row in matrix()}
        self.assertEqual(len(cases),len(matrix()))
        self.assertTrue(ACCEPTED.isdisjoint(ROLE_REJECTED))
        self.assertTrue((ACCEPTED | ROLE_REJECTED).issubset(cases))
        self.assertIn('number_fraction_scalar_truncates',ACCEPTED)
        self.assertNotIn('number_scalar_array',ACCEPTED)
        self.assertNotIn('number_expected_exponent_integer',ACCEPTED)
        self.assertNotIn('number_expected_negative_zero',ACCEPTED)
        self.assertIn('pointer_octal',ACCEPTED)
        self.assertNotIn('pointer_octal_invalid',ACCEPTED)
        self.assertIn('glob_question_exact',ACCEPTED)
        self.assertNotIn('glob_question_literal',ACCEPTED)

    def test_raw_json_preserves_numeric_lexical_form_and_rejects_injection(self):
        payload={'bound_claims':{'value':'_bound_number_'}}
        self.assertIn(b': 42e0',numeric_payload(payload,'42e0'))
        self.assertIn(b': -0',numeric_payload(payload,'-0'))
        for raw in ['0,"extra":true','NaN','42','1e1000']:
            with self.assertRaises(ValueError):numeric_payload(payload,raw)
        for wrong in [{}, {'value':['_bound_number_','_bound_number_']}]:
            with self.assertRaises(ValueError):numeric_payload(wrong,'-0')
        self.assertEqual(payload,{'bound_claims':{'value':'_bound_number_'}})

    def test_partial_requests_are_jwt_and_null_type_is_rejected_without_changing_glob(self):
        rows={name:(body,status,kind,bounds) for name,body,status,kind,bounds in partial_steps()}
        self.assertTrue(all(body['role_type']=='jwt' for body,_,_,_ in rows.values()))
        self.assertEqual(rows['ttl_only'][2:],('string',{'value':'a*'}))
        self.assertEqual(rows['empty_map'][3],{})
        self.assertEqual(rows['null_map'][3],{})
        self.assertIsNone(rows['null_type'][0]['bound_claims_type'])
        self.assertEqual(rows['null_type'][1:],(400,'glob',{'value':'a*'}))

    def test_required_cases_reject_incomplete_matrix_partial_or_restart(self):
        required=required_comparison()
        rows=[{'case':name,'passed':True} for name in sorted(required)]
        self.assertTrue(valid_rows(rows,required))
        for phase in ['static.matrix.number_expected_exponent_integer.login','remote.partial.null_type.shape',
                      'remote.restart.bound_preserved','static.issued.renew_no_provider']:
            self.assertFalse(valid_rows([r for r in rows if r['case']!='bound_claims.'+phase],required))
        self.assertFalse(valid_rows(rows+[rows[0]],required))
        self.assertFalse(valid_rows([dict(row,passed=1) for row in rows],required))
        self.assertFalse(valid_rows([dict(row,token='sensitive') for row in rows],required))

    def test_trace_never_serializes_token_response_or_accepts_string_observation(self):
        class Client:
            def request(self,*args,**kwargs):return Response(200,{'auth':{'client_token':'sensitive-sentinel'}})
        rows=[]
        with self.assertRaises(Failure):Trace(Client(),rows,'static').call('deny','auth/a/login',expected=400)
        self.assertNotIn('sensitive-sentinel',json.dumps(rows))
        with self.assertRaises(Failure):Trace(None,rows,'static').check('secret',True,secret='sentinel')

    def test_gate_requires_real_order_and_no_unknown_fields(self):
        row={'phase':'bound_role_changed','events':EVENTS,'held_before_release':True,
             'concurrent_completed_before_release':True,'request_pending_before_release':True,'within_gate_budget':True}
        self.assertTrue(valid_gate([row]))
        for field in ('held_before_release','concurrent_completed_before_release','request_pending_before_release','within_gate_budget'):
            self.assertFalse(valid_gate([dict(row,**{field:False})]))
        self.assertFalse(valid_gate([dict(row,events=list(reversed(EVENTS)))]))
        self.assertFalse(valid_gate([dict(row,credential='sentinel')]))
        self.assertFalse(valid_gate([row,row]))
        self.assertFalse(valid_gate(None))


if __name__=='__main__':unittest.main()
