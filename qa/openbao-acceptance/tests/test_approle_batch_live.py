import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import approle_batch_live as live

class AppRoleBatchComparisonGuards(unittest.TestCase):
    def rows(self):return copy.deepcopy(live.calibrated_rows())
    def candidate(self):
        rows=live.equal_lane(self.rows())
        normal={'auth':False,'auth_type':'none','configured_type':'none','errors':False,
                'lookup_type':'none','warnings':False}
        rows += [dict(normal,case='type.null.tune',status=204),
                 dict(normal,case='type.null.write',status=400,errors=True),
                 dict(normal,case='type.null.read',status=404)]
        return rows
    def test_real_calibration_and_terminal_scenarios_required_without_count_gate(self):
        rows=self.rows();finished=list(live.contract.SCENARIOS)
        self.assertTrue(live.complete(rows,finished,'oracle'))
        self.assertTrue(live.complete(rows+[{'case':'additional.status','status':200}],finished,'oracle'))
        self.assertFalse(live.complete(rows,finished[:-1],'oracle'))
        self.assertFalse(live.complete(rows,finished+[finished[0]],'oracle'))
        self.assertFalse(live.complete(rows[:-1],finished,'oracle'))
        self.assertFalse(live.complete([{'case':'padding.'+str(i)} for i in range(200)],finished,'oracle'))
    def test_sid_identity_failure_consumption_is_never_excluded(self):
        rows=self.rows();finished=list(live.contract.SCENARIOS)
        for name in ('identity.disabled_secret_use.disabled_login',
                     'identity.disabled_secret_use.secret_lookup',
                     'identity.disabled_secret_use.after_enable'):
            altered=copy.deepcopy(rows);row=next(r for r in altered if r['case']==name)
            self.assertIn(row,live.equal_lane(altered))
            row['status']=200
            self.assertFalse(live.complete(altered,finished,'oracle'),name)
            self.assertFalse(live.exact_subset(live.equal_lane(altered),live.equal_lane(rows)))
    def test_null_is_explicit_asymmetric_divergence_not_two_status_allowlist(self):
        oracle=self.rows();candidate=self.candidate();finished=list(live.contract.SCENARIOS)
        self.assertTrue(live.complete(candidate,finished,'candidate'))
        self.assertTrue(live.null_lane(oracle,'oracle')['passed'])
        self.assertFalse(live.null_lane(oracle,'candidate')['passed'])
        self.assertFalse(live.null_lane(candidate,'oracle')['passed'])
        self.assertEqual(live.equal_lane(oracle),live.equal_lane(candidate))
        for status in (200,204,403,500,503):
            rows=copy.deepcopy(candidate)
            next(r for r in rows if r['case']=='type.null.write')['status']=status
            self.assertFalse(live.complete(rows,finished,'candidate'))
    def test_equal_lane_preserves_unexpected_rows_and_duplicate_rejected(self):
        rows=self.rows();finished=list(live.contract.SCENARIOS)
        self.assertFalse(live.complete(rows+[rows[0]],finished,'oracle'))
        self.assertNotEqual(live.equal_lane(rows),live.equal_lane(rows+[{'case':'unexpected.failure','status':500}]))
        self.assertFalse(live.complete(rows+[{'case':'type.null.extra','status':200}],finished,'oracle'))
    def test_fixture_captures_bearer_and_secret_id_without_copying_response(self):
        auth={'client_token':'private-bearer','accessor':'private-accessor'}
        data={'secret_id':'private-sid','secret_id_accessor':'private-sid-accessor','role_id':'private-role'}
        trace=live.contract.Trace(SimpleNamespace(request=lambda *a,**k:SimpleNamespace(status=500,body={'auth':auth,'data':data,'errors':['private-body']})))
        trace.call('safe','projection','POST','ignored')
        for value in (*auth.values(),*data.values()):
            self.assertIn(value,trace.sensitive);self.assertNotIn(value,json.dumps(trace.rows))
        self.assertNotIn('private-body',json.dumps(trace.rows))
    def test_calibration_is_bound_to_exact_real_receipt(self):
        with patch.object(live,'file_hash',return_value='0'*64):
            with self.assertRaisesRegex(ValueError,'oracle_calibration_changed'):live.calibrated_rows()

if __name__=='__main__':unittest.main()
