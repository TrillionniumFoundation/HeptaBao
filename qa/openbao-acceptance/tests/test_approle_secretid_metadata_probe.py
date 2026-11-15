import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock
P = Path(__file__).resolve().parents[1] / 'approle_secretid_metadata_probe.py'
spec = importlib.util.spec_from_file_location('metadata_probe', P)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class Guards(unittest.TestCase):
    def test_projection_preserves_empty_null_missing_distinction_and_fixed_values(self):
        self.assertEqual(m.metadata_projection(None), {'shape': 'null'})
        self.assertEqual(m.metadata_projection({}), {'shape': 'map', 'value': {}})
        self.assertEqual(m.metadata_projection({'role_name':'spoofed','env':'one'})['value'],
                         {'role_name':'spoofed','env':'one'})
    def test_unknown_values_are_not_emitted(self):
        secret='sensitive-canary-0123456789'
        encoded=str(m.metadata_projection({secret:secret,'env':secret}))
        self.assertNotIn(secret, encoded); self.assertIn('sha256',encoded)
    def test_absent_bearer_never_calls_admin_client(self):
        trace=Mock()
        with self.assertRaises(m.ScenarioFailure):m.bearer(trace,'test','')
        trace.call.assert_not_called()
        with self.assertRaises(m.ScenarioFailure):m.credential({'auth':{'accessor':'present'}})
    def test_batch_renew_does_not_invent_accessor(self):
        trace=Mock();m.renew(trace,'test',{'client_token':'synthetic-batch','accessor':''})
        self.assertEqual(trace.call.call_count,2)
        self.assertTrue(all(c.args[2]!='auth/token/renew-accessor' for c in trace.call.call_args_list))
        trace.observe.assert_called_once_with('test.accessor_not_applicable',absent_accessor=True,endpoint_not_called=True)
    def test_exact_metadata_cases_and_named_phase_completeness(self):
        names={name for name,_ in m.INPUTS}
        self.assertTrue({'null','empty','json_duplicate','role_conflict','csv_duplicate','direct_map','direct_number','direct_bool'}<=names)
        trace=Mock();trace.finished=list(m.SCENARIOS);trace.rows=[{'case':f'parse.{issue}.{kind}.{case}.issue'}
            for issue,kind in m.MODES for case,_ in m.INPUTS]
        self.assertTrue(m.complete(trace));trace.rows.pop();self.assertFalse(m.complete(trace))
        trace.rows.append(dict(trace.rows[0]));self.assertFalse(m.complete(trace))
    def test_parse_input_original_types_are_not_pre_normalized(self):
        values=dict(m.INPUTS)
        self.assertIsNone(values['null']['metadata'])
        self.assertIsInstance(values['json_map']['metadata'],str)
        self.assertIsInstance(values['direct_map']['metadata'],dict)
        self.assertIs(type(values['direct_bool']['metadata']),bool)

if __name__=='__main__':unittest.main()
