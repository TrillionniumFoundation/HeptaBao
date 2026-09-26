import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
import approle_secretid_metadata_supplement as f
RECEIPT=Path(__file__).resolve().parents[1]/'evidence/approle-secretid-metadata-supplement-official-b56954e.json'

class SupplementTests(unittest.TestCase):
    def test_original_receipt_has_every_named_input_and_unchanged_pins(self):
        value=json.loads(RECEIPT.read_text())
        self.assertEqual(f.file_hash(RECEIPT),'d46ee29bff78d8a57d131ad461738ab7b8a9687bd99adadfebe514ec1db82c56')
        self.assertEqual(f.file_hash(Path(f.__file__)),value['runner_sha256'])
        self.assertEqual(value['status'],'observed')
        for key in ('inputs_unchanged','secrets_absent','processes_stopped'):self.assertIs(value[key],True)
        self.assertEqual(set(value['completed_scenarios']),f.SCENARIOS)
        names=[row['case'] for row in value['cases']]
        self.assertEqual(len(names),len(set(names)))
        for name,_ in f.INPUTS:self.assertIn('parser.'+name+'.issue',names)
    def test_recorded_parser_boundaries_remain_exact(self):
        rows={row['case']:row for row in json.loads(RECEIPT.read_text())['cases']}
        for name in ('base64_unpadded','json_empty_value','spaced_json_null'):
            self.assertEqual(rows['parser.'+name+'.issue']['status'],400)
        for name in ('csv_reverse_duplicate','csv_case','csv_empty_segments','json_empty_key','json_empty_both',
                     'json_unicode','json_control','json_long_key','json_long_value','json_65_keys','base64_json_null'):
            for suffix in ('issue','login','bearer'):self.assertEqual(rows['parser.'+name+'.'+suffix]['status'],200)
        self.assertEqual(rows['parser.csv_reverse_duplicate.stored.raw']['data_metadata']['value'],{'env':'last'})
        self.assertEqual(rows['parser.json_empty_both.stored.raw']['data_metadata']['value'],{'':''})
        self.assertEqual(rows['parser.base64_json_null.stored.raw']['data_metadata']['value'],{})
        self.assertEqual(len(rows['parser.json_65_keys.stored.raw']['data_metadata']['value']),65)
    def test_sensitive_projection_hashes_are_reproducible_without_printing_values(self):
        rows={row['case']:row for row in json.loads(RECEIPT.read_text())['cases']}
        for name,value in (('json_unicode',{'env':'汉字','键':'值'}),('json_control',{'env':'one\ntwo','tab':'a\tb'}),
                           ('json_case',{'Env':'Prod'}),('json_long_value',{'env':'v'*1025})):
            self.assertEqual(rows['parser.'+name+'.stored.raw']['data_metadata'],f.contract.metadata_projection(value))
    def test_rejected_login_never_becomes_admin_bearer(self):
        t=Mock();t.call.return_value=(400,{'errors':['synthetic']})
        with (patch.object(f,'INPUTS',( ('one','{}'),)),patch.object(f.contract,'role',return_value=('path','rid')),
             patch.object(f.contract,'issue_sid',return_value=('sid','accessor')),patch.object(f.contract,'lookup_sid')):
            f.run(t,Mock())
        self.assertEqual(t.call.call_count,1)
        t.observe.assert_called_once_with('parser.one.no_issued_bearer',credential_issued=False)
    def test_success_without_token_stops(self):
        t=Mock();t.call.return_value=(200,{'auth':{}})
        with (patch.object(f,'INPUTS',( ('one','{}'),)),patch.object(f.contract,'role',return_value=('path','rid')),
             patch.object(f.contract,'issue_sid',return_value=('sid','accessor')),patch.object(f.contract,'lookup_sid')):
            with self.assertRaises(f.ScenarioFailure):f.run(t,Mock())
        self.assertEqual(t.call.call_count,1)

if __name__=='__main__':unittest.main()
