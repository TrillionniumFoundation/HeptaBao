import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import userpass_password_upgrade as fixture


class PasswordUpgradeGuards(unittest.TestCase):
    def test_legacy_binary_requires_its_actual_clean_qualified_receipt(self):
        receipt=json.loads(fixture.LEGACY_RECEIPT.read_text())
        fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt)
        for key,value in [('status','failed'),('build_source_commit','0'*40),
                          ('candidate_binary_sha256','0'*64),('runner_unchanged',1)]:
            with self.assertRaises(ValueError):
                fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,receipt|{key:value})
        damaged=copy.deepcopy(receipt)
        damaged['source_identity']['source_dirty']=True
        damaged['source_identity_after']=dict(damaged['source_identity'])
        with self.assertRaises(ValueError):fixture.admit_legacy_receipt(fixture.LEGACY_SHA256,damaged)

    def test_completion_requires_legacy_preservation_and_explicit_new_semantics(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED)]
        self.assertTrue(fixture.complete_checks(rows,required_cases=fixture.REQUIRED))
        for name in ('current_long_prefix_rejected','current_exact_suffix_rejected',
                     'current_new_suffix_credentials','downgrade_unseal_rejected',
                     'recovery_long_credentials'):
            self.assertFalse(fixture.complete_checks([r for r in rows if r['case']!=name],required_cases=fixture.REQUIRED))
        self.assertFalse(fixture.complete_checks(rows+[rows[0]],required_cases=fixture.REQUIRED))

    def test_failure_never_retries_password_mutation_or_releases_error_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            instance=SimpleNamespace(root=Path(directory),address='https://localhost:443',token='synthetic')
            with patch.object(fixture,'Client') as client:
                trace=fixture.Trace(instance,[])
                client.return_value.request.side_effect=TimeoutError('private')
                with self.assertRaises(TimeoutError):trace.write('lost','user',{'password':'private'})
                self.assertEqual(client.return_value.request.call_count,1)
                client.return_value.request.side_effect=None
                client.return_value.request.return_value=SimpleNamespace(status=400,body={'auth':{'client_token':'private'}})
                with self.assertRaises(fixture.ScenarioFailure):trace.login('rejected','user','private',400)
                self.assertNotIn('private',json.dumps(trace.rows))
                self.assertEqual(trace.rows[-1],{'case':'rejected_rejected','passed':False})


if __name__=='__main__':unittest.main()
