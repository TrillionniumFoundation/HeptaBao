import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import native_snapshot_cli_live as cli_fixture
import native_snapshot_rejection_live as fixture


class RejectionDiagnosticsGuards(unittest.TestCase):
    def invoke(self, stderr, code=2):
        diagnostics={}
        instance=SimpleNamespace(address='https://localhost:1234',root=Path('/private'),token='TOKEN_SENTINEL')
        with mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=code,stderr=stderr)) as run:
            outcome=cli_fixture.cli(Path('/bao'),instance,Path('/private'),'restore',Path('/private/a'),
                                    expected_error=403,diagnostics=diagnostics)
        self.assertEqual(run.call_count,1)
        self.assertNotIn('TOKEN_SENTINEL',json.dumps(diagnostics))
        self.assertNotIn('SECRET_SENTINEL',json.dumps(diagnostics))
        return outcome,diagnostics

    def test_http_denial_and_transport_failure_remain_distinct(self):
        passed,diag=self.invoke(b'Code: 403. Errors:\nSECRET_SENTINEL')
        self.assertTrue(passed);self.assertEqual(diag['http_status_codes'],[403]);self.assertEqual(diag['exit_code'],2)
        passed,diag=self.invoke(b'Error installing snapshot: unexpected EOF SECRET_SENTINEL')
        self.assertFalse(passed);self.assertEqual(diag['http_status_codes'],[])
        self.assertEqual(diag['transport_classes'],['unexpected_eof'])
        passed,diag=self.invoke(b'Code: 403. Errors:\nCode: 503. Errors:\nSECRET_SENTINEL')
        self.assertFalse(passed);self.assertEqual(diag['http_status_codes'],[403,503])

    def test_large_stderr_cannot_pass_and_diagnostics_stay_bounded(self):
        passed,diag=self.invoke(b'Code: 403. Errors:\n'+b'SECRET_SENTINEL'*6000)
        self.assertFalse(passed);self.assertFalse(diag['stderr_within_bound'])
        self.assertLess(len(json.dumps(diag)),512)

    def test_timeout_keeps_original_exception_without_exporting_text(self):
        diagnostics={};instance=SimpleNamespace(address='https://localhost',root=Path('/private'),token='token')
        error=subprocess.TimeoutExpired(['secret'],90,stderr=b'SECRET_SENTINEL timeout')
        with mock.patch.object(subprocess,'run',side_effect=error):
            with self.assertRaises(subprocess.TimeoutExpired):
                cli_fixture.cli(Path('/bao'),instance,Path('/private'),'restore',Path('/a'),diagnostics=diagnostics)
        self.assertTrue(diagnostics['subprocess_timeout']);self.assertIsNone(diagnostics['exit_code'])
        self.assertNotIn('SECRET_SENTINEL',json.dumps(diagnostics))

    def test_readback_kept_before_false_cli_assertion(self):
        rows=[]
        def check(name,passed):
            rows.append({'case':name,'passed':passed})
            if not passed:raise RuntimeError('rejected')
        with self.assertRaises(RuntimeError):fixture.record_upload_result(check,False,7,7,True)
        self.assertEqual(rows,[{'case':'generation_unchanged','passed':True},
                               {'case':'data_unchanged','passed':True},
                               {'case':'expired_actor_denied','passed':False}])

    def test_required_observations_not_hard_count(self):
        rows=[{'case':name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]+[{'case':'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        for index in range(len(rows)):self.assertFalse(fixture.complete(rows[:index]+rows[index+1:]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','passed':1}]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'exception','passed':True}]))
