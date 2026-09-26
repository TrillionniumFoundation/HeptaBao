import json
import http.client
import io
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

    def test_instance_setup_without_ambient_smoke_path(self):
        instance=mock.Mock(side_effect=OSError('constructor_reached'))
        with mock.patch.dict('sys.modules',{'smoke':None,'remote_jwks_live':SimpleNamespace(Instance=instance)}):
            with self.assertRaisesRegex(OSError,'constructor_reached'):
                fixture.run(Path('/candidate'),Path('/bao'),Path('/private'),[],{})
        instance.assert_called_once_with(Path('/candidate'),Path('/private/instance'))

    def test_http_denial_and_transport_failure_remain_distinct(self):
        passed,diag=self.invoke(b'Code: 403. Errors:\nSECRET_SENTINEL')
        self.assertTrue(passed);self.assertEqual(diag['http_status_codes'],[403]);self.assertEqual(diag['exit_code'],2)
        passed,diag=self.invoke(b'Error installing snapshot: unexpected EOF SECRET_SENTINEL')
        self.assertFalse(passed);self.assertEqual(diag['http_status_codes'],[])
        self.assertEqual(diag['transport_classes'],['unexpected_eof'])
        passed,diag=self.invoke(b'Code: 403. Errors:\nCode: 503. Errors:\nSECRET_SENTINEL')
        self.assertFalse(passed);self.assertEqual(diag['http_status_codes'],[403,503])

    def test_fixed_diagnostics_classify_closed_file_body_without_exporting_path(self):
        passed,diag=self.invoke(b'Error: net/http: HTTP/1.x transport connection broken: '
            b'http: ContentLength=46766 with Body length 0; read /SECRET_SENTINEL: file already closed')
        self.assertFalse(passed)
        self.assertEqual(diag['transport_classes'],['closed_file','http_transport','request_body','read_syscall'])
        for text,expected in [(b'use of closed network connection','closed_network'),
            (b'software caused connection abort','connection_aborted'),
            (b'server closed idle connection','server_closed_idle'),(b'write tcp SECRET_SENTINEL: write: broken pipe','write_syscall')]:
            _,diag=self.invoke(text);self.assertIn(expected,diag['transport_classes'])

    def test_raw_encodings_each_send_once_and_never_export_response_body(self):
        for chunked in (False,True):
            archive=mock.Mock();archive.stat.return_value.st_size=42
            archive.open.return_value.__enter__=mock.Mock(return_value=io.BytesIO(b'synthetic'))
            archive.open.return_value.__exit__=mock.Mock(return_value=False)
            connection=mock.Mock();response=connection.getresponse.return_value
            response.status=403;response.read.return_value=b'SECRET_SENTINEL'
            with mock.patch.object(http.client,'HTTPSConnection',return_value=connection):
                result=fixture.raw_rejection(SimpleNamespace(port=1234,context=None),archive,'TOKEN_SENTINEL',chunked=chunked)
            self.assertEqual(result,{'http_status':403,'response_complete':True,'error_class':None})
            self.assertNotIn('SENTINEL',json.dumps(result));connection.request.assert_called_once()
            headers=connection.request.call_args.kwargs['headers']
            self.assertEqual(connection.request.call_args.kwargs['encode_chunked'],chunked)
            self.assertEqual(headers.get('Transfer-Encoding'),'chunked' if chunked else None)
            self.assertEqual(headers.get('Content-Length'),None if chunked else '42')
            connection.close.assert_called_once()

    def test_raw_disconnect_not_misclassified_or_retried(self):
        archive=mock.Mock();archive.stat.return_value.st_size=42
        archive.open.return_value.__enter__=mock.Mock(return_value=io.BytesIO(b'synthetic'))
        archive.open.return_value.__exit__=mock.Mock(return_value=False)
        connection=mock.Mock();connection.request.side_effect=http.client.RemoteDisconnected('SECRET_SENTINEL')
        with mock.patch.object(http.client,'HTTPSConnection',return_value=connection):
            result=fixture.raw_rejection(SimpleNamespace(port=1234,context=None),archive,'token',chunked=False)
        self.assertEqual(result,{'http_status':None,'response_complete':False,'error_class':'remote_disconnected'})
        connection.request.assert_called_once();connection.close.assert_called_once()

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
