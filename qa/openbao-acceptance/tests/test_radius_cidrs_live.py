import unittest
from unittest.mock import MagicMock, patch
import radius_cidrs_live as fixture

class CompletionTests(unittest.TestCase):
    def rows(self):
        names=sorted(fixture.MILESTONES-{'complete'})+['complete']
        return [{'case':'radius_cidrs.'+name,'passed':True} for name in names]
    def test_complete_requires_distinct_real_milestones_and_final_marker(self):
        rows=self.rows();self.assertTrue(fixture.complete_scenarios(rows))
        self.assertFalse(fixture.complete_scenarios(rows[:-1]))
        self.assertFalse(fixture.complete_scenarios(rows+[rows[-1]]))
        rows[0]['passed']=False;self.assertFalse(fixture.complete_scenarios(rows))
    def test_denied_source_cannot_count_as_success_if_provider_contacted(self):
        class Provider:
            def __init__(self):self.calls=0
            def count(self):self.calls+=1;return self.calls
        class Client:
            last_family=4
            def request(self,*args,**kwargs):return fixture.Response(403,{})
        rows=[];trace=fixture.Trace(Client(),Provider(),rows)
        with self.assertRaises(fixture.ScenarioFailure):trace.call('denied','POST','auth/radius/login',status=403,pap=0)
        self.assertFalse(rows[-1]['passed'])
    def test_receipt_rejects_unbounded_or_secret_fields(self):
        trace=fixture.Trace(None,None,[])
        with self.assertRaises(ValueError):trace.check('safe',True,token='synthetic-token')
        with self.assertRaises(ValueError):trace.check('contains space',True)


class SpoofedOriginTests(unittest.TestCase):
    def test_forged_allowed_headers_do_not_change_the_real_denied_socket_origin(self):
        for forged in ['127.0.0.1', '127.0.0.2']:
            raw = MagicMock()
            tls = MagicMock()
            tls.getsockname.return_value = ('127.0.0.1', 43210)
            context = MagicMock()
            context.wrap_socket.return_value = tls
            connection = MagicMock()
            connection.getresponse.return_value.status = 403
            connection.getresponse.return_value.read.return_value = b'{}'
            with patch.object(fixture.ssl, 'create_default_context', return_value=context), \
                 patch.object(fixture.socket, 'create_connection', return_value=raw) as connect, \
                 patch.object(fixture.http.client, 'HTTPSConnection', return_value=connection):
                client = fixture.SourceClient('https://localhost:12345', 'synthetic-ca', 'synthetic-token', spoof_source=forged)
                response = client.request('GET', 'auth/token/lookup-self', source='127.0.0.1', spoof=True)
            self.assertEqual(response.status, 403)
            self.assertEqual(connect.call_args.kwargs['source_address'], ('127.0.0.1', 0))
            headers = connection.request.call_args.kwargs['headers']
            self.assertEqual(headers['X-Forwarded-For'], forged)
            self.assertEqual(headers['X-Real-IP'], forged)
            self.assertEqual(headers['Forwarded'], 'for=' + forged)
            self.assertEqual(client.last_family, 4)
            connection.close.assert_called_once()

    def test_spoof_address_rejects_header_injection_and_non_numeric_names(self):
        for value in ['localhost', '127.0.0.1:123', '127.0.0.1\r\nX-Vault-Token: sentinel', '']:
            with patch.object(fixture.ssl, 'create_default_context') as context:
                with self.assertRaises(ValueError):
                    fixture.SourceClient('https://localhost:12345', 'synthetic-ca', 'synthetic-token', spoof_source=value)
                context.assert_not_called()

if __name__=='__main__':unittest.main()
