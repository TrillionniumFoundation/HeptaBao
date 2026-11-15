import base64
import json
from types import SimpleNamespace
import unittest

import userpass_variable_salt_live as fixture

class VariableSaltGuards(unittest.TestCase):
    def test_vectors_have_exact_encoded_boundary_and_all_go_decoded_lengths(self):
        original=b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        standard=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        for length in fixture.LENGTHS:
            for interleaved in (False,True):
                value=fixture.hash_for_length(length,interleaved=interleaved)
                self.assertEqual(len(value),60)
                salt=value[7:29].encode().replace(b'\r',b'').replace(b'\n',b'')
                decoded=base64.b64decode(salt.translate(bytes.maketrans(original,standard))+b'==',validate=True)
                self.assertEqual(decoded,b'4'*length)
                self.assertEqual(value[29:],fixture.STANDARD_HASH[29:])

    def test_completion_needs_variable_salts_malformed_rejections_and_restart(self):
        rows=[{'case':fixture.PREFIX+name,'passed':True} for name in sorted(fixture.REQUIRED-{'complete'})]+[{'case':fixture.PREFIX+'complete','passed':True}]
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'extra','passed':True}]+rows[-1:]))
        for case in ('salt.13.login.credentials','salt.7.restart.credentials','bad.empty.login.no_credentials','old_token.valid'):
            self.assertFalse(fixture.complete([r for r in rows if r['case']!=fixture.PREFIX+case]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':fixture.PREFIX+'failed','passed':False}]+rows[-1:]))

    def test_error_response_with_credentials_fails_without_exposing_them(self):
        class Client:
            def __init__(self):self.calls=0
            def request(self,*args,**kwargs):
                self.calls+=1;return SimpleNamespace(status=400,body={'auth':{'client_token':'private'}})
        c=Client();rows=[];t=fixture.Trace(c,rows)
        with self.assertRaises(fixture.ScenarioFailure):t.login('denied','test',{'password':fixture.PASSWORD},status=400)
        self.assertEqual(c.calls,1)
        self.assertEqual(rows[-1],{'case':fixture.PREFIX+'denied.no_credentials','passed':False})
        self.assertNotIn('private',json.dumps(rows));self.assertNotIn(fixture.PASSWORD,json.dumps(rows))

if __name__=='__main__':unittest.main()
