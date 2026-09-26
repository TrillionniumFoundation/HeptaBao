import json
from types import SimpleNamespace
import unittest
import userpass_batch_contract as contract
import userpass_batch_live as fixture

class BatchContractGuards(unittest.TestCase):
    def test_named_matrix_and_terminal_observation_are_required(self):
        rows=[{'case':name,'status':200} for name in sorted(contract.REQUIRED_CASES-{'complete'})]
        rows.append({'case':'complete','observed':True})
        self.assertTrue(fixture.complete(rows))
        self.assertTrue(fixture.complete(rows[:-1]+[{'case':'extra','status':200}]+rows[-1:]))
        for index in range(len(rows)):self.assertFalse(fixture.complete(rows[:index]+rows[index+1:]))
        self.assertFalse(fixture.complete(rows+[rows[0]]))
        self.assertFalse(fixture.complete(rows[:-1]+[{'case':'complete','observed':1}]))

    def test_receipt_rejects_raw_fields_types_and_unnamed_padding(self):
        rows=[{'case':name,'status':200} for name in sorted(contract.REQUIRED_CASES-{'complete'})]+[{'case':'complete','observed':True}]
        for key,value in [('token','secret'),('status',True),('auth_type','secret'),('errors_present',1),('error_kind','raw message')]:
            changed=[dict(row) for row in rows];changed[0][key]=value
            self.assertFalse(fixture.complete(changed))
        self.assertFalse(fixture.complete([{'case':'padding_'+str(n),'status':200} for n in range(500)]+rows[-1:]))

    def test_projection_discards_passwords_tokens_and_error_echoes(self):
        secret='sensitive-bearer-never-in-receipt'
        response=SimpleNamespace(status=400,body={'errors':['unsafe '+secret],
            'auth':{'client_token':secret,'accessor':'private-accessor','token_type':'batch','renewable':False}})
        trace=contract.Trace(SimpleNamespace(request=lambda *a,**kw:response))
        trace.call('rejected','POST','test')
        self.assertNotIn(secret,json.dumps(trace.rows));self.assertNotIn('private-accessor',json.dumps(trace.rows))
        self.assertEqual(trace.rows[0]['error_kind'],'other')
        self.assertIn(secret,trace.sensitive)

    def test_cubbyhole_matrix_exercises_all_methods_without_exporting_credentials(self):
        requests=[]
        def request(method,path,fields,**kw):
            requests.append((method,path))
            if '/login/' in path:
                return SimpleNamespace(status=200,body={'auth':{'client_token':'sensitive-batch','accessor':'','token_type':'batch',
                    'metadata':{'username':'matrix'},'entity_id':'entity','orphan':True,'renewable':False}})
            if path.startswith('/v1/cubbyhole/'):
                return SimpleNamespace(status=400 if method in ('POST','PUT') else 403,body={'errors':['permission denied']})
            return SimpleNamespace(status=204,body={})
        trace=contract.Trace(SimpleNamespace(request=request));trace.password='sensitive-password'
        contract.cubbyhole_priority(trace)
        observed={r['case']:r['status'] for r in trace.rows}
        for name in ('create','update','read','unrelated','empty'):
            for method in ('post','put'):
                self.assertEqual(observed['cubby_priority.'+name+'.'+method],400)
            self.assertEqual(observed['cubby_priority.'+name+'.get'],403)
        self.assertEqual(sum(path.startswith('/v1/cubbyhole/') for _,path in requests),25)
        self.assertNotIn('sensitive-password',json.dumps(trace.rows));self.assertNotIn('sensitive-batch',json.dumps(trace.rows))

if __name__=='__main__':unittest.main()
