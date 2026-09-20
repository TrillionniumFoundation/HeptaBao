import unittest
from unittest.mock import patch
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

if __name__=='__main__':unittest.main()
