import unittest
import jwt_completion_clock_live as f

class ClockWindowGuards(unittest.TestCase):
    def valid(self):
        return {'send_wall':110_650_000_000,'send_mono':20_000_000_000,
                'entered_wall':110_670_000_000,'entered_mono':20_020_000_000,
                'local_created':111,'released_wall':111_040_000_000,'released_mono':20_390_000_000,
                'completed_wall':111_060_000_000,'completed_mono':20_410_000_000,
                'held_before_release':True,'local_completed_before_release':True,'remote_pending_before_release':True}

    def test_window_requires_measured_server_issuance_and_short_provider_interval(self):
        v=self.valid(); self.assertTrue(f.window_valid(v))
        for key,value in [('entered_wall',111_010_000_000),('local_created',110),
                          ('completed_mono',21_000_000_000),('released_wall',112_000_000_000),
                          ('remote_pending_before_release',False),('local_completed_before_release',False),
                          ('held_before_release',False),('local_created',True),('send_mono',-1)]:
            changed=dict(v,**{key:value}); self.assertFalse(f.window_valid(changed),key)
        for key in v:
            changed=dict(v); del changed[key]; self.assertFalse(f.window_valid(changed),key)

    def test_observed_clock_jump_or_reversed_events_is_not_a_valid_window(self):
        v=self.valid()
        v['completed_wall']+=30_000_000
        self.assertFalse(f.window_valid(v))
        v=self.valid(); v['released_mono']=v['entered_mono']-1
        self.assertFalse(f.window_valid(v))
        v=self.valid(); v['completed_mono']=v['send_mono']
        self.assertFalse(f.window_valid(v))

    def profile(self,baseline=False):
        required=f.COMMON|(f.OLD if baseline else f.NEW)
        rows=[{'case':n,'passed':True} for n in sorted(required-{'complete'})]+[{'case':'complete','passed':True}]
        return {'status':'passed','checks':rows,'window':f.safe_window(self.valid())}

    def test_no_observed_window_is_inconclusive_even_when_all_business_checks_succeed(self):
        candidate=self.profile()
        self.assertEqual(f.aggregate_status({'candidate':candidate},{'candidate'}),'passed')
        candidate['window']['window_satisfied']=False
        self.assertEqual(f.aggregate_status({'candidate':candidate},{'candidate'}),'inconclusive')
        candidate['status']='failed'
        self.assertEqual(f.aggregate_status({'candidate':candidate},{'candidate'}),'failed')
        self.assertEqual(f.aggregate_status({}, {'candidate'}),'failed')
        both={'baseline':self.profile(True),'candidate':self.profile()}
        self.assertEqual(f.aggregate_status(both,set(both)),'passed')
        both['baseline']['status']='inconclusive'
        self.assertEqual(f.aggregate_status(both,set(both)),'inconclusive')

    def test_success_requires_distinct_complete_phase_evidence_not_a_total_count(self):
        for baseline in (False,True):
            p=self.profile(baseline)
            self.assertTrue(f.complete(p['checks'],baseline))
            for row in p['checks']:
                self.assertFalse(f.complete([r for r in p['checks'] if r!=row],baseline),row['case'])
            for changed in (p['checks']+p['checks'][-1:],
                            p['checks'][:-1]+[{'case':'complete','passed':1}],
                            p['checks'][:-1]+[{'case':'complete','passed':True,'secret':'sentinel'}]):
                self.assertFalse(f.complete(changed,baseline))

    def test_old_failure_requires_exact_sealing_branch_not_any_503(self):
        self.assertTrue(f.old_sealing_rejection(503, {'errors':['batch sealing unavailable']}))
        self.assertFalse(f.old_sealing_rejection(503, {'errors':['storage unavailable']}))
        self.assertFalse(f.old_sealing_rejection(503, {'errors':['JWKS unavailable']}))
        self.assertFalse(f.old_sealing_rejection(503, {'errors':['batch sealing unavailable'], 'wrap_info':{'token':'secret'}}))
        self.assertFalse(f.old_sealing_rejection(400, {'errors':['batch sealing unavailable']}))

    def test_safe_projection_never_copies_arbitrary_provider_payload_or_absolute_time(self):
        v=self.valid(); v['token']='sensitive-sentinel'
        report=f.safe_window(v)
        self.assertNotIn('sensitive-sentinel',str(report))
        self.assertNotIn('send_wall',report)
        self.assertFalse(report['window_satisfied'])
        self.assertTrue(all(type(x) in (bool,int) for x in report.values()))

if __name__=='__main__': unittest.main()
