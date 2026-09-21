import unittest
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch
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

    def test_actual_run_postcheck_failures_keep_window_rows_and_private_work(self):
        # Exercise run -> main -> receipt, not a hand-made complete-check list.
        # Only the TLS/process edges and clock observations are synthetic.
        for fault in ('scan', 'cleanup'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                parent=Path(directory); parent.chmod(0o700)
                binary=parent/'binary'; binary.write_bytes(b'fixture-only-no-executable')
                output=parent/'receipt.json'
                issuer=SimpleNamespace(calls=[], block_entered=threading.Event(), block_release=threading.Event())
                issuer.origin='https://localhost:443'
                issuer.documents={}
                issuer.thread=SimpleNamespace(is_alive=lambda:False)
                issuer.block_next=lambda path:None
                issuer.release_block=issuer.block_release.set
                issuer.close=lambda:None
                value={}
                class Instance:
                    def __init__(self, binary, root):
                        self.root=root; root.mkdir(mode=0o700)
                        (root/'data').mkdir()
                        for name,content in [('server.json','{}'),('ca.crt','fixture-ca'),('audit.jsonl',''),('server.log','')]:
                            (root/name).write_text(content); (root/name).chmod(0o600)
                        (root/'data'/'fixture').write_bytes(b'fixture-data')
                        self.address='https://127.0.0.1:443'; self.process=object()
                    def start(self): pass
                    def stop(self):
                        self.process=None
                        if fault=='cleanup': raise OSError('fixed synthetic cleanup failure')
                    def call(self, method, path, body):
                        if path=='sys/init':
                            return 200,{'keys_base64':['eA=='],'root_token':'fixture-root'}
                        return 200,{}
                class Client:
                    def __init__(self,*args,**kwargs): pass
                    def request(self,method,path,payload=None,**kwargs):
                        if path=='/v1/auth/clock/login':
                            issuer.calls.append('/keys'); issuer.block_entered.set()
                            if not issuer.block_release.wait(2): raise RuntimeError('offline gate not released')
                            return SimpleNamespace(status=503,body={'errors':['batch sealing unavailable']})
                        if path=='/v1/auth/token/create-orphan':
                            return SimpleNamespace(status=200,body={'auth':{'client_token':'fixture-local'}})
                        if path=='/v1/auth/token/lookup-self':
                            return SimpleNamespace(status=200,body={'data':{'creation_time':111}})
                        if path=='/v1/clock-values/value':
                            if method=='GET': return SimpleNamespace(status=200,body={'data':value.copy()})
                            value.update(payload)
                        if path=='/v1/identity/entity/id':
                            return SimpleNamespace(status=404,body={})
                        return SimpleNamespace(status=204,body={})
                stamps=iter([(110_650_000_000,20_000_000_000),
                             (110_670_000_000,20_020_000_000),
                             (111_040_000_000,20_390_000_000),
                             (111_060_000_000,20_410_000_000)])
                digest=hashlib.sha256(binary.read_bytes()).hexdigest()
                argv=['clock-fixture','--binary',str(binary),'--expected-binary-sha256',digest,
                      '--build-source-commit','a'*40,'--baseline-binary',str(binary),
                      '--expected-baseline-sha256',digest,'--baseline-build-source-commit','b'*40,
                      '--work-parent',str(parent),'--output',str(output)]
                with ExitStack() as stack:
                    for name,replacement in [('Instance',Instance),('Client',Client),
                            ('bounded_issuer',lambda *args:issuer),('wait_launch_phase',lambda:None),
                            ('stamp',lambda:next(stamps)),('helpers',lambda:{'fixture':'a'*64}),
                            ('source_identity',lambda *args:{'source_dirty':False}),
                            ('contains_any',lambda *args:fault=='scan')]:
                        stack.enter_context(patch.object(f,name,replacement))
                    stack.enter_context(patch.object(f.time,'time_ns',return_value=111_010_000_000))
                    stack.enter_context(patch('sys.argv',argv))
                    stack.enter_context(patch('builtins.print'))
                    self.assertEqual(f.main(),1)
                report=json.loads(output.read_text())
                self.assertEqual(report['status'],'failed')
                profile=report['profiles']['baseline']
                self.assertEqual(profile['status'],'failed')
                self.assertIn('window',profile,profile)
                self.assertTrue(profile['window']['window_satisfied'])
                rows={row['case']:row['passed'] for row in profile['checks']}
                for name in ('gate_order','old_clock_gap_denied','old_no_identity','local_bearer_usable'):
                    self.assertIs(rows[name],True)
                self.assertNotIn('complete',rows)
                if fault=='scan':
                    self.assertIs(rows['plaintext_absent'],False)
                    self.assertEqual(profile['failure'],'plaintext_absent')
                else:
                    self.assertEqual(profile['failure'],'fixture_OSError')
                retained=Path(report['retained_work_dir'])
                self.assertTrue(retained.is_relative_to(parent))
                self.assertTrue((retained/'baseline'/'candidate'/'data'/'fixture').is_file())

if __name__=='__main__': unittest.main()
