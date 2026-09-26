import dataclasses
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from heptabao.agent import Agent, AgentConfig
from heptabao.private_state import StateDirectory, token_snapshot
from heptabao.transport import BaoError, Response, canonical


class Clock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class FakeClient:
    def __init__(self): self.calls=[]; self.queued=[]
    def __call__(self, *args, **kwargs): return self
    def request(self, method, path, payload=None, **kwargs):
        self.calls.append((method,path,payload,kwargs))
        value=self.queued.pop(0)
        if isinstance(value,Exception): raise value
        return value
    def token(self, value='synthetic-agent-bearer', ttl=60, uses=0, **changes):
        auth={'client_token':value,'lease_duration':ttl,'renewable':True,'token_type':'service','policies':['default']}
        auth.update(changes)
        self.queued.extend([Response(200,{'auth':auth}), Response(200,{'data':{'num_uses':uses,'ttl':ttl,'renewable':True,'type':'service','policies':['default']}})])


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.store=self.root/'store'; self.store.mkdir(mode=0o700)
        for name,value in [('ca','synthetic-ca'),('role','synthetic-role'),('secret','synthetic-secret')]:
            p=self.root/name; p.write_text(value); p.chmod(0o600)
        self.config=AgentConfig('https://localhost:8200',str(self.root/'ca'),str(self.root/'role'),str(self.root/'secret'),str(self.store))
        self.clock=Clock(); self.fake=FakeClient()
    def open(self):
        state=StateDirectory(self.store,writer=True)
        self.addCleanup(state.close)
        agent=Agent(self.config,state,client_factory=self.fake,wall=self.clock,monotonic=self.clock)
        return agent,state

    def test_real_private_sink_checkpoint_and_resumption(self):
        agent,state=self.open(); self.fake.token()
        self.assertEqual(agent.step(),'authenticated')
        token,meta=token_snapshot(state,100,self.config.binding())
        self.assertEqual(token,'synthetic-agent-bearer')
        self.assertEqual(meta['expires_at'],160)
        self.assertNotIn(token,state.read('state.json').decode())
        self.assertEqual((self.store/'token').stat().st_mode&0o777,0o600)
        state.close(); agent,state=self.open()
        self.fake.queued.append(Response(200,{'data':{'num_uses':0,'ttl':60,'renewable':True,'type':'service','policies':['default']}}))
        self.assertEqual(agent.step(),'ready')
        self.assertEqual(len(self.fake.calls),3)

    def test_pending_login_on_timeout_cannot_be_retried_or_adopted(self):
        agent,state=self.open(); self.fake.queued.append(BaoError('transport_outcome_unknown'))
        with self.assertRaises(BaoError):agent.step()
        self.assertEqual(state.json('state.json')['phase'],'auth_pending')
        self.assertFalse((self.store/'token').exists())
        with self.assertRaises(BaoError):agent.step()
        self.assertEqual(len(self.fake.calls),1)
        state.close()
        with self.assertRaisesRegex(BaoError,'pending_or_invalid'):self.open()

    def test_renewal_pending_hides_sink_and_never_retries_unknown(self):
        agent,state=self.open();self.fake.token();agent.step();self.clock.now=131
        self.fake.queued.append(BaoError('transport_outcome_unknown'))
        with self.assertRaises(BaoError):agent.step()
        self.assertEqual(state.json('state.json')['phase'],'renew_pending')
        self.assertFalse((self.store/'token').exists())
        with self.assertRaises(BaoError):agent.step()
        self.assertEqual(len(self.fake.calls),3)

    def test_confirmed_renewal_denial_allows_bounded_reauthentication(self):
        agent,state=self.open();self.fake.token();agent.step();self.clock.now=131
        self.fake.queued.append(Response(403,{'errors':['do-not-log-me']}))
        self.assertEqual(agent.step(),'reauthenticate'); self.fake.token('synthetic-second-token')
        self.assertEqual(agent.step(),'authenticated')
        self.assertEqual(state.json('state.json')['authentications'],2)

    def test_renewal_is_requested_from_now_and_republished_privately(self):
        agent,state=self.open();self.fake.token();agent.step();self.clock.now=131
        self.fake.token()
        self.assertEqual(agent.step(),'renewed')
        self.assertEqual(state.json('state.json')['expires_at'],191)
        self.assertEqual(self.fake.calls[2][2],{'increment':60})

    def test_expired_resumption_never_reuses_the_old_sink(self):
        agent,state=self.open();self.fake.token();agent.step();state.close();self.clock.now=161
        agent,state=self.open()
        self.assertEqual(agent.state['phase'],'empty');self.assertFalse((self.store/'token').exists())
        self.fake.token('new-token');self.assertEqual(agent.step(),'authenticated')

    def test_clock_regression_and_trust_drift_fail_before_network(self):
        agent,state=self.open();self.fake.token();agent.step();self.clock.now=99
        with self.assertRaisesRegex(BaoError,'clock_regression'):agent.step()
        self.clock.now=101;(self.root/'ca').write_text('changed-ca')
        with self.assertRaisesRegex(BaoError,'trust_configuration_changed'):agent.step()
        self.assertEqual(len(self.fake.calls),2)

    def test_finite_use_root_or_excessive_ttl_never_publish_token(self):
        for ttl,uses,extra in [(60,1,{}),(999999,0,{}),(60,0,{'policies':['root']}),(60,0,{'renewable':False})]:
            with self.subTest(ttl=ttl,uses=uses,extra=extra):
                agent,state=self.open();self.fake.token(ttl=ttl,uses=uses,**extra)
                with self.assertRaises(BaoError):agent.step()
                self.assertFalse((self.store/'token').exists())
                state.close();(self.store/'state.json').unlink();self.fake.queued.clear()

    def test_public_credentials_reject_before_checkpoint_or_network(self):
        agent,state=self.open();(self.root/'secret').chmod(0o644)
        with self.assertRaises(BaoError):agent.step()
        self.assertEqual(self.fake.calls,[])
        self.assertIsNone(state.read('state.json',optional=True))

    def test_budget_persists_across_restart_and_stop_does_not_claim_revocation(self):
        self.config=dataclasses.replace(self.config,max_authentications=1)
        agent,state=self.open();self.fake.token();agent.step();agent.stop()
        self.assertEqual(state.json('state.json')['phase'],'stopped')
        self.assertFalse((self.store/'token').exists());state.close()
        agent,state=self.open()
        with self.assertRaisesRegex(BaoError,'budget_exhausted'):agent.step()
        self.assertEqual(len(self.fake.calls),2)

    def test_sink_publication_failure_keeps_pending_not_ready(self):
        agent,state=self.open();self.fake.token()
        real=state.publish
        def fail_ready(name,value):
            if value.get('phase')=='ready':raise BaoError('state_publication_unknown')
            return real(name,value)
        with patch.object(state,'publish',side_effect=fail_ready),self.assertRaises(BaoError):agent.step()
        self.assertEqual(state.json('state.json')['phase'],'auth_pending')
        with self.assertRaises(BaoError):token_snapshot(state,100,self.config.binding())
        state.close()
        with self.assertRaises(BaoError):self.open()

    def test_token_digest_tamper_rejected_before_request(self):
        agent,state=self.open();self.fake.token();agent.step();(self.store/'token').write_text('changed')
        with self.assertRaisesRegex(BaoError,'snapshot_changed'):agent.step()
        self.assertEqual(len(self.fake.calls),2)

    def test_second_writer_hardlinks_symlink_components_and_replaced_lock_reject(self):
        _,state=self.open()
        with self.assertRaisesRegex(BaoError,'writer_fenced'):StateDirectory(self.store,writer=True)
        state.write('one',b'secret');os.link(self.store/'one',self.store/'two')
        with self.assertRaises(BaoError):state.read('one')
        with self.assertRaises(BaoError):state.write('one',b'changed')
        alias=self.root/'alias';alias.symlink_to(self.store,target_is_directory=True)
        with self.assertRaises(BaoError):StateDirectory(alias)
        (self.store/'.agent.lock').rename(self.store/'old.lock')
        with self.assertRaises(BaoError):state.write('new',b'x')

    def test_replaced_directory_cannot_redirect_sink(self):
        _,state=self.open();self.store.rename(self.root/'moved');self.store.mkdir(mode=0o700)
        with self.assertRaises(BaoError):state.write('token',b'cannot-write')
        self.assertFalse((self.store/'token').exists())

    def test_orphan_token_not_silently_adopted(self):
        p=self.store/'token';p.write_text('orphan');p.chmod(0o600)
        with self.assertRaisesRegex(BaoError,'orphan_token'):self.open()



    def test_frozen_ca_bytes_are_forwarded_to_tls_not_reopened_by_path(self):
        from unittest.mock import Mock
        agent, state = self.open()
        factory = Mock(return_value=self.fake)
        agent.factory = factory
        self.fake.token()
        agent.step()
        self.assertEqual(factory.call_count, 2)
        for call in factory.call_args_list:
            self.assertEqual(call.kwargs['trusted_ca_pem'], b'synthetic-ca')

    def test_restart_refuses_a_different_token_class_before_renewal(self):
        agent, state = self.open()
        self.fake.token()
        agent.step()
        state.close()
        agent, state = self.open()
        self.fake.queued.append(Response(200, {'data': {
            'num_uses': 0, 'ttl': 60, 'renewable': True,
            'type': 'batch', 'policies': ['default'],
        }}))
        with self.assertRaisesRegex(BaoError, 'resumed_token_rejected'):
            agent.step()
        self.assertEqual(len(self.fake.calls), 3)


if __name__=='__main__':unittest.main()
