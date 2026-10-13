"""Managed-secret and template custody regressions, with no network authority."""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from heptabao import managed_secrets as managed
from heptabao import templates
from heptabao.token_authority import TokenAuthority
from heptabao.private_state import StateDirectory
from heptabao.transport import BaoError, canonical

PATH='database/creds/unit'
TOKEN='synthetic-unit-token'
TOKEN_HASH=hashlib.sha256(TOKEN.encode('ascii')).hexdigest()


def response(body, status=200):
    return SimpleNamespace(status=status, body=body)


def lease_body():
    return {'data':{'value':'synthetic-unit-only'},'lease_id':'unit-lease',
            'lease_duration':30,'renewable':True}


class ManagedCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='heptabao-managed-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.root.chmod(0o700)
        self.clock=100.0
        self.time_patch=patch.object(managed.time,'time',lambda:self.clock)
        self.mono_patch=patch.object(managed.time,'monotonic',lambda:self.clock)
        self.time_patch.start();self.mono_patch.start()
        self.addCleanup(self.time_patch.stop);self.addCleanup(self.mono_patch.stop)
        self.agent_path=self.root/'agent';self.agent_path.mkdir(mode=0o700)
        self.managed_path=self.root/'managed';self.managed_path.mkdir(mode=0o700)
        ca=self.root/'ca';ca.write_bytes(b'synthetic unit trust bytes');ca.chmod(0o600)
        self.agent=SimpleNamespace(state_dir=str(self.agent_path),ca_file=str(ca),
            binding=lambda:'unit-agent-binding',address='https://127.0.0.1:1',
            namespace='',timeout=.2)
        raw=TOKEN.encode('ascii')+b'\n'
        with StateDirectory(self.agent_path,writer=True) as directory:
            directory.write('token',raw)
            directory.publish('state.json',{'schema':1,'binding':self.agent.binding(),
                'phase':'ready','generation':0,'observed_wall':99.,'expires_at':1000.,'token_num_uses':0,
                'token_sha256':hashlib.sha256(raw).hexdigest()})
        self.authority=TokenAuthority('ready',0,TOKEN_HASH,1000.,1000.,99.)
        self.requests=[]
        self.answer=lambda method,path,payload=None:response(lease_body())
        test=self
        class SyntheticClient:
            def request(self,method,path,payload=None):
                test.requests.append((method,path))
                return test.answer(method,path,payload)
        self.owner=managed.ManagedSecrets({'state_dir':str(self.managed_path),
            'routes':[{'path':PATH,'effectful':True}]},self.agent,threading.Event(),
            client_factory=lambda *args,**kwargs:SyntheticClient(),token_authority=lambda:self.authority)
        self.addCleanup(self.owner.close)

    def ready(self, *, phase='ready', deadline=130.):
        row={'phase':phase,'token_hash':TOKEN_HASH,'body':lease_body(),
             'lease_id':'unit-lease','renewable':True,'observed_wall':100.,
             'wall_deadline':deadline,'deadline':deadline,'renew_at':99.,'refresh_wall':105.}
        self.owner.rows[PATH]=row
        self.owner._save()
        return row

    def test_subsecond_original_grant_is_live_with_zero_integer_metadata(self):
        self.ready(deadline=100.9)
        self.answer=lambda *args:response({'data':{}})
        result=self.owner.secret(PATH)
        self.assertEqual(result['Data'],{'value':'synthetic-unit-only'})
        self.assertEqual(result['LeaseDuration'],0)
        self.assertEqual(self.owner.delivery([PATH],TOKEN_HASH),100.9)
        self.clock=100.9
        with self.assertRaises(BaoError):self.owner.delivery([PATH],TOKEN_HASH)

    def test_zero_metadata_cannot_release_an_expired_original_grant(self):
        row=self.ready(deadline=100.)
        row['body']['lease_duration']=0
        with self.assertRaises(BaoError):self.owner.delivery([PATH],TOKEN_HASH)
        self.assertEqual(self.requests,[])

    def test_zero_lookup_ttl_cannot_mint_reconciled_authority(self):
        row=self.ready(phase='lookup_pending')
        self.answer=lambda *args:response({'data':{'id':'unit-lease','ttl':0,'renewable':True}})
        self.owner.maintain()
        self.assertEqual(row['phase'],'lookup_pending')
        self.assertEqual(self.owner.events['reconciled'],0)
        with self.assertRaises(BaoError):self.owner.secret(PATH)
        self.assertEqual(self.requests,[('POST','/v1/sys/leases/lookup')])

    def test_publication_crossing_exact_lease_deadline_removes_output(self):
        self.ready(deadline=101.)
        test=self
        class Directory:
            value=None
            def read(self,*args,**kwargs):return self.value
            def write(self,name,value):self.value=value;test.clock=101.
            def remove(self,name):self.value=None
        directory=Directory()
        renderer=templates.Templates.__new__(templates.Templates)
        job={'destination_dir':'/synthetic','destination_name':'unit'}
        renderer.config={'jobs':[job],'poll_interval_seconds':1}
        renderer.next_poll=0;renderer.stop=self.owner.stop;renderer.secrets=self.owner
        renderer.directories={'/synthetic':directory};renderer.written=set();renderer.published={}
        renderer.publication_lock=threading.RLock()
        renderer.events={'changed':0,'rendered':0,'blocked':0}
        renderer._render=lambda job:(b'synthetic-only',{PATH},TOKEN_HASH,105.)
        renderer.step()
        self.assertIsNone(directory.value)
        self.assertEqual(renderer.published,{})
        self.assertEqual(renderer.events['rendered'],0)
        self.assertEqual(renderer.events['blocked'],1)

    def token_grant(self,wall=120.,mono=120.,observed=100.,generation=0):
        self.authority=TokenAuthority('ready',generation,TOKEN_HASH,wall,mono,observed)
        with StateDirectory(self.agent_path,writer=True) as directory:
            state=directory.json('state.json')
            directory.publish('state.json',{**state,'expires_at':wall,'observed_wall':observed,'generation':generation})

    def test_wall_rollback_above_observed_cannot_extend_original_token_mono_grant(self):
        self.token_grant()
        with patch.object(managed.time,'time',lambda:110.),patch.object(managed.time,'monotonic',lambda:110.):
            self.assertEqual(self.owner.delivery(set(),TOKEN_HASH),120.)
        with patch.object(managed.time,'time',lambda:105.),patch.object(managed.time,'monotonic',lambda:115.):
            self.assertEqual(self.owner.delivery(set(),TOKEN_HASH),120.)
        with patch.object(managed.time,'time',lambda:110.),patch.object(managed.time,'monotonic',lambda:120.):
            with self.assertRaises(BaoError):self.owner.delivery(set(),TOKEN_HASH)
        self.assertEqual(self.requests,[])

    def test_cleaner_keeps_original_token_expiry_during_wall_rollback(self):
        self.token_grant()
        value,published=self.cleaner_tick(wall=105.,mono=120.,paths=set(),wall_deadline=120.)
        self.assertIsNone(value);self.assertEqual(published,{})
        self.assertEqual(self.requests,[])

    def test_pending_token_capsule_withdraws_output_even_with_same_sink_digest(self):
        self.authority=None
        value,published=self.cleaner_tick(wall=105.,mono=105.,paths=set())
        self.assertIsNone(value);self.assertEqual(published,{})
        with self.assertRaises(BaoError):self.owner.delivery(set(),TOKEN_HASH)
        self.assertEqual(self.requests,[])

    def test_new_generation_same_token_cannot_reauthorize_prior_published_sink(self):
        self.token_grant(wall=140.,mono=140.,generation=1)
        value,published=self.cleaner_tick(wall=105.,mono=105.,paths=set())
        self.assertIsNone(value);self.assertEqual(published,{})
        self.assertEqual(self.owner.delivery(set(),TOKEN_HASH,include_wall=True)[-1],1)
        self.assertEqual(self.requests,[])

    def test_cleaner_expiry_does_not_wait_for_subscription_network_lock(self):
        self.token_grant()
        result=[]
        with self.owner.lock:
            worker=threading.Thread(target=lambda:result.append(self.cleaner_tick(wall=105.,mono=120.,paths=set())))
            worker.start();worker.join(.3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result,[(None,{})]);self.assertEqual(self.requests,[])

    def cleaner_tick(self,*,wall,mono,paths=None,wall_deadline=130.,observed_wall=100.):
        renderer=templates.Templates.__new__(templates.Templates)
        class Directory:
            value=b'synthetic-only'
            def remove(self,name):self.value=None
        class OneTick:
            calls=0
            def wait(self,timeout):self.calls+=1;return self.calls>1
        directory=Directory();renderer.directories={'unit':directory}
        renderer.publication_lock=threading.RLock();renderer.stop=self.owner.stop
        renderer.secrets=self.owner;renderer.cleaner_stop=OneTick()
        renderer.published={('unit','unit'):(130.,set([PATH]) if paths is None else paths,TOKEN_HASH,wall_deadline,observed_wall,0)}
        with patch.object(templates.time,'time',lambda:wall),patch.object(templates.time,'monotonic',lambda:mono):
            renderer._clean_expired()
        return directory.value,renderer.published

    def test_expiry_cleaner_withdraws_on_forward_wall_jump_without_network(self):
        self.ready(deadline=120.)
        value,published=self.cleaner_tick(wall=120.,mono=105.)
        self.assertIsNone(value);self.assertEqual(published,{})
        self.assertEqual(self.requests,[])

    def test_expiry_cleaner_withdraws_static_output_at_exact_token_wall_deadline(self):
        value,published=self.cleaner_tick(wall=110.,mono=105.,paths=set(),wall_deadline=110.)
        self.assertIsNone(value);self.assertEqual(published,{})
        self.assertEqual(self.requests,[])

    def test_expiry_cleaner_withdraws_on_wall_regression(self):
        self.ready()
        value,published=self.cleaner_tick(wall=99.,mono=105.)
        self.assertIsNone(value);self.assertEqual(published,{})
        self.assertEqual(self.requests,[])

    def test_expiry_cleaner_preserves_live_exact_original_grant(self):
        self.ready()
        value,published=self.cleaner_tick(wall=129.9,mono=129.9)
        self.assertEqual(value,b'synthetic-only');self.assertEqual(len(published),1)
        self.assertEqual(self.requests,[])

    def test_cache_lookup_cannot_deliver_after_lease_expiry(self):
        self.ready(deadline=101.)
        def late_lookup(*args):
            self.clock=102.
            return response({'data':{}})
        self.answer=late_lookup
        with self.assertRaises(BaoError) as caught:self.owner.secret(PATH)
        self.assertEqual(caught.exception.code,'managed_secret_lease_expired_before_delivery')
        self.assertEqual(self.requests,[('GET','/v1/auth/token/lookup-self')])

    def test_issue_response_cannot_deliver_expired_lease(self):
        def late_issue(*args):
            self.clock=132.
            return response(lease_body())
        self.answer=late_issue
        with self.assertRaises(BaoError) as caught:self.owner.secret(PATH)
        self.assertEqual(caught.exception.code,'managed_secret_lease_expired_before_delivery')
        self.assertEqual(len(self.requests),1)

    def test_issue_publication_failure_fences_every_later_delivery(self):
        publish=self.owner.directory.publish
        calls=0
        def fail_final(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:raise BaoError('state_publication_unknown')
            return publish(*args,**kwargs)
        with patch.object(self.owner.directory,'publish',fail_final):
            with self.assertRaises(BaoError):self.owner.secret(PATH)
        self.assertTrue(self.owner.storage_failed)
        for _ in range(2):
            with self.assertRaises(BaoError) as caught:self.owner.secret(PATH)
            self.assertEqual(caught.exception.code,'managed_secret_durable_publication_unknown')
        self.assertEqual(len(self.requests),1)
        saved=json.loads((self.managed_path/'subscriptions.json').read_text())
        self.assertEqual(saved['rows'][PATH]['phase'],'issue_pending')

    def test_renew_publication_failure_fences_cached_data(self):
        self.ready()
        publish=self.owner.directory.publish
        calls=0
        def fail_final(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:raise BaoError('state_publication_unknown')
            return publish(*args,**kwargs)
        with patch.object(self.owner.directory,'publish',fail_final):
            with self.assertRaises(BaoError):self.owner.maintain()
        self.assertTrue(self.owner.storage_failed)
        with self.assertRaises(BaoError):self.owner.secret(PATH)
        self.assertEqual(self.requests,[('POST','/v1/sys/leases/renew')])
        saved=json.loads((self.managed_path/'subscriptions.json').read_text())
        self.assertEqual(saved['rows'][PATH]['phase'],'renew_pending')

    def test_reconcile_rejects_unrelated_lease_identity(self):
        self.ready(phase='lookup_pending')
        self.answer=lambda *args:response({'data':{'id':'unrelated','ttl':30,'renewable':False}})
        self.owner.maintain()
        self.assertEqual(self.owner.rows[PATH]['phase'],'lookup_pending')
        self.assertEqual(self.owner.events['reconciled'],0)
        with self.assertRaises(BaoError):self.owner.delivery([PATH],TOKEN_HASH)

    def test_static_label_cannot_retry_unknown_entered_get(self):
        directory=self.root/'mislabelled';directory.mkdir(mode=0o700)
        owner=managed.ManagedSecrets({'state_dir':str(directory),
            'routes':[{'path':PATH,'effectful':False}]},self.agent,threading.Event(),
            client_factory=self.owner.client_factory,token_authority=lambda:self.authority)
        self.addCleanup(owner.close)
        def unknown(*args):raise BaoError('upstream_outcome_unknown')
        self.answer=unknown
        with self.assertRaises(BaoError):owner.secret(PATH)
        self.assertEqual(owner.rows[PATH]['phase'],'issue_pending')
        with self.assertRaises(BaoError):owner.secret(PATH)
        self.assertEqual(len(self.requests),1)
        saved=json.loads((directory/'subscriptions.json').read_text())
        self.assertEqual(saved['rows'][PATH]['phase'],'issue_pending')

    def test_server_unavailable_cannot_clear_issuance_fence(self):
        self.answer=lambda *args:response({'errors':['synthetic_unknown_outcome']},503)
        with self.assertRaises(BaoError):self.owner.secret(PATH)
        self.assertEqual(self.owner.rows[PATH]['phase'],'issue_pending')
        with self.assertRaises(BaoError):self.owner.secret(PATH)
        self.assertEqual(len(self.requests),1)

    def test_reconcile_adopts_nonrenewable_projection(self):
        self.ready(phase='lookup_pending')
        self.answer=lambda *args:response({'data':{'id':'unit-lease','ttl':30,'renewable':False}})
        self.owner.maintain()
        self.assertEqual(self.owner.rows[PATH]['phase'],'ready')
        self.assertIs(self.owner.rows[PATH]['renewable'],False)
        self.answer=lambda *args:response({'data':{}})
        self.assertIs(self.owner.secret(PATH)['Renewable'],False)

    def test_invalid_durable_row_is_fenced_with_fixed_error(self):
        bad=self.root/'bad';bad.mkdir(mode=0o700)
        config=managed.configuration({'state_dir':str(bad),'routes':[{'path':PATH,'effectful':True}]},self.agent)
        binding=hashlib.sha256(canonical({'agent':self.agent.binding(),'managed':config})).hexdigest()
        with StateDirectory(bad,writer=True) as directory:
            directory.publish('subscriptions.json',{'schema':1,'binding':binding,'rows':{PATH:None}})
        with self.assertRaises(BaoError):managed.ManagedSecrets(config,self.agent,threading.Event(),client_factory=lambda *a,**k:None,token_authority=lambda:self.authority)
        # Constructor failure must release the writer lock as well.
        with StateDirectory(bad,writer=True):pass


class TemplateCustodyTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os,'memfd_create'),'immutable executable platform not admitted')
    def test_renderer_fifo_rejects_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory(prefix='heptabao-renderer-fifo-unit-') as temporary:
            root=Path(temporary);root.chmod(0o700)
            fifo=root/'renderer';os.mkfifo(fifo,0o600)
            owner=templates.Templates.__new__(templates.Templates)
            owner.config={'renderer':str(fifo),'renderer_sha256':'0'*64}
            errors=[]
            def admission():
                try:
                    descriptor,_=owner._renderer()
                    os.close(descriptor)
                except BaoError as error:errors.append(error.code)
            worker=threading.Thread(target=admission);worker.start();worker.join(.3)
            blocked=worker.is_alive()
            # The regression cleanup releases only this fixture's FIFO if an
            # older implementation blocks before fstat can reject the type.
            if blocked:
                writer=os.open(fifo,os.O_WRONLY|os.O_NONBLOCK)
                os.close(writer);worker.join(1)
            self.assertFalse(worker.is_alive())
            self.assertFalse(blocked,'renderer admission waited for a FIFO writer')
            self.assertEqual(errors,['template_renderer_requires_trusted_executable'])

    def test_stop_between_render_and_publish_withdraws_output(self):
        owner=templates.Templates.__new__(templates.Templates)
        owner.stop=threading.Event();owner.next_poll=0.;owner.written=set();owner.published={}
        owner.publication_lock=threading.RLock()
        owner.config={'poll_interval_seconds':1,'jobs':[{'destination_dir':'unit','destination_name':'unit.env'}]}
        owner.events={'changed':0,'rendered':0,'blocked':0}
        class Sink:
            writes=0
            removed=False
            def read(self,*args,**kwargs):return None
            def write(self,*args):self.writes+=1
            def remove(self,*args):self.removed=True
        sink=Sink();owner.directories={'unit':sink}
        def render(*args):
            owner.stop.set()
            return b'synthetic',set(),TOKEN_HASH,time.monotonic()+1
        owner._render=render
        owner.secrets=SimpleNamespace(delivery=lambda *args,**kwargs:(time.monotonic()+1,time.time()+1,time.time(),0) if kwargs.get('include_wall') else time.monotonic()+1)
        owner.step()
        self.assertEqual(sink.writes,0)
        self.assertTrue(sink.removed)
        self.assertEqual(owner.events['blocked'],1)

    def test_pipe_backpressure_respects_absolute_deadline(self):
        owner=templates.Templates.__new__(templates.Templates);owner.stop=threading.Event()
        read_fd,write_fd=os.pipe()
        with contextlib.ExitStack() as stack:
            stack.callback(os.close,read_fd)
            stream=stack.enter_context(os.fdopen(write_fd,'wb',buffering=0))
            start=time.monotonic()
            with self.assertRaises(BaoError) as caught:
                owner._frame(SimpleNamespace(stdin=stream),{'synthetic':'x'*524288},start+.12)
            self.assertEqual(caught.exception.code,'template_deadline')
            self.assertLess(time.monotonic()-start,1.)

    @unittest.skipUnless(hasattr(os,'memfd_create'),'immutable executable platform not admitted')
    def test_replaced_renderer_path_cannot_change_admitted_executable(self):
        with tempfile.TemporaryDirectory(prefix='heptabao-renderer-unit-') as temporary:
            root=Path(temporary);root.chmod(0o700)
            source=root/'source';source.write_text('synthetic');source.chmod(0o600)
            renderer=root/'renderer';replacement=root/'replacement'
            def script(output):
                return '#!/usr/bin/python3\nimport sys,json\nsys.stdin.readline()\nprint(json.dumps({"op":"result","ok":True,"output":'+repr(output)+'}),flush=True)\n'
            renderer.write_text(script('admitted'));renderer.chmod(0o700)
            replacement.write_text(script('unadmitted'));replacement.chmod(0o700)
            owner=templates.Templates.__new__(templates.Templates);owner.stop=threading.Event();owner.events={'secret_calls':0}
            owner.config={'renderer':str(renderer),'renderer_sha256':hashlib.sha256(renderer.read_bytes()).hexdigest(),'timeout_seconds':2}
            owner.secrets=SimpleNamespace(owner_deadline=None,token_generation=lambda **kwargs:TOKEN_HASH,
                delivery=lambda *args,**kwargs:time.monotonic()+1)
            popen=templates.subprocess.Popen
            def swap(*args,**kwargs):
                os.replace(replacement,renderer)
                return popen(*args,**kwargs)
            with patch.object(templates.subprocess,'Popen',swap):
                output,paths,token_hash,_=owner._render({'source_file':str(source)})
            self.assertEqual(output,b'admitted')
            self.assertEqual(paths,set());self.assertEqual(token_hash,TOKEN_HASH)
            self.assertNotEqual(hashlib.sha256(renderer.read_bytes()).hexdigest(),owner.config['renderer_sha256'])


if __name__=='__main__':unittest.main()
