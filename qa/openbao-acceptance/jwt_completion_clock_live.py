#!/usr/bin/env python3
"""One-shot real TLS remote JWT/local batch clock ordering, optional old binary.

Only an observed event/time window is conclusive. No clock modification, retry,
provider forgery, HA or official differential. The old binary is optional and
must be independently pinned by the caller; its build identity is not inferred.
"""
from __future__ import annotations
import base64
from datetime import datetime
import importlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from jwt_api_tls_live import bounded_issuer
from jwt_split_phase_live import Work
from native_snapshot_cli_live import contains_any, private_parent
from online_evidence import admit_output, complete_checks, source_identity
from remote_jwks_live import Instance, signing_key, token, serialization

NANO = 1_000_000_000
WINDOW_FIELDS = frozenset({'send_wall', 'send_mono', 'entered_wall', 'entered_mono',
    'local_created', 'released_wall', 'released_mono', 'completed_wall', 'completed_mono',
    'held_before_release', 'local_completed_before_release', 'remote_pending_before_release'})
COMMON = frozenset({'initialized', 'unsealed', 'bounded_listener', 'kv_mount', 'kv_value', 'policy',
    'jwt_mount', 'config', 'role', 'provider_entered', 'local_issued', 'local_lookup',
    'local_bearer_usable', 'gate_order', 'one_jwks_request', 'processes_stopped', 'plaintext_absent', 'complete'})
NEW = frozenset({'remote_success', 'wrapper_clock', 'wrapper_lookup', 'wrapper_expiry',
    'unwrap', 'inner_batch_clock', 'inner_bearer_usable'})
OLD = frozenset({'old_clock_gap_denied', 'old_no_identity'})

class Failure(RuntimeError): pass


def stamp():
    # Adjacent wall/monotonic observations; exact security decisions remain in
    # the server. The window checker bounds observed clock disagreement.
    return time.time_ns(), time.monotonic_ns()


def window_valid(v):
    if not isinstance(v, dict) or set(v) != WINDOW_FIELDS:
        return False
    flags = ('held_before_release', 'local_completed_before_release', 'remote_pending_before_release')
    if any(v[name] is not True for name in flags): return False
    if any(type(v[name]) is not int or v[name] < 0 for name in WINDOW_FIELDS-set(flags)): return False
    send = v['send_wall']//NANO
    if v['entered_wall']//NANO != send or v['local_created'] != send+1: return False
    if v['released_wall']//NANO != send+1 or v['completed_wall']//NANO != send+1: return False
    if not v['send_mono'] <= v['entered_mono'] <= v['released_mono'] <= v['completed_mono']: return False
    if not 0 < v['completed_mono']-v['send_mono'] < NANO: return False
    for point in ('entered', 'released', 'completed'):
        wall = v[point+'_wall']-v['send_wall']
        mono = v[point+'_mono']-v['send_mono']
        if wall < 0 or abs(wall-mono) > 20_000_000: return False
    return True


def safe_window(v):
    return {'window_satisfied': window_valid(v),
            'provider_arrival_ns': v.get('entered_mono', 0)-v.get('send_mono', 0),
            'complete_from_send_ns': v.get('completed_mono', 0)-v.get('send_mono', 0),
            'release_from_send_ns': v.get('released_mono', 0)-v.get('send_mono', 0),
            'local_created_second_delta': v.get('local_created', 0)-v.get('send_wall', 0)//NANO,
            'held_before_release': v.get('held_before_release') is True,
            'local_completed_before_release': v.get('local_completed_before_release') is True,
            'remote_pending_before_release': v.get('remote_pending_before_release') is True}


def wait_launch_phase():
    # Waiting before a single mutation is not a retry. At most one alignment
    # attempt; overscheduling simply yields an inconclusive observed window.
    now = time.time_ns()
    target = (now//NANO)*NANO+650_000_000
    if target <= now: target += NANO
    deadline = time.monotonic()+2
    while time.time_ns() < target and time.monotonic() < deadline:
        time.sleep(min(0.005, max(0.0, (target-time.time_ns())/NANO)))


def old_sealing_rejection(status, body):
    return (status == 503 and isinstance(body, dict) and body.get('errors') == ['batch sealing unavailable']
            and not any(body.get(k) for k in ('auth', 'data', 'wrap_info')))


def complete(rows, baseline):
    return complete_checks(rows, required_cases=COMMON | (OLD if baseline else NEW)) and rows[-1]['case']=='complete'


def run(binary, work, baseline):
    rows, samples, timing = [], [], {}
    instance = issuer = worker = None
    result = {'status':'failed', 'checks':rows, 'baseline':baseline, 'failure':None}
    def check(name, passed):
        if not re.fullmatch('[a-z0-9_]{1,120}', name) or type(passed) is not bool: raise Failure('unsafe_check')
        rows.append({'case':name, 'passed':passed})
        if not passed: raise Failure(name)
    def remember(v):
        samples.append(v.encode() if isinstance(v,str) else v); return v
    try:
        instance = Instance(binary, work/'candidate')
        path = instance.root/'server.json'; config=json.loads(path.read_text())
        config.update(outbound_endpoints=[], timeout_seconds=5, lifecycle_interval_seconds=0)
        private_write(path, config)
        check('bounded_listener', json.loads(path.read_text())['timeout_seconds']==5)
        issuer = bounded_issuer(instance.root/'tls.crt', instance.root/'tls.key')
        key,jwk = signing_key('ES256','clock')
        remember(key.private_numbers().private_value.to_bytes(32,'big'))
        for enc in (serialization.Encoding.PEM,serialization.Encoding.DER):
            remember(key.private_bytes(enc,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        issuer.documents['/keys']={'keys':[jwk]}
        instance.start()
        status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        check('initialized',status==200)
        share=remember(init['keys_base64'][0]); remember(base64.b64decode(share,validate=True))
        for v in init.get('keys',[]): remember(v); remember(bytes.fromhex(v))
        admin=remember(init['root_token']); instance.token=admin
        check('unsealed',instance.call('POST','sys/unseal',{'key':share})[0]==200)
        client=Client(instance.address,str(instance.root/'ca.crt'),admin,timeout=5)
        remote=Client(instance.address,str(instance.root/'ca.crt'),admin,timeout=5)
        def call(name,path,payload=None,method='POST',expected=204,bearer=None):
            r=client.request(method,'/v1/'+path,payload,token=bearer)
            check(name,r.status==expected); return r.body
        call('kv_mount','sys/mounts/clock-values',{'type':'kv','options':{'version':'1'}})
        value={'value':remember('synthetic-clock-'+secrets.token_hex(24))}
        call('kv_value','clock-values/value',value)
        call('policy','sys/policies/acl/clock',{'policy':'path "clock-values/*" { capabilities = ["read"] }'})
        call('jwt_mount','sys/auth/clock',{'type':'jwt'})
        call('config','auth/clock/config',{'bound_issuer':issuer.origin,'jwks_url':issuer.origin+'/keys',
             'jwks_ca_pem':(instance.root/'ca.crt').read_text(),'jwt_supported_algs':['ES256']})
        call('role','auth/clock/role/test',{'role_type':'jwt','user_claim':'sub','bound_audiences':['heptabao-test'],
             'token_type':'batch','token_policies':['clock'],'token_ttl':600,'token_max_ttl':600})
        assertion=remember(token(key,jwk,issuer.origin))
        preceding=len(issuer.calls); issuer.block_next('/keys')
        def remote_once():
            wait_launch_phase()
            timing['send_wall'],timing['send_mono']=stamp()
            try:
                return remote.request('POST','/v1/auth/clock/login',{'role':'test','jwt':assertion},token='',wrap_ttl='1s')
            finally:
                timing['completed_wall'],timing['completed_mono']=stamp()
        worker=Work(remote_once)
        check('provider_entered',issuer.block_entered.wait(3))
        timing['entered_wall'],timing['entered_mono']=stamp()
        next_second=timing['send_wall']//NANO+1
        deadline=time.monotonic()+1.2
        while time.time_ns()//NANO < next_second and time.monotonic()<deadline:
            time.sleep(0.001)
        local=call('local_issued','auth/token/create-orphan',{'type':'batch','policies':['clock'],'ttl':600},expected=200)
        local_token=remember(local['auth']['client_token'])
        lookup=call('local_lookup','auth/token/lookup-self',method='GET',bearer=local_token,expected=200)
        timing['local_created']=lookup['data']['creation_time']
        r=client.request('GET','/v1/clock-values/value',token=local_token)
        check('local_bearer_usable',r.status==200 and r.body.get('data')==value)
        timing['held_before_release']=not issuer.block_release.is_set()
        timing['local_completed_before_release']=True
        timing['remote_pending_before_release']=not worker.done.is_set()
        check('gate_order',all(timing[n] for n in ('held_before_release','local_completed_before_release','remote_pending_before_release')))
        timing['released_wall'],timing['released_mono']=stamp(); issuer.release_block()
        if not worker.done.wait(5): raise Failure('remote_completion_timeout')
        response=worker.result()
        check('one_jwks_request',issuer.calls[preceding:]==['/keys'])
        result['window']=safe_window(timing); result['remote_status']=response.status
        for envelope,keyname in (('auth','client_token'),('auth','accessor'),('wrap_info','token'),('wrap_info','accessor')):
            secret=(response.body.get(envelope) or {}).get(keyname)
            if isinstance(secret,str) and secret: remember(secret)
        # No favorable scheduling assumption may turn a missed old-gap window
        # into a qualification pass, regardless of the server's outcome.
        if not window_valid(timing):
            result['status']='inconclusive'; result['failure']='timing_window_not_observed'
        elif baseline:
            check('old_clock_gap_denied',old_sealing_rejection(response.status,response.body))
            listed=client.request('LIST','/v1/identity/entity/id')
            check('old_no_identity',listed.status in (200,404) and not (listed.body.get('data') or {}).get('keys'))
            result['status']='passed'
        else:
            check('remote_success',response.status==200 and response.body.get('auth') is None
                  and isinstance(response.body.get('wrap_info'),dict))
            info=response.body['wrap_info']; wrapper=remember(info['token'])
            created=int(datetime.fromisoformat(info['creation_time'].replace('Z','+00:00')).timestamp())
            check('wrapper_clock',created==timing['local_created'] and info.get('ttl')==1)
            looked=call('wrapper_lookup','auth/token/lookup',{'token':wrapper},expected=200)
            data=looked.get('data') or {}
            check('wrapper_expiry',data.get('creation_time')==created and data.get('expire_time_unix')==created+1)
            unwrapped=call('unwrap','sys/wrapping/unwrap',{},bearer=wrapper,expected=200)
            bearer=remember(unwrapped['auth']['client_token'])
            looked=client.request('GET','/v1/auth/token/lookup-self',token=bearer)
            check('inner_batch_clock',looked.status==200 and (looked.body.get('data') or {}).get('creation_time')==created
                  and (looked.body.get('data') or {}).get('type')=='batch')
            r=client.request('GET','/v1/clock-values/value',token=bearer)
            check('inner_bearer_usable',r.status==200 and r.body.get('data')==value)
            result['status']='passed'
    except Exception as error:
        result['status']='failed'
        result['failure']=next((r['case'] for r in reversed(rows) if not r['passed']), 'fixture_'+type(error).__name__)
    finally:
        try:
            if issuer is not None: issuer.release_block()
            if worker is not None:
                worker.thread.join(timeout=6)
                if worker.thread.is_alive(): raise Failure('worker_cleanup')
        finally:
            try:
                if instance is not None: instance.stop()
            finally:
                if issuer is not None: issuer.close()
    check('processes_stopped', instance is not None and instance.process is None and issuer is not None and not issuer.thread.is_alive())
    paths=list((instance.root/'data').rglob('*'))+[instance.root/'audit.jsonl',instance.root/'server.log']
    check('plaintext_absent',bool(samples) and all(not contains_any(p,samples) for p in paths if p.is_file()))
    if result['status']=='passed': check('complete',True)
    return result


def aggregate_status(reports, expected):
    if set(reports) != set(expected) or any(r.get('status') == 'failed' for r in reports.values()):
        return 'failed'
    if any(r.get('status') == 'inconclusive' or (r.get('window') or {}).get('window_satisfied') is not True
           for r in reports.values()):
        return 'inconclusive'
    if not all(r.get('status') == 'passed' and complete(r.get('checks', []), n == 'baseline')
               for n,r in reports.items()):
        return 'failed'
    return 'passed'


def helpers():
    names=('bao_http','heptabao.transport','core_isolation','jwt_api_tls_live','jwt_split_phase_live',
           'native_snapshot_cli_live','online_evidence','remote_jwks_live','external_tls_fixtures','smoke')
    return {n:file_hash(Path(importlib.import_module(n).__file__)) for n in names}


def main():
    p=SafeArgumentParser(description=__doc__)
    for name in ('binary','work-parent','output'): p.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-binary-sha256','build-source-commit'): p.add_argument('--'+name,required=True)
    p.add_argument('--baseline-binary',type=Path)
    p.add_argument('--expected-baseline-sha256'); p.add_argument('--baseline-build-source-commit')
    a=p.parse_args()
    specs=[('candidate',a.binary,a.expected_binary_sha256,a.build_source_commit)]
    baseline=(a.baseline_binary,a.expected_baseline_sha256,a.baseline_build_source_commit)
    if any(v is not None for v in baseline):
        if not all(v is not None for v in baseline): p.error('baseline_identity_incomplete')
        specs.insert(0,('baseline',*baseline))
    binaries={}
    for name,path,digest,commit in specs:
        if not re.fullmatch('[a-f0-9]{64}',digest) or not re.fullmatch('[a-f0-9]{40}',commit): p.error('invalid_identity')
        binary=path.resolve(strict=True)
        if file_hash(binary)!=digest: p.error('binary_mismatch')
        binaries[name]=(binary,digest,commit)
    output=a.output.absolute(); admitted=admit_output(output); parent=private_parent(a.work_parent)
    before={n:source_identity(ROOT,v[0]) for n,v in binaries.items()}
    if any(v['source_dirty'] for v in before.values()): p.error('source_dirty')
    runner=file_hash(Path(__file__)); inputs=helpers()
    work=Path(tempfile.mkdtemp(prefix='jwt-clock-',dir=parent)); work.chmod(0o700)
    reports={}; failure=None
    def interrupted(signum,frame): raise Failure('fixture_interrupted')
    handlers={n:signal.signal(n,interrupted) for n in (signal.SIGTERM,signal.SIGINT)}
    try:
        for name,(binary,_,_) in binaries.items():
            directory=work/name; directory.mkdir(mode=0o700)
            reports[name]=run(binary,directory,name=='baseline')
            if reports[name]['status']=='failed': break
    except Exception as error: failure='fixture_'+type(error).__name__
    finally:
        for n,h in handlers.items(): signal.signal(n,h)
    after={n:source_identity(ROOT,v[0]) for n,v in binaries.items()}
    unchanged=before==after and not any(v['source_dirty'] for v in after.values())
    runner_ok=runner==file_hash(Path(__file__)); helpers_ok=inputs==helpers()
    if not unchanged or not runner_ok or not helpers_ok: failure='inputs_changed'
    status = 'failed' if failure else aggregate_status(reports, binaries)
    if status == 'failed' and failure is None: failure='profile_failed_or_incomplete'
    report={'schema':'heptabao.jwt-completion-clock-live.v1','status':status,'failure':failure,'profiles':reports,
        'source_identity':before,'source_identity_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':{n:v[2] for n,v in binaries.items()},'build_identity_basis':'caller_supplied_commit_and_exact_binary_sha256',
        'runner_sha256':runner,'runner_unchanged':runner_ok,'helper_sha256':inputs,'helpers_unchanged':helpers_ok,
        'mutation_retries':0,'listener_timeout_seconds':5,'client_timeout_seconds':5,
        'clock_modified':False,'physical_clock_trust_claim':False,'official_differential':False,'ha_covered':False,
        'old_gap_reproduced':reports.get('baseline',{}).get('status')=='passed',
        'retained_work_dir':str(work) if status!='passed' else None,'independent_qualification':False}
    if admit_output(output)!=admitted: raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if status=='passed': shutil.rmtree(work)
    print(json.dumps({'status':status,'failure':failure,'profiles':{n:{'status':r['status'],'checks':len(r['checks'])} for n,r in reports.items()}}))
    return {'passed':0,'failed':1,'inconclusive':2}[status]

if __name__=='__main__': raise SystemExit(main())
