#!/usr/bin/env python3
"""Three TLS voters: finite AppRole SecretID consumption on Identity failure.

Candidate-only logical HA qualification, not unknown-write or physical durability.
"""
from __future__ import annotations
import hashlib
import importlib
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import tempfile

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from native_snapshot_cli_live import contains_any, private_parent
from native_snapshot_ha_live import SaveCluster
from native_snapshot_ha_restore_live import restart
from online_evidence import admit_output, complete_checks, source_identity
from userpass_batch_ha import canonical, lookup_matches, rejected, standby_response

MOUNT = 'approle-batch-ha'
ROLE = 'auth/'+MOUNT+'/role/finite'
LOGIN = 'auth/'+MOUNT+'/login'
PATH = MOUNT+'/value'
PHASES = ('issued', 'disabled', 'restored', 'successor', 'restarted')
REQUIRED = frozenset({'three_processes','five_second_listeners','first_login_forwarded',
    'batch_shape','identity_disabled','denied_login_forwarded','denied_login_no_credentials',
    'identity_restored','step_down','successor_changed','full_restart','processes_stopped',
    'plaintext_absent','complete'} | {phase+'_all_voters' for phase in PHASES}
    | {f'{phase}_n{node}_{kind}' for phase in PHASES for node in (1,2,3)
       for kind in ('kv','lookup','secret_state')}
    | {f'{phase}_n{node}_no_reuse' for phase in ('successor','restarted') for node in (1,2,3)})


def complete(rows):
    return complete_checks(rows, required_cases=REQUIRED) and rows[-1]['case'] == 'complete'


def rejected_secret(status, body):
    return status == 400 and isinstance(body,dict) and isinstance(body.get('errors'),list) and bool(body['errors']) and not any(body.get(k) for k in ('auth','data','wrap_info'))


def secret_state(status, body, remaining):
    if remaining == 0:
        # Existing public SecretID lookup reports an exhausted/missing ID as 204.
        return status == 204 and isinstance(body,dict) and not any(body.get(k) for k in ('data','auth','wrap_info'))
    return status == 200 and isinstance(body,dict) and isinstance(body.get('data'),dict) and type(body['data'].get('secret_id_num_uses')) is int and body['data']['secret_id_num_uses'] == remaining


def verify_voters(cluster, token, entity, credential, digest, phase, check):
    if phase not in PHASES or len(cluster.nodes)!=3 or {n.node_id for n in cluster.nodes}!={1,2,3}:
        raise FixtureError('complete_voter_matrix_required')
    alive, remaining = phase != 'disabled', 1 if phase == 'issued' else 0
    for node in cluster.nodes:
        prefix=f'{phase}_n{node.node_id}_'
        status,body=node.call('GET',PATH,token=token)
        check(prefix+'kv',(status==200 and hashlib.sha256(canonical(body.get('data'))).hexdigest()==digest) if alive else rejected(status,body))
        status,body=node.call('GET','auth/token/lookup-self',token=token)
        good=lookup_matches(status,body,token,alive=alive)
        if alive: good=good and body['data'].get('entity_id')==entity
        check(prefix+'lookup',good)
        status,body=node.call('POST',ROLE+'/secret-id/lookup',{'secret_id':credential['secret_id']},token=cluster.root_token)
        check(prefix+'secret_state',secret_state(status,body,remaining))
        if phase in ('successor','restarted'):
            status,body=node.call('POST',LOGIN,credential,token='')
            check(prefix+'no_reuse',rejected_secret(status,body))
    check(phase+'_all_voters',True)


def helpers():
    names=('bao_http','heptabao.transport','core_isolation','ha_destructive','ha_network_partition',
        'native_snapshot_cli_live','native_snapshot_ha_live','native_snapshot_ha_restore_live',
        'userpass_batch_ha','online_evidence')
    return {name:file_hash(Path(importlib.import_module(name).__file__)) for name in names}


def run(binary,work,rows):
    cluster=None; samples=[]
    def check(case,passed):
        if not isinstance(case,str) or not re.fullmatch('[a-z0-9_]{1,120}',case) or type(passed) is not bool or any(r['case']==case for r in rows):
            raise FixtureError('unsafe_observation')
        rows.append({'case':case,'passed':passed})
        if not passed: raise FixtureError(case)
    try:
        cluster=SaveCluster(binary,work/'cluster');cluster.bootstrap()
        check('three_processes',len({n.process.pid for n in cluster.nodes})==3)
        check('five_second_listeners',all(json.loads((n.root/'server.json').read_text())['timeout_seconds']==5 for n in cluster.nodes))
        leader,root=cluster.leader(),cluster.root_token
        samples.extend((root.encode(),cluster.unseal_key.encode()))
        def call(node,case,method,path,body=None,*,token=None,expected=200):
            status,value=node.call(method,path,body,token=root if token is None else token)
            check(case,status==expected);return value
        def follower(case):
            active=cluster.leader();node=next(n for n in cluster.nodes if n.node_id!=active.node_id)
            status,body=node.call('GET','sys/leader')
            check(case+'_standby',standby_response(status,body,f'https://127.0.0.1:{active.http_port}'))
            return node
        call(leader,'kv_mount','POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}},expected=204)
        value={'value':secrets.token_hex(128)};samples.append(value['value'].encode());digest=hashlib.sha256(canonical(value)).hexdigest()
        call(leader,'seed_value','PUT',PATH,value,expected=204)
        call(leader,'policy','POST','sys/policies/acl/'+MOUNT,{'policy':f'path "{MOUNT}/*" {{ capabilities=["read"] }}'},expected=204)
        call(leader,'approle_mount','POST','sys/auth/'+MOUNT,{'type':'approle'},expected=204)
        call(leader,'role','POST',ROLE,{'token_type':'batch','token_ttl':600,'token_max_ttl':600,
            'token_policies':[MOUNT],'secret_id_ttl':600,'secret_id_num_uses':2},expected=204)
        rid=call(leader,'role_id','GET',ROLE+'/role-id')['data']['role_id']
        sid=call(leader,'secret_id','POST',ROLE+'/secret-id',{})['data']
        samples.extend(x.encode() for x in (rid,sid['secret_id'],sid['secret_id_accessor']))
        credential={'role_id':rid,'secret_id':sid['secret_id']}
        body=call(follower('first_login'),'first_login_forwarded','POST',LOGIN,credential,token='')
        auth=body.get('auth') or {};token=auth.get('client_token');entity=auth.get('entity_id')
        check('batch_shape',isinstance(token,str) and token.startswith('hvb.') and auth.get('token_type')=='batch'
            and auth.get('renewable') is False and auth.get('accessor') in ('',None)
            and isinstance(entity,str) and bool(entity))
        samples.append(token.encode())
        verify_voters(cluster,token,entity,credential,digest,'issued',check)
        call(cluster.leader(),'identity_disabled','POST','identity/entity/id/'+entity,{'disabled':True},expected=204)
        denied=call(follower('denied_login'),'denied_login_forwarded','POST',LOGIN,credential,token='',expected=403)
        check('denied_login_no_credentials',rejected(403,denied))
        verify_voters(cluster,token,entity,credential,digest,'disabled',check)
        call(cluster.leader(),'identity_restored','POST','identity/entity/id/'+entity,{'disabled':False},expected=204)
        verify_voters(cluster,token,entity,credential,digest,'restored',check)
        leader=cluster.leader();previous=leader.node_id
        call(leader,'step_down','POST','sys/step-down',{},expected=204)
        check('successor_changed',cluster.leader().node_id!=previous)
        verify_voters(cluster,token,entity,credential,digest,'successor',check)
        restart(cluster);check('full_restart',True)
        verify_voters(cluster,token,entity,credential,digest,'restarted',check)
        cluster.close();check('processes_stopped',all(n.process is None for n in cluster.nodes))
        files=[p for n in cluster.nodes for base in (n.data_dir,n.root/'raft') for p in base.rglob('*') if p.is_file()]
        files += [p for n in cluster.nodes for p in (n.root/'audit.jsonl',n.root/'process.log') if p.exists()]
        check('plaintext_absent',bool(files) and all(not contains_any(p,samples) for p in files))
        check('complete',True)
    finally:
        if cluster is not None:cluster.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ('binary','work-parent','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--expected-binary-sha256',required=True);parser.add_argument('--build-source-commit',required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.build_source_commit) or not re.fullmatch('[0-9a-f]{64}',args.expected_binary_sha256):parser.error('candidate_pins_required')
    binary=args.binary.resolve(strict=True)
    if file_hash(binary)!=args.expected_binary_sha256:parser.error('candidate_binary_mismatch')
    output=args.output.absolute();admitted=admit_output(output)
    before=source_identity(ROOT,binary);runner=file_hash(Path(__file__));helper=helpers()
    work=Path(tempfile.mkdtemp(prefix='approle-batch-ha-',dir=private_parent(args.work_parent)));work.chmod(0o700)
    rows=[];failure=None
    def interrupted(signum,frame):raise FixtureError('fixture_interrupted')
    handlers={kind:signal.signal(kind,interrupted) for kind in (signal.SIGTERM,signal.SIGINT)}
    try:run(binary,work,rows)
    except Exception as error:failure=next((r['case'] for r in reversed(rows) if not r['passed']),'fixture_'+type(error).__name__)
    finally:
        for kind,handler in handlers.items():signal.signal(kind,handler)
    after=source_identity(ROOT,binary);source_ok=before==after and after['binary_sha256']==args.expected_binary_sha256
    runner_ok=file_hash(Path(__file__))==runner;helpers_ok=helpers()==helper
    if not source_ok or not runner_ok or not helpers_ok:failure='source_binary_or_helpers_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(rows):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.approle-batch-ha.v1','status':'failed' if failure else 'passed','failure':failure,'checks':rows,
        'source_identity':before,'source_identity_after':after,'source_and_binary_unchanged':source_ok,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner,'runner_unchanged':runner_ok,
        'helper_sha256':helper,'helpers_unchanged':helpers_ok,'node_count':3,'listener_timeout_seconds':5,
        'mutation_retries':0,'synthetic_only':True,'unknown_write_outcome_covered':False,
        'physical_failure_covered':False,'multi_host_covered':False,'direct_local_follower_reads_claimed':False,
        'full_openbao_compatibility':False,'retained_failure_work_dir':str(work) if failure else None}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(rows),'failure':failure}));return int(failure is not None)

if __name__=='__main__':raise SystemExit(main())
