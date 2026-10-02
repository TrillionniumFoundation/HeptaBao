#!/usr/bin/env python3
"""Three TLS voters: raw native 307, then explicitly resolved leader CLI I/O.

OpenBao 2.6.2 streaming CLI redirects are known broken; no automatic redirect or
mutation retry is attempted here. A separate second restore observes epoch 2.
"""
from __future__ import annotations
import hashlib
import http.client
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError
from native_snapshot_cli_live import cli, contains_any, private_parent
from native_snapshot_ha_live import SaveCluster, client_view, capacity_data, strict_archive
from native_snapshot_ha_restore_live import applied_index, canonical, publication, restart, restore_http
from official_openbao_launcher import pinned_artifact, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from sys_leader_live import Endpoint

MOUNT = 'native-redirect'
RAW_CASES = (
    ('get','GET','snapshot?after=a%2Fb+z&limit=00',None),
    ('head','HEAD','snapshot?after=head',None),
    ('post_headers_only','POST','snapshot?after=post',25_000_000),
    ('put_headers_only','PUT','snapshot-force?after=x%26y',25_000_000),
)
REQUIRED = frozenset({'three_processes','listener_deadlines','distinct_api_raft_addresses',
    'mounted','payload_ready','all_initial','finite_issued','initial_resolved',
    'redirects_complete','redirect_local_artifacts_unchanged','redirect_generation_unchanged',
    'redirect_uses_unchanged','redirect_spools_unchanged','step_down','successor_changed',
    'successor_resolved','successor_get_redirect','successor_upload_redirect','successor_redirect_unchanged',
    'save_resolved','cli_save','archive_complete','save_unchanged','first_changed','first_later_written',
    'restore_resolved','cli_restore','cli_new_generation','cli_raft_frontier_advanced','all_cli_restored',
    'second_changed','second_later_written','raw_restore_resolved','raw_second_restore',
    'raw_epoch_two','raw_new_publication','all_second_restored','restarted','all_reopened',
    'processes_stopped','plaintext_absent','complete'} | {'redirect_'+case[0] for case in RAW_CASES})


def complete(rows):
    return complete_checks(rows,required_cases=REQUIRED) and rows[-1]['case']=='complete'


def resolve_leader(cluster, observer):
    # No token, namespace or trust material is obtained from the response. Only
    # an exact API origin in this fixture's original deployment config is usable.
    endpoint=Endpoint(observer.http_port,cluster.root/'ca.crt')
    status,body=endpoint.call('GET')
    if status!=200 or body.get('ha_enabled') is not True or body.get('auth') or body.get('wrap_info'):
        raise FixtureError('anonymous_leader_unavailable')
    address=body.get('leader_address')
    nodes=[node for node in cluster.nodes if address==client_view(cluster,node).address]
    if len(nodes)!=1:raise FixtureError('leader_origin_not_configured')
    leader=nodes[0]
    if (observer is leader and body.get('is_self') is not True) or (observer is not leader and 'is_self' in body):
        raise FixtureError('leader_response_was_forwarded')
    return leader


def raw_redirect(node, token, method, route, length=None):
    """Send only bounded headers, never the declared upload body; no retries."""
    fields=(f'{method} /v1/sys/storage/raft/{route} HTTP/1.1\r\n'
        'Host: attacker.invalid:9\r\nX-Forwarded-Host: attacker.invalid:9\r\n'
        'X-Forwarded-Proto: http\r\n'
        f'X-Vault-Token: {token}\r\nConnection: close\r\n')
    if length is not None:fields+=f'Content-Type: application/gzip\r\nContent-Length: {length}\r\n'
    started=time.monotonic()
    with socket.create_connection(('127.0.0.1',node.http_port),timeout=7) as raw:
        with node.context.wrap_socket(raw,server_hostname='localhost') as tls:
            tls.sendall((fields+'\r\n').encode())
            response=http.client.HTTPResponse(tls);response.begin()
            # Bypass HTTPResponse's HEAD/Content-Length shortcut: trailing bytes
            # on the actual wire must not be hidden by an asserted zero length.
            body=response.fp.read(4097)
            if len(body)>4096:raise FixtureError('redirect_body_unbounded')
            result=(response.status,response.getheaders(),body,(time.monotonic()-started)*1000)
            response.close();return result


def good_redirect(result, origin, route):
    status,pairs,body,elapsed=result
    headers={}
    for key,value in pairs:
        key=key.lower()
        if key in headers:return False
        headers[key]=value
    return (status==307 and body==b'' and headers.get('location')==origin+'/v1/sys/storage/raft/'+route
        and headers.get('content-length')=='0' and headers.get('connection','').lower()=='close'
        and headers.get('cache-control')=='no-store' and headers.get('x-content-type-options')=='nosniff'
        and not headers.get('content-type','').startswith('application/gzip')
        and type(elapsed) in (int,float) and 0<=elapsed<5000)


def artifacts(cluster):
    return [durable_manifest(node.data_dir) for node in cluster.nodes]


def spools(cluster):
    values=[]
    for node in cluster.nodes:
        path=node.data_dir/'.snapshot-transfer'
        if path.is_symlink():raise FixtureError('spool_symlink')
        values.append((path.exists(),durable_manifest(path) if path.exists() else None))
    return values


def cli_once(bao,cluster,node,work,command,path,observations,case):
    diagnostics={};started=time.monotonic()
    observations[case]={'attempted':True,'direct_node':node.node_id}
    try:
        result=cli(bao,client_view(cluster,node),work,command,path,diagnostics=diagnostics)
        observations[case]['exit_code']=result
    finally:
        observations[case].update({'diagnostics':diagnostics,'elapsed_ms':round((time.monotonic()-started)*1000,3)})
    return result==0


def run(binary,bao,work,checks,observations):
    def check(case,passed):
        if type(passed) is not bool:raise FixtureError('nonboolean_observation')
        checks.append({'case':case,'passed':passed})
        if not passed:raise FixtureError(case)
    cluster=None;samples=[]
    try:
        cluster=SaveCluster(binary,work/'cluster');cluster.bootstrap()
        check('three_processes',len({n.process.pid for n in cluster.nodes})==3)
        check('listener_deadlines',all(json.loads((n.root/'server.json').read_text())['timeout_seconds']==5 for n in cluster.nodes))
        check('distinct_api_raft_addresses',all(n.http_port!=n.raft_port and
            cluster.peers[str(n.node_id)]['api_address']==client_view(cluster,n).address for n in cluster.nodes))
        leader=cluster.leader();token=cluster.root_token
        check('mounted',leader.call('POST','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}},token=token)[0]==204)
        original={f'k{i:02}':{'value':secrets.token_hex(2048),'ordinal':i} for i in range(8)}
        hashes={key:hashlib.sha256(canonical(value)).hexdigest() for key,value in original.items()}
        samples += [value['value'][:80].encode() for value in original.values()]
        for key,value in original.items():check('seed_'+key,leader.call('PUT',MOUNT+'/'+key,value,token=token)[0]==204)
        check('payload_ready',True)
        def verify(phase):
            for node in cluster.nodes:
                for key,digest in hashes.items():
                    status,body=node.call('GET',MOUNT+'/'+key,token=token)
                    check(phase+'_node_'+str(node.node_id)+'_'+key,
                        status==200 and hashlib.sha256(canonical(body.get('data'))).hexdigest()==digest)
                check(phase+'_later_absent_'+str(node.node_id),node.call('GET',MOUNT+'/later',token=token)[0]==404)
            check(phase,True)
        verify('all_initial')
        status,body=leader.call('POST','auth/token/create',{'policies':['default'],'num_uses':2,'ttl':600},token=token)
        check('finite_issued',status==200 and bool(body.get('auth',{}).get('client_token')))
        limited=body['auth']['client_token'];samples += [token.encode(),cluster.unseal_key.encode(),limited.encode()]
        # Warm all local stores before asserting that redirect cannot sync or
        # publish an application update. Audit files are outside data_dir.
        for node in cluster.nodes:node.call('GET',MOUNT+'/k00',token=token)
        standby=next(node for node in cluster.nodes if node is not leader)
        resolved=resolve_leader(cluster,standby);check('initial_resolved',resolved is leader)
        before=artifacts(cluster);generation=capacity_data(leader,token)['generation'];spool_before=spools(cluster)
        observations['redirects']=[]
        for name,method,route,length in RAW_CASES:
            result=raw_redirect(standby,limited,method,route,length)
            check('redirect_'+name,good_redirect(result,client_view(cluster,leader).address,route))
            observations['redirects'].append({'case':name,'status':result[0],
                'body_bytes':len(result[2]),'elapsed_ms':round(result[3],3),'declared_upload_bytes':length,
                'upload_body_sent':False,'location_matches_configured_leader':True})
        check('redirects_complete',True)
        check('redirect_local_artifacts_unchanged',artifacts(cluster)==before)
        check('redirect_generation_unchanged',capacity_data(leader,token)['generation']==generation)
        check('redirect_spools_unchanged',spools(cluster)==spool_before)
        status,body=leader.call('POST','auth/token/lookup',{'token':limited},token=token)
        check('redirect_uses_unchanged',status==200 and body.get('data',{}).get('num_uses')==2)
        former=leader
        check('step_down',leader.call('POST','sys/step-down',{},token=token)[0]==204)
        leader=cluster.leader();check('successor_changed',leader is not former)
        check('successor_resolved',resolve_leader(cluster,former) is leader)
        before=artifacts(cluster)
        for case,method,route,length in [('successor_get_redirect','GET','snapshot?after=successor',None),
                ('successor_upload_redirect','POST','snapshot-force',25_000_000)]:
            result=raw_redirect(former,limited,method,route,length)
            check(case,good_redirect(result,client_view(cluster,leader).address,route))
        check('successor_redirect_unchanged',artifacts(cluster)==before)
        # Explicit resolution is separate from the CLI. Never give it a standby
        # address or rely on its broken automatic 307 stream replay.
        leader=resolve_leader(cluster,former);check('save_resolved',True)
        archive=work/'leader.snap';before=capacity_data(leader,token)['generation']
        check('cli_save',cli_once(bao,cluster,leader,work,'save',archive,observations,'cli_save'))
        metadata=strict_archive(archive);observations['archive']=metadata;check('archive_complete',True)
        check('save_unchanged',capacity_data(leader,token)['generation']==before)
        check('first_changed',leader.call('PUT',MOUNT+'/k00',{'value':'first-changed'},token=token)[0]==204)
        check('first_later_written',leader.call('PUT',MOUNT+'/later',{'value':'first-later'},token=token)[0]==204)
        leader=resolve_leader(cluster,former);check('restore_resolved',True)
        before=capacity_data(leader,token)['generation'];frontier=applied_index(leader,token)
        check('cli_restore',cli_once(bao,cluster,leader,work,'restore',archive,observations,'cli_restore'))
        after=capacity_data(leader,token)['generation']
        check('cli_new_generation',after>before)
        check('cli_raft_frontier_advanced',applied_index(leader,token)>frontier)
        observations['cli_effects']={'previous_generation':before,'published_generation':after,
            'epoch_response_observed':False,'one_restore_command':True}
        verify('all_cli_restored')
        # This is a new, deliberate mutation phase, not retry/reconciliation of
        # the successful CLI restore. Its response exposes the epoch counter.
        check('second_changed',leader.call('PUT',MOUNT+'/k01',{'value':'second-changed'},token=token)[0]==204)
        check('second_later_written',leader.call('PUT',MOUNT+'/later',{'value':'second-later'},token=token)[0]==204)
        leader=resolve_leader(cluster,former);check('raw_restore_resolved',True)
        before=capacity_data(leader,token)['generation']
        second=publication(restore_http(leader,token,archive),before,metadata['generation'],previous_epoch=1)
        check('raw_second_restore',second is not None)
        check('raw_epoch_two',second['replay_epoch']==2)
        check('raw_new_publication',capacity_data(leader,token)['generation']==second['published_local_generation'])
        observations['independent_second_restore']=second
        verify('all_second_restored')
        restart(cluster);check('restarted',True);verify('all_reopened')
        observations['value_hashes']=hashes
    finally:
        if cluster is not None:cluster.close()
    check('processes_stopped',all(node.process is None for node in cluster.nodes))
    files=[p for p in work.rglob('*') if p.is_file() and not p.is_symlink()
        and (p.name in ('server.log','process.log','audit.jsonl') or 'data' in p.relative_to(work).parts or 'raft' in p.relative_to(work).parts)]
    check('plaintext_absent',bool(files) and all(not contains_any(path,samples) for path in files))
    check('complete',True)


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--work-parent',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',args.build_source_commit):parser.error('full source commit required')
    binary=args.binary.resolve(strict=True);parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
    bao=verify_inputs();cli_hash=file_hash(bao);before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='native-redirect-',dir=parent));checks=[];observations={};failure=None
    def interrupted(signum,frame):raise FixtureError('fixture_interrupted')
    handlers={kind:signal.signal(kind,interrupted) for kind in (signal.SIGTERM,signal.SIGINT)}
    try:run(binary,bao,work,checks,observations)
    except Exception as error:failure=next((row['case'] for row in reversed(checks) if row['passed'] is not True),'fixture_'+type(error).__name__)
    finally:
        for kind,handler in handlers.items():signal.signal(kind,handler)
    after=source_identity(ROOT,binary);runner_ok=runner_hash==file_hash(Path(__file__));cli_ok=cli_hash==file_hash(bao)
    if before!=after or not(runner_ok and cli_ok):failure='source_binary_or_fixture_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.native-snapshot-redirect.v1','status':'failed' if failure else 'passed','failure':failure,
        'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':before==after,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_ok,'official_cli_sha256':cli_hash,'official_cli_unchanged':cli_ok,
        'official_cli_version':'2.6.2','official_cli_artifact_sha256':pinned_artifact()['artifact_sha256'],
        'retained_failure_work_dir':str(work) if failure else None,'listener_timeout_seconds':5,'node_count':3,
        'raw_redirect_verified':failure is None,'direct_resolved_leader_cli_verified':failure is None,
        'cli_save_attempts':1 if 'cli_save' in observations else 0,'cli_restore_attempts':1 if 'cli_restore' in observations else 0,
        'numeric_epoch_observed_in_separate_second_restore':failure is None,'automatic_cli_redirect_tested':False,
        'missing_api_address_covered':False,'mutation_retry':False,'physical_hosts':False,
        'cross_seal_force':False,'openbao_state_interoperability':False,'full_openbao_compatibility':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if not failure:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)


if __name__=='__main__':raise SystemExit(main())
