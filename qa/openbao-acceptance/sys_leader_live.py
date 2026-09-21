#!/usr/bin/env python3
"""Public local leader diagnosis: pinned official lifecycle + real candidate HA.

This samples local Raft observations, never claims quorum/read authority from
sys/leader. Candidate active_time and cluster API address remain unsupported.
"""
from __future__ import annotations
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, file_hash
from ha_destructive import FixtureError, free_port
from ha_network_partition import inactive_health
from native_snapshot_cli_live import contains_any, private_parent
from native_snapshot_ha_live import SaveCluster, capacity
from official_openbao_launcher import certificates, oracle_environment, verify_inputs
from online_evidence import admit_output, complete_checks, source_identity
from remote_jwks_live import Instance

COMMON_PHASES = frozenset({'uninitialized','post','head','initialized','sealed','unsealed',
    'anonymous','invalid_token','namespace_wrap','body_ignored','finite_issued','finite',
    'finite_unchanged','resealed','http_edges'})
HA_PHASES = frozenset({'ha_initial','ha_finite_issued','ha_standby_finite','ha_uses_unchanged',
    'ha_reads_unchanged','ha_restarted_sealed','ha_reunsealed','ha_quorum_lost',
    'ha_partition_diagnostic','ha_partition_read_rejected','ha_recovered','ha_step_down',
    'ha_successor','ha_successor_changed','ha_value_retained','ha_cleanup','plaintext_absent'})
ALLOWED = frozenset({'ha_enabled','is_self','leader_address','raft_committed_index','raft_applied_index'})

# Exact outer-middleware/dedicated-handler observations. Status 200 means the
# normal leader response for the current lifecycle (HA sealed is then 503).
HTTP_EDGE_CASES = (
    ('list','GET','list=true',{},None,200),
    ('scan','GET','scan=true',{},None,200),
    ('both','GET','list=true&scan=true',{},None,400),
    ('invalid_selector','GET','scan=invalid',{},None,400),
    ('unknown','GET','unknown=value',{},None,200),
    ('bare','GET','bare',{},None,200),
    ('invalid_escape','GET','unknown=%GG',{},None,200),
    ('duplicate','GET','list=true&list=false',{},None,200),
    ('bad_wrap','GET','',{'X-Vault-Wrap-TTL':'invalid'},None,200),
    ('bad_format','GET','',{'X-Vault-Wrap-Format':'synthetic'},None,200),
    ('bad_namespace','GET','',{'X-Vault-Namespace':'a//b'},None,200),
    ('unsupported_header','GET','',{'X-Vault-Synthetic':'x'},None,200),
    ('post_invalid_json','POST','',{'Content-Type':'application/json'},'{',405),
    ('post_text','POST','',{'Content-Type':'text/plain'},'synthetic',405),
    ('get_text','GET','',{'Content-Type':'text/plain'},'synthetic',200),
    ('first_false','GET','list=false&list=true&scan=true',{},None,200),
    ('first_true','GET','list=true&list=false&scan=true',{},None,400),
    ('first_empty','GET','list=&list=true&scan=true',{},None,200),
    ('first_invalid','GET','list=invalid&list=false',{},None,400),
    ('second_invalid','GET','list=false&list=invalid',{},None,200),
    ('bad_value_skipped','GET','list=%GG&list=true&scan=true',{},None,400),
    ('bad_value_only','GET','list=%GG&scan=true',{},None,200),
    ('bad_key_skipped','GET','li%GGst=true&scan=true',{},None,200),
    ('bad_unrelated_then_both','GET','unrelated=%GG&list=true&scan=true',{},None,400),
    ('semicolon_pair_skipped','GET','list=true;x=1&scan=true',{},None,200),
    ('semicolon_scan_skipped','GET','list=true&scan=true;x=1',{},None,200),
    ('encoded_semicolon','GET','list=true%3B',{},None,400),
    ('encoded_key','GET','%6cist=true&scan=true',{},None,400),
    ('bare_first','GET','list&list=true&scan=true',{},None,200),
    ('nul_value','GET','list=%00',{},None,400),
    ('invalid_utf8_value','GET','scan=%FF',{},None,400),
    ('invalid_utf8_key','GET','%FF=true&scan=true',{},None,200),
    ('both_false','GET','list=FALSE&scan=0',{},None,200),
    ('post_invalid_selector','POST','list=invalid&scan=true',{},None,405),
    ('head_invalid_selector','HEAD','list=invalid&scan=true',{},None,405),
    ('method_options','OPTIONS','',{},None,405),
    ('method_trace','TRACE','',{},None,405),
    ('method_connect','CONNECT','',{},None,405),
    ('method_propfind','PROPFIND','',{},None,405),
    ('method_lowercase','get','',{},None,405),
    ('method_mixedcase','GeT','',{},None,405),
    ('method_numeric','123','',{},None,405),
    ('method_punctuation',"!#$%&'*+-.^_`|~",'',{},None,405),
)

HTTP_INVALID_METHODS = (
    ('method_slash',b'BAD/METHOD'),
    ('method_colon',b'BAD:METHOD'),
    ('method_parentheses',b'BAD(METHOD)'),
    ('method_tab',b'G\tET'),
    ('method_delete_control',b'BAD\x7f'),
    ('method_non_ascii',b'BAD\xc3\xa9'),
    ('method_empty',b''),
    ('method_space',b'BAD METHOD'),
)


def complete(rows, *, oracle_only=False):
    prefixes = ('official_file','official_raft') if oracle_only else ('official_file','official_raft','candidate_file')
    required = {'complete'} | {prefix+'_'+name for prefix in prefixes for name in COMMON_PHASES}
    required |= {prefix+'_http_'+case[0] for prefix in prefixes for case in HTTP_EDGE_CASES}
    required |= {prefix+'_http_'+case[0] for prefix in prefixes for case in HTTP_INVALID_METHODS}
    if not oracle_only:
        required |= { 'candidate_file_'+name for name in COMMON_PHASES } | HA_PHASES
    return (complete_checks(rows, required_cases=frozenset(required)) and rows[-1]['case']=='complete')


def shape(status, body, *, ha, sealed=False, is_self=None, address=None, official=False):
    if not ha:
        return status==200 and body=={'ha_enabled':False}
    if sealed:
        return status==503 and body=={'errors':['Vault is sealed']}
    if status!=200 or not isinstance(body,dict) or body.get('ha_enabled') is not True:
        return False
    allowed = ALLOWED | ({'active_time','leader_cluster_address'} if official else set())
    if not set(body).issubset(allowed):return False
    if is_self is True and body.get('is_self') is not True:return False
    if is_self is False and 'is_self' in body:return False
    if address is not None and body.get('leader_address')!=address:return False
    for key in ('raft_committed_index','raft_applied_index'):
        if key in body and (type(body[key]) is not int or body[key]<=0):return False
    if body.get('raft_applied_index',0)>body.get('raft_committed_index',0):return False
    return True


class Endpoint:
    def __init__(self,port,ca):
        self.port=port;self.context=ssl.create_default_context(cafile=str(ca))
    @property
    def address(self):return f'https://127.0.0.1:{self.port}'
    def call(self,method,path='sys/leader',body=None,*,token='',headers=None):
        values={} if headers is None else dict(headers)
        if token:values['X-Vault-Token']=token
        if body is not None:values['Content-Type']='application/json'
        return self.raw_call(method,path,None if body is None else json.dumps(body),headers=values)
    def raw_call(self,method,path,body=None,*,headers=None,timeout=15):
        connection=http.client.HTTPSConnection('127.0.0.1',self.port,context=self.context,timeout=timeout)
        try:
            connection.request(method,'/v1/'+path,body,{} if headers is None else headers)
            response=connection.getresponse();raw=response.read(65537)
            if len(raw)>65536:raise FixtureError('oversize_status_response')
            return response.status,json.loads(raw) if raw else {}
        finally:connection.close()
    def raw_method_status(self,method):
        # Bypass http.client's own method validator so malformed cases reach
        # the server. No credentials, arbitrary response text, or body data is
        # retained in the evidence; the net/http 400 body is not logical JSON.
        with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
            with self.context.wrap_socket(raw,server_hostname='127.0.0.1') as connection:
                connection.settimeout(5)
                connection.sendall(method+b' /v1/sys/leader HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                response=http.client.HTTPResponse(connection)
                response.begin()
                if len(response.read(65537))>65536:raise FixtureError('oversize_status_response')
                return response.status


def http_edges(endpoint,prefix,ha,check,observations):
    for name,method,query,headers,raw_body,expected in HTTP_EDGE_CASES:
        path='sys/leader'+('?' + query if query else '')
        status,body=endpoint.raw_call(method,path,raw_body,headers=headers,timeout=5)
        valid=(shape(status,body,ha=ha,sealed=True,official=prefix.startswith('official')) if expected==200
               else status==expected and body==({} if method=='HEAD' else {'errors':[]}))
        check(prefix+'_http_'+name,valid)
        observations.append({'case':prefix+'_http_'+name,'status':status,'fields':sorted(body)})
    for name,method in HTTP_INVALID_METHODS:
        status=endpoint.raw_method_status(method)
        check(prefix+'_http_'+name,status==400)
        observations.append({'case':prefix+'_http_'+name,'status':status})
    check(prefix+'_http_edges',True)


class Official:
    def __init__(self,binary,root,raft):
        root.mkdir(mode=0o700);certificates(root);(root/'data').mkdir(mode=0o700)
        self.root=root;self.binary=binary;self.process=None;self.log=None
        self.endpoint=Endpoint(free_port(),root/'ca.crt');cluster_port=free_port()
        if self.endpoint.port==cluster_port:raise FixtureError('port_collision')
        storage='raft' if raft else 'file'
        private_write(root/'server.json',{'disable_mlock':True,'ui':False,
            'api_addr':self.endpoint.address,'cluster_addr':f'https://127.0.0.1:{cluster_port}',
            'storage':{storage:{'path':str(root/'data'),**({'node_id':'leader-probe'} if raft else {})}},
            'listener':[{'tcp':{'address':f'127.0.0.1:{self.endpoint.port}',
                'tls_cert_file':str(root/'tls.crt'),'tls_key_file':str(root/'tls.key')}}]})
    def start(self):
        self.log=(self.root/'server.log').open('ab');os.chmod(self.root/'server.log',0o600)
        self.process=subprocess.Popen([str(self.binary),'server','-config='+str(self.root/'server.json')],
            stdout=self.log,stderr=self.log,env=oracle_environment(self.root))
        ready(self.endpoint,501)
    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        if self.log is not None and not self.log.closed:self.log.close()


def ready(endpoint,status):
    end=time.monotonic()+15
    while time.monotonic()<end:
        try:
            if endpoint.call('GET','sys/health')[0]==status:return
        except (OSError,http.client.HTTPException):pass
        time.sleep(.05)
    raise FixtureError('readiness_timeout')


def lifecycle(endpoint,prefix,ha,check,observations):
    def observe(name,token='',headers=None,body=None,sealed=False):
        status,value=endpoint.call('GET',token=token,headers=headers,body=body)
        check(prefix+'_'+name,shape(status,value,ha=ha,sealed=sealed,is_self=True if ha and not sealed else None,
            address=endpoint.address if ha and not sealed else None,official=prefix.startswith('official')))
        observations.append({'case':prefix+'_'+name,'status':status,'fields':sorted(value)})
    observe('uninitialized',sealed=True)
    http_edges(endpoint,prefix,ha,check,observations)
    check(prefix+'_post',endpoint.call('POST',body={})==(405,{'errors':[]}))
    check(prefix+'_head',endpoint.call('HEAD')==(405,{}))
    status,initialized=endpoint.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    check(prefix+'_initialized',status==200 and bool(initialized.get('root_token')) and len(initialized.get('keys_base64',[]))==1)
    token,key=initialized['root_token'],initialized['keys_base64'][0]
    observe('sealed',sealed=True)
    check(prefix+'_unsealed',endpoint.call('POST','sys/unseal',{'key':key})[0]==200);ready(endpoint,200)
    observe('anonymous');observe('invalid_token',token='synthetic-invalid')
    observe('namespace_wrap',headers={'X-Vault-Namespace':'nonexistent','X-Vault-Wrap-TTL':'60s'})
    observe('body_ignored',body={'ignored':True})
    status,issued=endpoint.call('POST','auth/token/create',{'policies':['default'],'num_uses':2,'ttl':600},token=token)
    check(prefix+'_finite_issued',status==200 and bool(issued.get('auth',{}).get('client_token')))
    limited=issued['auth']['client_token'];observe('finite',token=limited)
    status,value=endpoint.call('POST','auth/token/lookup',{'token':limited},token=token)
    check(prefix+'_finite_unchanged',status==200 and value.get('data',{}).get('num_uses')==2)
    check(prefix+'_sealed_again',endpoint.call('POST','sys/seal',{},token=token)[0]==204)
    observe('resealed',sealed=True)
    return [token.encode(),key.encode(),limited.encode()]


def candidate_ha(binary,root,check,observations,samples):
    cluster=None
    try:
        cluster=SaveCluster(binary,root);cluster.bootstrap();leader=cluster.leader()
        endpoints={n.node_id:Endpoint(n.http_port,cluster.root/'ca.crt') for n in cluster.nodes}
        def all_views(current,phase):
            for node in cluster.nodes:
                endpoint=endpoints[node.node_id]
                status,body=endpoint.call('GET')
                check(phase+'_'+str(node.node_id),shape(status,body,ha=True,is_self=node is current,
                      address=endpoints[current.node_id].address))
                check(phase+'_indexes_'+str(node.node_id),type(body.get('raft_applied_index')) is int
                      and type(body.get('raft_committed_index')) is int)
                observations.append({'case':phase+'_'+str(node.node_id),'status':status,
                    'fields':sorted(body),'is_self':body.get('is_self',False),
                    'applied_index':body.get('raft_applied_index'),'committed_index':body.get('raft_committed_index')})
            check(phase,True)
        all_views(leader,'ha_initial')
        marker='retained-leader-diagnostic'
        cluster.write(leader,'leader-diagnostic',marker)
        status,issued=leader.call('POST','auth/token/create',{'policies':['default'],'num_uses':2,'ttl':600},token=cluster.root_token)
        check('ha_finite_issued',status==200 and bool(issued.get('auth',{}).get('client_token')))
        limited=issued['auth']['client_token'];before=capacity(leader,cluster.root_token)
        standby=next(n for n in cluster.nodes if n is not leader)
        status,body=endpoints[standby.node_id].call('GET',token=limited)
        check('ha_standby_finite',shape(status,body,ha=True,is_self=False,address=endpoints[leader.node_id].address))
        check('ha_reads_unchanged',capacity(leader,cluster.root_token)==before)
        status,body=leader.call('POST','auth/token/lookup',{'token':limited},token=cluster.root_token)
        check('ha_uses_unchanged',status==200 and body.get('data',{}).get('num_uses')==2)
        standby.stop();standby.start()
        status,body=endpoints[standby.node_id].call('GET')
        check('ha_restarted_sealed',shape(status,body,ha=True,sealed=True))
        check('ha_reunsealed',standby.call('POST','sys/unseal',{'key':cluster.unseal_key})[0]==200)
        leader=cluster.leader()
        for link in cluster.links.values():link.set_blocked(True)
        time.sleep(3)
        check('ha_quorum_lost',all(inactive_health(*n.call('GET','sys/health')) for n in cluster.nodes))
        for node in cluster.nodes:
            start=time.monotonic();status,body=endpoints[node.node_id].call('GET')
            check('ha_partition_diagnostic_'+str(node.node_id),shape(status,body,ha=True))
            observations.append({'case':'ha_partition_diagnostic_'+str(node.node_id),'status':status,
                'elapsed_ms':round((time.monotonic()-start)*1000,3),'fields':sorted(body)})
        check('ha_partition_diagnostic',True)
        check('ha_partition_read_rejected',leader.call('GET','secret/data/leader-diagnostic',token=cluster.root_token)[0]==503)
        cluster._heal();leader=cluster.leader();check('ha_recovered',True)
        check('ha_step_down',leader.call('POST','sys/step-down',{},token=cluster.root_token)[0]==204)
        successor=cluster.leader();check('ha_successor_changed',successor.node_id!=leader.node_id)
        all_views(successor,'ha_successor')
        for node in cluster.nodes:cluster.read(node,'leader-diagnostic',marker)
        check('ha_value_retained',True)
        samples.extend([cluster.root_token.encode(),cluster.unseal_key.encode(),limited.encode()])
    finally:
        if cluster is not None:cluster.close()
    check('ha_cleanup',all(n.process is None for n in cluster.nodes))


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path);parser.add_argument('--build-source-commit')
    parser.add_argument('--oracle-only',action='store_true')
    parser.add_argument('--work-parent',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if not args.oracle_only and (args.binary is None or not re.fullmatch('[0-9a-f]{40}',args.build_source_commit or '')):
        parser.error('candidate binary and full build source commit required')
    parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
    bao=verify_inputs();oracle_hash=file_hash(bao);runner_hash=file_hash(Path(__file__))
    binary=None if args.oracle_only else args.binary.resolve(strict=True)
    before=None if binary is None else source_identity(ROOT,binary)
    work=Path(tempfile.mkdtemp(prefix='sys-leader-',dir=parent));checks=[];observations=[];samples=[];failure=None
    def check(name,condition):
        checks.append({'case':name,'passed':condition is True})
        if condition is not True:raise FixtureError(name)
    def stop(signum,frame):raise FixtureError('interrupted')
    handlers={kind:signal.signal(kind,stop) for kind in (signal.SIGINT,signal.SIGTERM)}
    try:
        for storage in ('file','raft'):
            instance=Official(bao,work/('official-'+storage),storage=='raft')
            try:
                instance.start();samples.extend(lifecycle(instance.endpoint,'official_'+storage,storage=='raft',check,observations))
            finally:instance.stop()
        if binary is not None:
            instance=Instance(binary,work/'candidate-file')
            try:
                instance.start();samples.extend(lifecycle(Endpoint(instance.port,instance.root/'ca.crt'),'candidate_file',False,check,observations))
            finally:instance.stop()
            candidate_ha(binary,work/'candidate-ha',check,observations,samples)
            files=[p for p in work.rglob('*') if p.is_file() and not p.is_symlink()
                   and (p.name in ('server.log','process.log','audit.jsonl') or 'data' in p.relative_to(work).parts or 'raft' in p.relative_to(work).parts)]
            check('plaintext_absent',bool(files) and all(not contains_any(p,samples) for p in files))
        check('complete',True)
    except Exception as error:
        failure=next((r['case'] for r in reversed(checks) if not r['passed']),'fixture_'+type(error).__name__)
    finally:
        for kind,handler in handlers.items():signal.signal(kind,handler)
    after=None if binary is None else source_identity(ROOT,binary)
    unchanged=before==after;runner_unchanged=runner_hash==file_hash(Path(__file__));oracle_unchanged=oracle_hash==file_hash(bao)
    if not unchanged or not runner_unchanged or not oracle_unchanged:failure='source_binary_runner_or_oracle_changed'
    if before is not None and (before['source_dirty'] or after['source_dirty']):failure='source_dirty'
    if not complete(checks,oracle_only=args.oracle_only):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.sys-leader-observations.v1','status':'failed' if failure else 'passed','failure':failure,
        'checks':checks,'observations':observations,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':unchanged,'build_source_commit':args.build_source_commit,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,'official_version':'2.6.2',
        'official_binary_sha256':oracle_hash,'official_binary_unchanged':oracle_unchanged,
        'retained_failure_work_dir':str(work) if failure else None,'oracle_only':args.oracle_only,
        'unsupported_fields':['active_time','leader_cluster_address'],'candidate_ha_live':binary is not None and failure is None,
        'diagnostic_grants_read_authority':False,'ha_uninitialized_process_covered':False,
        'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if not failure:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)
if __name__=='__main__':raise SystemExit(main())
