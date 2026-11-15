#!/usr/bin/env python3
"""One real three-process TLS cluster: userpass CIDR and no-default policies."""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from online_evidence import admit_output, complete_checks, source_identity
from userpass_password_live import private_parent

MOUNT='ha-userpass-params'
POLICY='ha-userpass-params'
REQUIRED=frozenset({'standby_confirmed','forwarded_login_issued','spoofed_login_rejected',
 'spoofed_read_rejected','finite_denied_rejected','finite_not_consumed','finite_second_value',
 'finite_exhausted_rejected','clear_old_snapshot','clear_new_issued','named_root_accessor_shape',
 'nil_root_token_rejected','nil_no_extension','empty_root_accessor_shape','toggle_old_snapshot',
 'stepdown_accepted','successor_changed','former_leader_is_standby','stepdown_bound_denied_rejected',
 'stepdown_named_accessor_shape','stepdown_nil_token_rejected','stepdown_empty_accessor_shape',
 'full_restart','restart_bound_denied_rejected','restart_named_accessor_shape',
 'restart_nil_token_rejected','restart_empty_accessor_shape','all_voters_snapshot_agree',
 'secrets_absent','complete'})

class Trace:
    def __init__(self,client,rows,sensitive):self.client,self.rows,self.sensitive=client,rows,sensitive
    def check(self,name,condition):
        if not re.fullmatch(r'[a-z0-9_]{1,120}',name):raise ValueError('unsafe_case')
        self.rows.append({'case':name,'passed':condition is True})
        if condition is not True:raise ScenarioFailure(name)
    def call(self,name,method,path,body=None,*,status=200,token=None,source='127.0.0.1',spoof=False):
        response=self.client.request(method,path,body,token=token,source=source,spoof=spoof)
        self.check(name+'_status',response.status==status)
        self.check(name+'_ipv4',self.client.last_family==4)
        if status>=400:self.check(name+'_rejected',not response.body.get('auth') and not response.body.get('wrap_info'))
        return response.body
    def user(self,name,user,fields):return self.call(name,'POST',f'auth/{MOUNT}/users/{user}',fields,status=204)
    def login(self,name,user,password,policies,*,source='127.0.0.2',status=200,spoof=False):
        response=self.call(name,'POST',f'auth/{MOUNT}/login/{user}',{'password':password},token='',source=source,status=status,spoof=spoof)
        if status!=200:return None
        auth=response.get('auth') or {}
        self.check(name+'_issued',bool(auth.get('client_token')) and bool(auth.get('accessor')) and auth.get('policies')==policies and auth.get('metadata')=={'username':user})
        self.sensitive.append(auth['client_token']);return auth
    def lookup(self,name,auth):
        data=self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']},source='127.0.0.1').get('data') or {}
        self.check(name+'_valid',data.get('id')==auth['client_token'] and type(data.get('ttl')) is int and data['ttl']>0)
        return data
    def read(self,name,auth,*,source='127.0.0.2',status=200,spoof=False):
        result=self.call(name,'GET','ha-params-kv/item',token=auth['client_token'],source=source,status=status,spoof=spoof)
        if status==200:self.check(name+'_value',result.get('data')=={'value':'synthetic'})
    def renew(self,name,auth,policies,*,status=200,self_status=200):
        for via,path,body,actor,source in (
            ('self','renew-self',{},auth['client_token'],'127.0.0.2'),
            ('token','renew',{'token':auth['client_token']},None,'127.0.0.1'),
            ('accessor','renew-accessor',{'accessor':auth['accessor']},None,'127.0.0.1')):
            expected=self_status if via=='self' else status
            result=self.call(name+'_'+via,'POST','auth/token/'+path,dict(body,increment=300),token=actor,source=source,status=expected)
            if expected==200:
                a=result.get('auth') or {}
                self.check(name+'_'+via+'_shape',a.get('policies')==policies and a.get('renewable') is True and bool(a.get('client_token'))==(via!='accessor'))

def projection(data):
    # Countdown TTL is not an immutable fact. Absolute expiry must match after
    # acknowledged renewals through each voter (these are API views, not dumps).
    return {key:data.get(key) for key in ('id','accessor','policies','bound_cidrs','creation_time','expire_time','meta','num_uses')}

def secret_free(paths,samples):
    samples=[value.encode() if isinstance(value,str) else value for value in samples]
    samples=[value for value in samples if len(value)>=16]
    overlap=max(map(len,samples),default=1)
    for path in paths:
        if not path.is_file() or path.is_symlink():continue
        with path.open('rb') as stream:
            tail=b''
            while chunk:=stream.read(65536):
                raw=tail+chunk
                if any(value in raw for value in samples):return False
                tail=raw[-overlap:]
    return True

def complete(rows):
    return complete_checks(rows,required_cases=REQUIRED) and rows[-1]['case']=='complete'

def run(binary,root,rows,inherited,diagnostics):
    from ha_network_partition import PartitionCluster
    from radius_cidrs_live import SourceClient
    cluster=None;sensitive=[]
    try:
        cluster=PartitionCluster(binary,root/'cluster');cluster.bootstrap();inherited.extend(cluster.scenarios)
        leader=cluster.leader();follower=next(n for n in cluster.nodes if n is not leader)
        sensitive.extend([cluster.root_token,cluster.unseal_key,cluster.replication_key])
        password=secrets.token_urlsafe(32);sensitive.append(password)
        def trace(node):return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}',cluster.root/'ca.crt',cluster.root_token,spoof_source='127.0.0.2'),rows,sensitive)
        t=trace(follower)
        status,health=follower.call('GET','sys/health')
        t.check('standby_confirmed',status==429 and health.get('standby') is True)
        t.call('mount','POST','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
        t.call('kv_mount','POST','sys/mounts/ha-params-kv',{'type':'kv','options':{'version':'1'}},status=204)
        rules='path "ha-params-kv/*" {capabilities=["read"]} path "auth/token/lookup-self" {capabilities=["read"]} path "auth/token/renew-self" {capabilities=["update"]}'
        t.call('policy','PUT','sys/policies/acl/'+POLICY,{'policy':rules},status=204)
        t.call('seed','POST','ha-params-kv/item',{'value':'synthetic'},status=204)
        fields={'password':password,'token_ttl':300,'token_max_ttl':1800,'token_policies':[POLICY],'token_no_default_policy':True,'token_bound_cidrs':['127.0.0.2']}
        t.user('user','named',fields)
        bound=t.login('forwarded_login','named',password,[POLICY])
        t.login('spoofed_login','named',password,[],source='127.0.0.1',status=403,spoof=True)
        t.read('spoofed_read',bound,source='127.0.0.1',status=403,spoof=True)
        t.read('forwarded_read',bound);t.renew('named_root',bound,[POLICY])
        t.user('finite_config','named',{'token_num_uses':2})
        finite=t.login('finite_login','named',password,[POLICY])
        t.read('finite_denied',finite,source='127.0.0.1',status=403,spoof=True)
        t.check('finite_not_consumed',t.lookup('finite_uses',finite).get('num_uses')==2)
        t.read('finite_first',finite);t.read('finite_second',finite);t.read('finite_exhausted',finite,status=403)
        t.user('clear_user','named',{'token_num_uses':0,'token_bound_cidrs':[],'token_no_default_policy':False})
        t.check('clear_old_snapshot',t.lookup('clear_old',bound).get('bound_cidrs')==['127.0.0.2'])
        clear=t.login('clear_new','named',password,['default',POLICY],source='127.0.0.1')
        t.read('clear_new_read',clear,source='127.0.0.1')
        for user in ('nil','empty'):
            f={'password':password,'token_ttl':300,'token_max_ttl':1800,'token_no_default_policy':True}
            if user=='empty':f['token_policies']=[]
            t.user(user+'_user',user,f)
        nil=t.login('nil_login','nil',password,[]);empty=t.login('empty_login','empty',password,[])
        before=t.lookup('nil_before',nil);t.renew('nil_root',nil,[],status=500,self_status=403)
        t.check('nil_no_extension',before.get('expire_time')==t.lookup('nil_after',nil).get('expire_time'))
        t.renew('empty_root',empty,[],self_status=403)
        t.user('toggle_empty','empty',{'token_no_default_policy':False})
        t.login('toggle_new','empty',password,['default'],source='127.0.0.1')
        t.check('toggle_old_snapshot',t.lookup('toggle_old',empty).get('policies')==[])
        # The mutation is attempted once. Only leadership readiness is polled.
        primary=trace(leader);response=primary.call('stepdown','POST','sys/step-down',{},status=204)
        primary.check('stepdown_accepted',not response)
        successor=cluster.leader();primary.check('successor_changed',successor is not leader)
        status,health=leader.call('GET','sys/health');primary.check('former_leader_is_standby',status==429 and health.get('standby') is True)
        def verify(node,phase):
            now=trace(node)
            now.read(phase+'_bound_denied',bound,source='127.0.0.1',status=403,spoof=True)
            now.read(phase+'_bound_allowed',bound)
            now.read(phase+'_unbound_allowed',clear,source='127.0.0.1')
            now.renew(phase+'_named',bound,[POLICY])
            now.renew(phase+'_nil',nil,[],status=500,self_status=403)
            now.renew(phase+'_empty',empty,[],self_status=403)
        verify(leader,'stepdown')
        for node in cluster.nodes:node.stop()
        for node in cluster.nodes:node.start(wait=False)
        for node in cluster.nodes:node.wait_ready()
        cluster.wait_quorum()
        for node in cluster.nodes:
            if node.call('POST','sys/unseal',{'key':cluster.unseal_key})[0]!=200:raise ScenarioFailure('restart_unseal_failed')
        leader=cluster.leader();follower=next(n for n in cluster.nodes if n is not leader)
        trace(follower).check('full_restart',len(cluster.running())==3)
        verify(follower,'restart')
        views=[]
        for node in cluster.nodes:
            v=trace(node);values=[]
            for name,auth,bounds,policies in [('bound',bound,['127.0.0.2'],[POLICY]),('clear',clear,[],['default',POLICY]),('nil',nil,[],[]),('empty',empty,[],[])]:
                data=v.lookup('voter_'+str(node.node_id)+'_'+name,auth)
                v.check('voter_'+str(node.node_id)+'_'+name+'_snapshot',data.get('bound_cidrs',[])==bounds and data.get('policies')==policies)
                values.append(projection(data))
            views.append(values)
        t.check('all_voters_snapshot_agree',all(view==views[0] for view in views))
        for node in cluster.nodes:node.stop()
        paths=[]
        for node in cluster.nodes:
            paths.extend(p for folder in (node.data_dir,node.root/'raft') for p in folder.rglob('*'))
            paths.extend([node.root/'process.log',node.root/'audit.jsonl'])
        encoded=json.dumps(rows).encode()
        t.check('secrets_absent',secret_free(paths,sensitive) and not any((s.encode() if isinstance(s,str) else s) in encoded for s in sensitive))
        t.check('complete',True)
    except Exception:
        if cluster is not None:
            for node in cluster.running():
                try:
                    status,body=node.call('GET','sys/health',timeout=2)
                    diagnostics.append({'node_id':node.node_id,'status':status,**{k:body[k] for k in ('sealed','standby','ha_active','ha_application_ready') if type(body.get(k)) is bool}})
                except Exception:diagnostics.append({'node_id':node.node_id,'unavailable':True})
        raise
    finally:
        if cluster is not None:cluster.close()


def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ('binary','output','work-parent'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--build-source-commit',required=True);args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('full build commit required')
    binary=args.binary.resolve(strict=True);output=args.output.absolute();admitted=admit_output(output)
    before=source_identity(ROOT,binary);runner=file_hash(Path(__file__))
    root=Path(tempfile.mkdtemp(prefix='userpass-params-ha-',dir=private_parent(args.work_parent)));root.chmod(0o700)
    rows,inherited,diagnostics=[],[],[];failure=None
    try:run(binary,root,rows,inherited,diagnostics)
    except Exception as error:failure=next((r['case'] for r in reversed(rows) if r['passed'] is not True),'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary);unchanged=before==after;runner_unchanged=runner==file_hash(Path(__file__))
    if not unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(rows) or not inherited:failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.userpass-params-ha.v1','status':'passed' if failure is None else 'failed','failure':failure,
      'checks':rows,'bootstrap_checks':inherited,'diagnostics':diagnostics,'source_identity':before,'source_identity_after':after,
      'source_and_binary_unchanged':unchanged,'runner_sha256':runner,'runner_unchanged':runner_unchanged,'build_source_commit':args.build_source_commit,
      'cluster_count':1,'voters':3,'socket_peer_families':[4],'source_client_timeout_seconds':5,'mutation_retries':0,
      'snapshot_agreement_basis':'HTTPS lookup through each voter after transitions; not raw local dumps',
      'same_host':True,'synthetic_only':True,'physical_fault_qualification':False,'full_openbao_compatibility':False,
      'independent_qualification':False,'production_authority':False,'retained_failure_work_dir':str(root) if failure else None}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(root)
    print(json.dumps({'status':report['status'],'checks':len(rows),'failure':failure}))
    return int(failure is not None)

if __name__=='__main__':raise SystemExit(main())
