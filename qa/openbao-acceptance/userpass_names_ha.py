#!/usr/bin/env python3
"""One three-process TLS cluster: fresh userpass canonical account names.

Uses actual standby forwarding, raw ACL paths, a leader transition and complete
cluster restart. No candidate is launched by offline guards.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from bao_http import SafeArgumentParser,private_write
from core_isolation import ROOT,ScenarioFailure,file_hash
from online_evidence import admit_output,complete_checks,source_identity
from userpass_password_live import private_parent
from userpass_params_ha import secret_free,projection

MOUNT='ha-userpass-names'
REQUIRED=frozenset({'standby_confirmed','forwarded_upper_issued','forwarded_lower_issued','same_entity',
 'initial_canonical_alias','initial_single_account','raw_acl_denied_rejected','raw_acl_allowed_status',
 'acl_result_is_canonical','stepdown_accepted','successor_changed','former_leader_is_standby',
 'stepdown_login_issued','stepdown_same_entity','stepdown_renew_accessor_shape','full_restart',
 'restart_login_issued','restart_same_entity','restart_renew_accessor_shape','all_voters_canonical',
 'all_voters_token_snapshot_agree','secrets_absent','complete'})
class Trace:
    def __init__(self,client,rows,sensitive):self.client,self.rows,self.sensitive=client,rows,sensitive
    def check(self,name,condition):
        if re.fullmatch('[a-z0-9_]{1,120}',name) is None:raise ValueError('unsafe_case')
        self.rows.append({'case':name,'passed':condition is True})
        if condition is not True:raise ScenarioFailure(name)
    def call(self,name,method,path,body=None,*,status=200,token=None):
        result=self.client.request(method,path,body,token=token,source='127.0.0.1')
        self.check(name+'_status',result.status==status)
        self.check(name+'_ipv4',self.client.last_family==4)
        if status>=400:self.check(name+'_rejected',not result.body.get('auth') and not result.body.get('wrap_info'))
        return result.body
    def login(self,name,user,password):
        auth=self.call(name,'POST',f'auth/{MOUNT}/login/{user}',{'password':password},token='').get('auth') or {}
        self.check(name+'_issued',all(isinstance(auth.get(k),str) and bool(auth[k]) for k in ('client_token','accessor','entity_id'))
            and auth.get('metadata')=={'username':'mixed'})
        self.sensitive.append(auth['client_token']);return auth
    def lookup(self,name,auth):
        data=self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']}).get('data') or {}
        self.check(name+'_valid',data.get('id')==auth['client_token'] and data.get('meta')=={'username':'mixed'}
            and data.get('entity_id')==auth['entity_id'] and type(data.get('ttl')) is int and data['ttl']>0)
        return data
    def one_account(self,name):
        data=self.call(name+'_list','LIST',f'auth/{MOUNT}/users').get('data') or {}
        self.check(name+'_single_account',data.get('keys')==['mixed'])
    def alias(self,name,entity):
        data=self.call(name+'_entity','GET','identity/entity/id/'+entity).get('data') or {}
        aliases=data.get('aliases') or []
        self.check(name+'_canonical_alias',len(aliases)==1 and aliases[0].get('name')=='mixed')
    def renew(self,name,auth):
        for via,path,body,actor in [('self','renew-self',{},auth['client_token']),
            ('token','renew',{'token':auth['client_token']},None),('accessor','renew-accessor',{'accessor':auth['accessor']},None)]:
            renewed=self.call(name+'_'+via,'POST','auth/token/'+path,dict(body,increment=120),token=actor).get('auth') or {}
            self.check(name+'_'+via+'_shape',renewed.get('metadata')=={'username':'mixed'} and renewed.get('renewable') is True
                and bool(renewed.get('client_token'))==(via!='accessor'))

def complete(rows):return complete_checks(rows,required_cases=REQUIRED) and rows[-1]['case']=='complete'

def run(binary,root,rows,inherited,diagnostics):
    from ha_network_partition import PartitionCluster
    from radius_cidrs_live import SourceClient
    cluster=None;sensitive=[]
    try:
        cluster=PartitionCluster(binary,root/'cluster');cluster.bootstrap();inherited.extend(cluster.scenarios)
        leader=cluster.leader();follower=next(node for node in cluster.nodes if node is not leader)
        sensitive.extend([cluster.root_token,cluster.unseal_key,cluster.replication_key])
        password=secrets.token_urlsafe(32);sensitive.append(password)
        def trace(node):return Trace(SourceClient(f'https://127.0.0.1:{node.http_port}',cluster.root/'ca.crt',cluster.root_token),rows,sensitive)
        t=trace(follower);status,health=follower.call('GET','sys/health')
        t.check('standby_confirmed',status==429 and health.get('standby') is True)
        t.call('mount','POST','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
        t.call('create','POST',f'auth/{MOUNT}/users/MiXeD',{'password':password,'token_ttl':300,'token_max_ttl':1800},status=204)
        held=t.login('forwarded_upper','MIXED',password);other=t.login('forwarded_lower','mixed',password)
        t.check('same_entity',held['entity_id']==other['entity_id'])
        t.alias('initial',held['entity_id']);t.one_account('initial')
        t.call('admin_policy','PUT','sys/policies/acl/names-admin',{'policy':f'path "auth/{MOUNT}/users/MiXeD" {{ capabilities=["update"] }}'},status=204)
        admin=t.call('admin_token','POST','auth/token/create',{'policies':['names-admin'],'ttl':300}).get('auth') or {}
        sensitive.append(admin['client_token'])
        t.call('raw_acl_denied','POST',f'auth/{MOUNT}/users/mixed',{'token_ttl':121},status=403,token=admin['client_token'])
        t.call('raw_acl_allowed','POST',f'auth/{MOUNT}/users/MiXeD',{'token_ttl':121},status=204,token=admin['client_token'])
        data=t.call('read_updated','GET',f'auth/{MOUNT}/users/MIXED').get('data') or {}
        t.check('acl_result_is_canonical',data.get('token_ttl')==121)
        t.renew('initial_renew',held)
        primary=trace(leader)
        result=primary.call('stepdown','POST','sys/step-down',{},status=204)
        primary.check('stepdown_accepted',not result.get('auth') and not result.get('wrap_info'))
        successor=cluster.leader();primary.check('successor_changed',successor is not leader)
        status,health=leader.call('GET','sys/health');primary.check('former_leader_is_standby',status==429 and health.get('standby') is True)
        def verify(node,phase):
            check=trace(node);auth=check.login(phase+'_login','mIxEd',password)
            check.check(phase+'_same_entity',auth['entity_id']==held['entity_id'])
            check.one_account(phase);check.alias(phase,held['entity_id']);check.renew(phase+'_renew',held)
        verify(leader,'stepdown')
        for node in cluster.nodes:node.stop()
        for node in cluster.nodes:node.start(wait=False)
        for node in cluster.nodes:node.wait_ready()
        cluster.wait_quorum()
        for node in cluster.nodes:
            if node.call('POST','sys/unseal',{'key':cluster.unseal_key})[0]!=200:raise ScenarioFailure('restart_unseal_failed')
        leader=cluster.leader();follower=next(node for node in cluster.nodes if node is not leader)
        t.check('full_restart',len(cluster.running())==3);verify(follower,'restart')
        views=[]
        for node in cluster.nodes:
            check=trace(node);name='voter_'+str(node.node_id)
            check.one_account(name);check.alias(name,held['entity_id']);check.renew(name+'_renew',held)
        # All acknowledgments above precede these read-only projections. Avoid
        # comparing countdown TTL or expiries captured before a later renewal.
        for node in cluster.nodes:views.append(projection(trace(node).lookup('final_voter_'+str(node.node_id),held)))
        t.check('all_voters_canonical',len(views)==3)
        t.check('all_voters_token_snapshot_agree',all(view==views[0] for view in views))
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
                    diagnostics.append({'node_id':node.node_id,'status':status,**{key:body[key] for key in ('sealed','standby','ha_active','ha_application_ready') if type(body.get(key)) is bool}})
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
    root=Path(tempfile.mkdtemp(prefix='userpass-names-ha-',dir=private_parent(args.work_parent)));root.chmod(0o700)
    rows,inherited,diagnostics=[],[],[];failure=None
    try:run(binary,root,rows,inherited,diagnostics)
    except Exception as error:failure=next((r['case'] for r in reversed(rows) if r['passed'] is not True),'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary);unchanged=before==after;runner_unchanged=runner==file_hash(Path(__file__))
    if not unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(rows) or not inherited:failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.userpass-names-ha.v1','status':'passed' if failure is None else 'failed','failure':failure,
      'checks':rows,'bootstrap_checks':inherited,'diagnostics':diagnostics,'source_identity':before,'source_identity_after':after,
      'source_and_binary_unchanged':unchanged,'runner_sha256':runner,'runner_unchanged':runner_unchanged,'build_source_commit':args.build_source_commit,
      'cluster_count':1,'voters':3,'socket_peer_families':[4],'source_client_timeout_seconds':5,'mutation_retries':0,
      'snapshot_agreement_basis':'HTTPS lookup through each voter after transitions; not raw local dumps',
      'same_host':True,'synthetic_only':True,'physical_fault_qualification':False,'mfa_runtime_covered':False,'full_openbao_compatibility':False,
      'independent_qualification':False,'production_authority':False,'retained_failure_work_dir':str(root) if failure else None}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(root)
    print(json.dumps({'status':report['status'],'checks':len(rows),'failure':failure}))
    return int(failure is not None)

if __name__=='__main__':raise SystemExit(main())
