#!/usr/bin/env python3
"""Userpass numeric CIDR issuance and token snapshots using real HTTPS peers.

Selected service-token profile; excludes Unix SockAddr, case folding, batch,
strict IP binding and HA forwarding (a separate profile).
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import userpass_password_live as shared
from userpass_password_live import private_parent,free_port,safe_files
from bao_http import SafeArgumentParser,private_read,private_write
from core_isolation import ROOT,ScenarioFailure,file_hash
from official_openbao_launcher import verify_inputs,start_oracle,stop_oracle,restart_oracle
from online_evidence import admit_output,source_identity
from radius_renewal_live import renewal_token_shape,wrapped_renewal_shape
PREFIX='userpass_cidrs.'
REQUIRED=frozenset({'denied.login','denied.wrong_password','denied.empty_password','denied.read','denied.renew',
 'actor_scope.accessor.shape','child.other_source','orphan.other_source','wrapped_login.token_denied_other_source',
 'wrapped_login.single_use','changed.old_renew.self.shape','finite.exhausted','finite.first','finite.second',
 'parse.mapped_prefix.canonical','v6.renew.self.shape','alias.null_read.shape','alias.new_read.shape',
 'invalid.password_preserved.issued','invalid.new_password_denied.no_auth','clear.empty_read.shape',
 'clear.old_snapshot.snapshot','restart.old_renew.self.shape','restart.v6_renew.self.shape',
 'receipt.no_sensitive_values','secrets_absent','complete'})
class Trace:
    def __init__(self,client,rows):self.client,self.rows=client,rows;self.tokens=[];self.password=secrets.token_urlsafe(24)
    def check(self,name,passed,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):raise ValueError('unsafe_trace')
        self.rows.append({'case':PREFIX+name,**safe,'passed':passed is True})
        if passed is not True:raise ScenarioFailure(PREFIX+name)
    def call(self,name,method,path,body=None,*,status=200,token=None,source='127.0.0.1',wrap_ttl=None,spoof=False):
        response=self.client.request(method,path,body,token=token,source=source,wrap_ttl=wrap_ttl,spoof=spoof)
        self.check(name,response.status==status,status=response.status,source_family=self.client.last_family)
        if status>=400:self.check(name+'.no_credentials',not response.body.get('auth') and not response.body.get('wrap_info'))
        return response.body
    def config(self,name,body,*,status=204):return self.call(name,'POST','auth/source/users/source',body,status=status)
    def read_bounds(self,name,bounds,legacy):
        data=self.call(name,'GET','auth/source/users/source').get('data') or {}
        self.check(name+'.shape',data.get('token_bound_cidrs')==bounds and (data.get('bound_cidrs')==legacy if legacy else 'bound_cidrs' not in data))
    def login(self,name,*,source='127.0.0.1',status=200,password=None):
        body=self.call(name,'POST','auth/source/login/source',{'password':self.password if password is None else password},token='',source=source,status=status)
        auth=body.get('auth') or {}
        if status==200:
            self.check(name+'.issued',bool(auth.get('client_token')) and bool(auth.get('accessor')) and auth.get('renewable') is True and auth.get('metadata')=={'username':'source'})
            self.tokens.append(auth['client_token'])
        else:self.check(name+'.no_auth',not auth and not body.get('wrap_info'))
        return auth
    def bounds(self,name,auth,expected,*,source='127.0.0.1'):
        data=self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']},source=source).get('data') or {}
        self.check(name+'.snapshot',data.get('bound_cidrs',[])==expected)
    def renew_all(self,name,auth,*,self_source='127.0.0.1',admin_source='127.0.0.2'):
        for via,path,body,actor,source in [('self','renew-self',{},auth['client_token'],self_source),('token','renew',{'token':auth['client_token']},None,admin_source),('accessor','renew-accessor',{'accessor':auth['accessor']},None,admin_source)]:
            result=self.call(name+'.'+via,'POST','auth/token/'+path,dict(body,increment=120),token=actor,source=source)
            self.check(name+'.'+via+'.shape',renewal_token_shape(result.get('auth'),auth['client_token'],via_accessor=via=='accessor'))
def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    for row in rows:
        if (not isinstance(row,dict) or row.get('passed') is not True or not isinstance(row.get('case'),str)
            or re.fullmatch(r'userpass_cidrs\.[a-z0-9_.]{1,140}',row['case']) is None
            or any(k not in ('case','passed','status','source_family') for k in row)
            or ('status' in row and (type(row['status']) is not int or not 100<=row['status']<=599))
            or ('source_family' in row and row['source_family'] not in (4,6))):return False
    names=[row['case'] for row in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}.issubset(names)

def run_scenarios(client,restart,rows):
    t=Trace(client,rows);c=t.call
    c('mount','POST','sys/auth/source',{'type':'userpass'},status=204)
    c('kv_mount','POST','sys/mounts/cidr-kv',{'type':'kv','options':{'version':'1'}},status=204)
    rules='path "cidr-kv/*" { capabilities = ["create", "read", "update"] } path "auth/token/create" { capabilities = ["update", "sudo"] } path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }'
    c('policy','PUT','sys/policies/acl/cidr-user',{'policy':rules},status=204)
    c('seed','POST','cidr-kv/item',{'value':'synthetic'},status=204)
    t.config('config',dict(password=t.password,token_ttl=120,token_max_ttl=600,token_policies=['cidr-user'],token_bound_cidrs=['127.0.0.1/32']))
    original=t.login('allowed.login');t.bounds('allowed.lookup',original,['127.0.0.1'],source='127.0.0.2')
    t.login('denied.login',source='127.0.0.2',status=403)
    t.login('denied.wrong_password',source='127.0.0.2',password=t.password+'x',status=400)
    t.login('denied.empty_password',source='127.0.0.2',password='',status=500)
    for name,method,path,body in [('lookup','GET','auth/token/lookup-self',None),('read','GET','cidr-kv/item',None),('write','POST','cidr-kv/item',{'value':'denied'}),('renew','POST','auth/token/renew-self',{'increment':300})]:
        result=c('denied.'+name,method,path,body,token=original['client_token'],source='127.0.0.2',status=403,spoof=True)
        t.check('denied.'+name+'.no_auth',not result.get('auth') and not result.get('wrap_info'))
    c('allowed.read','GET','cidr-kv/item',token=original['client_token'])
    c('allowed.write','POST','cidr-kv/item',{'value':'allowed'},token=original['client_token'],status=204)
    t.renew_all('actor_scope',original)
    for name,path,inherits in [('child','create',True),('orphan','create-orphan',False)]:
        auth=c(name+'.create','POST','auth/token/'+path,{'policies':['default'],'ttl':120},token=original['client_token']).get('auth',{});t.tokens.append(auth['client_token'])
        t.bounds(name+'.lookup',auth,['127.0.0.1'] if inherits else [])
        c(name+'.other_source','GET','auth/token/lookup-self',token=auth['client_token'],source='127.0.0.2',status=403 if inherits else 200)
        c(name+'.own_source','GET','auth/token/lookup-self',token=auth['client_token'])
    wrapped_login=c('wrapped_login.accepted','POST','auth/source/login/source',{'password':t.password},token='',wrap_ttl='60s')
    t.check('wrapped_login.outer',not wrapped_login.get('auth') and bool(wrapped_login.get('wrap_info',{}).get('token')))
    login_wrapper=wrapped_login['wrap_info']['token'];t.tokens.append(login_wrapper)
    login_inner=c('wrapped_login.unwrap_other_source','POST','sys/wrapping/unwrap',{},token=login_wrapper,source='127.0.0.2').get('auth',{})
    t.check('wrapped_login.inner',bool(login_inner.get('client_token')) and login_inner.get('accessor')==wrapped_login['wrap_info'].get('wrapped_accessor'))
    t.tokens.append(login_inner['client_token'])
    c('wrapped_login.token_denied_other_source','GET','auth/token/lookup-self',token=login_inner['client_token'],source='127.0.0.2',status=403)
    c('wrapped_login.token_allowed','GET','auth/token/lookup-self',token=login_inner['client_token'])
    c('wrapped_login.single_use','POST','sys/wrapping/unwrap',{},token=login_wrapper,source='127.0.0.2',status=400)
    t.config('changed.config',{'token_bound_cidrs':['192.0.2.0/24']})
    t.login('changed.new_login',status=403)
    t.renew_all('changed.old_renew',original);t.bounds('changed.old_lookup',original,['127.0.0.1'])
    wrapped=c('wrapped.accepted','POST','auth/token/renew-self',{'increment':120},token=original['client_token'],wrap_ttl='60s')
    t.check('wrapped.outer',wrapped_renewal_shape(wrapped,original['client_token']));wrapper=wrapped['wrap_info']['token'];t.tokens.append(wrapper)
    inner=c('wrapped.unwrap','POST','sys/wrapping/unwrap',token=wrapper)
    t.check('wrapped.inner',renewal_token_shape(inner.get('auth'),original['client_token'],via_accessor=False))
    denied=c('wrapped.denied','POST','auth/token/renew-self',{'increment':300},token=original['client_token'],source='127.0.0.2',status=403,wrap_ttl='60s')
    t.check('wrapped.no_publication',not denied.get('auth') and not denied.get('wrap_info'))
    t.config('finite.config',{'token_bound_cidrs':['127.0.0.1'],'token_num_uses':2})
    finite=t.login('finite.login')
    c('finite.denied_no_use','GET','cidr-kv/item',token=finite['client_token'],source='127.0.0.2',status=403)
    c('finite.first','GET','cidr-kv/item',token=finite['client_token'])
    c('finite.second','GET','cidr-kv/item',token=finite['client_token'])
    c('finite.exhausted','GET','cidr-kv/item',token=finite['client_token'],status=403)
    t.config('finite.restore',{'token_num_uses':0})
    for name,value,normalized,status in [('host_bits','127.0.0.2/24','127.0.0.2/24',200),('mapped','::ffff:127.0.0.1/128','127.0.0.1',200),('mapped_prefix','::ffff:127.0.0.2/120','127.0.0.2/24',200),('port','127.0.0.1:999','127.0.0.1:999',200),('v6_excludes_v4','::/0','::/0',403)]:
        t.config('parse.'+name,{'token_bound_cidrs':[value]})
        data=c('parse.'+name+'.read','GET','auth/source/users/source').get('data',{})
        t.check('parse.'+name+'.canonical',data.get('token_bound_cidrs')==[normalized])
        t.login('parse.'+name+'.login',status=status)
    t.config('v6.config',{'token_bound_cidrs':['::1/128']})
    v6=t.login('v6.login',source='::1');t.bounds('v6.lookup',v6,['::1'])
    c('v6.reject_v4','GET','auth/token/lookup-self',token=v6['client_token'],status=403)
    t.renew_all('v6.renew',v6,self_source='::1')
    t.config('alias.legacy',{'bound_cidrs':['127.0.0.1/32']})
    t.config('alias.partial',{'token_ttl':121})
    t.read_bounds('alias.legacy_read',['127.0.0.1'],['127.0.0.1'])
    t.config('alias.both',{'bound_cidrs':['192.0.2.1'],'token_bound_cidrs':'127.0.0.2/24'})
    t.read_bounds('alias.both_read',['127.0.0.2/24'],['127.0.0.2/24'])
    t.config('alias.null_wins',{'bound_cidrs':['192.0.2.1'],'token_bound_cidrs':None})
    t.read_bounds('alias.null_read',[],None)
    t.config('alias.reseed',{'bound_cidrs':['127.0.0.1']})
    t.config('alias.new_only',{'token_bound_cidrs':['::1']})
    t.read_bounds('alias.new_read',['::1'],None)
    t.config('invalid.atomic',{'password':'new-uninstalled-password','token_bound_cidrs':{'ip':'127.0.0.1'}},status=400)
    t.read_bounds('invalid.unchanged',['::1'],None)
    t.login('invalid.password_preserved',source='::1')
    t.login('invalid.new_password_denied',source='::1',password='new-uninstalled-password',status=400)
    t.config('clear.empty',{'token_bound_cidrs':''})
    t.read_bounds('clear.empty_read',[],None)
    t.config('clear.reseed',{'token_bound_cidrs':['127.0.0.1']})
    t.config('clear.null',{'token_bound_cidrs':None})
    unbound=t.login('clear.login',source='127.0.0.2');t.bounds('clear.lookup',unbound,[])
    c('clear.cross_family','GET','auth/token/lookup-self',token=unbound['client_token'],source='::1')
    t.bounds('clear.old_snapshot',original,['127.0.0.1'])
    restart();t.check('restart.same_store',True)
    t.bounds('restart.old_snapshot',original,['127.0.0.1']);t.bounds('restart.v6_snapshot',v6,['::1'])
    c('restart.reject','GET','auth/token/lookup-self',token=original['client_token'],source='127.0.0.2',status=403)
    t.renew_all('restart.old_renew',original);t.renew_all('restart.v6_renew',v6,self_source='::1')
    t.check('receipt.no_sensitive_values',not any(secret in json.dumps(t.rows) for secret in [t.password,'new-uninstalled-password',*t.tokens]))
    return [t.password,'new-uninstalled-password',*t.tokens]

def main():
    import radius_cidrs_live as source_helper
    from radius_cidrs_live import SourceClient
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path)
    parser.add_argument('--build-source-commit')
    parser.add_argument('--oracle-only',action='store_true')
    parser.add_argument('--work-parent',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if not args.oracle_only and (args.binary is None or not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit or '')):
        parser.error('candidate binary and full build commit required')
    parent=private_parent(args.work_parent);output=args.output.absolute();admitted=admit_output(output)
    binary=args.binary.resolve(strict=True) if args.binary else None
    before=source_identity(ROOT,binary) if not args.oracle_only else None
    runner_hash=file_hash(Path(__file__));helper_hash=file_hash(Path(shared.__file__));source_helper_hash=file_hash(Path(source_helper.__file__));bao=verify_inputs();bao_hash=file_hash(bao)
    work=Path(tempfile.mkdtemp(prefix='userpass-cidrs-',dir=parent))
    previous_work=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    oracle=instance=None;cases={};failures={}
    try:
        oracle_port=free_port();oracle=start_oracle(oracle_port)
        stop_oracle(oracle)
        oracle_config=Path(oracle['root'])/'server.json';settings=json.loads(oracle_config.read_text())
        settings['listener'][0]['tcp']['address']=f'[::]:{oracle_port}'
        private_write(oracle_config,settings,replace=True);restart_oracle(oracle)
        oracle_root=Path(oracle['root']);root_token=private_read(oracle['token_file']).decode().strip()
        def restart_reference():stop_oracle(oracle);restart_oracle(oracle)
        targets=[('oracle',SourceClient(oracle['address'],oracle['ca_file'],root_token),restart_reference,oracle_root,
                  [root_token,private_read(oracle_root/'unseal.key').decode().strip()])]
        if not args.oracle_only:
            from remote_jwks_live import Instance
            instance=Instance(binary,work/'candidate')
            config_path=instance.root/'server.json';config=json.loads(config_path.read_text())
            config.update(lifecycle_interval_seconds=0,outbound_endpoints=[],listen=f'[::]:{instance.port}')
            private_write(config_path,config,replace=True);instance.start()
            status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            if status!=200:raise ScenarioFailure('candidate_init')
            instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
            if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_unseal')
            def restart_candidate():
                instance.stop();instance.start()
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_restart')
            targets.append(('candidate',SourceClient(instance.address,str(instance.root/'ca.crt'),instance.token),restart_candidate,
                            instance.root,[instance.token,key]))
        for side,client,restart,data_root,credentials in targets:
            cases[side]=[]
            try:
                credentials+=run_scenarios(client,restart,cases[side])
                safe=safe_files(data_root,credentials)
                cases[side].append({'case':PREFIX+'secrets_absent','passed':safe is True})
                if not safe:raise ScenarioFailure('secret_scan_failed')
                cases[side].append({'case':PREFIX+'complete','passed':True})
            except Exception as error:
                failures[side]=next((r['case'] for r in reversed(cases[side]) if r['passed'] is not True),'fixture_'+type(error).__name__)
    except Exception as error:failures['setup']='fixture_'+type(error).__name__
    finally:
        try:
            if instance is not None:instance.stop()
        finally:
            if oracle is not None:stop_oracle(oracle)
            if previous_work is None:os.environ.pop('HB_ORACLE_WORK_ROOT',None)
            else:os.environ['HB_ORACLE_WORK_ROOT']=previous_work
    after=source_identity(ROOT,binary) if before else None
    unchanged=before==after if before else None
    runner_unchanged=runner_hash==file_hash(Path(__file__)) and helper_hash==file_hash(Path(shared.__file__)) and source_helper_hash==file_hash(Path(source_helper.__file__));oracle_unchanged=bao_hash==file_hash(bao)
    equal=cases.get('oracle')==cases.get('candidate') if not args.oracle_only else None
    passed=(not failures and runner_unchanged and oracle_unchanged and set(cases)==({'oracle'} if args.oracle_only else {'oracle','candidate'})
            and all(complete(rows) for rows in cases.values())
            and (args.oracle_only or unchanged and equal and not before['source_dirty'] and not after['source_dirty']))
    report={'schema':'heptabao.userpass-cidrs-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'helper_sha256':helper_hash,'runner_unchanged':runner_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,'username_case_covered':False,
        'source_helper_sha256':source_helper_hash,'actual_socket_origin':True,'ha_forwarding_covered':False,'unix_sockaddr_covered':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
