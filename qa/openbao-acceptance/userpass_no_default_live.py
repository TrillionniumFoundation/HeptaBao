#!/usr/bin/env python3
"""Userpass default-policy control and nil/empty policy renewal vs OpenBao2.6.2.

Scoped service-token semantics; no batch, case folding or identity-policy matrix.
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
from bao_http import Client,SafeArgumentParser,private_read,private_write
from core_isolation import ROOT,ScenarioFailure,file_hash
from official_openbao_launcher import verify_inputs,start_oracle,stop_oracle,restart_oracle
from online_evidence import admit_output,source_identity
PREFIX='userpass_no_default.'
REQUIRED=frozenset({'nil.login.shape','nil.renew.token','nil.empty_same.token.shape','nil.null_same.accessor.shape',
 'toggle.false.old.self.shape','toggle.true.old.self.shape','toggle.null.new.shape','explicit.login.shape',
 'changed.self','changed.accessor','changed.expiry_unchanged','restore.self.shape','wrap.inner.shape','wrap.single_use',
 'restart.nil.token.shape','restart.old_no_default.self.shape','restart.old_default.self.shape','restart.child.token.shape',
 'invalid.atomic','invalid.password_preserved.shape','secrets_absent','complete'})

class Trace:
    def __init__(self,client,rows):self.client,self.rows=client,rows;self.sensitive=[];self.password=secrets.token_urlsafe(24);self.sensitive.append(self.password)
    def check(self,name,passed,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):raise ValueError('unsafe_trace')
        self.rows.append({'case':PREFIX+name,**safe,'passed':passed is True})
        if passed is not True:raise ScenarioFailure(PREFIX+name)
    def call(self,name,path,body=None,*,method='POST',status=200,token=None,wrap_ttl=None):
        response=self.client.request(method,'/v1/'+path,body,token=token,wrap_ttl=wrap_ttl)
        self.check(name,response.status==status,status=response.status)
        if status>=400:self.check(name+'.no_credentials',not response.body.get('auth') and not response.body.get('wrap_info'))
        return response.body
    def write(self,name,user,fields,*,status=204):return self.call(name,'auth/nd/users/'+user,fields,status=status)
    def read(self,name,user,flag,policies):
        data=self.call(name,'auth/nd/users/'+user,method='GET').get('data') or {}
        self.check(name+'.shape',data.get('token_no_default_policy') is flag and data.get('token_policies')==policies and 'token_policies_configured' not in data)
    def shape(self,name,auth,policies,*,bearer=True):
        self.check(name+'.shape',isinstance(auth,dict) and auth.get('policies')==policies and auth.get('token_policies')==(policies if policies else None)
            and ('token_policies' in auth)==bool(policies) and auth.get('renewable') is True and bool(auth.get('client_token')) is bearer and bool(auth.get('accessor')))
        if bearer:self.sensitive.append(auth['client_token'])
    def login(self,name,user,policies):
        auth=self.call(name,'auth/nd/login/'+user,{'password':self.password},token='').get('auth') or {}
        self.shape(name,auth,policies);return auth
    def renew(self,name,auth,policies,*,status=200,self_status=None):
        for via,path,body,actor in [('self','renew-self',{},auth['client_token']),('token','renew',{'token':auth['client_token']},None),('accessor','renew-accessor',{'accessor':auth['accessor']},None)]:
            expected=(self_status if self_status is not None else status) if via=='self' else status
            result=self.call(name+'.'+via,'auth/token/'+path,dict(body,increment=120),token=actor,status=expected)
            if expected==200:self.shape(name+'.'+via,result.get('auth') or {},policies,bearer=via!='accessor')
    def lookup(self,name,auth,policies):
        data=self.call(name,'auth/token/lookup',{'token':auth['client_token']}).get('data') or {}
        self.check(name+'.shape',data.get('policies')==policies)
        return data

def run_scenarios(client,restart,rows):
    t=Trace(client,rows);c=t.call
    c('mount','sys/auth/nd',{'type':'userpass'},status=204)
    c('tune','sys/auth/nd/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    rules='path "auth/token/renew-self" {capabilities=["update"]} path "auth/token/lookup-self" {capabilities=["read"]} path "auth/token/create" {capabilities=["update"]}'
    c('policy','sys/policies/acl/nd-user',{'policy':rules},method='PUT',status=204)
    held={}
    for tag,extra,policies in [('nil',{},[]),('empty',{'token_policies':[]},[]),('null',{'token_policies':None},[]),('default',{'token_policies':['default']},['default'])]:
        t.write(tag+'.write',tag,dict(password=t.password,token_no_default_policy=True,**extra));t.read(tag+'.read',tag,True,policies)
        auth=t.login(tag+'.login',tag,policies);held[tag]=auth;t.lookup(tag+'.lookup',auth,policies)
        t.renew(tag+'.renew',auth,policies,status=500 if tag=='nil' else 200,self_status=403 if not policies else 200)
        if tag=='nil':
            for name,value in [('empty',[]),('null',None)]:
                t.write('nil.to_'+name,'nil',{'token_policies':value});t.renew('nil.'+name+'_same',auth,[],self_status=403)
    t.write('named.write','named',{'password':t.password,'token_no_default_policy':True,'token_policies':['nd-user']});absent=t.login('named.login','named',['nd-user'])
    for tag,fields,flag in [('partial',{'token_ttl':120},True),('false',{'token_no_default_policy':False},False),('true',{'token_no_default_policy':True},True),('null',{'token_no_default_policy':None},False)]:
        t.write('toggle.'+tag,'named',fields);t.read('toggle.'+tag+'.read','named',flag,['nd-user']);t.renew('toggle.'+tag+'.old',absent,['nd-user'])
        new=t.login('toggle.'+tag+'.new','named',['nd-user'] if flag else ['default','nd-user'])
        if tag=='false':default=new
    t.write('explicit.write','named',{'token_no_default_policy':True,'token_policies':['default','nd-user']});explicit=t.login('explicit.login','named',['default','nd-user']);t.renew('explicit.renew',explicit,['default','nd-user'])
    t.write('invalid.atomic','named',{'password':'uninstalled-password','token_no_default_policy':{}},status=400)
    t.login('invalid.password_preserved','named',['default','nd-user'])
    before=t.lookup('changed.before',absent,['nd-user'])
    t.write('changed.write','named',{'token_policies':['other']});t.renew('changed',absent,['nd-user'],status=500)
    after=t.lookup('changed.after',absent,['nd-user']);t.check('changed.expiry_unchanged',before.get('expire_time')==after.get('expire_time'))
    c('changed.wrap','auth/token/renew-self',{'increment':120},token=absent['client_token'],status=500,wrap_ttl='60s')
    t.write('restore.write','named',{'token_policies':['nd-user']});t.renew('restore',absent,['nd-user'])
    # Token API explicitly controls its own no-default flag; it does not inherit
    # the mutable account setting or userpass renewal provenance.
    child=c('child.create','auth/token/create',{'policies':['nd-user'],'no_default_policy':True,'ttl':120},token=absent['client_token']).get('auth') or {};t.shape('child',child,['nd-user'])
    wrapped=c('wrap.login','auth/nd/login/named',{'password':t.password},token='',wrap_ttl='60s');t.check('wrap.outer',not wrapped.get('auth') and bool(wrapped.get('wrap_info',{}).get('token')))
    wrapper=wrapped['wrap_info']['token'];t.sensitive.append(wrapper)
    inner=c('wrap.unwrap','sys/wrapping/unwrap',{},token=wrapper).get('auth') or {};t.shape('wrap.inner',inner,['nd-user'])
    c('wrap.single_use','sys/wrapping/unwrap',{},token=wrapper,status=400)
    restart();t.check('restart.same_store',True)
    t.renew('restart.nil',held['nil'],[],self_status=403);t.renew('restart.old_no_default',absent,['nd-user']);t.renew('restart.old_default',default,['default','nd-user']);t.renew('restart.child',child,['nd-user'])
    t.read('restart.config','named',True,['nd-user']);return t.sensitive+['uninstalled-password']

def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    for row in rows:
        if (not isinstance(row,dict) or row.get('passed') is not True or not isinstance(row.get('case'),str)
            or re.fullmatch(r'userpass_no_default\.[a-z0-9_.]{1,140}',row['case']) is None
            or any(k not in ('case','passed','status') for k in row)
            or ('status' in row and (type(row['status']) is not int or not 100<=row['status']<=599))):return False
    names=[row['case'] for row in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}.issubset(names)

def main():
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
    runner_hash=file_hash(Path(__file__));helper_hash=file_hash(Path(shared.__file__));bao=verify_inputs();bao_hash=file_hash(bao)
    work=Path(tempfile.mkdtemp(prefix='userpass-no-default-',dir=parent))
    previous_work=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    oracle=instance=None;cases={};failures={}
    try:
        oracle=start_oracle(free_port())
        oracle_root=Path(oracle['root']);root_token=private_read(oracle['token_file']).decode().strip()
        def restart_reference():stop_oracle(oracle);restart_oracle(oracle)
        targets=[('oracle',Client(oracle['address'],oracle['ca_file'],root_token),restart_reference,oracle_root,
                  [root_token,private_read(oracle_root/'unseal.key').decode().strip()])]
        if not args.oracle_only:
            from remote_jwks_live import Instance
            instance=Instance(binary,work/'candidate')
            config_path=instance.root/'server.json';config=json.loads(config_path.read_text())
            config.update(lifecycle_interval_seconds=0,outbound_endpoints=[])
            private_write(config_path,config,replace=True);instance.start()
            status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
            if status!=200:raise ScenarioFailure('candidate_init')
            instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
            if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_unseal')
            def restart_candidate():
                instance.stop();instance.start()
                if instance.call('POST','sys/unseal',{'key':key})[0]!=200:raise ScenarioFailure('candidate_restart')
            targets.append(('candidate',Client(instance.address,str(instance.root/'ca.crt'),instance.token),restart_candidate,
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
    runner_unchanged=runner_hash==file_hash(Path(__file__)) and helper_hash==file_hash(Path(shared.__file__));oracle_unchanged=bao_hash==file_hash(bao)
    equal=cases.get('oracle')==cases.get('candidate') if not args.oracle_only else None
    passed=(not failures and runner_unchanged and oracle_unchanged and set(cases)==({'oracle'} if args.oracle_only else {'oracle','candidate'})
            and all(complete(rows) for rows in cases.values())
            and (args.oracle_only or unchanged and equal and not before['source_dirty'] and not after['source_dirty']))
    report={'schema':'heptabao.userpass-no-default-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'helper_sha256':helper_hash,'runner_unchanged':runner_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,'username_case_covered':False,
        'nil_presence_covered':True,'legacy_upgrade_covered':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
