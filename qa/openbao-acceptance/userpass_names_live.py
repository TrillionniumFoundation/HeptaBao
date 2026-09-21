#!/usr/bin/env python3
"""Fresh native userpass account-name corpus against pinned OpenBao 2.6.2.

Common operations compare exactly. Uppercase password/policies subroute ghost
writes are separately observed deliberate divergences, never parity assertions.
Legacy exact mounts and their issued tokens require the real upgrade profile.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import sys

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity
from userpass_password_live import private_parent, free_port, safe_files

PREFIX='userpass_names.'
MOUNT='native-names'
REQUIRED=frozenset({'mounted.status','created.status','read_lower.canonical','read_upper.canonical',
    'initial_list.canonical','login_lower.credentials','login_upper.credentials','login_mixed.credentials',
    'same_entity','canonical_alias','general_replace.status','old_password.status','replacement.credentials',
    'general_list.canonical','held_token.valid','renew.canonical','reset_lower.status','reset_lower_login.credentials',
    'policies_lower.status','policies_login.canonical','raw_acl_denied.status','raw_acl_update.status',
    'restart_login.credentials','restart_entity','restart_held.valid','deleted.status','deleted_login.status',
    'deleted_read.status','secrets_absent','complete'})
DEVIATIONS=frozenset({'password_write.status','password_old.status','password_new.status','password_list.shape',
    'password_delete.status','password_after_delete.shape','policies_write.status','policies_login.shape','policies_list.shape'})

class Trace:
    def __init__(self,client,rows):self.client,self.rows,self.sensitive=client,rows,[]
    def check(self,name,condition,**observations):
        if re.fullmatch(r'[a-z0-9_.]{1,140}',name) is None or any(type(v) not in (int,bool) for v in observations.values()):
            raise ValueError('unsafe_observation')
        self.rows.append({'case':PREFIX+name,'passed':condition is True,**observations})
        if condition is not True:raise ScenarioFailure(PREFIX+name)
    def call(self,name,path,fields=None,*,method='POST',status=200,bearer=None):
        result=self.client.request(method,'/v1/'+path,fields,token=bearer)
        self.check(name+'.status',result.status==status,status=result.status)
        if status>=400:self.check(name+'.no_credentials',not result.body.get('auth') and not result.body.get('wrap_info'))
        return result.body
    def write(self,name,user,fields,*,status=204,bearer=None):
        return self.call(name,f'auth/{MOUNT}/users/{user}',fields,status=status,bearer=bearer)
    def login(self,name,user,password,*,status=200):
        body=self.call(name,f'auth/{MOUNT}/login/{user}',{'password':password},status=status)
        if status!=200:return None
        auth=body.get('auth') or {}
        self.check(name+'.credentials',all(isinstance(auth.get(k),str) and len(auth[k])>=16 for k in ('client_token','accessor'))
            and auth.get('metadata')=={'username':user.lower()} and isinstance(auth.get('entity_id'),str) and bool(auth['entity_id']))
        self.sensitive.extend([auth['client_token'],auth['accessor']]);return auth
    def valid(self,name,auth):
        data=self.call(name,'auth/token/lookup-self',method='GET',bearer=auth['client_token']).get('data') or {}
        self.check(name+'.valid',data.get('id')==auth['client_token'] and data.get('meta')=={'username':'mixed'} and data.get('ttl',0)>0)
    def keys(self,name):return (self.call(name,f'auth/{MOUNT}/users',method='LIST').get('data') or {}).get('keys')

def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(r,dict) or r.get('passed') is not True or not isinstance(r.get('case'),str)
        or re.fullmatch(r'userpass_names\.[a-z0-9_.]{1,140}',r['case']) is None
        or set(r)-{'case','passed','status'} or ('status' in r and (type(r['status']) is not int or not 100<=r['status']<=599)) for r in rows):return False
    names=[r['case'] for r in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}<=set(names)

def complete_deviations(rows):
    if not isinstance(rows,list) or not rows:return False
    names=[r.get('case') for r in rows]
    return len(names)==len(set(names)) and {PREFIX+n for n in DEVIATIONS}<=set(names) and all(
        r.get('passed') is True and not (set(r)-{'case','passed','status'})
        and isinstance(r.get('case'),str) and re.fullmatch(r'userpass_names\.[a-z0-9_.]{1,140}',r['case'])
        and ('status' not in r or type(r['status']) is int and 100<=r['status']<=599) for r in rows)

def run_scenarios(client,restart,rows):
    t=Trace(client,rows)
    t.call('mounted','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
    t.call('tuned','sys/auth/'+MOUNT+'/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    password,replacement,reset=[secrets.token_urlsafe(24) for _ in range(3)];t.sensitive.extend([password,replacement,reset])
    t.write('created','MiXeD',{'password':password,'token_ttl':120})
    for label,name in [('lower','mixed'),('upper','MIXED')]:
        data=t.call('read_'+label,f'auth/{MOUNT}/users/{name}',method='GET').get('data') or {}
        t.check('read_'+label+'.canonical',data.get('token_ttl')==120 and data.get('token_policies')==[])
    t.check('initial_list.canonical',t.keys('initial_list')==['mixed'])
    auths=[t.login('login_'+label,name,password) for label,name in [('lower','mixed'),('upper','MIXED'),('mixed','mIxEd')]]
    t.check('same_entity',len({auth['entity_id'] for auth in auths})==1)
    entity=t.call('entity','identity/entity/id/'+auths[0]['entity_id'],method='GET').get('data') or {}
    aliases=entity.get('aliases') or []
    t.check('canonical_alias',len(aliases)==1 and aliases[0].get('name')=='mixed')
    t.write('general_replace','MIXED',{'password':replacement})
    t.login('old_password','mixed',password,status=400)
    t.login('replacement','mIxEd',replacement)
    t.check('general_list.canonical',t.keys('general_list')==['mixed'])
    t.valid('held_token',auths[0])
    renew=t.call('renew','auth/token/renew-self',{},bearer=auths[0]['client_token']).get('auth') or {}
    t.check('renew.canonical',renew.get('metadata')=={'username':'mixed'} and renew.get('client_token')==auths[0]['client_token'])
    t.write('reset_lower','mixed/password',{'password':reset})
    t.login('reset_lower_login','MIXED',reset)
    t.call('policy','sys/policies/acl/name-policy',{'policy':'path "secret/names" { capabilities = ["read"] }'},status=204)
    t.write('policies_lower','mixed/policies',{'policies':['name-policy']})
    policy_auth=t.login('policies_login','MIXED',reset)
    t.check('policies_login.canonical',set(policy_auth.get('policies',[]))=={'default','name-policy'})
    t.call('admin_policy','sys/policies/acl/name-admin',{'policy':f'path "auth/{MOUNT}/users/MiXeD" {{ capabilities = ["update"] }}'},status=204)
    admin=t.call('admin_token','auth/token/create',{'policies':['name-admin'],'ttl':120}).get('auth') or {}
    t.sensitive.append(admin['client_token'])
    t.write('raw_acl_denied','mixed',{'token_ttl':121},status=403,bearer=admin['client_token'])
    t.write('raw_acl_update','MiXeD',{'token_ttl':121},bearer=admin['client_token'])
    restart()
    again=t.login('restart_login','MIXED',reset)
    t.check('restart_entity',again['entity_id']==auths[0]['entity_id'])
    t.valid('restart_held',auths[0])
    t.call('deleted',f'auth/{MOUNT}/users/MIXED',method='DELETE',status=204)
    t.login('deleted_login','mixed',reset,status=400)
    t.call('deleted_read',f'auth/{MOUNT}/users/mixed',method='GET',status=404)
    return t.sensitive

def run_divergences(client,side,rows):
    t=Trace(client,rows);oracle=side=='oracle'
    old,new=secrets.token_urlsafe(24),secrets.token_urlsafe(24);t.sensitive.extend([old,new])
    t.write('password_create','resetcase',{'password':old})
    t.write('password_write','RESETCASE/password',{'password':new})
    t.login('password_old','resetcase',old,status=200 if oracle else 400)
    t.login('password_new','resetcase',new,status=400 if oracle else 200)
    t.check('password_list.shape',t.keys('password_list')==(['RESETCASE','resetcase'] if oracle else ['resetcase']))
    t.call('password_delete',f'auth/{MOUNT}/users/RESETCASE',method='DELETE',status=204)
    result=client.request('LIST',f'/v1/auth/{MOUNT}/users',None)
    t.check('password_after_delete.shape',(result.status==200 and (result.body.get('data') or {}).get('keys')==['RESETCASE']) if oracle else result.status==404)
    t.write('policies_create','policycase',{'password':old})
    t.write('policies_write','POLICYCASE/policies',{'policies':['name-policy']})
    auth=t.login('policies_login','POLICYCASE',old)
    t.check('policies_login.shape',set(auth.get('policies',[]))==({'default'} if oracle else {'default','name-policy'}))
    t.check('policies_list.shape',t.keys('policies_list')==(['POLICYCASE','RESETCASE','policycase'] if oracle else ['policycase']))
    return t.sensitive


def helper_hashes():
    names=("bao_http","core_isolation","official_openbao_launcher","online_evidence","userpass_password_live","heptabao","heptabao.transport")
    return {name:file_hash(Path(sys.modules[name].__file__)) for name in names}

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
    runner_hash=file_hash(Path(__file__));helpers=helper_hashes();bao=verify_inputs();bao_hash=file_hash(bao)
    work=Path(tempfile.mkdtemp(prefix='userpass-names-',dir=parent))
    previous_work=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    oracle=instance=None;cases={};divergences={};failures={}
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
                divergences[side]=[]
                credentials+=run_divergences(client,side,divergences[side])
                safe=safe_files(data_root,credentials)
                cases[side].append({'case':PREFIX+'secrets_absent','passed':safe is True})
                if not safe:raise ScenarioFailure('secret_scan_failed')
                cases[side].append({'case':PREFIX+'complete','passed':True})
            except Exception as error:
                failures[side]=next((r['case'] for r in reversed(cases[side]+divergences.get(side,[])) if r['passed'] is not True),'fixture_'+type(error).__name__)
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
    runner_unchanged=runner_hash==file_hash(Path(__file__));oracle_unchanged=bao_hash==file_hash(bao)
    equal=cases.get('oracle')==cases.get('candidate') if not args.oracle_only else None
    helpers_unchanged=helpers==helper_hashes()
    passed=(not failures and runner_unchanged and oracle_unchanged and helpers_unchanged and set(cases)==({'oracle'} if args.oracle_only else {'oracle','candidate'})
            and all(complete(rows) for rows in cases.values()) and all(complete_deviations(rows) for rows in divergences.values())
            and (args.oracle_only or unchanged and equal and not before['source_dirty'] and not after['source_dirty']))
    report={'schema':'heptabao.userpass-names-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'helper_sha256':helpers,'helpers_unchanged':helpers_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,
        'deliberate_divergences':divergences,'uppercase_subroute_ghost_writes_reproduced':False,
        'legacy_mount_adoption_covered':False,'prior_binary_upgrade_covered':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
