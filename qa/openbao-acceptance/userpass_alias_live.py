#!/usr/bin/env python3
"""Native userpass valid legacy/token field precedence and route username capture.

Requires the preceding userpass-password QA helper. No casing migration or
exact deprecated GET-field presence claim. Uses one fixture-owned mount.
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
from userpass_password_live import private_parent, free_port, safe_files
from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity

PREFIX='userpass_alias.'
MOUNT=shared.MOUNT
USERNAME_CASES=[('other','bob'),('null',None),('empty',''),('number',123),('boolean',False),('object',{'target':'bob'})]
REQUIRED=frozenset({'mounted.status','alias.both.values','alias.null.values','alias.keep.values','alias.zero.values',
    'path.created.status','path.absent.status','reset.target.credentials','reset.other.credentials',
    'policies.both.values','policies.null.values','error.invalid.status','error.password.credentials',
    'error.values','restart.target.credentials','restart.other.credentials','restart.values','secrets_absent','complete'}) \
    | frozenset(f'path.{label}.{phase}' for label,_ in USERNAME_CASES for phase in ('update.status','login.credentials','other_password.status','other_password.no_credentials'))

class Trace(shared.Trace):
    def check(self,name,condition,**observations):
        if (not isinstance(name,str) or re.fullmatch(r'[a-z0-9_.]{1,140}',name) is None
                or any(type(v) not in (int,bool) for v in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case':PREFIX+name,'passed':condition is True,**observations})
        if condition is not True:raise ScenarioFailure(PREFIX+name)


def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(r,dict) or not {'case','passed'} <= set(r) or r['passed'] is not True
           or not isinstance(r['case'],str) or re.fullmatch(r'userpass_alias\.[a-z0-9_.]{1,140}',r['case']) is None
           or any(k not in ('case','passed','status') for k in r)
           or ('status' in r and (type(r['status']) is not int or not 100<=r['status']<=599)) for r in rows):return False
    names=[r['case'] for r in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}.issubset(names)


def run_scenarios(client,restart,rows):
    t=Trace(client,rows)
    t.call('mounted','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
    t.call('tuned','sys/auth/'+MOUNT+'/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    for name in ('old-policy','new-policy'):
        t.call('policy.'+name.replace('-','_'),'sys/policies/acl/'+name,
               {'policy':'path "auth/token/lookup-self" { capabilities = ["read"] }'},status=204)
    password=secrets.token_urlsafe(24);other=secrets.token_urlsafe(24);replacement=secrets.token_urlsafe(24)
    t.sensitive.extend([password,other,replacement])
    def values(case,ttl,maximum,policies):
        d=t.call(case+'.read',f'auth/{MOUNT}/users/alice',method='GET').get('data') or {}
        t.check(case+'.values',d.get('token_ttl')==ttl and d.get('token_max_ttl')==maximum and d.get('token_policies')==policies)
    t.write('alias.both','alice',{'password':password,'ttl':40,'token_ttl':70,'max_ttl':100,'token_max_ttl':300,
                                 'policies':['old-policy'],'token_policies':['new-policy']})
    values('alias.both',70,300,['new-policy'])
    t.write('alias.null','alice',{'ttl':80,'token_ttl':None,'max_ttl':400,'token_max_ttl':None,
                                'policies':['old-policy'],'token_policies':None})
    values('alias.null',80,400,[])
    t.write('alias.keep','alice',{'token_ttl':None,'token_max_ttl':None})
    values('alias.keep',80,400,[])
    t.write('alias.zero','alice',{'ttl':90,'token_ttl':0,'max_ttl':500,'token_max_ttl':0})
    values('alias.zero',0,0,[])
    t.write('path.created','path-only',{'username':'body-only','password':password})
    t.call('path.absent',f'auth/{MOUNT}/users/body-only',method='GET',status=404)
    t.write('path.other_created','bob',{'password':other})
    for label,username in USERNAME_CASES:
        t.write('path.'+label+'.update','alice',{'username':username,'token_ttl':90})
        t.login('path.'+label+'.login','alice',{'username':username,'password':password})
        t.login('path.'+label+'.other_password','alice',{'username':username,'password':other},status=400)
    t.write('reset.path','alice/password',{'username':'bob','password':replacement})
    t.login('reset.target','alice',{'password':replacement})
    t.login('reset.other','bob',{'password':other})
    t.write('policies.both','alice/policies',{'username':{'target':'bob'},'policies':['old-policy'],'token_policies':['new-policy']})
    values('policies.both',90,0,['new-policy'])
    t.write('policies.null','alice/policies',{'username':None,'policies':['old-policy'],'token_policies':None})
    values('policies.null',90,0,[])
    t.write('error.invalid','alice',{'password':password,'ttl':40,'token_ttl':'bad-duration'},status=400)
    t.login('error.password','alice',{'password':replacement})
    values('error',90,0,[])
    restart()
    t.login('restart.target','alice',{'username':'bob','password':replacement})
    t.login('restart.other','bob',{'password':other})
    values('restart',90,0,[])
    return t.sensitive


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
    work=Path(tempfile.mkdtemp(prefix='userpass-alias-',dir=parent))
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
    report={'schema':'heptabao.userpass-alias-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'helper_sha256':helper_hash,'runner_unchanged':runner_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,'username_case_covered':False,
        'deprecated_readback_presence_covered':False,'ignored_alias_malformed_values_covered':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
