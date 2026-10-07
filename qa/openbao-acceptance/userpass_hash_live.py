#!/usr/bin/env python3
"""Userpass imported bcrypt credentials vs pinned OpenBao2.6.2.

Uses an explicitly detected, preinstalled Python bcrypt solely for synthetic
hash generation. Never installs dependencies. Variable-size decoded salts are
not covered; the candidate accepts Go Cost admission but rejects such logins.
"""
from __future__ import annotations
import importlib
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

PREFIX='userpass_hash.'
MOUNT=shared.MOUNT
REQUIRED=frozenset({'mounted.status','roundtrip.imported.credentials','roundtrip.plain.credentials',
    'roundtrip.original_token.valid','restart.imported.credentials','restart.old_token.valid',
    'both.create.status','both.update.status','both.reset.status','both.preserved.credentials',
    'empty.hash_preserved.credentials','empty.plain_preserved.credentials','read.no_hash',
    'invalid_limit.status','invalid_limit.preserved.credentials','secrets_absent','complete'}) \
    | frozenset(f'cost.{cost}.{phase}' for cost in (4,5,10,12,13) for phase in ('write.status',)) \
    | frozenset(f'cost.{cost}.{phase}' for cost in (5,10,12) for phase in ('login.credentials','wrong.status','restart.credentials')) \
    | frozenset(f'format.{name}.{phase}' for name in ('two','two_a','two_b','two_y','two_x','two_z','one_a','plus_cost',
          'version_separator','cost_separator','extra_tail','unicode_tail','noncanon_salt') for phase in ('write.status','login.credentials','wrong.status')) \
    | frozenset(f'bad.{name}.{phase}' for name in ('short_tail','salt','hash','unicode_hash') for phase in ('write.status','login.status','login.no_credentials','restart.status'))

class Trace(shared.Trace):
    def check(self,name,condition,**observations):
        if (not isinstance(name,str) or re.fullmatch(r'[a-z0-9_.]{1,140}',name) is None
                or any(type(v) not in (int,bool) for v in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case':PREFIX+name,'passed':condition is True,**observations})
        if condition is not True:raise ScenarioFailure(PREFIX+name)


def generator_capability():
    module=importlib.import_module('bcrypt')
    version=getattr(module,'__version__','')
    if not isinstance(version,str) or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version) is None:
        raise ValueError('unsupported_hash_generator')
    if not callable(getattr(module,'hashpw',None)) or not callable(getattr(module,'gensalt',None)):
        raise ValueError('unavailable_hash_generator')
    return {'module':'bcrypt','version':version,'preinstalled':True}


def vectors(password):
    module=importlib.import_module('bcrypt')
    return {cost:module.hashpw(password.encode(),module.gensalt(rounds=cost)).decode('ascii') for cost in (5,10,12)}


def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(r,dict) or not {'case','passed'} <= set(r) or r['passed'] is not True
           or not isinstance(r['case'],str) or re.fullmatch(r'userpass_hash\.[a-z0-9_.]{1,140}',r['case']) is None
           or any(k not in ('case','passed','status') for k in r)
           or ('status' in r and (type(r['status']) is not int or not 100<=r['status']<=599)) for r in rows):return False
    names=[r['case'] for r in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}.issubset(names)


def formats(h):
    alphabet='./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    salt=h[:28]+alphabet[alphabet.index(h[28])+1]+h[29:]
    return [('two',h[:2]+h[3:]),('two_a','$2a'+h[3:]),('two_b',h),('two_y','$2y'+h[3:]),
        ('two_x','$2x'+h[3:]),('two_z','$2z'+h[3:]),('one_a','$1a'+h[3:]),('plus_cost',h[:4]+'+5'+h[6:]),
        ('version_separator',h[:3]+'!'+h[4:]),('cost_separator',h[:6]+'!'+h[7:]),
        ('extra_tail',h+'EXTRA'),('unicode_tail',h+'短'),('noncanon_salt',salt)]


def run_scenarios(client,restart,rows):
    t=Trace(client,rows)
    t.call('mounted','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
    t.call('tuned','sys/auth/'+MOUNT+'/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    password=secrets.token_urlsafe(24);plain=secrets.token_urlsafe(24)
    hashes=vectors(password);h=hashes[5]
    t.sensitive.extend([password,plain,*hashes.values()])
    for cost in (4,5,10,12,13):
        value=hashes[cost] if cost in hashes else h[:4]+f'{cost:02}'+h[6:]
        t.sensitive.append(value)
        t.write(f'cost.{cost}.write',f'cost{cost}',{'password_hash':value},status=204 if cost in hashes else 400)
        if cost in hashes:
            t.login(f'cost.{cost}.login',f'cost{cost}',{'password':password})
            t.login(f'cost.{cost}.wrong',f'cost{cost}',{'password':plain},status=400)
    for name,value in formats(h):
        t.sensitive.append(value)
        t.write('format.'+name+'.write',name,{'password_hash':value})
        t.login('format.'+name+'.login',name,{'password':password})
        t.login('format.'+name+'.wrong',name,{'password':plain},status=400)
    for name,value in [('short_tail',h[:-1]),('salt',h[:7]+'!'+h[8:]),('hash',h[:-1]+'!'),('unicode_hash',h[:-1]+'短')]:
        t.sensitive.append(value)
        t.write('bad.'+name+'.write','bad-'+name,{'password_hash':value})
        t.login('bad.'+name+'.login','bad-'+name,{'password':password},status=400)
    for name,value in [('version','$3a'+h[3:]),('literal','not-bcrypt')]:
        t.write('rejected.'+name,name,{'password_hash':value},status=400)
    t.write('roundtrip.created','roundtrip',{'password':plain})
    held=t.login('roundtrip.initial','roundtrip',{'password':plain})
    for label,suffix in [('create','new-both'),('update','roundtrip'),('reset','roundtrip/password')]:
        t.write('both.'+label,suffix,{'password':plain,'password_hash':h},status=400)
    t.login('both.preserved','roundtrip',{'password':plain})
    t.write('roundtrip.to_hash','roundtrip/password',{'username':'ignored','password':'','password_hash':h})
    t.login('roundtrip.imported','roundtrip',{'password':password})
    t.login('roundtrip.plain_old','roundtrip',{'password':plain},status=400)
    for label,body in [('missing',{}),('null',{'password':None,'password_hash':None}),('empty',{'password':'','password_hash':''})]:
        t.write('empty.hash.'+label,'roundtrip',body)
        t.write('reset.empty.'+label,'roundtrip/password',body,status=400)
    t.login('empty.hash_preserved','roundtrip',{'password':password})
    t.write('invalid_limit','roundtrip',{'password':plain,'token_ttl':'bad-duration'},status=400)
    t.login('invalid_limit.preserved','roundtrip',{'password':password})
    data=t.call('read.user',f'auth/{MOUNT}/users/roundtrip',method='GET').get('data') or {}
    t.check('read.no_hash',not {'password','password_hash','imported_bcrypt','salt','verifier'} & set(data))
    t.write('roundtrip.to_plain','roundtrip/password',{'password':plain,'password_hash':None})
    t.login('roundtrip.plain','roundtrip',{'password':plain})
    t.login('roundtrip.hash_old','roundtrip',{'password':password},status=400)
    t.write('empty.plain','roundtrip',{'password_hash':''})
    t.login('empty.plain_preserved','roundtrip',{'password':plain})
    t.write('roundtrip.final_hash','roundtrip',{'password':None,'password_hash':h})
    t.valid_token('roundtrip.original_token',held)
    t.write('reset.missing','unknown/password',{'password_hash':h},status=500)
    restart()
    t.login('restart.imported','roundtrip',{'password':password})
    t.valid_token('restart.old_token',held)
    for cost in (5,10,12):t.login(f'cost.{cost}.restart',f'cost{cost}',{'password':password})
    for name in ('short_tail','salt','hash','unicode_hash'):
        t.login('bad.'+name+'.restart','bad-'+name,{'password':password},status=400)
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
    work=Path(tempfile.mkdtemp(prefix='userpass-hash-',dir=parent))
    previous_work=os.environ.get('HB_ORACLE_WORK_ROOT');os.environ['HB_ORACLE_WORK_ROOT']=str(work)
    oracle=instance=None;cases={};failures={};generator=None
    try:
        generator=generator_capability()
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
    report={'schema':'heptabao.userpass-hash-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'helper_sha256':helper_hash,'runner_unchanged':runner_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,'username_case_covered':False,
        'preinstalled_hash_generator':generator,'nonstandard_variable_salt_covered':False,'nonstandard_variable_salt_login_rejected':True,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
