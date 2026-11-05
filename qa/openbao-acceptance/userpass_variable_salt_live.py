#!/usr/bin/env python3
"""Pinned OpenBao comparison for imported bcrypt salts containing CR/LF.

Fixed public synthetic vectors were generated with preinstalled Python bcrypt
and independently accepted by the official executable. No generator is needed
at execution time; no credentials are included in receipts.
"""
from __future__ import annotations
import json
import base64
import os
from pathlib import Path
import re
import shutil
import tempfile
import userpass_password_live as shared
from userpass_password_live import private_parent, free_port, safe_files
from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity

PREFIX='userpass_variable_salt.'
MOUNT=shared.MOUNT
PASSWORD='synthetic-variable-salt-password'
STANDARD_HASH='$2b$05$LBOyLBOyLBOyLBOyLBOyL.vDH2ayPGA4d6ZFXVWLxHPr5G37aKPsy'
LENGTHS=(1,4,7,10,13,16)
BAD=('empty','invalid_length','tab','space')
REQUIRED=frozenset({'mounted.status','secrets_absent','complete','old_token.valid'}) | frozenset(
    f'salt.{length}.{phase}' for length in LENGTHS for phase in ('write.status','login.credentials','wrong.status','restart.credentials')) | frozenset(
    f'bad.{name}.{phase}' for name in BAD for phase in ('write.status','login.status','login.no_credentials','restart.status')) | frozenset(
    f'layout.{name}.{phase}' for name in ('interleaved','major_two','plus_cost','tail_suffix') for phase in ('write.status','login.credentials','restart.credentials'))

class Trace(shared.Trace):
    def check(self,name,condition,**observations):
        if (not isinstance(name,str) or re.fullmatch(r'[a-z0-9_.]{1,140}',name) is None
                or any(type(v) not in (int,bool) for v in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case':PREFIX+name,'passed':condition is True,**observations})
        if condition is not True:raise ScenarioFailure(PREFIX+name)


def encode_salt(value):
    standard=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    bcrypt64=b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return base64.b64encode(value).rstrip(b'=').translate(bytes.maketrans(standard,bcrypt64)).decode()


def hash_for_length(length,*,interleaved=False):
    text=encode_salt(b'4'*length)
    padding='\r\n'*((22-len(text))//2)
    if interleaved:text=text[:1]+padding+text[1:]
    else:text+=padding
    if len(text)!=22:raise ValueError('invalid_synthetic_vector')
    return STANDARD_HASH[:7]+text+STANDARD_HASH[29:]


def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(r,dict) or not {'case','passed'} <= set(r) or r['passed'] is not True
           or not isinstance(r['case'],str) or re.fullmatch(r'userpass_variable_salt\.[a-z0-9_.]{1,140}',r['case']) is None
           or any(k not in ('case','passed','status') for k in r)
           or ('status' in r and (type(r['status']) is not int or not 100<=r['status']<=599)) for r in rows):return False
    names=[r['case'] for r in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}.issubset(names)


def run_scenarios(client,restart,rows):
    t=Trace(client,rows)
    t.call('mounted','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
    t.sensitive.append(PASSWORD)
    for length in LENGTHS:
        value=hash_for_length(length);t.sensitive.append(value)
        name='salt'+str(length)
        t.write(f'salt.{length}.write',name,{'password_hash':value})
        auth=t.login(f'salt.{length}.login',name,{'password':PASSWORD})
        if length==13:held=auth
        t.login(f'salt.{length}.wrong',name,{'password':'wrong prefix '+PASSWORD},status=400)
    value=hash_for_length(13)
    layouts={'interleaved':hash_for_length(13,interleaved=True),'major_two':value[:2]+value[3:],
             'plus_cost':value[:4]+'+5'+value[6:],'tail_suffix':value+'EXTRA'}
    for name,value in layouts.items():
        t.sensitive.append(value);t.write('layout.'+name+'.write',name,{'password_hash':value})
        t.login('layout.'+name+'.login',name,{'password':PASSWORD})
    invalid={'empty':'\r\n'*11,'invalid_length':'.'*21+'\n','tab':'.'*20+'\t\t','space':'.'*20+'  '}
    for name,text in invalid.items():
        value=STANDARD_HASH[:7]+text+STANDARD_HASH[29:];t.sensitive.append(value)
        t.write('bad.'+name+'.write','bad-'+name,{'password_hash':value})
        t.login('bad.'+name+'.login','bad-'+name,{'password':PASSWORD},status=400)
    restart()
    for length in LENGTHS:t.login(f'salt.{length}.restart','salt'+str(length),{'password':PASSWORD})
    for name in layouts:t.login('layout.'+name+'.restart',name,{'password':PASSWORD})
    for name in invalid:t.login('bad.'+name+'.restart','bad-'+name,{'password':PASSWORD},status=400)
    t.valid_token('old_token',held)
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
    work=Path(tempfile.mkdtemp(prefix='userpass-variable-salt-',dir=parent))
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
    report={'schema':'heptabao.userpass-variable-salt-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'helper_sha256':helper_hash,'runner_unchanged':runner_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,'username_case_covered':False,
        'vector_basis':'fixed synthetic bcrypt and periodic salt equivalence, independently checked against OpenBao', 'decoded_salt_lengths':list(LENGTHS),'nonstandard_variable_salt_covered':True,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
