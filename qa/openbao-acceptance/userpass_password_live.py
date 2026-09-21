#!/usr/bin/env python3
"""Native userpass password admission/reset semantics vs pinned OpenBao2.6.2.

This does not cover bcrypt hash import, prior-binary long-credential upgrades, username folding or
non-string weak conversion. Both servers and credentials are fixture-owned.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import tempfile

from bao_http import Client, SafeArgumentParser, private_read, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from official_openbao_launcher import verify_inputs, start_oracle, stop_oracle, restart_oracle
from online_evidence import admit_output, source_identity

PREFIX = 'userpass_password.'
MOUNT = 'password-semantics'
SHORT = [('ascii','x'),('unicode','短'),('emoji','🔐'),('space',' '),('decomposed','e\u0301')]
EMPTY = [('missing',{}),('empty',{'password':''}),('null',{'password':None})]
BOUNDARIES = [('ascii71','a'*71),('ascii72','a'*72),('ascii73','a'*73),
              ('unicode71','短'*23+'ab'),('unicode72','短'*24),('unicode73','短'*24+'x')]
REQUIRED = frozenset({'mounted.status','composed_mismatch.status','composed_mismatch.no_credentials',
    'reset.short.status','reset.new.credentials','reset.old.status','reset.old.no_credentials',
    'reset.old_token.valid','restart.old_token.valid','restart.reset.credentials','secrets_absent','complete'}) \
    | frozenset(f'short.{label}.{phase}' for label,_ in SHORT for phase in ('write.status','login.credentials','restart.credentials')) \
    | frozenset(f'create.{label}.{phase}' for label,_ in EMPTY for phase in ('status','no_credentials','absent.status')) \
    | frozenset(f'update.{label}.{phase}' for label,_ in EMPTY for phase in ('status','fields','login.credentials')) \
    | frozenset(f'reset.{label}.{phase}' for label,_ in EMPTY for phase in ('status','no_credentials','preserved.credentials')) \
    | frozenset(f'unknown_reset.{label}.{phase}' for label in ('short','empty','null','missing') for phase in ('status','no_credentials','absent.status')) \
    | frozenset(f'login.{name}.{label}.{phase}' for name in ('existing','unknown') for label in ('missing','empty','null','wrong') for phase in ('status','no_credentials'))


REQUIRED |= frozenset(f'bounds.{label}.{phase}' for label,_ in BOUNDARIES for phase in ('create.status','update.status','reset.status'))
REQUIRED |= frozenset({'bounds.old_token.valid','bounds.restart_token.valid',
    'bounds.ascii73.create.absent.status','bounds.unicode73.create.absent.status',
    'bounds.ascii73.update.preserved.credentials','bounds.unicode73.update.preserved.credentials',
    'bounds.ascii73.reset.preserved.credentials','bounds.unicode73.reset.preserved.credentials'})

class Trace:
    def __init__(self, client, rows):
        self.client,self.rows=client,rows
        self.sensitive=[]

    def check(self,name,condition,**observations):
        if (not isinstance(name,str) or re.fullmatch(r'[a-z0-9_.]{1,140}',name) is None
                or any(type(v) not in (int,bool) for v in observations.values())):
            raise ValueError('unsafe_observation')
        self.rows.append({'case':PREFIX+name,'passed':condition is True,**observations})
        if condition is not True:raise ScenarioFailure(PREFIX+name)

    def call(self,name,path,fields=None,*,method='POST',status=200,bearer=None):
        result=self.client.request(method,'/v1/'+path,fields,token=bearer)
        self.check(name+'.status',result.status==status,status=result.status)
        if status>=400:
            self.check(name+'.no_credentials',not result.body.get('auth') and not result.body.get('wrap_info'))
        return result.body

    def write(self,name,user,fields,*,status=204):
        return self.call(name,f'auth/{MOUNT}/users/{user}',fields,status=status)

    def login(self,name,user,fields,*,status=200):
        body=self.call(name,f'auth/{MOUNT}/login/{user}',fields,status=status)
        if status!=200:return None
        auth=body.get('auth') or {}
        self.check(name+'.credentials',all(isinstance(auth.get(k),str) and len(auth[k])>=16 for k in ('client_token','accessor'))
                   and auth.get('metadata')=={'username':user})
        self.sensitive.append(auth['client_token'])
        return auth['client_token']

    def valid_token(self,name,token):
        data=self.call(name,'auth/token/lookup-self',method='GET',bearer=token).get('data') or {}
        self.check(name+'.valid',data.get('id')==token and type(data.get('ttl')) is int and data['ttl']>0)


def complete(rows):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(r,dict) or not {'case','passed'} <= set(r) or r['passed'] is not True
           or not isinstance(r['case'],str) or re.fullmatch(r'userpass_password\.[a-z0-9_.]{1,140}',r['case']) is None
           or any(k not in ('case','passed','status') for k in r)
           or ('status' in r and (type(r['status']) is not int or not 100<=r['status']<=599)) for r in rows):return False
    names=[r['case'] for r in rows]
    return len(names)==len(set(names)) and names[-1]==PREFIX+'complete' and {PREFIX+n for n in REQUIRED}.issubset(names)


def run_scenarios(client,restart,rows):
    t=Trace(client,rows)
    t.call('mounted','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
    t.call('tuned','sys/auth/'+MOUNT+'/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    for label,fields in EMPTY:
        name='create-'+label
        t.write('create.'+label,name,fields,status=400)
        t.call('create.'+label+'.absent',f'auth/{MOUNT}/users/{name}',method='GET',status=404)
    for label,password in SHORT:
        t.write('short.'+label+'.write',label,{'password':password})
        t.login('short.'+label+'.login',label,{'password':password})
    t.login('composed_mismatch','decomposed',{'password':'é'},status=400)
    password=secrets.token_urlsafe(24);t.sensitive.append(password)
    t.write('update.created','updates',{'password':password})
    for index,(label,fields) in enumerate(EMPTY):
        fields={**fields,'token_ttl':121+index}
        t.write('update.'+label,'updates',fields)
        data=t.call('update.'+label+'.read',f'auth/{MOUNT}/users/updates',method='GET').get('data') or {}
        t.check('update.'+label+'.fields',data.get('token_ttl')==121+index)
        t.login('update.'+label+'.login','updates',{'password':password})
    t.write('reset.created','reset-user',{'password':password})
    held=t.login('reset.initial','reset-user',{'password':password})
    for label,fields in EMPTY:
        t.write('reset.'+label,'reset-user/password',fields,status=400)
        t.login('reset.'+label+'.preserved','reset-user',{'password':password})
    for label,fields in [('short',{'password':'z'}),*EMPTY]:
        t.write('unknown_reset.'+label,'unknown-reset/password',fields,status=500)
        t.call('unknown_reset.'+label+'.absent',f'auth/{MOUNT}/users/unknown-reset',method='GET',status=404)
    t.write('reset.short','reset-user/password',{'password':'新'})
    t.login('reset.new','reset-user',{'password':'新'})
    t.login('reset.old','reset-user',{'password':password},status=400)
    t.valid_token('reset.old_token',held)
    for kind,name in [('existing','reset-user'),('unknown','unknown-login')]:
        for label,fields in EMPTY:
            t.login(f'login.{kind}.{label}',name,fields,status=500)
        t.login(f'login.{kind}.wrong',name,{'password':'incorrect'},status=400)
    # Source-backed and separately observed byte boundaries. Each rejected
    # replacement must leave the preceding password and issued token usable.
    boundary_initial=secrets.token_urlsafe(24);t.sensitive.append(boundary_initial)
    t.write('bounds.initial','bounds-current',{'password':boundary_initial})
    boundary_token=t.login('bounds.issued','bounds-current',{'password':boundary_initial})
    previous=boundary_initial
    for label,password in BOUNDARIES:
        size=len(password.encode())
        if size!=int(label[-2:]):raise ValueError('invalid_boundary_fixture')
        expected=500 if size>72 else 204
        t.write('bounds.'+label+'.create',label,{'password':password},status=expected)
        if expected==204:
            t.login('bounds.'+label+'.created',label,{'password':password})
        else:
            t.call('bounds.'+label+'.create.absent',f'auth/{MOUNT}/users/{label}',method='GET',status=404)
        t.write('bounds.'+label+'.update','bounds-current',{'password':password},status=expected)
        if expected==204:previous=password
        t.login('bounds.'+label+'.update.preserved','bounds-current',{'password':previous})
        t.write('bounds.'+label+'.reset','bounds-current/password',{'password':password},status=expected)
        t.login('bounds.'+label+'.reset.preserved','bounds-current',{'password':previous})
    t.valid_token('bounds.old_token',boundary_token)
    restart()
    t.valid_token('bounds.restart_token',boundary_token)
    t.login('bounds.restart_password','bounds-current',{'password':previous})
    for label,password in SHORT:
        t.login('short.'+label+'.restart',label,{'password':password})
    t.login('restart.reset','reset-user',{'password':'新'})
    t.valid_token('restart.old_token',held)
    return t.sensitive


def private_parent(path):
    path=path.absolute()
    for part in [path,*path.parents]:
        if not stat.S_ISDIR(part.lstat().st_mode):raise ValueError('unsafe_work_parent')
    if path.stat().st_uid!=os.getuid() or stat.S_IMODE(path.stat().st_mode)!=0o700:
        raise ValueError('private_work_parent_required')
    return path


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def safe_files(root,credentials):
    # A one-byte synthetic password cannot be searched as a substring of random
    # ciphertext: it inevitably occurs. Scan unpredictable credentials/tokens,
    # and reject any explicit password field in structured log records instead.
    needles=[s.encode() for s in credentials if len(s.encode())>=16]
    paths=[p for p in (root/'data').rglob('*') if p.is_file() and not p.is_symlink()]
    paths += [root/'server.log',root/'audit.jsonl']
    for path in paths:
        if not path.exists():continue
        with path.open('rb') as stream:
            tail=b''
            while chunk:=stream.read(65536):
                data=tail+chunk
                if any(needle in data for needle in needles):return False
                tail=data[-max([len(n) for n in needles],default=1):]
    def password_field(value):
        if isinstance(value,dict):
            return any((k in ('password','password_hash') and isinstance(v,str) and bool(v)) or password_field(v) for k,v in value.items())
        if isinstance(value,list):return any(password_field(v) for v in value)
        return False
    for path in [root/'server.log',root/'audit.jsonl']:
        if not path.exists():continue
        with path.open('r',errors='replace') as stream:
            for line in stream:
                try:value=json.loads(line)
                except ValueError:continue
                if password_field(value):return False
    return True


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
    runner_hash=file_hash(Path(__file__));bao=verify_inputs();bao_hash=file_hash(bao)
    work=Path(tempfile.mkdtemp(prefix='userpass-password-',dir=parent))
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
    runner_unchanged=runner_hash==file_hash(Path(__file__));oracle_unchanged=bao_hash==file_hash(bao)
    equal=cases.get('oracle')==cases.get('candidate') if not args.oracle_only else None
    passed=(not failures and runner_unchanged and oracle_unchanged and set(cases)==({'oracle'} if args.oracle_only else {'oracle','candidate'})
            and all(complete(rows) for rows in cases.values())
            and (args.oracle_only or unchanged and equal and not before['source_dirty'] and not after['source_dirty']))
    report={'schema':'heptabao.userpass-password-comparison.v1','status':'passed' if passed else 'failed',
        'candidate_source':before,'candidate_source_after':after,'source_and_binary_unchanged':unchanged,
        'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'oracle_binary_sha256':bao_hash,'oracle_binary_unchanged':oracle_unchanged,'target_version':'2.6.2',
        'oracle_only':args.oracle_only,'cases':cases,'cases_match':equal,'failures':failures,
        'retained_failure_work_dir':str(work) if not passed else None,'password_hash_import_covered':False,
        'password_over_72_bytes_covered':True,'prior_binary_long_credential_upgrade_covered':False,'username_case_covered':False,'weak_scalar_conversion_covered':False,
        'synthetic_only':True,'full_openbao_compatibility':False,'independent_qualification':False,'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if passed:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'cases':{side:len(rows) for side,rows in cases.items()},'failures':failures}))
    return int(not passed)

if __name__=='__main__':raise SystemExit(main())
