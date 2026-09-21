#!/usr/bin/env python3
"""One official CLI upload with an expired actor, on a fresh file-backed TLS node.

Diagnostic profile only: 5-second listener, no HA, no mutation retry, no raw CLI
stderr in the receipt. A transport failure is not accepted as an HTTP 403 pass.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time
from types import SimpleNamespace

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from native_snapshot_cli_live import cli, inspect_archive, private_parent
from official_openbao_launcher import verify_inputs
from online_evidence import admit_output, source_identity

REQUIRED = frozenset({'initialized', 'unsealed', 'mounted', 'seed_complete', 'cli_save',
    'archive_contract', 'actor_created', 'actor_expired', 'expired_actor_denied',
    'generation_unchanged', 'data_unchanged', 'complete'})


def complete(rows):
    if not rows or any(not isinstance(row, dict) or set(row) != {'case','passed'}
            or row['passed'] is not True or not isinstance(row['case'],str)
            or re.fullmatch(r'[a-z0-9_]{1,120}',row['case']) is None for row in rows): return False
    names=[row['case'] for row in rows]
    return len(names)==len(set(names)) and names[-1]=='complete' and REQUIRED.issubset(names)


def record_upload_result(check, denied, before, after, values_unchanged):
    # Keep independent readback observations even when the CLI loses the response.
    check('generation_unchanged', after == before)
    check('data_unchanged', values_unchanged)
    check('expired_actor_denied', denied)


def run(binary, bao, work, checks, observations):
    from smoke import Instance
    instance=None
    def check(name, value):
        checks.append({'case':name,'passed':value is True})
        if value is not True: raise ScenarioFailure(name)
    try:
        instance=Instance(binary,work/'instance')
        config_path=instance.root/'server.json';config=json.loads(config_path.read_text())
        config.update(lifecycle_interval_seconds=0,outbound_endpoints=[],timeout_seconds=5)
        private_write(config_path,config,replace=True);instance.start()
        status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        check('initialized',status==200)
        instance.token=initialized['root_token']
        check('unsealed',instance.call('POST','sys/unseal',{'key':initialized['keys_base64'][0]})[0]==200)
        client=Client(instance.address,str(instance.root/'ca.crt'),instance.token,timeout=5)
        def call(method,path,body=None):
            response=client.request(method,'/v1/'+path,body);return response.status,response.body
        def generation():
            status,body=call('GET','sys/internal/capacity')
            if status!=200:raise ScenarioFailure('capacity_unavailable')
            return body['data']['generation']
        check('mounted',call('POST','sys/mounts/rejection',{'type':'kv','options':{'version':'1'}})[0]==204)
        hashes={}
        for index in range(8):
            value={'value':secrets.token_hex(2048)}
            check('seed_'+str(index),call('PUT','rejection/k'+str(index),value)[0]==204)
            hashes[index]=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).digest()
        check('seed_complete',True)
        archive=work/'native.snap'
        check('cli_save',cli(bao,instance,work,'save',archive)==0)
        meta=inspect_archive(archive);check('archive_contract',meta['state_bytes']>0)
        observations.update(archive_bytes=archive.stat().st_size,archive_sha256=file_hash(archive),
                            listener_timeout_seconds=5,restore_attempts=0)
        status,body=call('POST','auth/token/create',{'policies':['root'],'ttl':'1s'})
        check('actor_created',status==200 and bool(body.get('auth',{}).get('client_token')))
        token=body['auth']['client_token']
        lease=body['auth'].get('lease_duration')
        observations['issued_lease_seconds']=lease if type(lease) is int else None
        time.sleep(2.1)
        expired_client=Client(instance.address,str(instance.root/'ca.crt'),token,timeout=5)
        expired=expired_client.request('GET','/v1/auth/token/lookup-self')
        observations['expired_lookup_status']=expired.status
        check('actor_expired',expired.status==403)
        before=generation();diagnostics={};observations['expired_actor_cli']=diagnostics
        observations['restore_attempts']=1
        denied=cli(bao,SimpleNamespace(address=instance.address,root=instance.root,token=token),
                   work,'restore',archive,expected_error=403,diagnostics=diagnostics)
        after=generation();values_unchanged=True
        for index,digest in hashes.items():
            status,body=call('GET','rejection/k'+str(index))
            actual=hashlib.sha256(json.dumps(body.get('data'),sort_keys=True,separators=(',',':')).encode()).digest()
            values_unchanged &= status==200 and actual==digest
        observations.update(generation_before=before,generation_after=after)
        record_upload_result(check,denied,before,after,values_unchanged)
        check('complete',True)
    finally:
        if instance is not None:instance.stop()


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--work-parent',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit):parser.error('full build commit required')
    binary=args.binary.resolve(strict=True);output=args.output.absolute()
    parent=private_parent(args.work_parent);admitted=admit_output(output)
    bao=verify_inputs();bao_hash=file_hash(bao)
    before=source_identity(ROOT,binary);runner_hash=file_hash(Path(__file__))
    work=Path(tempfile.mkdtemp(prefix='native-rejection-',dir=parent))
    checks,observations,failure=[],{},None
    try:run(binary,bao,work,checks,observations)
    except Exception as error:
        failure=next((row['case'] for row in reversed(checks) if row['passed'] is not True),
                     'fixture_'+type(error).__name__)
    after=source_identity(ROOT,binary)
    runner_unchanged=runner_hash==file_hash(Path(__file__));cli_unchanged=bao_hash==file_hash(bao)
    if before!=after or not runner_unchanged or not cli_unchanged:failure='source_binary_cli_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete(checks):failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.native-snapshot-rejection.v1','status':'failed' if failure else 'passed',
            'failure':failure,'checks':checks,'observations':observations,
            'source_identity':before,'source_identity_after':after,'source_and_binary_unchanged':before==after,
            'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
            'official_cli_version':'2.6.2','official_cli_sha256':bao_hash,'official_cli_unchanged':cli_unchanged,
            'retained_failure_work_dir':str(work) if failure else None,'ha_restore_covered':False,
            'diagnostic_only':True,'full_openbao_compatibility':False,'synthetic_only':True}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(work)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return int(failure is not None)


if __name__=='__main__':raise SystemExit(main())
