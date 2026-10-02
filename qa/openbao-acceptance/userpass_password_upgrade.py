#!/usr/bin/env python3
"""Actual schema37 PBKDF credentials -> schema38 opt-in 72-byte input semantics.

The old executable creates both 72-byte and 900-byte passwords. No stored
credential or schema is fabricated, and no failed mutation is retried.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, complete_checks, source_identity
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance
from userpass_password_live import safe_files

LEGACY_SOURCE = 'c3c5d14ceaf9b7fac0cfe5ace130ba7dc7e2fdce'
LEGACY_SHA256 = 'bdee57626438da447e19d23e06fa461d3c243c3b1a508ad3cce0046baa50aa2f'
LEGACY_RECEIPT = ROOT/'qa/openbao-acceptance/evidence/kv1-packed-upgrade256-c3c5d14.json'
MOUNT = 'password-upgrade'
REQUIRED = frozenset({'legacy.long.credentials','legacy.exact.credentials',
    'legacy.exact_suffix.rejected','pure.application_unchanged','pure.reads_unchanged',
    'pure_restart.application_unchanged','pure_restart.reads_unchanged',
    'current.long.credentials','current.long_prefix.rejected','current.long_suffix.rejected',
    'current.exact_suffix.rejected','current.new_suffix.credentials',
    'current.explicit_reset_suffix.credentials','current.long_replacement.rejected',
    'current.long_preserved.credentials','current.held_token.valid',
    'reopen.application_unchanged','reopen.long.credentials','reopen.long_prefix.rejected',
    'reopen.new_suffix.credentials','reopen.reset_suffix.credentials',
    'downgrade.unseal.rejected','downgrade.health.rejected','downgrade.application_unchanged',
    'recovery.long.credentials','recovery.new_suffix.credentials','recovery.held_token.valid',
    'secret_samples_absent','complete'})
REQUIRED = frozenset(name.replace('.', '_') for name in REQUIRED)


def admit_legacy_receipt(expected, receipt):
    before=receipt.get('source_identity',{})
    if (expected != LEGACY_SHA256 or receipt.get('status') != 'passed'
        or receipt.get('schema') != 'heptabao.kv1-packed-upgrade.v1'
        or receipt.get('build_source_commit') != LEGACY_SOURCE
        or receipt.get('candidate_binary_sha256') != LEGACY_SHA256
        or before.get('binary_sha256') != LEGACY_SHA256 or before.get('source_dirty') is not False
        or before.get('source_commit') != '7813fa42698773d895651c6bbb6111b868fec656'
        or receipt.get('source_identity_after') != before
        or receipt.get('source_and_binary_unchanged') is not True or receipt.get('runner_unchanged') is not True):
        raise ValueError('qualified_legacy37_receipt_required')


class Trace:
    def __init__(self, instance, rows):
        self.client=Client(instance.address,str(instance.root/'ca.crt'),instance.token,timeout=5)
        self.rows=rows
        self.sensitive=[instance.token]

    def check(self, name, condition):
        name=name.replace('.', '_')
        if re.fullmatch(r'[a-z0-9_.]{1,120}',name) is None:raise ValueError('unsafe_case_label')
        self.rows.append({'case':name,'passed':condition is True})
        if condition is not True:raise ScenarioFailure(name)

    def call(self, name, method, path, body=None, expected=200, bearer=None):
        result=self.client.request(method,'/v1/'+path,body,token=bearer)
        self.check(name+'.status',result.status == expected)
        if expected >= 400:
            self.check(name+'.rejected',not result.body.get('auth') and not result.body.get('wrap_info'))
        return result.body

    def write(self, name, user, fields, expected=204):
        return self.call(name,'POST',f'auth/{MOUNT}/users/{user}',fields,expected)

    def login(self, name, user, password, expected=200):
        body=self.call(name,'POST',f'auth/{MOUNT}/login/{user}',{'password':password},expected,bearer='')
        if expected != 200:return None
        auth=body.get('auth') or {}
        self.check(name+'.credentials',all(isinstance(auth.get(k),str) and len(auth[k])>=16
            for k in ('client_token','accessor')) and auth.get('metadata')=={'username':user})
        self.sensitive.append(auth['client_token'])
        return auth['client_token']

    def held(self, name, token):
        data=self.call(name,'GET','auth/token/lookup-self',bearer=token).get('data') or {}
        self.check(name+'.valid',data.get('id')==token and type(data.get('ttl')) is int and data['ttl']>0)


def run(instance, candidate, legacy, rows):
    instance.start()
    status, initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status != 200:raise ScenarioFailure('initialization_failed')
    instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
    t=Trace(instance,rows)
    exact=secrets.token_hex(36)
    long=exact+secrets.token_hex(414)
    t.sensitive.extend([key,exact,long])
    t.call('legacy.unseal','POST','sys/unseal',{'key':key})
    t.call('legacy.mount','POST','sys/auth/'+MOUNT,{'type':'userpass'},204)
    t.write('legacy.long_write','long',{'password':long})
    t.write('legacy.exact_write','exact',{'password':exact})
    held=t.login('legacy.long','long',long)
    t.login('legacy.exact','exact',exact)
    t.login('legacy.exact_suffix','exact',exact+'x',403)
    store=instance.root/'data'
    user=t.call('legacy.user_read','GET',f'auth/{MOUNT}/users/long').get('data')
    def restart(binary, label):
        instance.stop();instance.binary=binary;instance.start()
        t.call(label+'.unseal','POST','sys/unseal',{'key':key})
    instance.stop();application=durable_manifest(store,application_only=True)
    for phase in ('pure','pure_restart'):
        restart(candidate,phase)
        t.check(phase+'.application_unchanged',durable_manifest(store,application_only=True)==application)
        before=durable_manifest(store)
        t.check(phase+'.user_preserved',t.call(phase+'.user','GET',f'auth/{MOUNT}/users/long').get('data')==user)
        t.held(phase+'.held_token',held)
        t.check(phase+'.reads_unchanged',durable_manifest(store)==before)
    t.login('current.long','long',long)
    t.login('current.long_prefix','long',exact,400)
    t.login('current.long_suffix','long',long+'x',400)
    t.login('current.exact_suffix','exact',exact+'x',400)
    for label,fields in [('missing',{}),('null',{'password':None}),('empty',{'password':''})]:
        t.write('current.preserve_'+label+'.write','long',fields)
        t.login('current.preserve_'+label+'.login','long',long)
    t.write('current.new_write','new',{'password':exact})
    t.login('current.new_suffix','new',exact+'x'*953)
    t.write('current.explicit_reset','exact/password',{'password':exact})
    t.login('current.explicit_reset_suffix','exact',exact+'x'*953)
    t.write('current.long_replacement','long',{'password':long},500)
    t.login('current.long_preserved','long',long)
    t.held('current.held_token',held)
    instance.stop();application=durable_manifest(store,application_only=True)
    restart(candidate,'reopen')
    t.check('reopen.application_unchanged',durable_manifest(store,application_only=True)==application)
    t.login('reopen.long','long',long)
    t.login('reopen.long_prefix','long',exact,400)
    t.login('reopen.new_suffix','new',exact+'x'*953)
    t.login('reopen.reset_suffix','exact',exact+'x'*953)
    instance.stop();application=durable_manifest(store,application_only=True)
    instance.binary=legacy;instance.start()
    t.call('downgrade.unseal','POST','sys/unseal',{'key':key},503)
    t.call('downgrade.health','GET','sys/health',expected=503)
    instance.stop()
    t.check('downgrade.application_unchanged',durable_manifest(store,application_only=True)==application)
    restart(candidate,'recovery')
    t.login('recovery.long','long',long)
    t.login('recovery.new_suffix','new',exact+'x'*953)
    t.held('recovery.held_token',held)
    instance.stop()
    t.check('secret_samples_absent',safe_files(instance.root,t.sensitive))
    t.check('complete',True)


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--legacy-binary',type=Path,required=True)
    parser.add_argument('--expected-legacy-sha256',required=True)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('invalid build commit')
    candidate,legacy=args.binary.resolve(strict=True),args.legacy_binary.resolve(strict=True)
    admit_legacy_receipt(args.expected_legacy_sha256,json.loads(LEGACY_RECEIPT.read_text()))
    candidate_hash,legacy_hash=validate_binary_pins(candidate,legacy,args.expected_legacy_sha256)
    output=args.output.absolute();admitted=admit_output(output)
    before,runner_hash=source_identity(ROOT,candidate),file_hash(Path(__file__))
    root=Path(tempfile.mkdtemp(prefix='userpass-password-upgrade-'));root.chmod(0o700)
    instance=None;rows=[];failure=None
    try:
        instance=Instance(legacy,root/'candidate')
        config_path=instance.root/'server.json';config=json.loads(config_path.read_text())
        config.update(lifecycle_interval_seconds=0,outbound_endpoints=[])
        private_write(config_path,config,replace=True)
        run(instance,candidate,legacy,rows)
    except Exception as error:
        failure=next((r['case'] for r in reversed(rows) if r['passed'] is not True),'fixture_'+type(error).__name__)
    finally:
        if instance is not None:instance.stop()
    after=source_identity(ROOT,candidate)
    unchanged=before==after and file_hash(legacy)==legacy_hash and after['binary_sha256']==candidate_hash
    runner_unchanged=file_hash(Path(__file__))==runner_hash
    if not unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete_checks(rows,required_cases=REQUIRED) or not rows or rows[-1]['case']!='complete':
        failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.userpass-password-upgrade.v1','status':'passed' if failure is None else 'failed',
        'failure':failure,'checks':rows,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':unchanged,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'build_source_commit':args.build_source_commit,'legacy_source_commit':LEGACY_SOURCE,
        'legacy_binary_sha256':legacy_hash,'legacy_receipt_sha256':file_hash(LEGACY_RECEIPT),
        'from_schema':37,'minimum_to_schema':38,'legacy_password_bytes':[72,900],
        'credential_storage_fabricated':False,'old_reader_actually_executed':True,'mutation_retries':0,
        'application_artifact_scope':'all entries except root ledger.hbl re-sealed before schema admission',
        'retained_failure_work_dir':str(root) if failure else None,'synthetic_only':True,
        'full_openbao_compatibility':False,'ha_or_postgresql_covered':False,'independent_qualification':False,
        'production_authority':False}
    if admit_output(output)!=admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(root)
    print(json.dumps({'status':report['status'],'checks':len(rows),'failure':failure}))
    return int(failure is not None)

if __name__=='__main__':raise SystemExit(main())
