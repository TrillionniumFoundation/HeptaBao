#!/usr/bin/env python3
"""Actual schema39 exact account names -> schema40 fresh-mount canonical names.

The operator supplies the frozen schema39 binary/build/qualified receipt pins.
No encrypted state, stored schema, credential or provenance is fabricated.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from bao_http import Client,SafeArgumentParser,private_write
from core_isolation import ROOT,ScenarioFailure,file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output,complete_checks,source_identity
from provider_renewal_upgrade import durable_manifest
from userpass_password_live import safe_files,private_parent
from userpass_no_default_live import complete as legacy_complete

LEGACY_MOUNT='legacy-names'
FRESH_MOUNT='fresh-names'
REQUIRED=frozenset({'legacy_distinct_entities','legacy_exact_list','pure_application_unchanged','pure_reads_unchanged',
 'pure_restart_application_unchanged','pure_restart_reads_unchanged','current_upper_exact','current_lower_exact',
 'current_missing_upper_renew_token_status','current_missing_upper_renew_accessor_status','current_missing_upper_expiry_unchanged',
 'current_recreated_upper_renew_shape','fresh_same_entity','fresh_single_account','reopen_application_unchanged',
 'reopen_legacy_upper_exact','reopen_legacy_lower_exact','reopen_fresh_canonical','downgrade_unseal_rejected',
 'downgrade_health_rejected','downgrade_application_unchanged','recovery_legacy_upper_exact','recovery_legacy_lower_exact',
 'recovery_fresh_canonical','secret_samples_absent','complete'})

def admit_legacy_receipt(expected,source,receipt):
    before=receipt.get('candidate_source') or {}
    sides=receipt.get('cases') or {}
    if (not re.fullmatch('[0-9a-f]{64}',expected) or not re.fullmatch('[0-9a-f]{40}',source)
        or receipt.get('schema')!='heptabao.userpass-no-default-comparison.v1'
        or receipt.get('status')!='passed' or receipt.get('oracle_only') is not False
        or receipt.get('build_source_commit')!=source or before.get('binary_sha256')!=expected
        or before.get('source_dirty') is not False or receipt.get('candidate_source_after')!=before
        or receipt.get('cases_match') is not True or receipt.get('source_and_binary_unchanged') is not True
        or receipt.get('runner_unchanged') is not True or receipt.get('oracle_binary_unchanged') is not True
        or receipt.get('failures') or set(sides)!={'oracle','candidate'} or sides['oracle']!=sides['candidate']
        or not all(legacy_complete(rows) for rows in sides.values())):
        raise ValueError('qualified_schema39_userpass_receipt_required')

class Trace:
    def __init__(self,instance,rows):
        self.client=Client(instance.address,str(instance.root/'ca.crt'),instance.token)
        self.rows=rows;self.sensitive=[instance.token]
    def check(self,name,passed):
        name=name.replace('.','_')
        if not re.fullmatch('[a-z0-9_]{1,140}',name):raise ValueError('unsafe_case')
        self.rows.append({'case':name,'passed':passed is True})
        if passed is not True:raise ScenarioFailure(name)
    def call(self,name,method,path,fields=None,*,status=200,token=None):
        r=self.client.request(method,'/v1/'+path,fields,token=token)
        self.check(name+'.status',r.status==status)
        if status>=400:self.check(name+'.rejected',not r.body.get('auth') and not r.body.get('wrap_info'))
        return r.body
    def write(self,name,mount,user,fields):return self.call(name,'POST',f'auth/{mount}/users/{user}',fields,status=204)
    def login(self,name,mount,user,password,expected,*,status=200):
        auth=self.call(name,'POST',f'auth/{mount}/login/{user}',{'password':password},status=status,token='').get('auth') or {}
        if status!=200:return None
        self.check(name+'.issued',all(isinstance(auth.get(k),str) and bool(auth[k]) for k in ('client_token','accessor','entity_id'))
            and auth.get('metadata')=={'username':expected})
        self.sensitive.append(auth['client_token']);return auth
    def lookup(self,name,auth,expected):
        data=self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']}).get('data') or {}
        self.check(name+'.exact',data.get('id')==auth['client_token'] and data.get('meta')=={'username':expected} and data.get('entity_id')==auth['entity_id'])
        return data
    def renew(self,name,auth,expected):
        renewed=self.call(name,'POST','auth/token/renew',{'token':auth['client_token'],'increment':120}).get('auth') or {}
        self.check(name+'.shape',renewed.get('client_token')==auth['client_token'] and renewed.get('metadata')=={'username':expected})

def run(instance,candidate,legacy,rows):
    instance.start();status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure('initialization_failed')
    instance.token,key=init['root_token'],init['keys_base64'][0];t=Trace(instance,rows)
    upper,lower,fresh_password=[secrets.token_urlsafe(24) for _ in range(3)];t.sensitive.extend([key,upper,lower,fresh_password])
    t.call('legacy.unseal','POST','sys/unseal',{'key':key})
    t.call('legacy.mount','POST','sys/auth/'+LEGACY_MOUNT,{'type':'userpass'},status=204)
    t.call('legacy.tune','POST','sys/auth/'+LEGACY_MOUNT+'/tune',{'default_lease_ttl':300,'max_lease_ttl':900},status=204)
    held={};configs={}
    for user,password in [('Alice',upper),('alice',lower)]:
        label='upper' if user=='Alice' else 'lower'
        t.write('legacy.write_'+label,LEGACY_MOUNT,user,{'password':password})
        held[user]=t.login('legacy.login_'+label,LEGACY_MOUNT,user,password,user)
        configs[user]=t.call('legacy.read_'+label,'GET',f'auth/{LEGACY_MOUNT}/users/{user}').get('data')
    t.check('legacy.distinct_entities',held['Alice']['entity_id']!=held['alice']['entity_id'])
    t.check('legacy.exact_list',(t.call('legacy.list','LIST',f'auth/{LEGACY_MOUNT}/users').get('data') or {}).get('keys')==['Alice','alice'])
    store=instance.root/'data'
    def restart(binary,phase):
        instance.stop();instance.binary=binary;instance.start();t.call(phase+'.unseal','POST','sys/unseal',{'key':key})
    instance.stop();application=durable_manifest(store,application_only=True)
    for phase in ('pure','pure_restart'):
        restart(candidate,phase);t.check(phase+'.application_unchanged',durable_manifest(store,application_only=True)==application)
        before=durable_manifest(store)
        for label,user in [('upper','Alice'),('lower','alice')]:
            t.check(phase+'.'+label+'.config_exact',t.call(phase+'.read_'+label,'GET',f'auth/{LEGACY_MOUNT}/users/{user}').get('data')==configs[user])
            t.lookup(phase+'.'+label,held[user],user)
        t.check(phase+'.reads_unchanged',durable_manifest(store)==before)
    # Old mounts remain exact even after a successful schema40 mutation/login.
    for label,user,password in [('upper','Alice',upper),('lower','alice',lower)]:
        issued=t.login('current.login_'+label,LEGACY_MOUNT,user,password,user)
        t.check('current.'+label+'.exact',issued['entity_id']==held[user]['entity_id'])
        t.login('current.wrong_'+label,LEGACY_MOUNT,user,lower if user=='Alice' else upper,user,status=400)
    before=t.lookup('current.upper_before',held['Alice'],'Alice')
    t.call('current.delete_upper','DELETE',f'auth/{LEGACY_MOUNT}/users/Alice',status=204)
    for tag,route,fields,expected in [('token','renew',{'token':held['Alice']['client_token']},204),('accessor','renew-accessor',{'accessor':held['Alice']['accessor']},500)]:
        result=t.call('current.missing_upper_renew_'+tag,'POST','auth/token/'+route,fields,status=expected)
        t.check('current.missing_upper_renew_'+tag+'.no_credentials',not result.get('auth') and not result.get('wrap_info'))
    after=t.lookup('current.upper_after',held['Alice'],'Alice')
    t.check('current.missing_upper_expiry_unchanged',before.get('expire_time')==after.get('expire_time'))
    t.login('current.lower_survives',LEGACY_MOUNT,'alice',lower,'alice')
    t.write('current.recreate_upper',LEGACY_MOUNT,'Alice',{'password':upper})
    t.renew('current.recreated_upper_renew',held['Alice'],'Alice')
    t.call('fresh.mount','POST','sys/auth/'+FRESH_MOUNT,{'type':'userpass'},status=204)
    t.write('fresh.created',FRESH_MOUNT,'MiXeD',{'password':fresh_password,'token_ttl':120})
    fresh=t.login('fresh.upper',FRESH_MOUNT,'MIXED',fresh_password,'mixed')
    again=t.login('fresh.lower',FRESH_MOUNT,'mixed',fresh_password,'mixed')
    t.check('fresh.same_entity',fresh['entity_id']==again['entity_id'])
    t.check('fresh.single_account',(t.call('fresh.list','LIST',f'auth/{FRESH_MOUNT}/users').get('data') or {}).get('keys')==['mixed'])
    # Re-enabling metadata must not discard the new durable mode.
    t.call('fresh.reenable','POST','sys/auth/'+FRESH_MOUNT,{'type':'userpass','description':'retained mode'},status=204)
    t.login('fresh.reenabled',FRESH_MOUNT,'mIxEd',fresh_password,'mixed')
    def verify(phase):
        for label,user,password in [('upper','Alice',upper),('lower','alice',lower)]:
            issued=t.login(phase+'.login_'+label,LEGACY_MOUNT,user,password,user)
            t.check(phase+'.legacy_'+label+'.exact',issued['entity_id']==held[user]['entity_id'])
            t.renew(phase+'.held_'+label,held[user],user)
        issued=t.login(phase+'.fresh_login',FRESH_MOUNT,'MIXED',fresh_password,'mixed')
        t.check(phase+'.fresh.canonical',issued['entity_id']==fresh['entity_id'])
    instance.stop();application=durable_manifest(store,application_only=True)
    restart(candidate,'reopen');t.check('reopen.application_unchanged',durable_manifest(store,application_only=True)==application);verify('reopen')
    instance.stop();application=durable_manifest(store,application_only=True)
    instance.binary=legacy;instance.start();t.call('downgrade.unseal','POST','sys/unseal',{'key':key},status=503)
    t.call('downgrade.health','GET','sys/health',status=503);instance.stop()
    t.check('downgrade.application_unchanged',durable_manifest(store,application_only=True)==application)
    restart(candidate,'recovery');verify('recovery');instance.stop()
    t.check('secret_samples_absent',safe_files(instance.root,t.sensitive));t.check('complete',True)


def old_reader_observed(rows):
    return any(row.get("case")=="downgrade_unseal_status" for row in rows)

def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--legacy-binary',type=Path,required=True)
    parser.add_argument('--expected-legacy-sha256',required=True)
    parser.add_argument('--legacy-build-source-commit',required=True)
    parser.add_argument('--legacy-receipt',type=Path,required=True)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--work-parent',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('invalid build commit')
    candidate,legacy=args.binary.resolve(strict=True),args.legacy_binary.resolve(strict=True)
    legacy_receipt=args.legacy_receipt.resolve(strict=True)
    receipt_hash=file_hash(legacy_receipt)
    admit_legacy_receipt(args.expected_legacy_sha256,args.legacy_build_source_commit,json.loads(legacy_receipt.read_text()))
    candidate_hash,legacy_hash=validate_binary_pins(candidate,legacy,args.expected_legacy_sha256)
    output=args.output.absolute();admitted=admit_output(output)
    before,runner_hash=source_identity(ROOT,candidate),file_hash(Path(__file__))
    parent=private_parent(args.work_parent)
    root=Path(tempfile.mkdtemp(prefix='userpass-names-upgrade-',dir=parent));root.chmod(0o700)
    instance=None;rows=[];failure=None
    try:
        from remote_jwks_live import Instance
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
    if not unchanged or not runner_unchanged or file_hash(legacy_receipt)!=receipt_hash:failure='source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete_checks(rows,required_cases=REQUIRED) or not rows or rows[-1]['case']!='complete':
        failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.userpass-names-upgrade.v1','status':'passed' if failure is None else 'failed',
        'failure':failure,'checks':rows,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':unchanged,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'build_source_commit':args.build_source_commit,'legacy_source_commit':args.legacy_build_source_commit,
        'legacy_binary_sha256':legacy_hash,'legacy_receipt_sha256':receipt_hash,
        'from_schema':39,'minimum_to_schema':40,'legacy_mount_adopted':False,
        'credential_storage_fabricated':False,'account_name_or_identity_rewritten':False,
        'old_reader_actually_executed':old_reader_observed(rows),'mutation_retries':0,
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
