#!/usr/bin/env python3
"""Actual schema38 userpass records -> schema39 CIDR and default-policy semantics.

The old executable creates every legacy account/token; no stored state, schema
or policy-list provenance is fabricated. HTTP peers are real socket addresses.
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
from userpass_password_live import safe_files, private_parent

LEGACY_SOURCE='b4942e9530c6ad44540d41084b292eb84d688798'
LEGACY_SHA256='413cc1a58192f57b992fcb04ee94df601347e9e7630b468d627e9155ef3f74b1'
LEGACY_RECEIPT=ROOT/'qa/openbao-acceptance/evidence/userpass-password-b4942e9.json'
MOUNT='params-upgrade'
REQUIRED=frozenset({'legacy_empty_issued','legacy_named_issued','pure_application_unchanged','pure_reads_unchanged',
 'pure_restart_application_unchanged','pure_restart_reads_unchanged','current_legacy_nil_root_renew_token_shape',
 'current_legacy_nil_root_renew_accessor_shape','current_old_named_other_source_shape','current_new_named_issued',
 'current_new_named_wrong_source_rejected','current_config_clear_old_snapshot_shape','current_clear_new_issued',
 'current_child_wrong_source_rejected','current_orphan_other_source_shape','current_fresh_nil_renew_token_rejected',
 'current_fresh_nil_expiry_unchanged','current_same_empty_renew_token_shape','current_same_empty_renew_accessor_shape',
 'reopen_application_unchanged','reopen_legacy_nil_renew_token_shape','reopen_old_bound_wrong_source_rejected',
 'reopen_fresh_nil_persist_renew_token_rejected','downgrade_unseal_rejected','downgrade_health_rejected',
 'downgrade_application_unchanged','recovery_old_bound_wrong_source_rejected','recovery_legacy_nil_renew_token_shape',
 'secret_samples_absent','complete'})

def admit_legacy_receipt(expected,receipt):
    before=receipt.get('candidate_source',{})
    if (expected!=LEGACY_SHA256 or receipt.get('schema')!='heptabao.userpass-password-comparison.v1'
        or receipt.get('status')!='passed' or receipt.get('oracle_only') is not False
        or receipt.get('build_source_commit')!=LEGACY_SOURCE or before.get('source_commit')!=LEGACY_SOURCE
        or before.get('binary_sha256')!=LEGACY_SHA256 or before.get('source_dirty') is not False
        or receipt.get('candidate_source_after')!=before or receipt.get('cases_match') is not True
        or receipt.get('source_and_binary_unchanged') is not True or receipt.get('runner_unchanged') is not True
        or receipt.get('oracle_binary_unchanged') is not True or receipt.get('failures')):
        raise ValueError('qualified_legacy38_receipt_required')
    sides=receipt.get('cases',{})
    if set(sides)!={'oracle','candidate'} or sides['oracle']!=sides['candidate']:
        raise ValueError('qualified_legacy38_actual_comparison_required')
    required={'userpass_password.compare.ascii.suffix1025.credentials','userpass_password.restart.old_token.valid','userpass_password.secrets_absent','userpass_password.complete'}
    for rows in sides.values():
        if not rows or any(row.get('passed') is not True for row in rows):raise ValueError('legacy_receipt_failed_case')
        names=[row.get('case') for row in rows]
        if len(names)!=len(set(names)) or not required.issubset(names) or names[-1]!='userpass_password.complete':raise ValueError('legacy_receipt_incomplete')

class Trace:
    def __init__(self,instance,rows,client=None):
        if client is None:
            from radius_cidrs_live import SourceClient
            client=SourceClient(instance.address,instance.root/'ca.crt',instance.token)
        self.client,self.rows=client,rows;self.sensitive=[instance.token]
    def check(self,name,passed):
        name=name.replace('.','_')
        if not re.fullmatch('[a-z0-9_]{1,140}',name):raise ValueError('unsafe_case')
        self.rows.append({'case':name,'passed':passed is True})
        if passed is not True:raise ScenarioFailure(name)
    def call(self,name,method,path,body=None,*,status=200,token=None,source='127.0.0.1'):
        r=self.client.request(method,path,body,token=token,source=source)
        self.check(name+'.status',r.status==status)
        self.check(name+'.source',self.client.last_family==4)
        if status>=400:self.check(name+'.rejected',not r.body.get('auth') and not r.body.get('wrap_info'))
        return r.body
    def write(self,name,user,fields):return self.call(name,'POST',f'auth/{MOUNT}/users/{user}',fields,status=204)
    def login(self,name,user,password,policies,*,status=200,source='127.0.0.1'):
        body=self.call(name,'POST',f'auth/{MOUNT}/login/{user}',{'password':password},status=status,token='',source=source)
        if status!=200:return None
        auth=body.get('auth') or {}
        self.check(name+'.issued',bool(auth.get('client_token')) and bool(auth.get('accessor')) and auth.get('policies')==policies and auth.get('metadata')=={'username':user})
        self.sensitive.append(auth['client_token']);return auth
    def lookup(self,name,auth,policies,bounds,*,self_lookup=False,source='127.0.0.2',status=200):
        data=self.call(name,'GET' if self_lookup else 'POST','auth/token/lookup-self' if self_lookup else 'auth/token/lookup',None if self_lookup else {'token':auth['client_token']},token=auth['client_token'] if self_lookup else None,source=source,status=status).get('data') or {}
        if status==200:self.check(name+'.shape',data.get('policies')==policies and data.get('bound_cidrs',[])==bounds and data.get('id')==auth['client_token'])
        return data
    def renew(self,name,auth,policies,*,self_status=200,status=200,self_source='127.0.0.1'):
        for tag,path,body,actor,source in [('self','renew-self',{},auth['client_token'],self_source),('token','renew',{'token':auth['client_token']},None,'127.0.0.2'),('accessor','renew-accessor',{'accessor':auth['accessor']},None,'127.0.0.2')]:
            expected=self_status if tag=='self' else status
            data=self.call(name+'.'+tag,'POST','auth/token/'+path,dict(body,increment=120),token=actor,source=source,status=expected)
            if expected==200:
                a=data.get('auth') or {};self.check(name+'.'+tag+'.shape',a.get('policies')==policies and a.get('renewable') is True and bool(a.get('client_token'))==(tag!='accessor'))
    def config(self,name,user,old):
        data=self.call(name,'GET',f'auth/{MOUNT}/users/{user}').get('data') or {}
        self.check(name+'.old_fields_preserved',all(data.get(k)==v for k,v in old.items()))
        self.check(name+'.new_defaults',data.get('token_bound_cidrs')==[] and data.get('token_no_default_policy') is False and 'bound_cidrs' not in data and 'token_policies_configured' not in data)

def run(instance,candidate,legacy,rows):
    instance.start();status,init=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure('initialization_failed')
    instance.token,key=init['root_token'],init['keys_base64'][0];t=Trace(instance,rows);password=secrets.token_urlsafe(24);t.sensitive.extend([key,password])
    t.call('legacy.unseal','POST','sys/unseal',{'key':key})
    t.call('legacy.mount','POST','sys/auth/'+MOUNT,{'type':'userpass'},status=204)
    t.call('legacy.tune','POST','sys/auth/'+MOUNT+'/tune',{'default_lease_ttl':120,'max_lease_ttl':600},status=204)
    rules='path "auth/token/renew-self" {capabilities=["update"]} path "auth/token/lookup-self" {capabilities=["read"]} path "auth/token/create" {capabilities=["update"]} path "auth/token/create-orphan" {capabilities=["update","sudo"]}'
    t.call('legacy.policy','PUT','sys/policies/acl/up-user',{'policy':rules},status=204)
    t.write('legacy.empty_write','empty',{'password':password})
    t.write('legacy.named_write','named',{'password':password,'token_policies':['up-user']})
    old_empty=t.login('legacy.empty','empty',password,['default']);old_named=t.login('legacy.named','named',password,['default','up-user'])
    old_configs={name:t.call('legacy.read_'+name,'GET',f'auth/{MOUNT}/users/{name}').get('data') for name in ('empty','named')}
    for name,data in old_configs.items():t.check('legacy.'+name+'.old_shape','token_no_default_policy' not in data and 'token_bound_cidrs' not in data)
    store=instance.root/'data'
    def restart(binary,phase):
        instance.stop();instance.binary=binary;instance.start();t.call(phase+'.unseal','POST','sys/unseal',{'key':key})
    instance.stop();application=durable_manifest(store,application_only=True)
    for phase in ('pure','pure_restart'):
        restart(candidate,phase);t.check(phase+'.application_unchanged',durable_manifest(store,application_only=True)==application)
        before=durable_manifest(store)
        for name in ('empty','named'):t.config(phase+'.'+name,name,old_configs[name])
        t.lookup(phase+'.old_empty',old_empty,['default'],[],self_lookup=True)
        t.lookup(phase+'.old_named',old_named,['default','up-user'],[],self_lookup=True)
        t.check(phase+'.reads_unchanged',durable_manifest(store)==before)
    # This is a real old list with unknown nil provenance. A flag-only write
    # must not reconstruct omitted policies; empty issued tokens can renew.
    t.write('current.legacy_flag','empty',{'token_no_default_policy':True})
    legacy_nil=t.login('current.legacy_nil','empty',password,[])
    t.renew('current.legacy_nil_root_renew',legacy_nil,[],self_status=403)
    t.renew('current.old_empty',old_empty,['default'],self_source='127.0.0.2')
    t.write('current.bound_named','named',{'token_bound_cidrs':['127.0.0.1'],'token_no_default_policy':True})
    t.login('current.named_denied','named',password,[],status=403,source='127.0.0.2')
    fresh=t.login('current.new_named','named',password,['up-user'])
    t.lookup('current.new_named_wrong_source',fresh,['up-user'],['127.0.0.1'],self_lookup=True,status=403)
    t.lookup('current.old_named_other_source',old_named,['default','up-user'],[],self_lookup=True)
    t.renew('current.old_named_renew',old_named,['default','up-user'],self_source='127.0.0.2')
    t.renew('current.new_named_renew',fresh,['up-user'])
    for tag,route,bounds in [('child','create',['127.0.0.1']),('orphan','create-orphan',[])]:
        auth=t.call('current.'+tag+'.create','POST','auth/token/'+route,{'policies':['up-user'],'no_default_policy':True,'ttl':120},token=fresh['client_token']).get('auth') or {};t.sensitive.append(auth['client_token'])
        t.lookup('current.'+tag+'.snapshot',auth,['up-user'],bounds)
        t.lookup('current.'+tag+('.wrong_source' if bounds else '.other_source'),auth,['up-user'],bounds,self_lookup=True,status=403 if bounds else 200)
    t.write('current.clear','named',{'token_bound_cidrs':[],'token_no_default_policy':False})
    t.lookup('current.config_clear_old_snapshot',fresh,['up-user'],['127.0.0.1'])
    clear=t.login('current.clear_new','named',password,['default','up-user'],source='127.0.0.2')
    for name in ('fresh','persist'):
        t.write('current.'+name+'.write',name,{'password':password,'token_no_default_policy':True})
    nil=t.login('current.fresh_nil','fresh',password,[]);persist=t.login('current.persist_nil','persist',password,[])
    before=t.lookup('current.fresh_nil_before',nil,[],[])
    t.renew('current.fresh_nil_renew',nil,[],status=500,self_status=403)
    after=t.lookup('current.fresh_nil_after',nil,[],[]);t.check('current.fresh_nil_expiry_unchanged',before.get('expire_time')==after.get('expire_time'))
    t.write('current.explicit_empty','fresh',{'token_policies':None})
    t.renew('current.same_empty_renew',nil,[],self_status=403)
    instance.stop();application=durable_manifest(store,application_only=True);restart(candidate,'reopen');t.check('reopen.application_unchanged',durable_manifest(store,application_only=True)==application)
    def verify(phase):
        t.lookup(phase+'.old_bound_wrong_source',fresh,['up-user'],['127.0.0.1'],self_lookup=True,status=403)
        t.lookup(phase+'.old_named',old_named,['default','up-user'],[],self_lookup=True)
        t.lookup(phase+'.new_unbound',clear,['default','up-user'],[],self_lookup=True)
        t.renew(phase+'.legacy_nil_renew',legacy_nil,[],self_status=403)
        t.renew(phase+'.fresh_nil_persist_renew',persist,[],status=500,self_status=403)
        t.renew(phase+'.explicit_empty_renew',nil,[],self_status=403)
        t.renew(phase+'.bound_renew',fresh,['up-user'])
    verify('reopen');instance.stop();application=durable_manifest(store,application_only=True)
    instance.binary=legacy;instance.start();t.call('downgrade.unseal','POST','sys/unseal',{'key':key},status=503);t.call('downgrade.health','GET','sys/health',status=503);instance.stop();t.check('downgrade.application_unchanged',durable_manifest(store,application_only=True)==application)
    restart(candidate,'recovery');verify('recovery');instance.stop();t.check('secret_samples_absent',safe_files(instance.root,t.sensitive));t.check('complete',True)


def main():
    parser=SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--legacy-binary',type=Path,required=True)
    parser.add_argument('--expected-legacy-sha256',required=True)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--work-parent',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('invalid build commit')
    candidate,legacy=args.binary.resolve(strict=True),args.legacy_binary.resolve(strict=True)
    admit_legacy_receipt(args.expected_legacy_sha256,json.loads(LEGACY_RECEIPT.read_text()))
    candidate_hash,legacy_hash=validate_binary_pins(candidate,legacy,args.expected_legacy_sha256)
    output=args.output.absolute();admitted=admit_output(output)
    before,runner_hash=source_identity(ROOT,candidate),file_hash(Path(__file__))
    parent=private_parent(args.work_parent)
    root=Path(tempfile.mkdtemp(prefix='userpass-params-upgrade-',dir=parent));root.chmod(0o700)
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
    if not unchanged or not runner_unchanged:failure='source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure='source_dirty'
    if not complete_checks(rows,required_cases=REQUIRED) or not rows or rows[-1]['case']!='complete':
        failure=failure or 'incomplete_observations'
    report={'schema':'heptabao.userpass-params-upgrade.v1','status':'passed' if failure is None else 'failed',
        'failure':failure,'checks':rows,'source_identity':before,'source_identity_after':after,
        'source_and_binary_unchanged':unchanged,'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,
        'build_source_commit':args.build_source_commit,'legacy_source_commit':LEGACY_SOURCE,
        'legacy_binary_sha256':legacy_hash,'legacy_receipt_sha256':file_hash(LEGACY_RECEIPT),
        'from_schema':38,'minimum_to_schema':39,'socket_peer_families':[4],
        'credential_storage_fabricated':False,'policy_presence_fabricated':False,
        'old_reader_actually_executed':True,'mutation_retries':0,
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
