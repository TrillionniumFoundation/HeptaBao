#!/usr/bin/env python3
"""Real schema-23 RADIUS URL state through schema-24 native config/users.

No handcrafted state: old finite/periodic/TokenApi tokens are issued by the
pinned legacy binary. Both PAP endpoints use synthetic signed UDP replies.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from bao_http import Client,SafeArgumentParser,private_write
from core_isolation import ROOT,ScenarioFailure,file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output,source_identity
from provider_renewal_upgrade import durable_manifest
from radius_native_live import NativeRadius
from radius_native_upgrade import Trace as RadiusTrace
from radius_renewal_live import RadiusResponder,SECRET,PASSWORD,renewal_token_shape
from remote_jwks_live import Instance

LEGACY_SOURCE='b100de4c55739f716f81e7f018cf86c1e6db0672'
LEGACY_SHA256='a576483f47b908092fcb9e351d278a5acc53924d06b8245186549a07349a242d'
LEGACY_RECEIPT=ROOT/'qa/openbao-acceptance/evidence/ldap-native-upgrade-b0c3981-to-b100de4.json'
NATIVE_SECRET=b'synthetic-native-radius-upgrade-secret'


def admit_legacy(candidate,legacy,expected,receipt):
    required={'build_source_commit':LEGACY_SOURCE,'harness_source_commit':LEGACY_SOURCE,
              'harness_source_dirty':False,'harness_source_unchanged':True,'binaries_unchanged':True,
              'candidate_binary_sha256':LEGACY_SHA256,'status':'passed'}
    if expected!=LEGACY_SHA256 or any(receipt.get(key)!=value for key,value in required.items()):
        raise ValueError('legacy_schema23_build_receipt_mismatch')
    return validate_binary_pins(candidate,legacy,expected)


class Trace(RadiusTrace):
    def check(self,name,condition,**observed):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(value) not in (bool,int) for value in observed.values()):
            raise ValueError('unsafe_trace_field')
        case='radius_config_native_upgrade.'+name
        self.cases.append({'case':case,**observed,'passed':bool(condition)})
        if not condition:raise ScenarioFailure(case)


def enroll(instance,legacy_provider,native_provider=None):
    settings=json.loads((instance.root/'server.json').read_text());settings['lifecycle_interval_seconds']=0
    def endpoint(provider):
        return {'origin':f'radius://127.0.0.1:{provider.port}','address':f'127.0.0.1:{provider.port}',
                'server_name':'127.0.0.1','ca_pem':'','path_prefix':'/'}
    settings['outbound_endpoints']=[dict(endpoint(legacy_provider),shared_secret=SECRET.decode())]
    if native_provider is not None:settings['outbound_endpoints'].append(endpoint(native_provider))
    private_write(instance.root/'server.json',settings,replace=True)


def auth_shape(auth):
    return all(isinstance(auth.get(key),str) and auth[key] for key in ('client_token','accessor','entity_id')) and auth.get('renewable') is True


def prepare_legacy(instance,provider,cases):
    instance.start();status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure('radius_config_native_upgrade.initialize')
    instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
    t=Trace(Client(instance.address,str(instance.root/'ca.crt'),instance.token),cases,provider)
    t.call('legacy.unseal','sys/unseal',{'key':key})
    rules=('path "secret/data/radius-config-upgrade" { capabilities = ["read"] }\n'
           'path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
           'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call('legacy.policy','sys/policies/acl/upgrade-reader',{'policy':rules},method='PUT',expected=204)
    t.call('legacy.value','secret/data/radius-config-upgrade',{'data':{'synthetic':True}})
    tokens={};configs={}
    for label,period,cap in [('finite',0,0),('periodic',300,900)]:
        mount='radius-'+label
        t.call('legacy.'+label+'.mount','sys/auth/'+mount,{'type':'radius'},expected=204)
        config={'url':f'radius://127.0.0.1:{provider.port}','token_policies':['default','upgrade-reader'],
                'token_ttl':300,'token_max_ttl':600,'token_period':period,'token_explicit_max_ttl':cap}
        t.call('legacy.'+label+'.config','auth/'+mount+'/config',config,expected=204);configs[label]=config
        auth=t.call('legacy.'+label+'.login','auth/'+mount+'/login',{'username':'alice','password':PASSWORD.decode()},token='',provider=True).get('auth',{})
        t.check('legacy.'+label+'.shape',auth_shape(auth) and auth.get('lease_duration')==300);tokens[label]=auth
        data=t.call('legacy.'+label+'.lookup','auth/token/lookup-self',method='GET',token=auth['client_token']).get('data',{})
        t.check('legacy.'+label+'.issued_parameters',data.get('period')==(period or None) and data.get('explicit_max_ttl')==cap)
    for label,path in [('child','auth/token/create'),('orphan','auth/token/create-orphan')]:
        auth=t.call('legacy.'+label+'.create',path,{'policies':['default','upgrade-reader'],'ttl':300},token=tokens['finite']['client_token']).get('auth',{})
        t.check('legacy.'+label+'.shape',auth_shape(auth));tokens[label]=auth
    for label in ('finite','periodic'):
        body=t.call('legacy.'+label+'.renew','auth/token/renew-self',{'increment':300},token=tokens[label]['client_token'],provider=True)
        t.check('legacy.'+label+'.renewed',body.get('auth',{}).get('lease_duration')==300)
    t.check('legacy.complete',True)
    return t,key,configs,tokens


def run_upgrade(instance,legacy_provider,native_provider,candidate,legacy,cases):
    t,key,configs,tokens=prepare_legacy(instance,legacy_provider,cases)
    instance.stop();store=instance.root/'data';old_application=durable_manifest(store,application_only=True)
    # schema23 cannot parse an empty process-secret enrollment. Changing only
    # deployment enrollment ensures downgrade tests exercise the state fence.
    enroll(instance,legacy_provider,native_provider);instance.binary=candidate;instance.start()
    t.call('current.unseal','sys/unseal',{'key':key})
    t.check('current.reopen_preserves_application',durable_manifest(store,application_only=True)==old_application)
    before=durable_manifest(store)
    for label,auth in tokens.items():
        value=t.call('current.'+label+'.read','secret/data/radius-config-upgrade',method='GET',token=auth['client_token'])
        t.check('current.'+label+'.value',value.get('data',{}).get('data')=={'synthetic':True})
        data=t.call('current.'+label+'.lookup','auth/token/lookup-self',method='GET',token=auth['client_token']).get('data',{})
        if label in ('finite','periodic'):
            t.check('current.'+label+'.issued_parameters',data.get('period')==(300 if label=='periodic' else None) and data.get('explicit_max_ttl')==(900 if label=='periodic' else 0))
    for label in ('finite','periodic'):
        data=t.call('current.'+label+'.config','auth/radius-'+label+'/config',method='GET').get('data',{})
        t.check('current.'+label+'.config_unchanged',all(data.get(k)==v for k,v in configs[label].items()))
    t.check('current.pure_reads_preserve_store',durable_manifest(store)==before)
    native_config={'host':'127.0.0.1','port':native_provider.port,'secret':NATIVE_SECRET.decode(),
                   'token_policies':['upgrade-reader'],'unregistered_user_policies':'native-fallback',
                   'token_ttl':300,'token_max_ttl':600}
    t.call('current.legacy_to_native_denied','auth/radius-finite/config',native_config,expected=409)
    t.check('current.profile_denial_unchanged',durable_manifest(store)==before)
    for label in ('finite','periodic'):
        body=t.call('current.'+label+'.renew','auth/token/renew-self',{'increment':300},token=tokens[label]['client_token'],provider=True)
        t.check('current.'+label+'.lease_preserved',body.get('auth',{}).get('lease_duration')==300)
    t.call('native.mount','sys/auth/radius-native',{'type':'radius'},expected=204)
    t.call('native.config','auth/radius-native/config',native_config,expected=204)
    native=Trace(t.client,cases,native_provider);before=durable_manifest(store)
    native.call('native.to_legacy_denied','auth/radius-native/config',configs['finite'],expected=409)
    native.check('native.profile_denial_unchanged',durable_manifest(store)==before)
    data=native.call('native.config_read','auth/radius-native/config',method='GET').get('data',{})
    native.check('native.secret_redacted','secret' not in data and NATIVE_SECRET.decode() not in json.dumps(data))
    native.call('native.user_absent','auth/radius-native/users/alice',method='GET',expected=404)
    auth=native.call('native.login_without_map','auth/radius-native/login',{'username':'alice','password':PASSWORD.decode()},token='',provider=True).get('auth',{})
    native.check('native.shape',auth_shape(auth) and auth.get('lease_duration')==300 and set(auth.get('token_policies',[]))=={'default','upgrade-reader','native-fallback'} and auth['entity_id']!=tokens['finite']['entity_id']);tokens['native']=auth
    for via,path,payload,actor in [('self','auth/token/renew-self',{},auth['client_token']),('token','auth/token/renew',{'token':auth['client_token']},None),('accessor','auth/token/renew-accessor',{'accessor':auth['accessor']},None)]:
        response=native.call('native.'+via+'.renew',path,dict(payload,increment=300),token=actor,provider=True)
        native.check('native.'+via+'.shape',response.get('auth',{}).get('lease_duration')==300 and renewal_token_shape(response.get('auth'),auth['client_token'],via_accessor=via=='accessor'))
    native.call('native.map_changed','auth/radius-native/users/alice',{'policies':['changed']},expected=204)
    before=durable_manifest(store)
    denied=native.call('native.changed_policy_denied','auth/token/renew-self',{'increment':300},token=auth['client_token'],provider=True,expected=500)
    native.check('native.changed_policy_no_mutation',not denied.get('auth') and not denied.get('wrap_info') and durable_manifest(store)==before)
    native.call('native.map_deleted','auth/radius-native/users/alice',method='DELETE',expected=204)
    native.call('native.fallback_restores_renewal','auth/token/renew-self',{'increment':300},token=auth['client_token'],provider=True)
    before=durable_manifest(store);native_provider.allow=False
    native.call('native.provider_reject','auth/token/renew-self',{'increment':300},token=auth['client_token'],provider=False,expected=400)
    native.check('native.provider_reject_no_mutation',durable_manifest(store)==before);native_provider.allow=True
    instance.stop();upgraded_application=durable_manifest(store,application_only=True)
    native.check('native.mutation_persisted',upgraded_application!=old_application)
    enroll(instance,legacy_provider);instance.binary=legacy;instance.start()
    t.call('downgrade.unseal_rejected','sys/unseal',{'key':key},expected=503)
    t.call('downgrade.still_sealed','sys/health',method='GET',expected=503)
    instance.stop();t.check('downgrade.application_unchanged',durable_manifest(store,application_only=True)==upgraded_application)
    enroll(instance,legacy_provider,native_provider);instance.binary=candidate;instance.start()
    t.call('recovery.unseal','sys/unseal',{'key':key})
    t.check('recovery.application_unchanged',durable_manifest(store,application_only=True)==upgraded_application)
    for label,auth in tokens.items():
        value=t.call('recovery.'+label+'.read','secret/data/radius-config-upgrade',method='GET',token=auth['client_token'])
        t.check('recovery.'+label+'.value',value.get('data',{}).get('data')=={'synthetic':True})
    for label in ('finite','periodic','native'):
        trace=native if label=='native' else t
        response=trace.call('recovery.'+label+'.renew','auth/token/renew-self',{'increment':300},token=tokens[label]['client_token'],provider=True)
        trace.check('recovery.'+label+'.lease',response.get('auth',{}).get('lease_duration')==300)
    legacy_provider.allow=False;native_provider.allow=False;legacy_cursor=legacy_provider.count();native_cursor=native_provider.count()
    for label in ('child','orphan'):
        t.call('recovery.'+label+'.renew_without_provider','auth/token/renew-self',{'increment':300},token=tokens[label]['client_token'])
    t.check('recovery.children_no_provider_dependency',legacy_provider.count()==legacy_cursor and native_provider.count()==native_cursor)
    instance.stop()
    secrets=[SECRET.decode(),NATIVE_SECRET.decode(),PASSWORD.decode(),key,instance.token,*(auth['client_token'] for auth in tokens.values())]
    files=[p for p in store.rglob('*') if p.is_file()]+[instance.root/'server.log',instance.root/'audit.jsonl']
    t.check('plaintext_credentials_absent',all(secret.encode() not in path.read_bytes() for path in files if path.exists() for secret in secrets))
    t.check('complete',True)


MILESTONES={'legacy.complete','current.pure_reads_preserve_store','current.profile_denial_unchanged','native.profile_denial_unchanged',
            'native.changed_policy_no_mutation','native.fallback_restores_renewal','native.provider_reject_no_mutation',
            'downgrade.application_unchanged','recovery.application_unchanged','recovery.children_no_provider_dependency','plaintext_credentials_absent','complete'}
def complete_scenarios(rows):
    if not rows or any(row.get('passed') is not True for row in rows):return False
    names=[row.get('case') for row in rows]
    if any(not isinstance(name,str) for name in names) or len(set(names))!=len(names):return False
    return {'radius_config_native_upgrade.'+name for name in MILESTONES}.issubset(names) and names[-1]=='radius_config_native_upgrade.complete'


def main():
    parser=SafeArgumentParser(description=__doc__)
    for name in ('binary','legacy-binary','expected-legacy-sha256','build-source-commit','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    if re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None:parser.error('full build source commit required')
    candidate,legacy=Path(args.binary).resolve(strict=True),Path(args.legacy_binary).resolve(strict=True)
    candidate_hash,legacy_hash=admit_legacy(candidate,legacy,args.expected_legacy_sha256,json.loads(LEGACY_RECEIPT.read_text()))
    output=Path(args.output).absolute();parent=admit_output(output);before=source_identity(ROOT,candidate);runner_hash=file_hash(Path(__file__))
    root=Path(tempfile.mkdtemp(prefix='heptabao-radius-config-upgrade-'));root.chmod(0o700)
    instance=None;providers=[]
    result={'schema':'heptabao.radius-config-native-upgrade.v1','from_schema':23,'minimum_to_schema':24,'synthetic_only':True,'actual_https_udp':True,
            'legacy_source_commit':LEGACY_SOURCE,'legacy_binary_sha256':legacy_hash,'legacy_receipt_sha256':file_hash(LEGACY_RECEIPT),
            'candidate_binary_sha256':candidate_hash,'build_source_commit':args.build_source_commit,'runner_sha256':runner_hash,
            'build_source_binding_basis':'caller-supplied commit and observed binary hash; not independent attestation',
            'full_openbao_compatibility':False,'full_migration_qualification':False,'rolling_upgrade_qualification':False,'independent_qualification':False,'production_authority':False,
            'reopen_replay_ledger_may_change':True,'unchanged_application_artifacts_scope':'all store entries except root ledger.hbl, rebuilt before schema admission',
            'deployment_enrollment_adaptation':'legacy process-secret endpoint retained; native address without process-secret added only for new binary; downgrade restores legacy-valid enrollment without changing store',
            'started_at_unix':time.time(),'cases':[]}
    try:
        instance=Instance(legacy,root/'instance');legacy_provider=RadiusResponder(require_ma=True);providers.append(legacy_provider)
        native_provider=NativeRadius(require_ma=True);native_provider.secret=NATIVE_SECRET;providers.append(native_provider)
        enroll(instance,legacy_provider)
        run_upgrade(instance,legacy_provider,native_provider,candidate,legacy,result['cases'])
        result['status']='passed' if complete_scenarios(result['cases']) else 'failed'
    except Exception as e:result['status']='failed';result['safe_failure_code']=str(e) if isinstance(e,ScenarioFailure) else 'unexpected_'+type(e).__name__
    finally:
        if instance is not None:instance.stop()
        for provider in providers:provider.close()
        shutil.rmtree(root);after=source_identity(ROOT,candidate)
        result['binaries_unchanged']=after['binary_sha256']==candidate_hash and file_hash(legacy)==legacy_hash
        for field in ('source_commit','source_tree','source_dirty','source_content_sha256'):result['harness_'+field]=before[field]
        result['harness_source_unchanged']=before==after;result['finished_at_unix']=time.time()
        if not result['binaries_unchanged'] or file_hash(Path(__file__))!=runner_hash or before!=after:result['status']='failed';result['safe_failure_code']='source_or_binary_changed_during_execution'
        if admit_output(output)!=parent:raise ValueError('report_parent_changed')
        private_write(output,result,replace=False)
    print(json.dumps({'status':result['status'],'checks':len(result['cases']),'safe_failure_code':result.get('safe_failure_code')}))
    return 0 if result['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
