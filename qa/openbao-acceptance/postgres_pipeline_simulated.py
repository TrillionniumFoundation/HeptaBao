#!/usr/bin/env python3
"""Real TLS Service/PG-wire/SCRAM pipeline against a labelled provider MODEL.

This intentionally does NOT execute provider.sql, PostgreSQL roles or sessions.
Use postgres_live.py with PostgreSQL 17 binaries for the real-provider gate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
from external_tls_fixtures import PgWireFixture
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'qa/single-node'))
from smoke import Instance


def run(binary,root,checks):
    instance=Instance(binary,root/'candidate')
    provider=PgWireFixture(instance.root/'tls.crt',instance.root/'tls.key')
    config_path=instance.root/'server.json'
    config=json.loads(config_path.read_text())
    config['lifecycle_interval_seconds']=0
    config['outbound_endpoints']=[dict(origin=provider.origin,address=f'127.0.0.1:{provider.port}',server_name='localhost',ca_pem=(instance.root/'ca.crt').read_text())]
    config_path.write_text(json.dumps(config));config_path.chmod(0o600)
    def check(name,condition):
        checks.append(dict(case=name,passed=condition is True))
        if condition is not True:raise RuntimeError(name)
    def call(method,path,body=None,**kwargs):return instance.call(method,path,body,**kwargs)
    def row(username):return next(v for v in provider.rows.values() if v['username']==username)
    def phase(identity):
        status,body=call('POST','sys/leases/lookup',{'lease_id':identity})
        return 'Retired' if status in (400,404) else body.get('data',{}).get('phase')
    def reconcile(identity):return call('POST','sys/leases/reconcile/'+identity,{})
    params={'plugin_name':'postgresql-database-plugin','connection_url':provider.origin+'/app','username':provider.manager,'password':provider.password,'allowed_roles':['reader','short']}
    try:
        instance.start();status,init=call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
        check('initialize',status==200);instance.token=init['root_token'];key=init['keys_base64'][0]
        check('unseal',call('POST','sys/unseal',{'key':key})[0]==200)
        check('mount',call('POST','sys/mounts/database',{'type':'database'})[0]==204)
        check('provider_config_auth_before_network',call('POST','database/config/local',params,token='invalid')[0]==403 and not provider.events)
        for mode in ('refuse_tls','wrong_server_proof'):
            provider.mode=mode
            check(mode+'_no_weak_auth_fallback',call('POST','database/config/local',params)[0]==503)
        provider.mode='normal'
        check('verified_scram_configuration',call('POST','database/config/local',params)[0]==204)
        check('configuration_never_returns_password',provider.password not in json.dumps(call('GET','database/config/local')[1]))
        check('no_arbitrary_sql',call('POST','database/roles/reader',{'db_name':'local','creation_statements':['CREATE USER dangerous']})[0]==400)
        check('role',call('POST','database/roles/reader',{'db_name':'local','provider_role':'app_reader','default_ttl':'30s','max_ttl':'300s'})[0]==204)
        check('unauthorized_issue_no_effect',call('GET','database/creds/reader',token='invalid')[0]==403 and not provider.events)
        check('wrapping_rejected_before_effect',call('GET','database/creds/reader',extra_headers={'X-Vault-Wrap-TTL':'60s'})[0]==501 and not provider.events)
        status,issued=call('GET','database/creds/reader');check('issue_after_durable_intent_and_readback',status==200 and issued.get('renewable') is True)
        identity=issued['lease_id'];username=issued['data']['username'];password=issued['data']['password'];initial=row(username)
        check('model_observed_matches_returned_credentials',initial['test_password']==password and initial['login'] is True)
        check('provider_id_is_scope_bound_not_api_id',initial['lease_id'].startswith('hb1:') and initial['lease_id']!=identity)
        check('lookup_active',phase(identity)=='Active')
        check('lease_list',identity.rsplit('/',1)[1] in call('LIST','sys/leases/lookup/database/creds/reader')[1]['data']['keys'])
        check('provider_identity_frozen',call('POST','database/config/local',params)[0]==409)
        check('mount_retains_provider_fences',call('DELETE','sys/mounts/database')[0]==409)
        status,renew=call('POST','sys/leases/renew',{'lease_id':identity,'increment':'100s'})
        check('renew_external_expiry_then_commit',status==200 and row(username)['seq']==2 and row(username)['expires']>initial['expires'])
        check('maximum_ttl_enforced',call('POST','sys/leases/renew',{'lease_id':identity,'increment':'25h'})[0]==400)
        instance.stop();instance.start();check('restart_unseal',call('POST','sys/unseal',{'key':key})[0]==200)
        check('renewed_lease_survives_restart',phase(identity)=='Active')
        check('authorized_path_not_redirected_by_body',call('POST','sys/leases/revoke/'+identity,{'lease_id':identity+'other'})[0]==400)
        check('precise_revoke',call('POST','sys/leases/revoke',{'lease_id':identity})[0]==204)
        check('model_retired_before_completion',initial['lease_id'] not in provider.rows and phase(identity)=='Retired')
        check('revoke_idempotent',call('POST','sys/leases/revoke',{'lease_id':identity})[0]==204)
        check('renew_revoked_rejected',call('POST','sys/leases/renew',{'lease_id':identity})[0]==400)
        # TLS disappears before provider execution, AFTER service intent exists.
        provider.mode='before_entry'
        status,pending=call('GET','database/creds/reader');pending_id=pending.get('lease_id','')
        check('transport_failure_retains_intent_no_secret',status==503 and pending_id.startswith('database/creds/') and 'data' not in pending)
        check('intent_visible_after_failure',phase(pending_id)=='PendingIssue')
        instance.stop();instance.start();check('pending_restart_unseal',call('POST','sys/unseal',{'key':key})[0]==200)
        check('pending_restart_is_not_reissued',phase(pending_id)=='PendingIssue')
        provider.mode='normal'
        check('missing_provider_issue_reconciles_to_retirement',reconcile(pending_id)[0]==204 and phase(pending_id)=='Retired')
        # Provider has applied, response disappears. No plaintext escapes; cancel
        # by a higher sequence instead of replaying issue or guessing absence.
        provider.mode='drop_after_apply';status,pending=call('GET','database/creds/reader');pending_id=pending.get('lease_id','')
        check('lost_post_apply_response_no_secret',status==503 and 'data' not in pending and phase(pending_id)=='PendingIssue')
        user=provider.rows[provider.events[-1][0]]['username']
        check('lost_response_model_effect_exists',row(user)['login'] is True)
        old=dict(row(user))
        check('reconcile_external_effect_before_success',reconcile(pending_id)[0]==204 and old['lease_id'] not in provider.rows and phase(pending_id)=='Retired')
        check('model_global_fence_rejects_delayed_issue',provider.apply([old['fence_id'],old['lease_id'],user,str(old['seq']),'issue',str(int(time.time())+60),'app_reader','ab'*32,'ab'*32])=='ERROR')
        provider.mode='wrong_observation';status,pending=call('GET','database/creds/reader');pending_id=pending.get('lease_id','')
        check('mismatched_readback_not_success',status==503 and phase(pending_id)=='PendingIssue')
        check('mismatched_readback_reconciles',reconcile(pending_id)[0]==204)
        status,issued=call('GET','database/creds/reader');check('renew_uncertainty_seed',status==200)
        identity=issued['lease_id'];username=issued['data']['username']
        provider.mode='drop_after_apply';status,response=call('POST','sys/leases/renew',{'lease_id':identity,'increment':'120s'})
        check('uncertain_renewal_durable',status==503 and phase(identity)=='PendingRenew')
        provider.mode='before_entry';check('unavailable_revoke_never_reports_completed',reconcile(identity)[0]==503 and phase(identity)=='PendingRevoke')
        provider.mode='normal';check('uncertain_renewal_retired_with_sequence_skip',reconcile(identity)[0]==204 and all(v['username']!=username for v in provider.rows.values()) and phase(identity)=='Retired')
        check('short_role',call('POST','database/roles/short',{'db_name':'local','provider_role':'app_reader','default_ttl':'2s','max_ttl':'10s'})[0]==204)
        instance.stop();config['lifecycle_interval_seconds']=1;config_path.write_text(json.dumps(config));config_path.chmod(0o600)
        instance.start();check('worker_unseal',call('POST','sys/unseal',{'key':key})[0]==200)
        status,issued=call('GET','database/creds/short');check('expiry_seed',status==200)
        username=issued['data']['username'];identity=issued['lease_id'];deadline=time.monotonic()+10
        # No API request triggers expiration; inspect only the external model.
        while any(v['username']==username for v in provider.rows.values()) and time.monotonic()<deadline:time.sleep(.1)
        check('idle_worker_retires_model_without_client_requests',all(v['username']!=username for v in provider.rows.values()))
        check('idle_worker_terminal_lease_retired',phase(identity)=='Retired')
        check('provider_protocol_fixture_clean',provider.server_errors==[])
        forbidden=[provider.password,password]
        check('audit_does_not_expose_credentials',all(v.encode() not in (instance.root/'audit.jsonl').read_bytes() for v in forbidden))
        check('encrypted_state_does_not_expose_credentials',all(v.encode() not in f.read_bytes() for f in (instance.root/'data').rglob('*') if f.is_file() for v in forbidden))
    finally:
        instance.stop();provider.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    binary=Path(a.binary).resolve(strict=True);output=Path(a.output).resolve();checks=[]
    if output.exists():p.error('output must be new')
    before=hashlib.sha256(binary.read_bytes()).hexdigest();root=Path(tempfile.mkdtemp(prefix='hb-pg-model-'))
    report={'schema':'heptabao.postgres-protocol-model.v1','provider_kind':'SIMULATED_PG_WIRE_NOT_POSTGRESQL','real_postgresql_executed':False,'provider_sql_executed':False,'independent_qualification':False,'checks':checks,'binary_sha256':before}
    try:
        run(binary,root,checks);report['status']='passed'
    except Exception as e:
        report['status']='failed';report['failure']=str(e) if type(e) is RuntimeError else type(e).__name__
    finally:
        shutil.rmtree(root)
        report['binary_unchanged']=hashlib.sha256(binary.read_bytes()).hexdigest()==before
        if not report['binary_unchanged']:report['status']='failed'
        report['check_count']=len(checks);output.write_text(json.dumps(report,indent=2)+'\n');output.chmod(0o600)
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':report.get('failure'),'real_postgresql_executed':False}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
