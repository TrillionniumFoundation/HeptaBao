#!/usr/bin/env python3
"""Pinned schema-25 native RADIUS enrollment through schema-26 API transport.

Real signed UDP PAP, private fresh stores, and exact legacy binary/source pins.
Preparation mode runs the old binary only and makes no upgrade claim.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
import time

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_native_live import NativeRadius, Trace as NativeTrace, SECRET, PASSWORD, config_matches
from radius_renewal_live import renewal_token_shape
from remote_jwks_live import Instance

LEGACY_SOURCE = '5c6aa9050787d15ab7278f6203a1dc598061755f'
LEGACY_SHA256 = '39639ae7db60fe2c78ad6403e7114708579ad7690ef28c83e1a862860b1a2751'
LEGACY_RECEIPT = ROOT / 'qa/openbao-acceptance/evidence/radius-native-live-5c6aa90.json'
MOUNT = 'radius-api-upgrade'
PORT_MOUNT = 'radius-api-port-upgrade'
CONFIG_PATH = 'auth/' + MOUNT + '/config'
VALUE_PATH = 'secret/data/radius-api-upgrade'


def admit_legacy_receipt(expected, receipt):
    identity = receipt.get('source_identity', {})
    if (expected != LEGACY_SHA256 or receipt.get('status') != 'passed'
            or receipt.get('source_and_binary_unchanged') is not True
            or receipt.get('cases_match') is not True
            or identity.get('source_commit') != LEGACY_SOURCE
            or identity.get('binary_sha256') != LEGACY_SHA256
            or identity.get('source_dirty') is not False):
        raise ValueError('legacy_schema25_build_receipt_mismatch')


def admit_legacy(candidate, legacy, expected, receipt):
    admit_legacy_receipt(expected, receipt)
    return validate_binary_pins(candidate, legacy, expected)


class Trace(NativeTrace):
    def check(self, name, condition, **observed):
        if (not re.fullmatch(r'[a-z0-9_.]{1,140}', name)
                or any(type(value) not in (bool, int) for value in observed.values())):
            raise ValueError('unsafe_upgrade_observation')
        case = 'radius_api_transport_upgrade.' + name
        self.rows.append({'case': case, **observed, 'passed': bool(condition)})
        if not condition:raise ScenarioFailure(case)
    def ttl(self, name, auth):
        value = self.call(name, 'GET', 'auth/token/lookup-self', token=auth['client_token']).get('data', {}).get('ttl')
        self.check(name + '.positive', type(value) is int and value > 0)
        return value


def enrolled_settings(instance, provider):
    settings = json.loads((instance.root / 'server.json').read_text())
    settings['lifecycle_interval_seconds'] = 0
    settings['outbound_endpoints'] = [{'origin': f'radius://127.0.0.1:{provider.port}',
        'address': f'127.0.0.1:{provider.port}', 'server_name': '127.0.0.1', 'ca_pem': '', 'path_prefix': '/'}]
    return settings


def restart(instance, binary, settings, t, name, key):
    instance.stop();private_write(instance.root / 'server.json', settings)
    instance.binary = binary;instance.start()
    t.call(name + '.unseal', 'POST', 'sys/unseal', {'key': key})


def renewals(t, prefix, auth, *, expected=200, contact=True, increment=300):
    for via, path, payload, actor in [
        ('self','renew-self',{},auth['client_token']),
        ('token','renew',{'token':auth['client_token']},None),
        ('accessor','renew-accessor',{'accessor':auth['accessor']},None),
    ]:
        cursor=t.provider.count()
        response=t.call(prefix+'.'+via,'POST','auth/token/'+path,dict(payload,increment=increment),
                        token=actor,expected=expected,contact=contact)
        if contact is None:t.check(prefix+'.'+via+'.no_pap',t.provider.count()==cursor)
        if expected==200:
            auth_result=response.get('auth',{})
            t.check(prefix+'.'+via+'.shape',auth_result.get('lease_duration')==increment
                    and renewal_token_shape(auth_result,auth['client_token'],via_accessor=via=='accessor'))
        else:t.check(prefix+'.'+via+'.no_secret',not response.get('auth') and not response.get('wrap_info'))


def prepare_legacy(instance, provider, cases):
    instance.start()
    status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure('radius_api_transport_upgrade.legacy.initialize')
    instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
    t=Trace(Client(instance.address,str(instance.root/'ca.crt'),instance.token),provider,cases)
    t.call('legacy.unseal','POST','sys/unseal',{'key':key})
    policy=('path "'+VALUE_PATH+'" { capabilities = ["read"] }\n'
            'path "auth/token/create" { capabilities = ["update", "sudo"] }\n'
            'path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }')
    t.call('legacy.policy','PUT','sys/policies/acl/upgrade-reader',{'policy':policy},expected=204)
    config={'host':'127.0.0.1','port':provider.port,'secret':SECRET.decode(),
            'token_ttl':300,'token_max_ttl':3600,'token_policies':['upgrade-reader']}
    tokens={}
    for name,mount in [('direct',MOUNT),('port_direct',PORT_MOUNT)]:
        t.call('legacy.'+name+'.mount','POST','sys/auth/'+mount,{'type':'radius'},expected=204)
        t.call('legacy.'+name+'.config','POST','auth/'+mount+'/config',config,expected=204)
        read=t.call('legacy.'+name+'.config_read','GET','auth/'+mount+'/config').get('data',{})
        t.check('legacy.'+name+'.enrollment_profile',config_matches(read,host='127.0.0.1',port=provider.port)
                and 'api_transport' not in read)
        tokens[name]=t.login('legacy.'+name+'.login',path='auth/'+mount+'/login',policies=['default','upgrade-reader'])
        renewals(t,'legacy.'+name+'.renew',tokens[name])
    t.call('legacy.value','POST',VALUE_PATH,{'data':{'synthetic':True}})
    for label,path in [('child','create'),('orphan','create-orphan')]:
        auth=t.call('legacy.'+label,'POST','auth/token/'+path,{'policies':['upgrade-reader'],'ttl':300},
                    token=tokens['direct']['client_token']).get('auth',{})
        t.check('legacy.'+label+'.shape',isinstance(auth.get('client_token'),str) and bool(auth['client_token']))
        tokens[label]=auth
    t.check('legacy.complete',True)
    return t,key,config,tokens


def run_upgrade(instance, provider, second, candidate, legacy, settings, cases):
    t,key,config,tokens=prepare_legacy(instance,provider,cases)
    direct=tokens['direct'];store=instance.root/'data'
    instance.stop();old_application=durable_manifest(store,application_only=True)
    restart(instance,candidate,settings,t,'current',key)
    t.check('current.reopen_preserves_application',durable_manifest(store,application_only=True)==old_application)
    before=durable_manifest(store)
    for label,auth in tokens.items():
        value=t.call('current.'+label+'.read','GET',VALUE_PATH,token=auth['client_token'])
        t.check('current.'+label+'.value',value.get('data',{}).get('data')=={'synthetic':True})
    data=t.call('current.config','GET',CONFIG_PATH).get('data',{})
    t.check('current.old_config_shape',config_matches(data,**{k:v for k,v in config.items() if k!='secret'})
            and 'api_transport' not in data)
    t.check('current.pure_reads_preserve_store',durable_manifest(store)==before)
    t.call('partial.secret','POST',CONFIG_PATH,{'secret':SECRET.decode()},expected=204)
    t.call('partial.token','POST',CONFIG_PATH,{'token_ttl':240,'token_policies':['upgrade-reader']},expected=204)
    no_enrollment=dict(settings,outbound_endpoints=[])
    restart(instance,candidate,no_enrollment,t,'partial.no_enrollment',key)
    ttl=t.ttl('partial.before',direct);before,cursor=durable_manifest(store),provider.count()
    rejected=t.call('partial.login_rejected','POST','auth/'+MOUNT+'/login',
                    {'username':'alice','password':PASSWORD.decode()},token='',expected=400)
    renewals(t,'partial.still_enrolled',direct,expected=400,contact=None)
    renewals(t,'partial.other_mount_still_enrolled',tokens['port_direct'],expected=400,contact=None)
    unchanged=durable_manifest(store)==before
    after=t.ttl('partial.after',direct)
    t.check('partial.no_egress_or_extension',provider.count()==cursor and unchanged and after<=ttl
            and not rejected.get('auth'))
    restart(instance,candidate,settings,t,'partial.restore_enrollment',key)
    renewals(t,'partial.restored',direct)
    t.check('partial.complete',True)

    # Each mount is promoted by exactly one explicit target field, unchanged in value.
    t.call('migration.same_host','POST',CONFIG_PATH,{'host':'127.0.0.1'},expected=204)
    t.call('migration.same_port','POST','auth/'+PORT_MOUNT+'/config',{'port':provider.port},expected=204)
    data=t.call('migration.read','GET',CONFIG_PATH).get('data',{})
    t.check('migration.internal_marker_hidden',config_matches(data,host='127.0.0.1',port=provider.port,token_ttl=240)
            and 'api_transport' not in data)
    instance.stop();promoted=durable_manifest(store,application_only=True)
    restart(instance,candidate,no_enrollment,t,'migration.restart',key)
    t.check('migration.restart_preserves_application',durable_manifest(store,application_only=True)==promoted)
    renewals(t,'migration.host_renew',direct)
    renewals(t,'migration.port_renew',tokens['port_direct'])
    fresh=t.login('migration.fresh',path='auth/'+MOUNT+'/login',policies=['default','upgrade-reader'])
    t.check('migration.identity_preserved',fresh.get('entity_id')==direct.get('entity_id'));tokens['fresh']=fresh
    t.check('migration.complete',True)

    t.call('target.dns','POST',CONFIG_PATH,{'host':'localhost'},expected=204)
    renewals(t,'target.dns_renew',direct)
    second.secret=b'rotated-api-transport-secret'
    t.call('target.new_peer_and_secret','POST',CONFIG_PATH,
           {'host':'::1','port':second.port,'secret':second.secret.decode()},expected=204)
    old_cursor=provider.count();t.provider=second
    renewals(t,'target.new_peer_renew',direct)
    t.check('target.old_peer_unused',provider.count()==old_cursor)
    t.check('target.actual_ipv6',second.peer_observation(second.count()-1)=={
        'request_count':1,'peer_family':6,'peer_loopback':True})
    second.allow=False
    for via,path,body,actor in [('self','renew-self',{},direct['client_token']),
                              ('token','renew',{'token':direct['client_token']},None),
                              ('accessor','renew-accessor',{'accessor':direct['accessor']},None)]:
        ttl=t.ttl('denied.'+via+'.before',direct);before=durable_manifest(store)
        reply=t.call('denied.'+via,'POST','auth/token/'+path,dict(body,increment=600),token=actor,
                     expected=400,contact=False,wrap_ttl='60s')
        unchanged=durable_manifest(store)==before;after=t.ttl('denied.'+via+'.after',direct)
        t.check('denied.'+via+'.atomic',unchanged and after<=ttl and not reply.get('auth') and not reply.get('wrap_info'))
    for label in ('child','orphan'):
        renewals(t,'independent.'+label,tokens[label],contact=None)
    t.check('independent.no_provider_credentials',not second.allow)
    second.allow=True;t.check('target.complete',True)

    instance.stop();upgraded=durable_manifest(store,application_only=True)
    t.check('migration.state_changed',upgraded!=old_application)
    private_write(instance.root/'server.json',settings);instance.binary=legacy;instance.start()
    t.call('downgrade.unseal_rejected','POST','sys/unseal',{'key':key},expected=503)
    t.call('downgrade.sealed','GET','sys/health',expected=503)
    instance.stop()
    t.check('downgrade.application_unchanged',durable_manifest(store,application_only=True)==upgraded)
    restart(instance,candidate,no_enrollment,t,'recovery',key)
    t.check('recovery.application_unchanged',durable_manifest(store,application_only=True)==upgraded)
    for label,auth in tokens.items():
        value=t.call('recovery.'+label+'.read','GET',VALUE_PATH,token=auth['client_token'])
        t.check('recovery.'+label+'.value',value.get('data',{}).get('data')=={'synthetic':True})
    renewals(t,'recovery.renew',direct)
    instance.stop()
    secrets=[SECRET.decode(),second.secret.decode(),PASSWORD.decode(),key,instance.token,
             *(auth['client_token'] for auth in tokens.values())]
    files=[p for p in store.rglob('*') if p.is_file()]+[instance.root/'server.log',instance.root/'audit.jsonl']
    t.check('plaintext_credentials_absent',all(secret.encode() not in p.read_bytes()
            for p in files if p.exists() for secret in secrets))
    t.check('complete',True)


MILESTONES={'legacy.complete','current.reopen_preserves_application','current.pure_reads_preserve_store',
            'partial.no_egress_or_extension','partial.complete','migration.restart_preserves_application',
            'migration.complete','target.old_peer_unused','target.actual_ipv6','target.complete',
            'independent.no_provider_credentials','downgrade.application_unchanged','recovery.application_unchanged',
            'plaintext_credentials_absent','complete'}
MILESTONES|={prefix+'.'+via+'.shape' for prefix in ('migration.host_renew','migration.port_renew',
            'target.dns_renew','target.new_peer_renew','recovery.renew') for via in ('self','token','accessor')}
MILESTONES|={'denied.'+via+'.atomic' for via in ('self','token','accessor')}
MILESTONES|={'independent.'+label+'.'+via+'.no_pap' for label in ('child','orphan') for via in ('self','token','accessor')}


def complete_scenarios(rows):
    if not rows or any(row.get('passed') is not True for row in rows):return False
    names=[row.get('case') for row in rows]
    if any(not isinstance(n,str) for n in names) or len(names)!=len(set(names)):return False
    return {'radius_api_transport_upgrade.'+n for n in MILESTONES}.issubset(names) and names[-1]=='radius_api_transport_upgrade.complete'


def main():
    parser = SafeArgumentParser(description=__doc__)
    for name in ("legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--binary")
    parser.add_argument("--legacy-prepare-only", action="store_true")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    legacy = Path(args.legacy_binary).resolve(strict=True)
    receipt = json.loads(LEGACY_RECEIPT.read_text())
    admit_legacy_receipt(args.expected_legacy_sha256, receipt)
    if args.legacy_prepare_only:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE:
            parser.error("legacy preparation requires only the pinned legacy build")
        candidate, candidate_hash = legacy, file_hash(legacy)
        if candidate_hash != LEGACY_SHA256:
            raise ValueError("legacy_schema25_binary_mismatch")
        legacy_hash = candidate_hash
    else:
        if not args.binary:
            parser.error("candidate binary required for upgrade")
        candidate = Path(args.binary).resolve(strict=True)
        candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256, receipt)
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before, runner_hash = source_identity(ROOT, candidate), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-radius-api-transport-upgrade-"))
    root.chmod(0o700)
    instance = provider = second = None
    result = {"schema": "heptabao.radius-api-transport-upgrade.v1", "from_schema": 25, "minimum_to_schema": 26,
              "legacy_prepare_only": args.legacy_prepare_only, "candidate_observed": not args.legacy_prepare_only,
              "synthetic_only": True, "actual_signed_udp_pap": True, "legacy_source_commit": LEGACY_SOURCE,
              "legacy_binary_sha256": legacy_hash, "legacy_receipt_sha256": file_hash(LEGACY_RECEIPT),
              "observed_binary_sha256": candidate_hash, "build_source_commit": args.build_source_commit,
              "runner_sha256": runner_hash,
              "build_source_binding_basis": "caller-supplied commit and observed binary hash; not independent attestation",
              "full_openbao_compatibility": False, "full_migration_qualification": False,
              "rolling_upgrade_qualification": False, "independent_qualification": False, "production_authority": False,
              "reopen_replay_ledger_may_change": True,
              "unchanged_application_artifacts_scope": "all store entries except root ledger.hbl, rebuilt before schema admission",
              "started_at_unix": time.time(), "cases": []}
    if not args.legacy_prepare_only:
        result["candidate_binary_sha256"] = candidate_hash
    try:
        instance = Instance(legacy, root / "instance")
        provider = NativeRadius(require_ma=True, dual_stack=True)
        second = NativeRadius(require_ma=True, dual_stack=True)
        settings = enrolled_settings(instance, provider)
        private_write(instance.root / "server.json", settings)
        if args.legacy_prepare_only:
            prepare_legacy(instance, provider, result["cases"])
            result["status"] = "passed_legacy_prepare"
        else:
            run_upgrade(instance, provider, second, candidate, legacy, settings, result["cases"])
            result["status"] = "passed" if complete_scenarios(result["cases"]) else "failed"
    except Exception as error:
        result["status"] = "failed"
        result["safe_failure_code"] = str(error) if isinstance(error, ScenarioFailure) else "unexpected_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        if provider is not None:
            provider.close()
        if second is not None:
            second.close()
        shutil.rmtree(root)
        after = source_identity(ROOT, candidate)
        result["binaries_unchanged"] = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
        for field in ("source_commit", "source_tree", "source_dirty", "source_content_sha256"):
            result["harness_" + field] = before[field]
        result["harness_source_unchanged"] = before == after
        if not result["binaries_unchanged"] or file_hash(Path(__file__)) != runner_hash or before != after:
            result["status"], result["safe_failure_code"] = "failed", "source_or_binary_changed_during_execution"
        if admit_output(output) != parent:
            raise ValueError("report_parent_changed")
        private_write(output, result, replace=False)
    print(json.dumps({"status": result["status"], "checks": len(result["cases"]), "safe_failure_code": result.get("safe_failure_code")}))
    return 0 if result["status"] in ("passed", "passed_legacy_prepare") else 1


if __name__ == "__main__":
    raise SystemExit(main())
