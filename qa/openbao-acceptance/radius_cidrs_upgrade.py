#!/usr/bin/env python3
"""Pinned schema26 to27 CIDR snapshot migration, real TLS and signed UDP PAP."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile
import time
from bao_http import SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from radius_cidrs_live import SourceClient, Trace
from radius_native_live import NativeRadius, SECRET, PASSWORD
from remote_jwks_live import Instance

LEGACY_SOURCE='7c10621a6ecc50d3945b70c4be234164284718b6'
LEGACY_HARNESS='d612b72f0ebd0785d9237ee9fdddfe6e1e521fa4'
LEGACY_SHA256='6cba84001ffb4c7c38701e46993d46848f7022e49ecf37617454014762fb4b0f'
LEGACY_RECEIPT=ROOT/'qa/openbao-acceptance/evidence/radius-native-live-d612b72.json'

def admit_legacy_receipt(expected,receipt):
    identity=receipt.get('source_identity',{})
    if (expected!=LEGACY_SHA256 or receipt.get('status')!='passed' or receipt.get('source_and_binary_unchanged') is not True or receipt.get('cases_match') is not True or receipt.get('build_source_commit')!=LEGACY_SOURCE or identity.get('source_commit')!=LEGACY_HARNESS or identity.get('binary_sha256')!=LEGACY_SHA256 or identity.get('source_dirty') is not False):raise ValueError('legacy_schema26_build_receipt_mismatch')

def admit_legacy(candidate,legacy,expected,receipt):
    admit_legacy_receipt(expected,receipt);return validate_binary_pins(candidate,legacy,expected)

def restart(instance,binary,t,label,key):
    instance.stop();instance.binary=binary;instance.start();t.call(label+'.unseal','POST','sys/unseal',{'key':key})

def prepare_legacy(instance,provider,cases):
    instance.start();status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure('radius_cidrs.upgrade.legacy.initialize')
    instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
    t=Trace(SourceClient(instance.address,instance.root/'ca.crt',instance.token),provider,cases)
    t.call('upgrade.legacy.unseal','POST','sys/unseal',{'key':key})
    t.call('upgrade.legacy.mount','POST','sys/auth/radius',{'type':'radius'},status=204)
    policy='path "auth/token/create" { capabilities = ["update", "sudo"] } path "auth/token/create-orphan" { capabilities = ["update", "sudo"] }'
    t.call('upgrade.legacy.policy','PUT','sys/policies/acl/cidr-issuer',{'policy':policy},status=204)
    t.config('upgrade.legacy.config',{'host':'127.0.0.1','port':provider.port,'secret':SECRET.decode(),'token_ttl':300,'token_max_ttl':3600,'token_policies':['cidr-issuer']})
    old=t.login('upgrade.legacy.login');t.bounds('upgrade.legacy.lookup',old,[])
    t.call('upgrade.legacy.other_source','GET','auth/token/lookup-self',token=old['client_token'],source='127.0.0.2')
    t.check('upgrade.legacy.complete',True);return t,key,old

def run_upgrade(instance,provider,candidate,legacy,cases):
    t,key,old=prepare_legacy(instance,provider,cases);store=instance.root/'data'
    instance.stop();application=durable_manifest(store,application_only=True)
    restart(instance,candidate,t,'upgrade.current',key)
    t.check('upgrade.current.reopen_unchanged',durable_manifest(store,application_only=True)==application)
    before=durable_manifest(store)
    t.bounds('upgrade.current.old_lookup',old,[])
    t.call('upgrade.current.old_other_source','GET','auth/token/lookup-self',token=old['client_token'],source='127.0.0.2')
    config=t.call('upgrade.current.config_read','GET','auth/radius/config').get('data',{})
    t.check('upgrade.current.empty_config',config.get('token_bound_cidrs')==[])
    t.check('upgrade.current.pure_reads_unchanged',durable_manifest(store)==before)
    restart(instance,candidate,t,'upgrade.current.second_restart',key)
    t.check('upgrade.current.second_restart_unchanged',durable_manifest(store,application_only=True)==application)
    t.config('upgrade.bound.config',{'token_bound_cidrs':['127.0.0.1']})
    direct=t.login('upgrade.bound.login');t.bounds('upgrade.bound.lookup',direct,['127.0.0.1'])
    t.call('upgrade.bound.old_unconstrained','GET','auth/token/lookup-self',token=old['client_token'],source='127.0.0.2')
    t.renew_all('upgrade.bound.old_renew',old,self_source='127.0.0.2')
    t.call('upgrade.bound.new_rejected','GET','auth/token/lookup-self',token=direct['client_token'],source='127.0.0.2',status=403)
    children={}
    for name,path,inherits in [('child','create',True),('orphan','create-orphan',False)]:
        auth=t.call('upgrade.'+name+'.create','POST','auth/token/'+path,{'policies':['default'],'ttl':300},token=direct['client_token']).get('auth',{});children[name]=auth;t.tokens.append(auth['client_token'])
        t.bounds('upgrade.'+name+'.lookup',auth,['127.0.0.1'] if inherits else [])
        t.call('upgrade.'+name+'.other_source','GET','auth/token/lookup-self',token=auth['client_token'],source='127.0.0.2',status=403 if inherits else 200)
    t.config('upgrade.clear.config',{'token_bound_cidrs':[]})
    t.bounds('upgrade.clear.issued_snapshot',direct,['127.0.0.1'])
    fresh=t.login('upgrade.clear.fresh',source='127.0.0.2');t.bounds('upgrade.clear.fresh_lookup',fresh,[])
    restart(instance,candidate,t,'upgrade.bound.restart',key)
    t.bounds('upgrade.bound.reopened_snapshot',direct,['127.0.0.1'])
    t.call('upgrade.bound.reopened_rejected','GET','auth/token/lookup-self',token=direct['client_token'],source='127.0.0.2',status=403)
    instance.stop();upgraded=durable_manifest(store,application_only=True)
    instance.binary=legacy;instance.start()
    denied=t.call('upgrade.downgrade.unseal','POST','sys/unseal',{'key':key},status=503)
    t.call('upgrade.downgrade.health','GET','sys/health',status=503)
    t.check('upgrade.downgrade.no_application_change',durable_manifest(store,application_only=True)==upgraded and not denied.get('auth'))
    restart(instance,candidate,t,'upgrade.recover',key)
    t.check('upgrade.recover.application_unchanged',durable_manifest(store,application_only=True)==upgraded)
    t.bounds('upgrade.recover.snapshot',direct,['127.0.0.1'])
    t.call('upgrade.recover.rejected','GET','auth/token/lookup-self',token=direct['client_token'],source='127.0.0.2',status=403)
    t.renew_all('upgrade.recover.renew',direct)
    t.call('upgrade.recover.child_rejected','GET','auth/token/lookup-self',token=children['child']['client_token'],source='127.0.0.2',status=403)
    t.call('upgrade.recover.orphan_unconstrained','GET','auth/token/lookup-self',token=children['orphan']['client_token'],source='127.0.0.2')
    t.check('upgrade.receipt_no_secrets',not any(value in json.dumps(cases) for value in [SECRET.decode(),PASSWORD.decode(),*t.tokens]))
    t.check('upgrade.complete',True)

MILESTONES={'upgrade.legacy.complete','upgrade.current.pure_reads_unchanged','upgrade.current.second_restart_unchanged','upgrade.bound.old_unconstrained','upgrade.child.other_source','upgrade.orphan.other_source','upgrade.clear.issued_snapshot.snapshot','upgrade.downgrade.no_application_change','upgrade.recover.snapshot.snapshot','upgrade.recover.rejected','upgrade.recover.renew.accessor.shape','upgrade.receipt_no_secrets','upgrade.complete'}
def complete_scenarios(rows):
    names=[r.get('case') for r in rows]
    return bool(rows) and all(r.get('passed') is True for r in rows) and len(names)==len(set(names)) and {'radius_cidrs.'+n for n in MILESTONES}.issubset(names) and names[-1]=='radius_cidrs.upgrade.complete'


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
            raise ValueError("legacy_schema26_binary_mismatch")
        legacy_hash = candidate_hash
    else:
        if not args.binary:
            parser.error("candidate binary required for upgrade")
        candidate = Path(args.binary).resolve(strict=True)
        candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256, receipt)
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before, runner_hash = source_identity(ROOT, candidate), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-radius-cidrs-upgrade-"))
    root.chmod(0o700)
    instance = provider = second = None
    result = {"schema": "heptabao.radius-cidrs-upgrade.v1", "from_schema": 26, "minimum_to_schema": 27,
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
        settings=json.loads((instance.root/'server.json').read_text());settings['lifecycle_interval_seconds']=0;settings['outbound_endpoints']=[]
        private_write(instance.root / "server.json", settings)
        if args.legacy_prepare_only:
            prepare_legacy(instance, provider, result["cases"])
            result["status"] = "passed_legacy_prepare"
        else:
            run_upgrade(instance, provider, candidate, legacy, result["cases"])
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
