#!/usr/bin/env python3
"""Pinned schema29 to30 LDAP no-default policy migration, real TLS and OpenLDAP Bind/Search."""
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
from ldap_cidrs_live import SourceClient, Trace
from ldap_native_live import NativeDirectory, configuration
from remote_jwks_live import Instance

LEGACY_SOURCE='a14a7fd03ed535dbc97fd33bff771bdd9b1f3bb7'
LEGACY_HARNESS='a14a7fd03ed535dbc97fd33bff771bdd9b1f3bb7'
LEGACY_SHA256='cb3477f0e2fb26ac6005a17aafb25b455b47834e2079df7a8a15556e0f14b55e'
LEGACY_RECEIPT=ROOT/'qa/openbao-acceptance/evidence/ldap-cidrs-a14a7fd.json'

def admit_legacy_receipt(expected,receipt):
    if LEGACY_HARNESS is None or LEGACY_RECEIPT is None:raise ValueError('legacy_schema29_receipt_not_yet_pinned')
    identity=receipt.get('source_identity',{})
    if (expected!=LEGACY_SHA256 or receipt.get('status')!='passed' or receipt.get('source_and_binary_unchanged') is not True or receipt.get('cases_match') is not True or receipt.get('build_source_commit')!=LEGACY_SOURCE or identity.get('source_commit')!=LEGACY_HARNESS or identity.get('binary_sha256')!=LEGACY_SHA256 or identity.get('source_dirty') is not False):raise ValueError('legacy_schema29_build_receipt_mismatch')

def admit_legacy(candidate,legacy,expected,receipt):
    admit_legacy_receipt(expected,receipt);return validate_binary_pins(candidate,legacy,expected)

def restart(instance,binary,t,label,key):
    instance.stop();instance.binary=binary;instance.start();t.call(label+'.unseal','POST','sys/unseal',{'key':key})

class UpgradeTrace(Trace):
    def check(self,name,passed,**safe):
        if not re.fullmatch(r'[a-z0-9_.]{1,140}',name) or any(type(v) not in (bool,int) for v in safe.values()):raise ValueError('unsafe_trace')
        self.rows.append({'case':'ldap_no_default.'+name,**safe,'passed':bool(passed)})
        if not passed:raise ScenarioFailure('ldap_no_default.'+name)
    def policies(self,name,auth,expected):
        data=self.call(name,'POST','auth/token/lookup',{'token':auth['client_token']}).get('data',{})
        self.check(name+'.snapshot',data.get('policies')==expected)
    def admin_renew(self,name,auth,*,status=200):
        for via,body in [('renew',{'token':auth['client_token']}),('renew-accessor',{'accessor':auth['accessor']})]:
            result=self.call(name+'.'+via,'POST','auth/token/'+via,dict(body,increment=120),status=status,provider=True)
            if status==200:self.check(name+'.'+via+'.empty_policies',result.get('auth',{}).get('policies')==[] and 'token_policies' not in result.get('auth',{}))

def prepare_legacy(instance,provider,cases):
    instance.start();status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure('ldap_no_default.upgrade.legacy.initialize')
    instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
    cfg=configuration('candidate',provider,(instance.root/'ca.crt').read_text(),token_ttl=300,token_max_ttl=3600);del cfg['token_policies']
    t=UpgradeTrace(SourceClient(instance.address,instance.root/'ca.crt',instance.token),provider,cfg,cases)
    t.call('upgrade.legacy.unseal','POST','sys/unseal',{'key':key})
    t.call('upgrade.legacy.mount','POST','sys/auth/ldap',{'type':'ldap'},status=204)
    t.config('upgrade.legacy.config',cfg)
    old=t.login('upgrade.legacy.login');t.policies('upgrade.legacy.lookup',old,['default'])
    t.check('upgrade.legacy.complete',True);return t,key,old

def run_upgrade(instance,provider,candidate,legacy,cases):
    t,key,old=prepare_legacy(instance,provider,cases);store=instance.root/'data'
    instance.stop();application=durable_manifest(store,application_only=True)
    restart(instance,candidate,t,'upgrade.current',key)
    t.check('upgrade.current.reopen_unchanged',durable_manifest(store,application_only=True)==application)
    before=durable_manifest(store)
    t.policies('upgrade.current.old_lookup',old,['default'])
    config=t.call('upgrade.current.config_read','GET','auth/ldap/config').get('data',{})
    t.check('upgrade.current.default_flag',config.get('token_no_default_policy') is False and config.get('token_policies')==[])
    t.check('upgrade.current.pure_reads_unchanged',durable_manifest(store)==before)
    restart(instance,candidate,t,'upgrade.current.second_restart',key)
    t.check('upgrade.current.second_restart_unchanged',durable_manifest(store,application_only=True)==application)
    t.config('upgrade.old_profile.enable',{'token_no_default_policy':True})
    t.renew_all('upgrade.old_default.renew',old)
    t.policies('upgrade.old_default.lookup',old,['default'])
    legacy_zero=t.login('upgrade.old_profile.zero_login');t.policies('upgrade.old_profile.zero_lookup',legacy_zero,[])
    # The actual old29 writer had already collapsed nil into an empty list.
    t.admin_renew('upgrade.old_profile.normalized_renew',legacy_zero)
    t.call('upgrade.new_profile.mount','POST','sys/auth/ldap-fresh',{'type':'ldap'},status=204)
    t.call('upgrade.new_profile.config','POST','auth/ldap-fresh/config',dict(t.configuration,token_no_default_policy=True),status=204)
    fresh=t.call('upgrade.new_profile.login','POST','auth/ldap-fresh/login/alice',{'password':provider.user_password},token='',provider=True).get('auth',{})
    t.tokens.append(fresh['client_token']);t.policies('upgrade.new_profile.lookup',fresh,[])
    t.admin_renew('upgrade.new_profile.nil_renew',fresh,status=500)
    t.call('upgrade.new_profile.explicit_empty','POST','auth/ldap-fresh/config',{'token_policies':[]},status=204)
    t.admin_renew('upgrade.new_profile.empty_renew',fresh)
    t.call('upgrade.named.policy','PUT','sys/policies/acl/ldap-renewer',{'policy':'path "auth/token/renew-self" { capabilities = ["update"] }'},status=204)
    t.config('upgrade.named.config',{'token_policies':['ldap-renewer']})
    bare=t.login('upgrade.named.login');t.policies('upgrade.named.lookup',bare,['ldap-renewer'])
    t.config('upgrade.named.toggle_false',{'token_no_default_policy':False})
    t.renew_all('upgrade.named.old_renew',bare);t.policies('upgrade.named.old_lookup',bare,['ldap-renewer'])
    defaults=t.login('upgrade.named.future_login');t.policies('upgrade.named.future_lookup',defaults,['default','ldap-renewer'])
    restart(instance,candidate,t,'upgrade.enabled.restart',key)
    t.renew_all('upgrade.enabled.reopened_renew',bare);t.policies('upgrade.enabled.snapshot',bare,['ldap-renewer'])
    t.admin_renew('upgrade.enabled.empty_presence_reopened',fresh)
    instance.stop();upgraded=durable_manifest(store,application_only=True)
    instance.binary=legacy;instance.start()
    denied=t.call('upgrade.downgrade.unseal','POST','sys/unseal',{'key':key},status=503)
    t.call('upgrade.downgrade.health','GET','sys/health',status=503)
    t.check('upgrade.downgrade.no_application_change',durable_manifest(store,application_only=True)==upgraded and not denied.get('auth'))
    restart(instance,candidate,t,'upgrade.recover',key)
    t.check('upgrade.recover.application_unchanged',durable_manifest(store,application_only=True)==upgraded)
    t.renew_all('upgrade.recover.renew',bare);t.policies('upgrade.recover.snapshot',bare,['ldap-renewer'])
    t.admin_renew('upgrade.recover.empty_presence',fresh)
    t.check('upgrade.receipt_no_secrets',not any(value in json.dumps(cases) for value in [provider.admin_password,provider.user_password,*t.tokens]))
    t.check('upgrade.complete',True)

MILESTONES={'upgrade.legacy.complete','upgrade.current.pure_reads_unchanged','upgrade.current.second_restart_unchanged','upgrade.old_default.renew.self.shape','upgrade.old_profile.normalized_renew.renew.empty_policies','upgrade.new_profile.nil_renew.renew','upgrade.new_profile.empty_renew.renew.empty_policies','upgrade.named.old_lookup.snapshot','upgrade.downgrade.no_application_change','upgrade.recover.snapshot.snapshot','upgrade.recover.empty_presence.renew.empty_policies','upgrade.receipt_no_secrets','upgrade.complete'}
def complete_scenarios(rows):
    names=[r.get('case') for r in rows]
    return bool(rows) and all(r.get('passed') is True for r in rows) and len(names)==len(set(names)) and {'ldap_no_default.'+n for n in MILESTONES}.issubset(names) and names[-1]=='ldap_no_default.upgrade.complete'


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
    if LEGACY_RECEIPT is None:raise ValueError("legacy_schema29_receipt_not_yet_pinned")
    receipt = json.loads(LEGACY_RECEIPT.read_text())
    admit_legacy_receipt(args.expected_legacy_sha256, receipt)
    if args.legacy_prepare_only:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE:
            parser.error("legacy preparation requires only the pinned legacy build")
        candidate, candidate_hash = legacy, file_hash(legacy)
        if candidate_hash != LEGACY_SHA256:
            raise ValueError("legacy_schema29_binary_mismatch")
        legacy_hash = candidate_hash
    else:
        if not args.binary:
            parser.error("candidate binary required for upgrade")
        candidate = Path(args.binary).resolve(strict=True)
        candidate_hash, legacy_hash = admit_legacy(candidate, legacy, args.expected_legacy_sha256, receipt)
    output = Path(args.output).absolute()
    parent = admit_output(output)
    before, runner_hash = source_identity(ROOT, candidate), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-ldap-no-default-upgrade-"))
    root.chmod(0o700)
    instance = provider = None
    result = {"schema": "heptabao.ldap-no-default-upgrade.v1", "from_schema": 29, "minimum_to_schema": 30,
              "legacy_prepare_only": args.legacy_prepare_only, "candidate_observed": not args.legacy_prepare_only,
              "synthetic_only": True, "actual_https_openldap": True, "legacy_source_commit": LEGACY_SOURCE,
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
        provider = NativeDirectory(root/'openldap',instance.root/'tls.crt',instance.root/'tls.key',instance.root/'ca.crt')
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
            provider.stop()
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
