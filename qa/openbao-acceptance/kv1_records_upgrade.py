#!/usr/bin/env python3
"""A historical schema-35 process creates real V4 state for the V5 transition.

Two read-only reopens must leave application artifacts byte-identical. The first
KV1 write publishes V5, preserves unrelated keys, and makes the old binary refuse
unseal without changing application artifacts. This small migration workload is
separate from the 24/32 MiB local and HA capacity fixtures.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import tempfile

from bao_http import Client, SafeArgumentParser, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from jwt_native_ttl_upgrade import scan_storage
from kv1_record_scale_live import Dataset, MOUNT
from online_evidence import admit_output, source_identity
from provider_renewal_upgrade import durable_manifest
from smoke import Instance

LEGACY_SOURCE = '0fc7925f46fafaf1f75521c8081b64d950be17d3'
LEGACY_SHA256 = 'f7397dbbc4874ff61ae286ee2fe3b223c1efed30cb465006585724d382a716e2'
LEGACY_RECEIPT = ROOT / 'qa/openbao-acceptance/evidence/userpass-native-0fc7925.json'
LEGACY_FORMAT = 'heptabao-state-owners-v4'
CURRENT_FORMAT = 'heptabao-state-records-v5'
PREFIX = 'kv1_records_upgrade.'
REQUIRED = frozenset({'legacy.complete', 'current.application_unchanged', 'current.reads_preserve_entire_store',
    'untouched_restart.application_unchanged', 'untouched_restart.reads_preserve_entire_store',
    'current.format_v4', 'untouched_restart.format_v4', 'migration.first_write', 'migration.format_v5',
    'migration.original_keys_retained', 'migration.deleted_absent', 'reopen.application_unchanged', 'reopen.format_v5',
    'reopen.records_retained', 'downgrade.unseal_rejected', 'downgrade.remains_sealed',
    'downgrade.application_unchanged', 'recovery.application_unchanged', 'recovery.format_v5',
    'recovery.records_retained', 'recovery.deleted_absent', 'plaintext_credentials_absent', 'complete'})


def require_legacy_pin():
    if (not isinstance(LEGACY_SOURCE,str) or re.fullmatch(r'[0-9a-f]{40}',LEGACY_SOURCE) is None
        or not isinstance(LEGACY_SHA256,str) or re.fullmatch(r'[0-9a-f]{64}',LEGACY_SHA256) is None
        or not isinstance(LEGACY_RECEIPT,Path)):
        raise ValueError('legacy_v4_pin_not_available')


def admit_legacy_receipt(expected,receipt):
    require_legacy_pin();source=receipt.get('candidate_source',{})
    if (expected!=LEGACY_SHA256 or receipt.get('status')!='passed' or receipt.get('cases_match') is not True
        or receipt.get('build_source_commit')!=LEGACY_SOURCE or receipt.get('source_and_binary_unchanged') is not True
        or receipt.get('runner_unchanged') is not True or source.get('source_commit')!=LEGACY_SOURCE
        or source.get('source_dirty') is not False or source.get('binary_sha256')!=LEGACY_SHA256):
        raise ValueError('legacy_v4_receipt_mismatch')


class Trace:
    def __init__(self,instance,rows):
        self.instance,self.rows=instance,rows
        self.client=Client(instance.address,str(instance.root/'ca.crt'),instance.token,timeout=30)
        self.secrets=[instance.token]

    def check(self,label,condition,**observed):
        if (not isinstance(label,str) or re.fullmatch(r'[a-z0-9_.]{1,140}',label) is None
            or any(type(value) not in (int,bool) for value in observed.values())):
            raise ScenarioFailure('invalid_observation_shape')
        self.rows.append({'case':PREFIX+label,'passed':condition is True,**observed})
        if condition is not True:raise ScenarioFailure(PREFIX+label)

    def call(self,label,path,body=None,*,method='POST',expected=200):
        result=self.client.request(method,'/v1/'+path,body)
        self.check(label,result.status==expected,status=result.status)
        return result.body

    def format(self,label,expected):
        data=self.call(label+'.capacity','sys/internal/capacity',method='GET').get('data') or {}
        self.check(label,data.get('state_storage_format')==expected)

    def verify(self,label,dataset):
        for key in sorted(dataset.hashes):
            result=self.client.request('GET','/v1/'+MOUNT+'/'+key)
            self.check(label+'.'+key.rsplit('/',1)[-1],dataset.matches(key,result.status,result.body))


def prepare_legacy(instance,rows):
    instance.start()
    status,initialized=instance.call('POST','sys/init',{'secret_shares':1,'secret_threshold':1})
    if status!=200:raise ScenarioFailure(PREFIX+'initialization_failed')
    instance.token,key=initialized['root_token'],initialized['keys_base64'][0]
    t=Trace(instance,rows);t.secrets.append(key)
    t.call('legacy.unseal','sys/unseal',{'key':key})
    t.call('legacy.mount','sys/mounts/'+MOUNT,{'type':'kv','options':{'version':'1'}},expected=204)
    data=Dataset()
    for ordinal in range(4):
        name=f'bulk/{ordinal:04d}';value=data.make_value(ordinal)
        t.call(f'legacy.write_{ordinal}',MOUNT+'/'+name,value,method='PUT',expected=204)
        data.remember(name,value)
    t.format('legacy.format_v4',LEGACY_FORMAT)
    t.verify('legacy.read',data)
    # An unrelated owner value makes accidental whole-root replacement visible.
    t.call('legacy.kv2','secret/data/record-migration-control',{'data':{'synthetic':True}})
    t.check('legacy.complete',True)
    return t,key,data


def restart(instance,binary,key,t,label):
    instance.stop();instance.binary=binary;instance.start()
    t.call(label+'.unseal','sys/unseal',{'key':key})


def verify_control(t,label):
    value=t.call(label+'.control','secret/data/record-migration-control',method='GET')
    t.check(label+'.control_preserved',value.get('data',{}).get('data')=={'synthetic':True})


def run_upgrade(instance,candidate,legacy,rows):
    t,key,data=prepare_legacy(instance,rows)
    store=instance.root/'data'
    instance.stop();application=durable_manifest(store,application_only=True)
    for phase in ('current','untouched_restart'):
        restart(instance,candidate,key,t,phase)
        t.check(phase+'.application_unchanged',durable_manifest(store,application_only=True)==application)
        before=durable_manifest(store)
        t.format(phase+'.format_v4',LEGACY_FORMAT)
        t.verify(phase+'.records',data);verify_control(t,phase)
        t.check(phase+'.reads_preserve_entire_store',durable_manifest(store)==before)
    value=data.make_value(1_000_000)
    t.call('migration.first_write',MOUNT+'/bulk/0000',value,method='PUT',expected=204)
    data.remember('bulk/0000',value)
    t.format('migration.format_v5',CURRENT_FORMAT)
    t.verify('migration.records',data);verify_control(t,'migration')
    t.check('migration.original_keys_retained',True)
    t.call('migration.delete',MOUNT+'/bulk/0001',method='DELETE',expected=204)
    data.forget('bulk/0001')
    body=t.call('migration.deleted_read',MOUNT+'/bulk/0001',method='GET',expected=404)
    t.check('migration.deleted_absent',not body.get('data'))
    instance.stop();application=durable_manifest(store,application_only=True)
    restart(instance,candidate,key,t,'reopen')
    t.check('reopen.application_unchanged',durable_manifest(store,application_only=True)==application)
    t.format('reopen.format_v5',CURRENT_FORMAT)
    t.verify('reopen.records',data);verify_control(t,'reopen')
    t.check('reopen.records_retained',True)
    instance.stop();application=durable_manifest(store,application_only=True)
    instance.binary=legacy;instance.start()
    t.call('downgrade.unseal_rejected','sys/unseal',{'key':key},expected=503)
    t.call('downgrade.remains_sealed','sys/health',method='GET',expected=503)
    instance.stop()
    t.check('downgrade.application_unchanged',durable_manifest(store,application_only=True)==application)
    restart(instance,candidate,key,t,'recovery')
    t.check('recovery.application_unchanged',durable_manifest(store,application_only=True)==application)
    t.format('recovery.format_v5',CURRENT_FORMAT)
    t.verify('recovery.records',data);verify_control(t,'recovery')
    t.check('recovery.records_retained',True)
    body=t.call('recovery.deleted_read',MOUNT+'/bulk/0001',method='GET',expected=404)
    t.check('recovery.deleted_absent',not body.get('data'))
    instance.stop()
    t.secrets.extend(data.sample_prefixes)
    t.check('plaintext_credentials_absent',scan_storage(instance.root,t.secrets))
    t.check('complete',True)


def complete(rows,prepare):
    if not isinstance(rows,list) or not rows:return False
    if any(not isinstance(row,dict) or row.get('passed') is not True or not isinstance(row.get('case'),str)
        or re.fullmatch(r'kv1_records_upgrade\.[a-z0-9_.]{1,140}',row['case']) is None
        or any(type(value) not in (int,bool) for key,value in row.items() if key not in ('case','passed')) for row in rows):return False
    names=[row['case'] for row in rows]
    required={'legacy.complete','legacy.format_v4','legacy.plaintext_credentials_absent'} if prepare else REQUIRED
    end='legacy.plaintext_credentials_absent' if prepare else 'complete'
    return (len(names)==len(set(names)) and {PREFIX+name for name in required}.issubset(names)
            and names[-1]==PREFIX+end)

def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--prepare-legacy", action="store_true")
    for name in ("legacy-binary", "expected-legacy-sha256", "build-source-commit", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require_legacy_pin()
    if re.fullmatch(r"[0-9a-f]{40}", args.build_source_commit) is None:
        parser.error("full build source commit required")
    legacy = Path(args.legacy_binary).resolve(strict=True)
    admit_legacy_receipt(args.expected_legacy_sha256, json.loads(LEGACY_RECEIPT.read_text()))
    if args.prepare_legacy:
        if args.binary is not None or args.build_source_commit != LEGACY_SOURCE or file_hash(legacy) != LEGACY_SHA256:
            parser.error("prepare requires only the pinned historical binary/source")
        candidate = legacy
        candidate_hash = legacy_hash = LEGACY_SHA256
    else:
        if args.binary is None:
            parser.error("candidate binary required")
        candidate = args.binary.resolve(strict=True)
        candidate_hash, legacy_hash = validate_binary_pins(candidate, legacy, args.expected_legacy_sha256)
    output = Path(args.output).absolute()
    admitted = admit_output(output)
    before = source_identity(ROOT, candidate)
    runner_hash = file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix="heptabao-kv1-records-upgrade-"))
    root.chmod(0o700)
    instance = None
    rows, failure = [], None
    try:
        instance = Instance(legacy, root / "candidate")
        settings = json.loads((instance.root / "server.json").read_text())
        settings.update(lifecycle_interval_seconds=0, outbound_endpoints=[])
        private_write(instance.root / "server.json", settings)
        if args.prepare_legacy:
            t, _, dataset = prepare_legacy(instance, rows)
            t.secrets.extend(dataset.sample_prefixes)
            instance.stop()
            t.check("legacy.plaintext_credentials_absent", scan_storage(instance.root, t.secrets))
        else:
            run_upgrade(instance, candidate, legacy, rows)
    except Exception as error:
        failure = str(error) if isinstance(error, ScenarioFailure) else "fixture_" + type(error).__name__
    finally:
        if instance is not None:
            instance.stop()
        shutil.rmtree(root)
    after = source_identity(ROOT, candidate)
    binaries_unchanged = after["binary_sha256"] == candidate_hash and file_hash(legacy) == legacy_hash
    source_unchanged = before == after
    runner_unchanged = file_hash(Path(__file__)) == runner_hash
    if not binaries_unchanged or not source_unchanged or not runner_unchanged:
        failure = "source_binary_or_runner_changed"
    if not complete(rows, args.prepare_legacy):
        failure = failure or "incomplete_observations"
    report = {"schema":"heptabao.kv1-records-upgrade.v1", "status":"passed" if failure is None else "failed",
        "from_schema":35, "minimum_to_schema":None if args.prepare_legacy else 36,
        "prepare_legacy_only":args.prepare_legacy, "failure":failure, "cases":rows,
        "source_identity":before, "source_and_binary_unchanged":source_unchanged,
        "legacy_source_commit":LEGACY_SOURCE, "legacy_binary_sha256":legacy_hash,
        "legacy_receipt_sha256":file_hash(LEGACY_RECEIPT),
        "candidate_binary_sha256":None if args.prepare_legacy else candidate_hash,
        "build_source_commit":args.build_source_commit,
        "build_source_binding_basis":"caller-supplied build commit and observed binary hash, not independent attestation",
        "binaries_unchanged":binaries_unchanged, "runner_sha256":runner_hash, "runner_unchanged":runner_unchanged,
        "candidate_startup_enrollment_empty":True, "reopen_replay_ledger_may_change":True,
        "application_artifact_scope":"all store entries except root ledger.hbl, rebuilt before schema validation",
        "from_storage_format":LEGACY_FORMAT, "to_storage_format":CURRENT_FORMAT,
        "capacity_above_16mib_covered":False, "ha_or_postgresql_covered":False, "first_write_migration":True,
        "synthetic_only":True, "rolling_upgrade_qualification":False, "full_migration_qualification":False,
        "independent_qualification":False, "production_authority":False}
    if admit_output(output) != admitted:
        raise ValueError("report_parent_changed")
    private_write(output, report, replace=False)
    print(json.dumps({"status":report["status"], "checks":len(rows), "failure":failure}))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
