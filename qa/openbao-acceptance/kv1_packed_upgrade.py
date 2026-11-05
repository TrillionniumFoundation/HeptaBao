#!/usr/bin/env python3
"""Real schema36 -> 37 fence, followed by independent dense local KV1 growth.

The default old36 seed is 256 actual HTTPS writes. Candidate density is 20,000
separate 600-byte canonical JSON records. This is NOT the schema35 whole-image
HA migration problem. No storage fabrication, bulk backdoor, retries, timeout
increase, or throughput pass threshold is used. Progress contains no credentials.
Requests are paced at 100/s under the unchanged production rate limit; elapsed
growth measurements include this pacing and are not service throughput results.
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

from bao_http import BaoError, Client, SafeArgumentParser, canonical, private_write
from core_isolation import ROOT, ScenarioFailure, file_hash
from identity_upgrade import validate_binary_pins
from jwt_native_ttl_upgrade import scan_storage
from kv1_record_scale_live import process_observation, measurement_delta, disk_observation
from online_evidence import admit_output, source_identity, complete_checks
from provider_renewal_upgrade import durable_manifest
from remote_jwks_live import Instance

LEGACY_SOURCE = '0adfc0d2e4ed1bc234bfcea17246e41e797f79c8'
LEGACY_SHA256 = '40eacb3fdc897cca44df381dac49d2273c66548ba440f50c6a7e07c602a23dfa'
LEGACY_RECEIPT = ROOT / 'qa/openbao-acceptance/evidence/kv1-record-backup-0adfc0d.json'
MOUNT = 'packed-upgrade'
VALUE_BYTES = 600
TARGET_RECORDS = 20_000
CHECKPOINT_RECORDS = 256
HTTP_TIMEOUT = 5
REQUESTS_PER_SECOND = 100
REQUIRED = frozenset({'legacy_seed_written', 'legacy_all_hashes', 'current_application_unchanged',
    'current_reads_noop_rejection_unchanged', 'second_open_application_unchanged',
    'second_open_reads_unchanged', 'first_mutation_succeeded', 'migration_all_hashes',
    'downgrade_unseal_refused', 'downgrade_remains_sealed', 'downgrade_application_unchanged',
    'recovery_all_hashes', 'growth_complete', 'dense_all_hashes', 'dense_point_update',
    'dense_restart_application_unchanged', 'dense_restart_all_hashes', 'secret_samples_absent', 'complete'})


def admit_legacy_receipt(expected, receipt):
    source = receipt.get('source_identity', {})
    if (expected != LEGACY_SHA256 or receipt.get('status') != 'passed'
        or receipt.get('schema') != 'heptabao.kv1-record-backup.v1'
        or receipt.get('build_source_commit') != LEGACY_SOURCE
        or receipt.get('source_and_binary_unchanged') is not True
        or receipt.get('runner_unchanged') is not True
        or source.get('source_commit') != LEGACY_SOURCE or source.get('source_dirty') is not False
        or source.get('binary_sha256') != LEGACY_SHA256
        or receipt.get('source_identity_after') != source):
        raise ValueError('legacy36_receipt_mismatch')


class DenseData:
    def __init__(self):
        self.hashes = {}
        self.samples = []
        self.first = None

    def make(self, ordinal):
        value = {'ordinal': ordinal, 'payload': ''}
        length = VALUE_BYTES - len(canonical(value))
        if length < 48:
            raise ValueError('invalid_dense_value_shape')
        value['payload'] = secrets.token_hex((length + 1) // 2)[:length]
        if len(canonical(value)) != VALUE_BYTES:
            raise ValueError('invalid_dense_value_size')
        if len(self.samples) < 8:
            self.samples.append(value['payload'][:48])
        return value

    def remember(self, ordinal, value):
        if len(canonical(value)) != VALUE_BYTES:
            raise ValueError('noncanonical_dense_size')
        self.hashes[ordinal] = hashlib.sha256(canonical(value)).hexdigest()
        if ordinal == 0:
            self.first = value

    def matches(self, ordinal, result):
        return (result.status == 200 and isinstance(result.body, dict)
                and isinstance(result.body.get('data'), dict)
                and hashlib.sha256(canonical(result.body['data'])).hexdigest() == self.hashes[ordinal])


class Trace:
    def __init__(self, instance, checks, progress=lambda value: None):
        self.instance, self.checks = instance, checks
        self.client = Client(instance.address, str(instance.root/'ca.crt'), instance.token, timeout=HTTP_TIMEOUT)
        self.progress, self.next_start = progress, 0.0

    def check(self, name, condition):
        if not isinstance(name, str) or re.fullmatch(r'[a-z0-9_]{1,120}', name) is None:
            raise ValueError('invalid_case_label')
        self.checks.append({'case': name, 'passed': condition is True})
        if condition is not True:
            raise ScenarioFailure(name)

    def response(self, method, path, body=None):
        delay = self.next_start - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        # Schedule from actual start: slow operations must not create a burst
        # of catch-up requests. This is pacing, never a retry.
        self.next_start = time.monotonic() + 1 / REQUESTS_PER_SECOND
        return self.client.request(method, '/v1/'+path, body)

    def request(self, method, path, body=None, expected=200):
        result = self.response(method, path, body)
        if result.status != expected:
            # Do not surface response bodies, target paths or exception strings.
            raise ScenarioFailure('unexpected_http_status_'+str(result.status))
        return result

    def value_path(self, ordinal):
        return MOUNT + '/dense/' + f'{ordinal:05d}'

    def verify(self, label, data):
        self.progress({'status':'in_progress','phase':label,'records_verified':0,
                       'records_present':len(data.hashes)})
        verified = 0
        for ordinal in sorted(data.hashes):
            result = self.response('GET', self.value_path(ordinal))
            if not data.matches(ordinal, result):
                self.check(label+'_record_'+str(ordinal), False)
            verified += 1
            if verified % CHECKPOINT_RECORDS == 0 or verified == len(data.hashes):
                self.progress({'status':'in_progress','phase':label,'records_verified':verified,
                               'records_present':len(data.hashes)})
        self.check(label, True)

    def format(self):
        result = self.request('GET', 'sys/internal/storage/capacity')
        if result.body.get('data', {}).get('state_storage_format') != 'heptabao-state-records-v5':
            raise ScenarioFailure('unexpected_storage_format')
        return result.body['data']


def complete(checks, observations, seed, target):
    return (type(seed) is int and type(target) is int and 2 <= seed <= target <= TARGET_RECORDS
            and complete_checks(checks, required_cases=REQUIRED)
            and checks[-1]['case'] == 'complete'
            and observations.get('legacy_records_written') == seed
            and observations.get('candidate_records_present') == target
            and observations.get('canonical_value_bytes') == VALUE_BYTES
            and observations.get('all_hashes_verified_after_restart') is True)


def run(instance, candidate, legacy, seed, target, checks, points, observations, progress):
    instance.start()
    status, initialized = instance.call('POST', 'sys/init', {'secret_shares':1,'secret_threshold':1})
    if status != 200:
        raise ScenarioFailure('legacy_initialization_failed')
    instance.token, key = initialized['root_token'], initialized['keys_base64'][0]
    t, data = Trace(instance, checks, progress), DenseData()
    t.request('POST', 'sys/unseal', {'key':key})
    t.request('POST', 'sys/mounts/'+MOUNT, {'type':'kv','options':{'version':'1'}}, expected=204)
    t.request('PUT', 'secret/data/packed-control', {'data':{'retained':True}})
    store = instance.root/'data'

    def verify_control():
        response = t.request('GET', 'secret/data/packed-control')
        if response.body.get('data', {}).get('data') != {'retained':True}:
            raise ScenarioFailure('unrelated_owner_changed')

    def restart(binary):
        instance.stop(); instance.binary = binary; instance.start()
        t.request('POST', 'sys/unseal', {'key':key})

    def checkpoint(phase, before, started, inserted):
        after = process_observation(instance.process.pid)
        capacity, disk = t.format(), disk_observation(store)
        t.check(f'{phase}_artifact_bound_{len(data.hashes)}', disk['largest_file_bytes'] <= 64*1024*1024)
        elapsed = (time.perf_counter_ns()-started)/1e9
        point = {'phase':phase, 'records_present':len(data.hashes), 'records_inserted':inserted,
            'canonical_payload_bytes':len(data.hashes)*VALUE_BYTES, 'elapsed_seconds':round(elapsed,6),
            'observed_records_per_second':round(inserted/elapsed,6),
            'disk':disk, 'capacity':{k:v for k,v in capacity.items() if type(v) is int and v >= 0},
            **measurement_delta(before,after)}
        points.append(point)
        progress({'status':'in_progress','phase':phase,'records_present':len(data.hashes),
                  'canonical_payload_bytes':len(data.hashes)*VALUE_BYTES,'checkpoint_count':len(points)})

    def grow(phase, end):
        inserted, before, started = 0, process_observation(instance.process.pid), time.perf_counter_ns()
        for ordinal in range(len(data.hashes), end):
            value = data.make(ordinal)
            # Never retry: acknowledgement loss is an unknown mutation outcome.
            t.request('PUT', t.value_path(ordinal), value, expected=204)
            data.remember(ordinal, value); inserted += 1
            if inserted == CHECKPOINT_RECORDS or ordinal+1 == end:
                checkpoint(phase, before, started, inserted)
                inserted, before, started = 0, process_observation(instance.process.pid), time.perf_counter_ns()

    grow('legacy', seed)
    observations['legacy_records_written'] = len(data.hashes)
    t.check('legacy_seed_written', len(data.hashes) == seed)
    t.verify('legacy_all_hashes', data); verify_control()
    instance.stop(); application = durable_manifest(store, application_only=True)
    restart(candidate)
    t.check('current_application_unchanged', durable_manifest(store, application_only=True) == application)
    before = durable_manifest(store)
    t.verify('current_all_hashes', data); verify_control(); t.format()
    t.request('PUT', t.value_path(0), data.first, expected=204)
    t.request('PUT', MOUNT+'/rejected', ['invalid'], expected=400)
    t.check('current_reads_noop_rejection_unchanged', durable_manifest(store) == before)
    restart(candidate)
    t.check('second_open_application_unchanged', durable_manifest(store, application_only=True) == application)
    before = durable_manifest(store)
    t.verify('second_open_all_hashes', data); verify_control(); t.format()
    t.check('second_open_reads_unchanged', durable_manifest(store) == before)
    replacement = data.make(0)
    t.request('PUT', t.value_path(0), replacement, expected=204); data.remember(0, replacement)
    t.check('first_mutation_succeeded', durable_manifest(store) != before)
    t.verify('migration_all_hashes', data); verify_control()

    # Actual old reader, not a forged schema field or expected parser failure.
    instance.stop(); application = durable_manifest(store, application_only=True)
    instance.binary = legacy; instance.start()
    t.check('downgrade_unseal_refused', t.response('POST','sys/unseal',{'key':key}).status == 503)
    t.check('downgrade_remains_sealed', t.response('GET','sys/health').status == 503)
    instance.stop()
    t.check('downgrade_application_unchanged', durable_manifest(store, application_only=True) == application)
    restart(candidate)
    t.check('recovery_application_unchanged', durable_manifest(store, application_only=True) == application)
    t.verify('recovery_all_hashes', data); verify_control()

    grow('candidate', target)
    t.check('growth_complete', len(data.hashes) == target)
    t.verify('dense_all_hashes', data); verify_control()
    before, started = process_observation(instance.process.pid), time.perf_counter_ns()
    replacement = data.make(target//2)
    t.request('PUT', t.value_path(target//2), replacement, expected=204); data.remember(target//2, replacement)
    t.check('dense_point_update', data.matches(target//2, t.response('GET',t.value_path(target//2))))
    observations['point_update'] = {'latency_ms':round((time.perf_counter_ns()-started)/1e6,3),
                                  **measurement_delta(before,process_observation(instance.process.pid))}
    instance.stop(); application = durable_manifest(store, application_only=True)
    restart(candidate)
    t.check('dense_restart_application_unchanged', durable_manifest(store, application_only=True) == application)
    t.verify('dense_restart_all_hashes', data); verify_control()
    observations.update(candidate_records_present=len(data.hashes), canonical_value_bytes=VALUE_BYTES,
                        all_hashes_verified_after_restart=True)
    instance.stop()
    t.check('secret_samples_absent', scan_storage(instance.root, [instance.token,key,*data.samples]))
    t.check('complete', True)


def safe_failure(error, checks):
    failed = next((row['case'] for row in reversed(checks)
                   if row.get('passed') is not True), None)
    if failed is not None:
        return failed
    if isinstance(error, ScenarioFailure) and re.fullmatch(r'unexpected_http_status_[0-9]{3}', str(error)):
        return str(error)
    if isinstance(error, BaoError) and error.code in {
        'transport_read_failed','transport_outcome_unknown','invalid_json',
        'response_object_required','response_size_limit','redirect_rejected'}:
        return 'client_' + error.code
    return 'fixture_' + type(error).__name__


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--legacy-binary',type=Path,required=True)
    parser.add_argument('--expected-legacy-sha256',required=True)
    parser.add_argument('--build-source-commit',required=True)
    parser.add_argument('--legacy-records',type=int,default=256)
    parser.add_argument('--target-records',type=int,default=TARGET_RECORDS)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    if (re.fullmatch(r'[0-9a-f]{40}',args.build_source_commit) is None
        or not 2 <= args.legacy_records <= args.target_records <= TARGET_RECORDS):
        parser.error('invalid explicit profile bounds or build commit')
    candidate, legacy = args.binary.resolve(strict=True), args.legacy_binary.resolve(strict=True)
    admit_legacy_receipt(args.expected_legacy_sha256,json.loads(LEGACY_RECEIPT.read_text()))
    candidate_hash, legacy_hash = validate_binary_pins(candidate,legacy,args.expected_legacy_sha256)
    output = args.output.absolute(); admitted = admit_output(output)
    progress_path = output.with_name(output.name+'.progress.json'); progress_parent = admit_output(progress_path)
    before, runner_hash = source_identity(ROOT,candidate), file_hash(Path(__file__))
    root = Path(tempfile.mkdtemp(prefix='heptabao-packed-upgrade-'));root.chmod(0o700)
    instance, checks, points, observations, failure = None, [], [], {}, None
    def progress(value):
        # Private diagnostic checkpoint; never a resume token or a pass receipt.
        if progress_path.parent.stat().st_ino != progress_parent[1] or progress_path.parent.stat().st_dev != progress_parent[0]:
            raise ValueError('progress_parent_changed')
        private_write(progress_path,value,replace=progress_path.exists())
    try:
        instance = Instance(legacy,root/'candidate')
        config = json.loads((instance.root/'server.json').read_text())
        config.update(lifecycle_interval_seconds=0,outbound_endpoints=[])
        private_write(instance.root/'server.json',config)
        run(instance,candidate,legacy,args.legacy_records,args.target_records,checks,points,observations,progress)
    except Exception as error:
        failure = safe_failure(error,checks)
    finally:
        if instance is not None:instance.stop()
    after = source_identity(ROOT,candidate)
    unchanged = before == after and file_hash(legacy) == legacy_hash and after['binary_sha256'] == candidate_hash
    runner_unchanged = file_hash(Path(__file__)) == runner_hash
    if not unchanged or not runner_unchanged:failure = 'source_binary_or_runner_changed'
    if before['source_dirty'] or after['source_dirty']:failure = 'source_dirty'
    if not complete(checks,observations,args.legacy_records,args.target_records):failure = failure or 'incomplete_observations'
    report = {'schema':'heptabao.kv1-packed-upgrade.v1','status':'passed' if failure is None else 'failed',
        'failure':failure,'checks':checks,'points':points,'observations':observations,
        'source_identity':before,'source_identity_after':after,'source_and_binary_unchanged':unchanged,
        'runner_sha256':runner_hash,'runner_unchanged':runner_unchanged,'build_source_commit':args.build_source_commit,
        'build_source_binding_basis':'caller supplied build commit, observed binary hash; no independent attestation',
        'legacy_source_commit':LEGACY_SOURCE,'legacy_binary_sha256':legacy_hash,'legacy_receipt_sha256':file_hash(LEGACY_RECEIPT),
        'candidate_binary_sha256':candidate_hash,'legacy_seed_records':args.legacy_records,'target_records':args.target_records,
        'from_schema':36,'minimum_to_schema':37,'schema_upgrade_evidence':'actual old reader refuses after first mutation; no internal decryption',
        'dense_20000_capacity_covered':failure is None and args.target_records == TARGET_RECORDS,
        'schema35_dense_ha_migration_covered':False,'historical_20000_seed_covered':failure is None and args.legacy_records == TARGET_RECORDS,
        'data_and_maintenance_http_timeout_seconds':HTTP_TIMEOUT,'bootstrap_helper_timeout_seconds':10,'mutation_retries':0,'bulk_import_backdoor':False,
        'workload_max_requests_per_second':REQUESTS_PER_SECOND,'growth_elapsed_includes_request_pacing':True,
        'verification_retries':0,'production_rate_limit_unchanged':True,
        'progress_is_resumable':False,'speedup_or_latency_gate':False,'ha_or_postgresql_covered':False,
        'application_artifact_scope':'all entries except root ledger.hbl, historically re-sealed before schema validation',
        'plaintext_scan_scope':'root token, unseal key and first eight random payload prefixes',
        'retained_failure_work_dir':str(root) if failure else None,
        'synthetic_only':True,'independent_qualification':False,'production_authority':False,
        'full_openbao_compatibility':False}
    if admit_output(output) != admitted:raise ValueError('report_parent_changed')
    private_write(output,report,replace=False)
    if failure is None:shutil.rmtree(root)
    progress({'status':report['status'],'completed':failure is None,'last_verified_checkpoint_records':max((point['records_present'] for point in points),default=0)})
    print(json.dumps({'status':report['status'],'checks':len(checks),'failure':failure}))
    return 0 if failure is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
