#!/usr/bin/env python3
"""Reconcile the r2 unknown mount on its exact cold clone; never replay it.

Fresh ordinary initialization retains V4 owner storage. The tested V5 seed
sequence is a dedicated KV2 mount and two CAS writes. Run it once on a cold
clone, remove that dedicated mount, then prove every two-share cold recovery.
The r1 state, response, failure evidence and all production nodes stay intact.
"""
import base64
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/heptabao-production-20261104-r1')
BASE = ROOT/'control/prepare_recoverable_seed_61ff_http_v2.py'
BASE_SHA = 'b7b14b6fcbf767d76873b215ce10119fe58beb50ec3fbd164b4925ceb188cfea'
R1 = ROOT/'authority/seed-custody/bootstrap-61ff8bef-r1'
R1_RESULT_SHA = '1fac5c29c563841aa0b85b28146197565ab0e794c7dbb33d149dc2b41b60cc9f'
R1_INIT_SHA = 'f2ebe0e0a356ead15bed458038c8f2c240a226d6548995951fb2feb885eae119'
R2 = ROOT/'authority/seed-custody/bootstrap-61ff8bef-r2'
R2_RESULT_SHA = '5856a6c7308d4f73b796ee4a14a58d6406727f50b1756b654d5826f24122cc34'
WORK = ROOT/'authority/seed-custody/bootstrap-61ff8bef-r3'
MOUNT = 'heptabao-seed-recovery-61ff'


def load_base():
    info = BASE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 501 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o500
            or hashlib.sha256(BASE.read_bytes()).hexdigest() != BASE_SHA):
        raise RuntimeError('original_seed_helper_pin')
    spec = importlib.util.spec_from_file_location('pinned_recoverable_seed', BASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base()


def copy_stopped_tree(source, destination, expected):
    base.mkdir(destination)
    for relative in sorted(expected, key=lambda value: (len(Path(value).parts), value)):
        target = destination/relative
        for parent in reversed(target.parents):
            if parent == destination or parent in destination.parents:
                continue
            if not parent.exists():
                base.mkdir(parent)
        path = source/relative
        raw = base.private_read(path, stat.S_IMODE(path.stat().st_mode))
        base.need(base.sha(raw) == expected[relative]['sha256'], 'original_cold_file_changed')
        base.put(target, raw)
    base.need(base.inventory(destination) == expected, 'exact_original_cipher_clone')


class ResumeRun(base.SeedRun):
    def capacity(self, label):
        code, body = self.request(label, 'GET', 'sys/internal/capacity', auth=True)
        self.check(label+'.status', code == 200 and isinstance(body.get('data'), dict))
        data = body['data']
        self.report.setdefault('capacity_observations', []).append({
            'label': label, **{key: data.get(key) for key in (
                'profile', 'state_storage_format', 'state_schema', 'state_bytes',
                'native_kv2_reader_format', 'opaque_owner_aggregate_bytes')}})
        return data

    def unseal_pair(self, pair, label):
        super().unseal_pair(pair, label)
        code, mounts = self.request(label+'-mounts', 'GET', 'sys/mounts', auth=True)
        self.check(label+'.temporary_mount_absent', code == 200
                   and MOUNT+'/' not in mounts.get('data', mounts))

    def execute(self):
        self.report.update(resumed_from_acknowledged_r1=True, initialization_repeated=False,
            original_r1_result_sha256=R1_RESULT_SHA, original_init_response_sha256=R1_INIT_SHA,
            source_helper_sha256=BASE_SHA, v4_to_v5_promoted=False,
            prior_unknown_mount_replayed=False, r2_unknown_mount_reconciled=False)
        self.report['boundary_before'] = base.boundary()
        r1raw = base.private_read(R1/'result.public.json')
        base.need(base.sha(r1raw) == R1_RESULT_SHA, 'original_result_pin')
        r1 = json.loads(r1raw)
        base.need(r1['failure'] == 'seed-initial.expected_seed_storage_format'
                  and r1['all_owned_children_stopped'] is True
                  and len(r1['requests']) == 7
                  and all(r['outcome'] == 'response_received' for r in r1['requests'])
                  and len(r1['processes']) == 1, 'acknowledged_original_attempt_required')
        r2raw = base.private_read(R2/'result.public.json')
        base.need(base.sha(r2raw) == R2_RESULT_SHA, 'r2_result_pin')
        r2 = json.loads(r2raw)
        base.need(r2['failure'] == 'fixed_seed_api_response_framing'
                  and r2['all_owned_children_stopped'] is True and len(r2['requests']) == 8
                  and all(r['outcome'] == 'response_received' for r in r2['requests'][:-1])
                  and len(r2['processes']) == 1, 'exact_r2_failure_boundary')
        unresolved = r2['requests'][-1]
        base.need(unresolved['outcome'] == 'unknown' and unresolved['method'] == 'POST'
                  and unresolved['path'] == 'sys/mounts/'+MOUNT
                  and unresolved['nonce'] == '0f2be8fc31a9430c91f67d784ae8e5b3'
                  and unresolved['request_body_sha256'] == 'c3d74e38f3a73ed4f46b635eb4f27fa6b53f5c92b0357ec35a4fd8a82cd91de7',
                  'only_the_exact_unknown_mount_can_be_reconciled')
        process = r2['processes'][0]
        base.need(process['stopped'] and not process['forced_kill'] and process['returncode'] == -15,
                  'original_process_gracefully_reaped')
        check = subprocess.run(['/bin/ps', '-p', str(process['pid']), '-o', 'command='],
                               capture_output=True, text=True, timeout=6)
        base.need(check.returncode in (0, 1), 'original_pid_observation_failed')
        old_argv = shlex.split(check.stdout.strip()) if check.stdout.strip() else []
        expected_argv = [str(ROOT/'release/heptabao-server'), '--config', str(R2/'seed/server.private.json')]
        base.need(old_argv != expected_argv, 'original_owned_server_still_active')
        initraw = base.private_read(R1/'initialization-response.private.json')
        base.need(len(initraw) == 591 and base.sha(initraw) == R1_INIT_SHA,
                  'exact_durable_initialization_response')
        init = json.loads(initraw)
        self.root_token, self.shares = init['root_token'], init['keys_base64']
        base.need(isinstance(self.root_token, str) and len(self.shares) == 3
                  and len(set(self.shares)) == 3
                  and all(len(base64.b64decode(s, validate=True)) >= 16 for s in self.shares),
                  'original_recovery_material_shape')
        self.secret_values = [self.root_token, *self.shares, *init.get('keys', [])]
        base.put(WORK/'initialization-response.private.json', initraw)
        self.r1_inventory = base.inventory(R1/'seed/state')
        self.original_inventory = base.inventory(R2/'seed/state')
        base.mkdir(WORK/'seed')
        copy_stopped_tree(R2/'seed/state', WORK/'seed/state', self.original_inventory)
        self.check('original_cipher_clone_exact', base.inventory(WORK/'seed/state') == self.original_inventory)
        self.start('seed')
        code, status = self.request('original-cold-seal-status', 'GET', 'sys/seal-status')
        self.check('original_cold_threshold', code == 200 and status.get('sealed') is True
                   and status.get('n') == 3 and status.get('t') == 2 and status.get('progress') == 0)
        for ordinal, index in enumerate((0, 1)):
            code, value = self.request('original-cold-share-'+str(index+1), 'POST', 'sys/unseal', {'key': self.shares[index]})
            self.check('original_cold_share_'+str(index+1), code == 200
                       and value.get('sealed') is (ordinal == 0)
                       and value.get('progress') == (1 if ordinal == 0 else 0))
        code, health = self.request('original-cold-health', 'GET', 'sys/health')
        self.check('original_cold_initialized', code == 200 and health.get('initialized') is True
                   and health.get('sealed') is False and isinstance(health.get('cluster_id'), str)
                   and bool(health['cluster_id']))
        self.cluster_id = health['cluster_id']
        code, lookup = self.request('original-root-lookup', 'GET', 'auth/token/lookup-self', auth=True)
        self.check('original_root_survives_cold_clone', code == 200 and lookup.get('data', {}).get('policies') == ['root'])
        initial = self.capacity('before-v5-promotion')
        self.check('r2_clone_has_admitted_pre_native_format',
                   (initial['state_storage_format'], initial['profile']) in (
                       ('heptabao-state-owners-v4', 'bounded-owner-state-v4'),
                       ('heptabao-state-records-v5', 'bounded-record-state-v5'))
                   and initial['native_kv2_reader_format'] is None)
        code, mounts = self.request('reconcile-unknown-mount-read-only', 'GET', 'sys/mounts', auth=True)
        registry = mounts.get('data', mounts)
        found = registry.get(MOUNT+'/') if isinstance(registry, dict) else None
        self.check('prior_unknown_mount_is_exact_committed_kv2', code == 200 and isinstance(found, dict)
                   and found.get('type') == 'kv' and found.get('options', {}).get('version') == '2')
        code, _ = self.request('reconcile-no-prior-cas-write', 'GET', MOUNT+'/data/proof', auth=True)
        self.check('no_prior_proof_value', code == 404)
        self.report['r2_unknown_mount_reconciled'] = True
        self.report['mount_reconciliation'] = {'original_request_nonce': unresolved['nonce'],
            'original_outcome_retained': 'unknown', 'observed_mount_metadata_sha256': base.sha(base.encoded(found)),
            'observed_type': 'kv', 'observed_version': '2', 'new_mount_request_sent': False,
            'followup_value_read_status': 404, 'scope': 'exact stopped r2 ciphertext clone'}
        for version in (1, 2):
            code, value = self.request('dedicated-cas-write-'+str(version), 'POST', MOUNT+'/data/proof',
                {'options': {'cas': version-1}, 'data': {'marker': 'seed-recovery-proof-'+str(version)}}, auth=True)
            self.check('dedicated_cas_version_'+str(version), code == 200 and value.get('data', {}).get('version') == version)
            self.capacity('after-dedicated-cas-'+str(version))
        code, value = self.request('dedicated-cas-read', 'GET', MOUNT+'/data/proof', auth=True)
        self.check('dedicated_latest_value_exact', code == 200
                   and value.get('data', {}).get('data') == {'marker': 'seed-recovery-proof-2'}
                   and value.get('data', {}).get('metadata', {}).get('version') == 2)
        code, _ = self.request('dedicated-mount-remove-once', 'DELETE', 'sys/mounts/'+MOUNT, auth=True)
        self.check('dedicated_mount_removed', code == 204)
        final = self.capacity('after-dedicated-mount-removal')
        self.check('clean_seed_retains_exact_v5', final['state_storage_format'] == 'heptabao-state-records-v5'
                   and final['profile'] == 'bounded-record-state-v5' and final['native_kv2_reader_format'] is None)
        self.report['v4_to_v5_promoted'] = True
        self.seal('v5-seed'); self.stop(); self.cold_archive()
        for pair in itertools.combinations(range(3), 2):
            name = 'cold-recovery-'+''.join(str(i+1) for i in pair)
            self.restore(name); self.start(name)
            code, status = self.request(name+'-initial-status', 'GET', 'sys/seal-status')
            self.check(name+'.cold_sealed_threshold', code == 200 and status.get('sealed') is True
                       and status.get('n') == 3 and status.get('t') == 2 and status.get('progress') == 0)
            self.unseal_pair(pair, name); self.seal(name); self.stop()
        self.check('original_r1_cipher_state_unchanged', base.inventory(R1/'seed/state') == self.r1_inventory)
        self.check('original_r2_cipher_state_unchanged', base.inventory(R2/'seed/state') == self.original_inventory)
        self.check('original_r2_receipt_unchanged', base.sha(base.private_read(R2/'result.public.json')) == R2_RESULT_SHA)
        self.check('original_r1_receipt_unchanged', base.sha(base.private_read(R1/'result.public.json')) == R1_RESULT_SHA)
        self.check('v5_cold_seed_still_exact', base.inventory(WORK/'seed/state') == self.seed_inventory)
        self.report['boundary_after'] = base.boundary()
        self.check('production_boundary_unchanged', self.report['boundary_before'] == self.report['boundary_after'])
        self.report.update(cluster_id=self.cluster_id, cold_recovery_pairs_verified=[[1, 2], [1, 3], [2, 3]],
            initialization_response_sha256=R1_INIT_SHA, recovery_share_sha256=[base.sha(s.encode()) for s in self.shares],
            original_r1_cipher_inventory=self.r1_inventory, original_r2_cipher_inventory=self.original_inventory)
        for path in sorted(WORK.rglob('server.*.private.log')):
            raw = base.private_read(path)
            self.check('server_log_no_credential_'+base.sha(str(path.relative_to(WORK)).encode())[:12],
                       all(secret.encode() not in raw for secret in self.secret_values))
        self.check('public_report_no_credential', all(secret.encode() not in base.encoded(self.report) for secret in self.secret_values))
        self.report['ok'] = True


def main():
    os.umask(0o077)
    base.boundary()
    base.need(not WORK.exists() and not WORK.is_symlink(), 'fresh_resume_work_required')
    base.mkdir(WORK); base.mkdir(WORK/'journal')
    base.put(WORK/'intent.public.json', {'schema': 'heptabao.unknown-mount-seed-reconciliation-intent.v1',
        'original_result_sha256': R1_RESULT_SHA, 'r2_result_sha256': R2_RESULT_SHA, 'original_init_sha256': R1_INIT_SHA,
        'initialize_again': False, 'original_http_seconds': base.HTTP_SECONDS,
        'original_state_modified': False, 'production_state_populated': False,
        'dedicated_mount': MOUNT, 'unknown_mount_replayed': False, 'temporary_mutations': 'read-only mount reconciliation, then new CAS0, CAS1, unmount exactly once on cold clone'})
    run = ResumeRun(WORK)
    handlers = {sig: signal.signal(sig, lambda number, frame: run.handle_signal(number))
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        run.execute()
    except BaseException as exc:
        run.report['ok'] = False
        run.report['failure'] = str(exc) if isinstance(exc, base.Refused) else type(exc).__name__
    finally:
        try:
            run.stop()
        except BaseException as exc:
            run.report['ok'] = False
            run.report['cleanup_failure'] = str(exc) if isinstance(exc, base.Refused) else type(exc).__name__
        run.report['all_owned_children_stopped'] = all(p['stopped'] for p in run.report['processes'])
        base.need(all(s.encode() not in base.encoded(run.report) for s in run.secret_values), 'public_secret_scan')
        digest = base.put(WORK/'result.public.json', run.report)
        run.root_token = None; run.shares = []; run.secret_values = []
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    print(json.dumps({'ok': run.report['ok'], 'result': str(WORK/'result.public.json'),
        'sha256': digest, 'all_owned_children_stopped': run.report['all_owned_children_stopped'],
        'initialization_repeated': False, 'production_service_started': False}))
    return 0 if run.report['ok'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc) if isinstance(exc, base.Refused) else type(exc).__name__,
                          'automatic_retry': False, 'initialization_repeated': False}))
        raise SystemExit(2)
