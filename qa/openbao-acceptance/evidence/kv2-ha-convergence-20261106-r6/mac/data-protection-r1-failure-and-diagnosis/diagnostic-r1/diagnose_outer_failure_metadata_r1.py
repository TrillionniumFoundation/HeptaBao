#!/usr/bin/env python3
"""One read-only post-failure metadata observation; no prior error reconstruction."""
import time
ENTRY = time.monotonic()
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OLD = ROOT / 'control/current-sqlite-data-protection-execution-r1'
END = ENTRY + 52
FIRED = False
FINISHING = False
OPENED = 0
CLOSED = 0
PUBLIC = {'schema': 'heptabao.current-data-protection-failed-admission-metadata.v1',
          'status': 'failed', 'original_job_id': '1a1b1f76336-fc05-7bc7',
          'original_failure_remains_failed': True, 'historical_primary_error_reconstructed': False,
          'observation_scope': 'later_read_only_metadata_not_original_failure_instant',
          'work_seconds': 52, 'runtime_seconds': 60, 'subprocesses_started': 0,
          'business_database_or_key_contents_opened': False, 'network_or_provider_called': False,
          'workflow_executed': False, 'existing_assets_modified': False,
          'private_values_or_fingerprints_published': False, 'formal_kv2_qualified': False}


class Refused(Exception):
    pass


class Stopped(BaseException):
    pass


def need(ok, label):
    if not ok:
        raise Refused(label)


def check():
    need(not FIRED and time.monotonic() < END, 'original_diagnostic_deadline')


def stopped(signum, frame):
    global FIRED
    FIRED = True
    if not FINISHING:
        raise Stopped()


def identity(st):
    return {'dev': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid, 'gid': st.st_gid,
            'mode': stat.S_IMODE(st.st_mode), 'file_type': stat.S_IFMT(st.st_mode),
            'nlink': st.st_nlink, 'bytes': st.st_size,
            'mtime_ns': st.st_mtime_ns, 'ctime_ns': st.st_ctime_ns}


def read_owned(path, maximum, pin=None):
    global OPENED, CLOSED
    check()
    need(path.resolve(strict=True) == path, 'canonical_original_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    OPENED += 1
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 501 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= maximum,
             'original_private_file_custody')
        raw = bytearray()
        while len(raw) <= maximum:
            check()
            part = os.read(fd, 65536)
            if not part:
                break
            raw.extend(part)
        ident = identity(before)
        need(len(raw) == before.st_size and len(raw) <= maximum
             and ident == identity(os.fstat(fd)) == identity(path.lstat()), 'original_file_changed_during_read')
        if pin is not None:
            need(len(raw) == pin[0] and hashlib.sha256(raw).hexdigest() == pin[1], 'original_public_bytes')
        return bytes(raw), ident
    finally:
        os.close(fd)
        CLOSED += 1


def main():
    global FINISHING
    numbers = (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    old = {n: signal.getsignal(n) for n in numbers}
    timer = signal.getitimer(signal.ITIMER_REAL)
    armed = False
    result = 1
    try:
        need(timer == (0.0, 0.0), 'foreign_timer_refused')
        for n in numbers:
            signal.signal(n, stopped)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, END - time.monotonic()))
        armed = True
        need(sys.platform == 'darwin' and os.geteuid() == 501 and sys.version_info[:3] == (3, 14, 3),
             'fixed_mac_python')
        public_raw, public_id = read_owned(OLD / 'result.public.json', 16384,
            (5109, 'c57baaa47b723ed073d09f8297b9e058bd45a4dc9e4741a8a436bd598bc15050'))
        prior = json.loads(public_raw)
        need(prior['status'] == 'failed' and prior['workflow_invoked'] is False, 'exact_failed_before_workflow')
        private_raw, private_id = read_owned(OLD / 'outer.private.json', 131072)
        need(private_id == prior['private_closure_file_identity'], 'original_private_record_identity')
        private = json.loads(private_raw)
        need(private['schema'] == 'heptabao.current-sqlite-outer-private.v1', 'original_private_schema')
        PUBLIC['original_primary_failure_retained_separately'] = any(
            name in private for name in ('primary_failure', 'primary_failure_code', 'first_failure', 'first_error'))
        PUBLIC['original_last_public_code'] = prior['failure_code'] if prior['failure_code'] == 'final_owned_custody_incomplete' else 'other'
        observations = private.get('actual_volume_observations', {})
        need(set(observations) <= {'Data', 'T5'}, 'original_volume_observation_roles')
        PUBLIC['original_volume_observation_roles'] = sorted(observations)
        binding = private['workflow_plan_binding']
        rows = []
        for alias, mount in (('Data', Path('/System/Volumes/Data')), ('T5', Path('/Volumes/T5'))):
            check()
            expected = binding['volume_identities'][alias]['directory']
            st = mount.lstat()
            now = {'dev': st.st_dev, 'inode': st.st_ino, 'uid': st.st_uid,
                   'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode)}
            saved = {k: expected[k] for k in now}
            rows.append({'role': alias, 'current_numeric_identity': now,
                         'original_stage_numeric_identity': saved,
                         'current_matches_original_stage_identity': now == saved,
                         'current_canonical_directory': mount.resolve(strict=True) == mount and stat.S_ISDIR(st.st_mode),
                         'current_owner_matches_original_outer_guard': st.st_uid in (0, 501),
                         'current_mode_matches_original_outer_guard': not bool(stat.S_IMODE(st.st_mode) & 0o022),
                         'original_stage_mode_matches_outer_guard': not bool(saved['mode'] & 0o022),
                         'original_diskutil_comparison_was_recorded_passed': alias in observations})
        PUBLIC['volume_directory_observations'] = rows
        plan = private['workflow_plan']
        attempts = {'capture': Path(plan['capture']['capture_parent']) / plan['capture']['capture_name'],
                    'archive': Path(plan['backup']['archive_parent']) / plan['backup']['archive_name'],
                    'key': Path(plan['backup']['key_parent']) / plan['backup']['key_name'],
                    'restore': Path(plan['restore']['restore_parent']) / plan['restore']['restore_name']}
        PUBLIC['current_attempt_roots_absent'] = {role: not os.path.lexists(path) for role, path in attempts.items()}
        PUBLIC['original_private_stdio_metadata'] = [
            {'role': role, 'bytes': (OLD / name).lstat().st_size,
             'mode': stat.S_IMODE((OLD / name).lstat().st_mode)}
            for role, name in (('stdout', 'workflow.stdout.private'), ('stderr', 'workflow.stderr.private'))]
        again, again_id = read_owned(OLD / 'outer.private.json', 131072)
        need(again == private_raw and again_id == private_id, 'original_private_record_unchanged')
        again, again_id = read_owned(OLD / 'result.public.json', 16384)
        need(again == public_raw and again_id == public_id, 'original_public_record_unchanged')
        check()
        PUBLIC.update(status='observation_completed', original_private_and_public_records_unchanged=True)
        result = 0
    except BaseException as error:
        PUBLIC.update(status='failed', error=str(error) if isinstance(error, Refused) else type(error).__name__)
    finally:
        FINISHING = True
        elapsed = time.monotonic() - ENTRY
        if FIRED or elapsed >= 52 or OPENED != CLOSED:
            PUBLIC.update(status='failed', error='original_deadline_or_handle_retirement')
            result = 1
        PUBLIC.update(deadline_fired=FIRED, elapsed_observation_seconds=elapsed,
                      original_file_descriptors_opened=OPENED, original_file_descriptors_closed=CLOSED,
                      all_original_file_descriptors_retired=OPENED == CLOSED)
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        for n, handler in old.items():
            signal.signal(n, handler)
        if armed:
            signal.setitimer(signal.ITIMER_REAL, *timer)
        if FIRED or time.monotonic() >= ENTRY + 60:
            PUBLIC.update(status='failed', error='final_original_deadline')
            result = 1
        print(json.dumps(PUBLIC, sort_keys=True, separators=(',', ':')), flush=True)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
