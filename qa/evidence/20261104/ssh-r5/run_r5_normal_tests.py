#!/usr/bin/env python3
"""Build once and run the exact reviewed twenty-two SSH tests in the normal profile."""
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import time

ROOT = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1')
SOURCE = ROOT / 'source-r5'
RUN = ROOT / 'normal-tests-r5'
COMMIT = '830f28505af7306bab898a648918a65a9e3e8c60'
TREE = '112394355eb52c4f88e90a0eea40e3a8ea6daef4'
TOOLCHAIN = '/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin'
PROFILE = {
    'PATH': TOOLCHAIN + ':/usr/bin:/bin',
    'CARGO_HOME': '/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home',
    'CARGO_TARGET_DIR': '/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target',
    'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16',
    'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_DEBUG': '0',
    'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
    'CARGO_BUILD_JOBS': '1',
}
EXPECTED = {
    'native_ssh_forward_public_key_original_ingress_and_completion_cannot_downgrade',
    'native_ssh_forward_public_key_does_not_invent_ingress_or_select_other_operations',
    'native_ssh_formal_otp_promotion_cold_verify_and_replay',
    'native_ssh_formal_acl_nonrenewable_revoke_and_segment_prefix',
    'native_ssh_formal_ca_real_signature_cold_typed_public_transport',
    'native_ssh_after_actual_audit_actor_revocation_never_delivers_otp',
    'native_ssh_after_actual_audit_changed_status_does_not_bypass_or_resign',
    'native_ssh_public_reply_cannot_lose_affine_transport_after_audit',
    'native_ssh_and_pki_original_idle_retire_both_without_touching_ca_or_kv',
    'native_ssh_consumed_verify_rechecks_original_issuer_after_actual_audit',
    'native_ssh_formal_batch_expiry_is_clipped_persistent_and_not_revivable',
    'native_ssh_formal_disabled_login_identity_stays_retired_after_reenable_and_cold',
    'native_ssh_actual_audit_cannot_refresh_original_deadline_or_repeat_signature',
    'native_ssh_formal_registry_tune_retire_and_recreate_preserves_other_graphs',
    'native_ssh_actual_audited_reply_cannot_follow_recreated_mount_incarnation',
    'native_ssh_child_and_response_wrap_ownership_remain_explicitly_closed',
    'native_ssh_actual_audit_io_failure_never_returns_the_signed_private_reply',
    'native_ssh_actual_audited_otp_retains_original_precise_issuer_expiry',
    'native_ssh_actual_archive_restore_preserves_otp_consumption_ca_and_observed_issuer_floor',
    'formal_native_ssh_ha_forwarded_otp_election_cold_consume_and_replay',
    'formal_native_ssh_ha_actual_ca_signature_and_raw_public_cold_readindex',
    'formal_native_ssh_ha_lost_quorum_cannot_issue_sign_or_disclose_public_key',
}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for data in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(data)
    return digest.hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(SOURCE), *args], text=True).strip()


def write(name, data):
    with (RUN / name).open('x') as file:
        json.dump(data, file, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())


def unchanged():
    assert git('rev-parse', 'HEAD') == COMMIT
    assert git('rev-parse', 'HEAD^{tree}') == TREE
    assert not git('status', '--porcelain')


def owned(label, args, cap):
    environment = dict(os.environ)
    environment.update(PROFILE)
    started = time.monotonic()
    timeout = False
    with (RUN / (label + '.stdout')).open('xb') as out, (RUN / (label + '.stderr')).open('xb') as err:
        process = subprocess.Popen(args, cwd=SOURCE, env=environment,
                                   stdout=out, stderr=err, start_new_session=True)
        try:
            code = process.wait(timeout=cap)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait(timeout=20)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=20)
    remaining = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if int(fields[2]) == process.pid:
                remaining.append(int(entry.name))
        except (OSError, ValueError, IndexError):
            pass
    result = {'label': label, 'args': args, 'exit_code': code, 'timed_out': timeout,
              'elapsed_seconds': time.monotonic() - started, 'owned_pgid': process.pid,
              'remaining': remaining, 'outer_cap_seconds': cap,
              'stdout_sha256': sha(RUN / (label + '.stdout')),
              'stderr_sha256': sha(RUN / (label + '.stderr'))}
    write(label + '.public.json', result)
    assert not remaining, 'owned compiler/test process remains'
    return result


def main():
    os.umask(0o077)
    assert not RUN.exists(), 'fresh test invocation required'
    unchanged()
    prior = json.loads((ROOT / 'prepare-r5/result.public.json').read_text())
    assert prior['source'] == COMMIT and prior['tree'] == TREE
    assert prior['status'] == 'prepared' and prior['fmt_exit'] == 0
    assert prior['prior_source_unchanged']
    RUN.mkdir(mode=0o700)
    intent = {'schema': 'native-ssh-normal22-r5', 'source': COMMIT, 'tree': TREE,
              'profile': PROFILE, 'default_features': ['native-v6-storage', 'native-v6-ha'],
              'fixture_features': [], 'tests': sorted(EXPECTED), 'test_count': 22,
              'production_services_changed': False, 'started_ns': time.time_ns()}
    write('intent.public.json', intent)
    result = {**intent, 'status': 'failed', 'runtime_tests_started': False}
    try:
        build = owned('build', [TOOLCHAIN + '/cargo', 'test', '--release', '--locked', '--offline',
                      '-p', 'heptabao-server', '--lib', '--no-run',
                      '--message-format=json-render-diagnostics'], 3600)
        result['build'] = build
        assert build['exit_code'] == 0 and not build['timed_out'], 'normal test compilation failed'
        artifacts = []
        for line in (RUN / 'build.stdout').read_text().splitlines():
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get('reason') == 'compiler-artifact' and message.get('profile', {}).get('test') and message.get('target', {}).get('name') == 'heptabao_server' and message.get('executable'):
                artifacts.append(Path(message['executable']))
        assert len(artifacts) == 1, 'one actual normal libtest artifact required'
        built = artifacts[0]
        assert built.is_file() and not built.is_symlink()
        binary_sha = sha(built)
        binary = RUN / 'retained-heptabao-server-libtest'
        with built.open('rb') as src, binary.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        binary.chmod(0o500)
        assert sha(binary) == binary_sha
        result['build_artifact'] = str(built)
        result['binary'] = {'path': str(binary), 'sha256': binary_sha, 'bytes': binary.stat().st_size}
        unchanged()
        listing = owned('list', [str(binary), 'native_ssh_', '--list'], 30)
        result['list'] = listing
        assert listing['exit_code'] == 0
        selected = [line[:-6] for line in (RUN / 'list.stdout').read_text().splitlines() if line.endswith(': test')]
        assert len(selected) == 22 and {name.rsplit('::', 1)[-1] for name in selected} == EXPECTED
        result['actual_test_names'] = selected
        assert sha(binary) == binary_sha
        result['runtime_tests_started'] = True
        tests = owned('tests', [str(binary), 'native_ssh_', '--nocapture', '--test-threads=1'], 600)
        result['tests_result'] = tests
        result['binary_unchanged'] = sha(binary) == binary_sha
        unchanged()
        result['source_unchanged'] = True
        result['status'] = 'passed' if tests['exit_code'] == 0 and not tests['timed_out'] and result['binary_unchanged'] else 'failed'
    except Exception as error:
        result['failure_type'] = type(error).__name__
        result['failure'] = str(error)
    finally:
        result['terminal_ns'] = time.time_ns()
        write('result.public.json', result)
        print(json.dumps(result))
    raise SystemExit(0 if result['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
