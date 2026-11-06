#!/usr/bin/env python3
"""One isolated TLS/native-V6 role assignment diagnosis on an existing Mac binary."""
from __future__ import annotations
import base64
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-jwt-default-diagnosis-r1')
SOURCE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/source-09c14-r1')
COMMIT = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
TREE = 'dfb0df97a2c74b1c0154f45342f3debb0ce438ab'
BINARY = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-09c14-r1/artifacts/heptabao-server')
BINARY_BYTES = 92359328
BINARY_SHA256 = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
FORMATTER = Path('/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/rustfmt')
FORMATTER_SHA256 = 'ca9cbe15a4add6baf62d8ce177015c9c48f209ebcf4364416b1953142e8701f8'
PYTHON_SHA256 = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
PINS = [
    ('qa/openbao-acceptance/kv2_dr_process_custody.py', 26131, '669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008'),
    ('qa/openbao-acceptance/owned_process.py', 28442, '0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0'),
    ('qa/single-node/smoke.py', 16470, 'ced4e40a825d3d98a285598d40b58c61083cfc397d0859a783958d855a161971'),
]
PRODUCTION_PINS = [
    ('crates/heptabao-server/src/auth.rs', 398266, '9f366e631019e55aca61717a324bf13c1995797ed088b5b9d8b80c4a11914f7f'),
    ('crates/heptabao-server/src/auth_token_policies.rs', 8679, '495249b1592cf239fb857e7ccde6c9e1224869c79a2392e03dfdabcb98ed65b9'),
]
TEST_PATH = 'crates/heptabao-server/src/service_native_jwt_tests.rs'
TEST_BYTES = 42377
TEST_SHA256 = 'd36bd868975958093c50218ad1e06b20a58b5156a37cd58718dfdc1654c1f156'
PRIOR_GIT_BLOB = '17a0a1b0a91c88497620e17d69329f8afaefce92'
CANDIDATE_GIT_BLOB = '807917a7839998a2cc69b6ea437c0c5fa2a1d4a5'
TARGET_FUNCTION = 'native_jwt_role_operations_keep_the_existing_legacy_acl_contract'
ROLE = 'auth/native-jwt/role/client'
TOTAL_SECONDS = 120.0
HTTP_SECONDS = 10.0
CLEANUP_SECONDS = 5.0
POLICY = ('path "jwt-kv/data/value" { capabilities = ["read"] } '
          'path "auth/token/lookup-self" { capabilities = ["read"] } '
          'path "auth/token/renew-self" { capabilities = ["update"] } '
          'path "auth/token/revoke-self" { capabilities = ["update"] }')
MANAGER = ('path "auth/native-jwt/role" { capabilities = ["list"] } '
           'path "auth/native-jwt/role/client" { capabilities = ["read","update","sudo"] }')
NO_SUDO = 'path "auth/native-jwt/role/client" { capabilities = ["read","update"] }'
STARTED = time.monotonic()
UNTIL = STARTED + TOTAL_SECONDS

class DiagnosticFailure(RuntimeError): pass

def need(ok, code):
    if not ok: raise DiagnosticFailure(code)

def remaining(minimum=0):
    need(time.monotonic() + minimum < UNTIL, 'original_diagnosis_absolute_deadline')

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def read_pinned(path, size, expected):
    remaining()
    need(path.resolve(strict=True) == path, 'source_alias_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size
             and not before.st_mode & 0o022 and 0 < size <= 1024 * 1024, 'bounded_regular_source')
        data = b''
        while len(data) <= size:
            remaining()
            part = os.read(fd, min(65536, size + 1 - len(data)))
            if not part: break
            data += part
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'stable_source')
        need(len(data) == size and hashlib.sha256(data).hexdigest() == expected, 'source_pin_mismatch')
        return data
    finally:
        os.close(fd)

def pin_executable(path, expected, expected_size=None):
    remaining()
    need(path.resolve(strict=True) == path, 'executable_alias_refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= 256 * 1024 * 1024
             and before.st_uid == 501 and not before.st_mode & 0o022, 'expected_executable_metadata')
        need(expected_size is None or before.st_size == expected_size, 'expected_executable_size')
        digest = hashlib.sha256(); count = 0
        while True:
            remaining()
            part = os.read(fd, 1024 * 1024)
            if not part: break
            digest.update(part); count += len(part)
            need(count <= before.st_size, 'bounded_executable')
        need(count == before.st_size and digest.hexdigest() == expected, 'executable_hash_mismatch')
        need(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()), 'executable_changed')
        return identity(before)
    finally:
        os.close(fd)

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def source_scope(original, candidate):
    old, new = original.decode(), candidate.decode()
    marker = 'fn ' + TARGET_FUNCTION + '() -> TestResult {'
    a, b = old.index(marker), new.index(marker)
    ae, be = old.index('\n#[test]', a), new.index('\n#[test]', b)
    need(old[:a] == new[:b] and old[ae:] == new[be:], 'only_target_function_changes')
    old_names = re.findall(r'#\[test\]\s*fn\s+(\w+)', old)
    need(old_names == re.findall(r'#\[test\]\s*fn\s+(\w+)', new) and len(old_names) == 15, 'same_fifteen_jwt_tests')
    need('        &f.actor(&manager, "POST", ROLE, json!({"token_ttl":301}))?,\n        204,' in new
         and 'status(&f.actor(&manager, "DELETE", ROLE, json!({}))?, 204);' in new,
         'success_status_contract_unchanged')
    return {'changed_function': TARGET_FUNCTION, 'all_other_test_file_bytes_unchanged': True,
            'test_names_unchanged': True, 'jwt_test_count': 15,
            'positive_update_and_delete_still_require_204': True, 'production_files_changed': False}

def main():
    report = {'schema': 'heptabao.native-jwt-default-policy-actual-mac-diagnosis.r1', 'status': 'failed',
              'host': 'mac', 'source_commit': COMMIT, 'source_tree': TREE,
              'binary_path': str(BINARY), 'binary_sha256': BINARY_SHA256, 'binary_bytes': BINARY_BYTES,
              'normal_release_binary': True, 'new_build_executed': False, 'product107_rerun': False,
              'changed_rust_test_executed': False, 'production_changed': False,
              'provider_requested': False, 'j3160_contacted': False, 'credential_values_or_digests_included': False,
              'diagnosis_seconds': TOTAL_SECONDS, 'http_timeout_seconds': HTTP_SECONDS,
              'cleanup_timeout_seconds': CLEANUP_SECONDS, 'automatic_retry': False,
              'checks': [], 'actor_policies': {}, 'full_replacement_qualified': False}
    owner = instance = None; sensitive = []; root_created = False
    hooks = {'popen': subprocess.Popen, 'killpg': os.killpg}
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGCHLD)}
    business_ok = False; scope_closed = False
    try:
        need(sys.platform == 'darwin' and os.geteuid() == 501, 'actual_mac_operator')
        with Path(sys.executable).open('rb') as stream:
            need(hashlib.file_digest(stream, 'sha256').hexdigest() == PYTHON_SHA256, 'qualified_python_pin')
        need(ROOT.parent.resolve(strict=True) == ROOT.parent and ROOT.parent.stat().st_dev == 16777244, 'original_t5_parent')
        need((SOURCE / '.git/HEAD').read_text().strip() == COMMIT, 'exact_detached_source_commit')
        os.umask(0o077); ROOT.mkdir(mode=0o700); root_created = True
        write_new(ROOT / 'diagnose_existing_mac_binary.py', SELF_SOURCE)
        report['runner_sha256'] = hashlib.sha256(SELF_SOURCE).hexdigest()
        report['runner_git_blob'] = git_blob(SELF_SOURCE)
        initial_binary = pin_executable(BINARY, BINARY_SHA256, BINARY_BYTES)
        initial_formatter = pin_executable(FORMATTER, FORMATTER_SHA256)
        for relative, size, digest in PINS + PRODUCTION_PINS:
            raw = read_pinned(SOURCE / relative, size, digest)
            if relative.startswith('qa/'):
                path = ROOT / 'inputs' / relative; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                write_new(path, raw)
        original = read_pinned(SOURCE / TEST_PATH, TEST_BYTES, TEST_SHA256)
        need(git_blob(original) == PRIOR_GIT_BLOB and git_blob(CANDIDATE_SOURCE) == CANDIDATE_GIT_BLOB, 'exact_original_and_candidate_blobs')
        expected = original.decode()
        for old_part, new_part in PATCH_BLOCKS:
            need(expected.count(old_part) == 1, 'one_exact_source_replacement')
            expected = expected.replace(old_part, new_part, 1)
        need(expected.encode() == CANDIDATE_SOURCE, 'exact_prepared_minimal_patch')
        report['static_scope'] = source_scope(original, CANDIDATE_SOURCE)
        (ROOT / 'candidate').mkdir(mode=0o700)
        candidate_path = ROOT / 'candidate/service_native_jwt_tests.rs'
        write_new(candidate_path, CANDIDATE_SOURCE)
        report['source_pins'] = [{'path': path, 'bytes': size, 'sha256': digest} for path, size, digest in PINS + PRODUCTION_PINS]
        input_path = ROOT / 'inputs/qa/openbao-acceptance'; sys.path.insert(0, str(input_path))
        import kv2_dr_process_custody as custody
        import owned_process
        spec = importlib.util.spec_from_file_location('jwt_diagnosis_smoke', ROOT / 'inputs/qa/single-node/smoke.py')
        smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
        need(owned_process._CURRENT is None, 'compatibility_api_under_qualified_custody')
        with custody.activated() as owner:
            try:
                remaining(60)
                version = subprocess.run([str(FORMATTER), '--version'], check=True, capture_output=True, timeout=10)
                need(not version.stderr and len(version.stdout) < 256, 'bounded_formatter_version')
                subprocess.run([str(FORMATTER), '--edition', '2024', str(candidate_path)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                subprocess.run([str(FORMATTER), '--edition', '2024', '--check', str(candidate_path)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                formatted = candidate_path.read_bytes()
                report['static_scope'] = source_scope(original, formatted)
                report['formatter'] = {'path': str(FORMATTER), 'sha256': FORMATTER_SHA256,
                    'version': version.stdout.decode().strip(), 'edition': '2024', 'format_exit_code': 0, 'check_exit_code': 0,
                    'only_new_copy_formatted': True, 'original_source_unchanged': True}
                report['candidate_source'] = {'path': str(candidate_path), 'bytes': len(formatted),
                    'sha256': hashlib.sha256(formatted).hexdigest(), 'git_blob': git_blob(formatted)}
                patch = ''.join(difflib.unified_diff(original.decode().splitlines(True), formatted.decode().splitlines(True),
                    fromfile='a/' + TEST_PATH, tofile='b/' + TEST_PATH))
                write_new(ROOT / 'fixture.patch', patch.encode())
                write_new(ROOT / 'static-review.public.json', (json.dumps(report['static_scope'], sort_keys=True) + '\n').encode())
                remaining(45)
                instance = smoke.Instance(BINARY, ROOT / 'server')
                config_path = instance.root / 'server.json'
                config = json.loads(config_path.read_text())
                need(config['listen'] == '127.0.0.1:' + str(instance.port), 'isolated_loopback_listener')
                config['storage'] = {'native_v6_file': {'path': config['data_dir']}}
                temporary = config_path.with_name('server.json.native.new')
                write_new(temporary, json.dumps(config).encode()); os.replace(temporary, config_path)
                report['storage_profile'] = 'native_v6_file'
                raw_call = instance.call
                def bounded_call(*args, **kwargs):
                    remaining(HTTP_SECONDS)
                    result = raw_call(*args, **kwargs)
                    remaining()
                    return result
                instance.call = bounded_call
                def check(name, ok, **facts):
                    report['checks'].append({'case': name, 'passed': bool(ok), **facts})
                    need(ok, name)
                def call(name, method, path, body=None, *, token=None, expected=200):
                    status, data = instance.call(method, path, body, token=token)
                    check(name, status == expected, status=status, expected=expected)
                    return data
                instance.start()
                initialized = call('initialize', 'POST', 'sys/init', {'secret_shares': 1, 'secret_threshold': 1}, token='')
                instance.token = initialized['root_token']; key = initialized['keys_base64'][0]
                sensitive.extend((instance.token, key)); initialized.clear()
                call('unseal', 'POST', 'sys/unseal', {'key': key}, token='')
                call('init_ack', 'POST', 'sys/init/ack', {}, expected=204)
                call('formal_activation', 'POST', 'sys/storage/native-v6/activate', {}, expected=204)
                capacity = call('capacity', 'GET', 'sys/internal/capacity')['data']
                check('formal_native_v6_reader', capacity.get('native_kv2_reader_format') == 2)
                call('kv_mount', 'POST', 'sys/mounts/jwt-kv', {'type': 'kv', 'options': {'version': '2'}}, expected=204)
                call('kv_value', 'POST', 'jwt-kv/data/value', {'options': {'cas': 0}, 'data': {'value': 'jwt-preserved'}})
                for policy, value in [('native-jwt', POLICY), ('jwt-role-manager', MANAGER), ('jwt-role-no-sudo', NO_SUDO)]:
                    call('policy.' + policy, 'PUT', 'sys/policies/acl/' + policy, {'policy': value}, expected=204)
                call('jwt_mount', 'POST', 'sys/auth/native-jwt', {'type': 'jwt'}, expected=204)
                # Public RFC8032 test key; this diagnostic performs no JWT login or provider call.
                public_key = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
                encoded_key = base64.urlsafe_b64encode(public_key).decode().rstrip('=')
                call('jwt_config', 'POST', 'auth/native-jwt/config', {
                    'issuer': 'https://native-jwt.example', 'audiences': ['native'], 'clock_skew_seconds': 0,
                    'keys': [{'kid': 'key', 'algorithm': 'EdDSA', 'key_base64': encoded_key}]}, expected=204)
                call('jwt_role', 'POST', ROLE, {'role_type': 'jwt', 'user_claim': 'sub', 'bound_audiences': ['native'],
                    'token_policies': ['native-jwt'], 'token_ttl': 300, 'token_max_ttl': 600, 'token_type': 'service'}, expected=204)
                original_role = call('role_readback', 'GET', ROLE)['data']
                check('role_retains_default_and_native', original_role['token_policies'] == ['default', 'native-jwt'])
                actors = {}
                specifications = [
                    ('original_missing_default', ['jwt-role-manager', 'native-jwt'], True, ['jwt-role-manager', 'native-jwt']),
                    ('explicit_default_still_removed', ['default', 'jwt-role-manager', 'native-jwt'], True, ['jwt-role-manager', 'native-jwt']),
                    ('missing_native', ['jwt-role-manager'], False, ['default', 'jwt-role-manager']),
                    ('missing_sudo', ['jwt-role-no-sudo', 'native-jwt'], False, ['default', 'jwt-role-no-sudo', 'native-jwt']),
                    ('corrected_manager', ['jwt-role-manager', 'native-jwt'], False, ['default', 'jwt-role-manager', 'native-jwt']),
                ]
                for name, policies, no_default, expected_policies in specifications:
                    response = call(name + '.create', 'POST', 'auth/token/create',
                        {'policies': policies, 'no_default_policy': no_default, 'ttl': '600s'})
                    auth = response['auth']; actual = auth['policies']
                    check(name + '.exact_nonroot_policies', actual == expected_policies and 'root' not in actual)
                    report['actor_policies'][name] = actual
                    actors[name] = auth['client_token']; sensitive.append(actors[name]); response.clear()
                listed = call('manager_list', 'GET', 'auth/native-jwt/role', token=actors['corrected_manager'])
                check('manager_list_contents', listed['data']['keys'] == ['client'])
                for name in ('original_missing_default', 'explicit_default_still_removed', 'missing_native', 'missing_sudo'):
                    denied = call(name + '.update_denied', 'POST', ROLE, {'token_ttl': 301}, token=actors[name], expected=403)
                    check(name + '.no_credential_or_data', all(field not in denied for field in ('auth', 'data', 'wrap_info')))
                    after = call(name + '.role_readback', 'GET', ROLE)['data']
                    check(name + '.role_unchanged', after == original_role)
                call('corrected_manager.update_allowed', 'POST', ROLE, {'token_ttl': 301}, token=actors['corrected_manager'], expected=204)
                changed = call('corrected_manager.role_readback', 'GET', ROLE, token=actors['corrected_manager'])['data']
                check('corrected_manager.only_ttl_changed', changed == {**original_role, 'token_ttl': 301})
                call('corrected_manager.delete_without_delete_capability', 'DELETE', ROLE, {}, token=actors['corrected_manager'], expected=204)
                call('role_absent_after_delete', 'GET', ROLE, expected=404)
                remaining(); business_ok = True
            finally:
                if instance is not None:
                    original_child = instance.process
                    instance.stop()
                    report['server_original_wait_exit_code'] = None if original_child is None else original_child.returncode
                    report['server_log_closed'] = getattr(instance, 'log', None) is None or instance.log.closed
            owner.assert_retired()
        scope_closed = True
        report['source_inputs_unchanged'] = all(read_pinned(SOURCE / relative, size, digest)
            == read_pinned(ROOT / 'inputs' / relative, size, digest) for relative, size, digest in PINS)
        for relative, size, digest in PRODUCTION_PINS: read_pinned(SOURCE / relative, size, digest)
        read_pinned(SOURCE / TEST_PATH, TEST_BYTES, TEST_SHA256)
        report['binary_identity_and_hash_unchanged'] = pin_executable(BINARY, BINARY_SHA256, BINARY_BYTES) == initial_binary
        report['formatter_identity_and_hash_unchanged'] = pin_executable(FORMATTER, FORMATTER_SHA256) == initial_formatter
        report['original_hooks_and_handlers_restored'] = (subprocess.Popen is hooks['popen'] and os.killpg is hooks['killpg']
            and handlers == {sig: signal.getsignal(sig) for sig in handlers})
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            report['no_direct_children'] = False
        except ChildProcessError:
            report['no_direct_children'] = True
        remaining()
    except DiagnosticFailure as error:
        report['error_code'] = str(error)
    except BaseException as error:
        report['error_type'] = type(error).__name__
    finally:
        if owner is not None: report['process_custody'] = owner.receipt()
        report['scope_closed_normally'] = scope_closed
        report['elapsed_seconds'] = time.monotonic() - STARTED
        passed = (business_ok and scope_closed and report.get('source_inputs_unchanged') is True
            and report.get('binary_identity_and_hash_unchanged') is True
            and report.get('formatter_identity_and_hash_unchanged') is True
            and report.get('original_hooks_and_handlers_restored') is True and report.get('no_direct_children') is True
            and report.get('server_original_wait_exit_code') == -9 and report.get('server_log_closed') is True
            and report.get('process_custody', {}).get('passed_process_custody') is True
            and report['elapsed_seconds'] < TOTAL_SECONDS and 'error_code' not in report and 'error_type' not in report)
        report['status'] = 'passed' if passed else 'failed'
        encoded = (json.dumps(report, sort_keys=True) + '\n').encode()
        need(not any(value.encode() in encoded for value in sensitive if value), 'public_secret_projection_refused')
        if root_created: write_new(ROOT / 'result.public.json', encoded)
        print(encoded.decode(), end='', flush=True)
    return 0 if report['status'] == 'passed' else 1

if __name__ == '__main__': raise SystemExit(main())
