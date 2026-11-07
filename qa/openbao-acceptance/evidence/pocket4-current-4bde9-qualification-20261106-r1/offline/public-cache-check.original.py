#!/usr/bin/env python3
"""Verify the received public cache with the two original Linux metadata commands."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import time

ROOT = Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
SOURCE = ROOT / 'source-4bde9'
OUT = ROOT / 'build-test-r1'
CARGO_HOME = ROOT / 'cargo-home-public-linux-r1'
INBOX = ROOT / 'linux-public-closure-inbox-r1'
TOOLCHAIN = Path('/home/alex/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
RECEIVER_RECEIPT_SHA = '9989b3beaa9774d875e5b7bdadc49053301ccc56b8dd5cbc4710acd23dc2031d'
COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
LOCK = 'd2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5'
EXPECTED = {
    'server': (19322, '1db4fc50cca8e55ea1238353bf00ddbdf91f58fd0c2fc69d5ec3aa1633c9a3e0'),
    'peer': (5221, '8985a6f6ccfdd7b94e2b22dd3fbc9b46162b00099e39621545f05959fff84c06'),
}
ORIGINAL_TREE_PINS = {
    'server': (19276, '3d112e6e8671700cd9c87b10e7c3f917b95633d469189c63cadf747ed736e707'),
    'peer': (5215, '40e70fe078077d01cb304131a61c2fa54c1dbbd9a871fe56151a321cc94c420f'),
}
PINNED_TOOLS = {
    'cargo': 'ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24',
    'rustc': '3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2',
    'rustfmt': '5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877',
}
os.umask(0o077)
env = {key: os.environ[key] for key in ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ')
       if key in os.environ}
env.update(CARGO_HOME=str(CARGO_HOME), CARGO_TARGET_DIR=str(ROOT / 'target-normal'), CARGO_BUILD_JOBS='1',
           CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
           CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
           CARGO_PROFILE_RELEASE_CODEGEN_UNITS='16', CARGO_PROFILE_RELEASE_LTO='false',
           CARGO_PROFILE_RELEASE_PANIC='unwind', CARGO_TERM_COLOR='never', RUSTFLAGS='',
           PATH=str(TOOLCHAIN) + ':/usr/bin:/bin', RUSTC=str(TOOLCHAIN / 'rustc'), RUSTFMT=str(TOOLCHAIN / 'rustfmt'),
           RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='', CARGO_BUILD_RUSTC_WRAPPER='', CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER='')


def need(ok, label):
    if not ok:
        raise RuntimeError(label)


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def source_identity():
    git_env = {'PATH': '/usr/bin:/bin', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'LC_ALL': 'C'}
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '-c', 'core.fsmonitor=false', '-c',
                                        'core.hooksPath=/dev/null', '-C', str(SOURCE), *args],
                                       env=git_env, stderr=subprocess.DEVNULL, timeout=15).decode().strip()
    need(git('rev-parse', 'HEAD') == COMMIT and git('rev-parse', 'HEAD^{tree}') == TREE
         and not git('status', '--porcelain', '--untracked-files=all'), 'clean_exact_source')
    need(digest(SOURCE / 'Cargo.lock') == LOCK, 'canonical_lock')


r = {'schema': 'heptabao.pocket4-linux-offline-dependencies.v2', 'status': 'running',
     'source_commit': COMMIT, 'source_tree': TREE, 'cargo_home': str(CARGO_HOME),
     'cargo_dependency_metadata_commands_executed': False, 'rust_build_or_product_tests_executed': False,
     'production_changed': False, 'formal_107_qualified': False, 'steps': [],
     'expected_tree_path_adaptation': {
         'only_replacement': {'from': '/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/source-4bde9',
                              'to': str(SOURCE)},
         'original_tree_pins': ORIGINAL_TREE_PINS,
         'expected_receiver_tree_pins': EXPECTED,
         'all_other_tree_bytes_unchanged': True}}
try:
    need(re.fullmatch(r'[0-9a-f]{64}', RECEIVER_RECEIPT_SHA), 'actual_transfer_receipt_must_be_bound')
    source_identity()
    for name, sha in PINNED_TOOLS.items():
        need(digest(TOOLCHAIN / name) == sha, 'exact_toolchain_' + name)
    need(digest(INBOX / 'receive.result.public.json') == RECEIVER_RECEIPT_SHA, 'actual_receiver_receipt_pin')
    received = json.loads((INBOX / 'receive.result.public.json').read_bytes())
    need(received['status'] == 'installed' and received['installed_file_count'] == 677
         and received['cargo_home'] == str(CARGO_HOME)
         and received['manifest_sha256'] == '0d74878d414151a41fa85927ff0732ea2ab123dcdf0955aa8cd75c5be2216897'
         and received['payload_sha256'] == '8e771190e6df05560f8a41bbf7992586137ee4ab730123301c6dba0d595759c9'
         and received['normal107_qualified'] is False
         and received['all_installed_files_sha256_readback_equal'] is True, 'actual_received_public_closure')
    need(digest(OUT / 'offline-dependencies.result.public.json')
         == '38e5e61a503d68f753d9e7efcbf613e38a1547f5353a5df04f3c5642ddcb3003',
         'original_offline_failure_preserved')
    logdir = OUT / 'offline-dependency-check-public-cache-r2'
    logdir.mkdir(mode=0o700)
    common = [str(TOOLCHAIN / 'cargo'), 'tree', '--locked', '--offline', '--target',
              'x86_64-unknown-linux-gnu', '--edges', 'normal,build,dev', '--prefix', 'none']
    for label, extra in [('server', ['-p', 'heptabao-server']),
                         ('peer', ['-p', 'heptabao-ha-service', '--features', 'native-v6-peer-ingress'])]:
        so, se = logdir / (label + '.stdout'), logdir / (label + '.stderr')
        row = {'label': label, 'argv': common + extra, 'cap_seconds': 60, 'attempts': 1, 'timed_out': False}
        began = time.monotonic()
        with so.open('xb') as outf, se.open('xb') as errf:
            try:
                p = subprocess.run(row['argv'], cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                                   stdout=outf, stderr=errf, timeout=60)
                row['exit_code'] = p.returncode
            except subprocess.TimeoutExpired:
                row.update(exit_code=None, timed_out=True)
            finally:
                outf.flush()
                errf.flush()
                os.fsync(outf.fileno())
                os.fsync(errf.fileno())
        row.update(seconds=time.monotonic() - began, stdout_bytes=so.stat().st_size,
                   stdout_sha256=digest(so), stderr_bytes=se.stat().st_size, stderr_sha256=digest(se))
        row['exact_expected_tree_bytes'] = (row['stdout_bytes'], row['stdout_sha256']) == EXPECTED[label]
        r['steps'].append(row)
        r['cargo_dependency_metadata_commands_executed'] = True
        need(row['exit_code'] == 0 and not row['timed_out'] and row['stderr_bytes'] == 0
             and row['exact_expected_tree_bytes'], 'original_' + label + '_offline_tree_not_exact')
    source_identity()
    need(digest(INBOX / 'receive.result.public.json') == RECEIVER_RECEIPT_SHA, 'receiver_receipt_unchanged')
    need(digest(OUT / 'offline-dependencies.result.public.json')
         == '38e5e61a503d68f753d9e7efcbf613e38a1547f5353a5df04f3c5642ddcb3003', 'old_failure_unchanged')
    r.update(status='passed', selected_linux_dependency_closures_available=True, source_and_lock_unchanged=True,
             actual_receiver_receipt_sha256=RECEIVER_RECEIPT_SHA, both_expected_full_tree_outputs_exact=True,
             original_failed_preparation_preserved=True, no_old_user_cache_modified=True)
except BaseException as error:
    r.update(status='failed', failure=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
finally:
    r['finished_at_unix'] = time.time()
    target = OUT / 'offline-dependencies-public-cache-r2.result.public.json'
    with target.open('x') as f:
        json.dump(r, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps({'status': r['status'], 'result': str(target),
                      'rust_build_or_product_tests_executed': False}), flush=True)
raise SystemExit(0 if r['status'] == 'passed' else 1)
