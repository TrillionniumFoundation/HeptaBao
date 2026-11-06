#!/usr/bin/env python3
"""Create-only offline QA checkout and read-only full34 source admission.

This prepares no candidate process, credential, listener or production change.
It preserves the existing DR quarantine and its original 31-case result.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
OLD = BASE / 'source-dr25-authbus-r2'
ROOT = BASE / 'ha-qa-af91-preparation-20261106-r1'
SOURCE = ROOT / 'source'
BUNDLE = BASE / 'control/ha-qa-af91-from-5ded.bundle'
OFFICIAL = BASE / 'full34-dr25-authbus-r2/quarantine/original-closure'
OLD_COMMIT = '5ded017e1c858b8602a73678acc29df75386a84d'
OLD_TREE = '9d1d040a063504ede67559fadb556897591642f2'
QA_COMMIT = 'af91ec0cecbb1c0bd717095d6d8696a3f73a1cee'
QA_TREE = 'c3c5755344f407149b84bfaec285f1dba9be90f6'
PRODUCT_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
BUNDLE_BYTES = 1009233
BUNDLE_SHA = '28a2c91da4c77cdb40f015100c57cb7b741fac91a2f77a7950761fd9b6a72144'
OFFICIAL_SHA = '89448bf85f01828b05c4ad5f310502bd116d57ea2bb29b0f368577420b79603d'
PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(value):
    return [str(getattr(value, key)) for key in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')]

def stable_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, 501)
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and 0 <= before.st_size <= maximum, 'stable_regular_input')
        data = bytearray()
        while len(data) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'stable_whole_input')
        return bytes(data), identity(before)
    finally:
        os.close(fd)

def create_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        done = 0
        while done < len(raw):
            count = os.write(fd, raw[done:])
            need(count > 0, 'private_write_progress')
            done += count
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)

def main():
    os.umask(0o077)
    started = time.monotonic()
    until = started + 60
    rows = []
    created = False
    report = {'schema': 'heptabao.mac-ha-qa-source-preparation.r1', 'ok': False,
              'qa_commit': QA_COMMIT, 'qa_tree': QA_TREE, 'product_commit': PRODUCT_COMMIT,
              'preparation_deadline_seconds': 60, 'source_root': str(SOURCE),
              'commands': rows, 'product_processes_started': 0, 'http_requests': 0,
              'credential_inputs_read': False, 'production_changed': False,
              'quarantined_dr_source_modified': False, 'ha_qualified': False,
              'full_replacement_qualified': False}
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/qianqi',
           'LANG': 'C', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_OPTIONAL_LOCKS': '0', 'PYTHONDONTWRITEBYTECODE': '1'}
    def remaining(cap):
        left = until - time.monotonic()
        need(left > 0, 'preparation_original_deadline')
        return min(left, cap)
    def command(label, arguments, cwd, cap=15):
        budget = remaining(cap)
        row = {'label': label, 'argv': arguments, 'cwd': str(cwd),
               'timeout_seconds': budget, 'started': False, 'outcome_known': False}
        rows.append(row)
        before = time.monotonic()
        row['started'] = True
        try:
            result = subprocess.run(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=budget, check=False, start_new_session=True)
            row.update(exit_code=result.returncode, outcome_known=True, timed_out=False,
                       stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr),
                       stdout_sha256=digest(result.stdout), stderr_sha256=digest(result.stderr))
            need(len(result.stdout) <= 1048576 and len(result.stderr) <= 1048576,
                 'bounded_public_git_output')
            if created:
                for name, raw in (('stdout', result.stdout), ('stderr', result.stderr)):
                    create_file(ROOT / (f'{len(rows):02d}-{label}.{name}'), raw)
            need(result.returncode == 0, 'git_command_failed_' + label)
            remaining(1)
            return result.stdout
        except subprocess.TimeoutExpired:
            row.update(timed_out=True, outcome_known=False)
            raise Refused('git_timeout_not_replayed') from None
        finally:
            row['elapsed_seconds'] = time.monotonic() - before
    def git(label, directory, *arguments, cap=15):
        return command(label, ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                              '-c', 'core.fsmonitor=false', *arguments], directory, cap)
    def freeze(prefix, directory, commit, tree):
        need(git(prefix + '-head', directory, 'rev-parse', 'HEAD').decode().strip() == commit,
             prefix + '_exact_commit')
        need(git(prefix + '-tree', directory, 'rev-parse', 'HEAD^{tree}').decode().strip() == tree,
             prefix + '_exact_tree')
        need(git(prefix + '-clean', directory, 'status', '--porcelain=v1',
                 '--untracked-files=all') == b'', prefix + '_clean')
    try:
        need(sys.platform == 'darwin' and os.geteuid() == 501, 'fixed_mac_owner')
        interpreter, _ = stable_file(Path(PYTHON), 1048576)
        need(digest(interpreter) == PYTHON_SHA and Path(sys.executable).resolve() == Path(PYTHON),
             'exact_python_interpreter')
        parent = BASE.lstat()
        need(BASE.resolve(strict=True) == BASE and stat.S_ISDIR(parent.st_mode)
             and parent.st_uid == 501 and not parent.st_mode & 0o022, 'owned_canonical_parent')
        need(OLD.resolve(strict=True) == OLD and OLD.is_dir(), 'existing_local_source')
        need(not ROOT.exists() and not ROOT.is_symlink(), 'new_preparation_root')
        bundle, bundle_identity = stable_file(BUNDLE, 1048576)
        need(len(bundle) == BUNDLE_BYTES and digest(bundle) == BUNDLE_SHA,
             'exact_offline_bundle')
        freeze('old-before', OLD, OLD_COMMIT, OLD_TREE)
        git('bundle-verify', OLD, 'bundle', 'verify', str(BUNDLE))
        os.mkdir(ROOT, 0o700)
        created = True
        git('clone-local', BASE, 'clone', '--local', '--no-hardlinks', '--no-checkout',
            str(OLD), str(SOURCE), cap=20)
        git('fetch-bundle', SOURCE, 'fetch', '--no-tags', str(BUNDLE), 'HEAD', cap=15)
        git('checkout-frozen', SOURCE, 'checkout', '--detach', QA_COMMIT)
        git('fsck', SOURCE, 'fsck', '--full', '--strict', cap=15)
        freeze('qa', SOURCE, QA_COMMIT, QA_TREE)
        git('product-unchanged', SOURCE, 'diff', '--quiet', PRODUCT_COMMIT, QA_COMMIT,
            '--', '.', ':(exclude)qa', ':(exclude)docs')
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))
        import native_v6_ha_official_history_live as official
        counts = {'native_loopback': len(official.native.REQUIRED_CHECKS),
                  'direct_lan': len(official.direct.DIRECT_CHECKS),
                  'official_history': len(official.EXTRA_CHECKS),
                  'integrated': len(official.OfficialHistoryRun.required_checks)}
        need(counts == {'native_loopback': 89, 'direct_lan': 98,
                        'official_history': 30, 'integrated': 128}, 'original_cohort_definitions')
        remaining(1)
        _, _, _, inputs, oracle_identity = official.admit_source(OFFICIAL, OFFICIAL_SHA)
        remaining(1)
        need(len(inputs) == 21, 'complete_official_source_inputs')
        report.update(defined_check_counts=counts, executed_ha_checks=0,
                      official_source_inputs=inputs,
                      official_source_admitted=True, official_source_receipt_sha256=OFFICIAL_SHA,
                      official_source_version=oracle_identity['version'],
                      source_baseline_required_checks=len(official.exact.CHECKS),
                      dr_checks_executed=0)
        for path, expected in inputs.items():
            raw, _ = stable_file(Path(path), 64 * 1048576)
            need(digest(raw) == expected, 'official_source_whole_inputs_unchanged')
        freeze('old-after', OLD, OLD_COMMIT, OLD_TREE)
        freeze('qa-after', SOURCE, QA_COMMIT, QA_TREE)
        after, after_identity = stable_file(BUNDLE, 1048576)
        need(after == bundle and after_identity == bundle_identity, 'bundle_unchanged')
        remaining(1)
        report.update(ok=True, all_commands_known_zero=all(row.get('exit_code') == 0
                      and row['outcome_known'] for row in rows), source_and_bundle_unchanged=True)
    except BaseException as error:
        report.update(error_type=type(error).__name__,
                      error_code=str(error) if isinstance(error, Refused) else 'source_preparation_failed')
    report['elapsed_seconds'] = time.monotonic() - started
    raw = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if created:
        create_file(ROOT / 'result.public.json', raw)
    print(raw.decode(), end='', flush=True)
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    sys.exit(main())
