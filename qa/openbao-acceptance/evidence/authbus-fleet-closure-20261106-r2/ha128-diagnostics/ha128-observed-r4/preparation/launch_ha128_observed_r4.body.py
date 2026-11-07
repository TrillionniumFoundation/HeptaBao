#!/usr/bin/env python3
"""Bind the existing official-history HA128 harness to current native artifacts.

Only the three new synthetic roots are mutable. Production clients, services,
credentials, routes and old fixtures are outside this launch. PINS is embedded
from the immutable af91 QA tree. This separate adapter observes the
complete original HA128 workload; no prefix stop or product change is present.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time

BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
SOURCE = BASE / 'ha-qa-af91-preparation-20261106-r1/source'
CONTROL = BASE / 'ha128-observed-current-launch-20261107-r4'
WORK = BASE / 'native-ha-official-history-4bde9-authbus-r4'
QA = SOURCE / 'qa/openbao-acceptance'
QA_COMMIT = 'af91ec0cecbb1c0bd717095d6d8696a3f73a1cee'
QA_TREE = 'c3c5755344f407149b84bfaec285f1dba9be90f6'
PRODUCT_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'
PRODUCT_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'
PYTHON = '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
LINUX_ROOT = '/home/qian/heptabao-current-pocket4-4bde9-qualification-20261106-r1'
LINUX_SHA = '85c1e21771cc1110e6442ba06cbda31db5ba7040d15f8b5c1930aa6fa40c5e5c'
LINUX_RECEIPT_SHA = '25263aa341d5525570da0c950ff519ed808110fc301c63fab7b1611015b7fa8e'
MAC_SHA = '5f75acb9822defded2ed21f2f0ed1c21895c5e7d8d8d595e9f1c4ee9b9eaa85c'
MAC_RECEIPT_SHA = 'eb4c910582b3848ae263e2717f4277f51b57124d9567090a6aef78df06594f9b'
OFFICIAL_SHA = '89448bf85f01828b05c4ad5f310502bd116d57ea2bb29b0f368577420b79603d'
PINS = {}  # ASSEMBLED_AF91_PYTHON_PINS
PAYLOADS = {}  # ASSEMBLED_DIAGNOSTIC_PAYLOADS
STDLIB_PINS = {
    '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/lib/python3.14/urllib/request.py':
        (77037, '7465dbf037295f8f04774c453ab84c31879999c507fa16a82627ce9bd9615992'),
    '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/lib/python3.14/http/client.py':
        (58043, 'a5cd9edd48e0bc67c2ea0b13ea45749d28cd8d6313bb103b17c13509f60a3e33'),
}
PAYLOAD_NAMES = {
    'ha128_transport_observed_r4.py', 'ha_http_transport_observer_formal_r1.py',
    'observe_ha128_r4_owned_x230_pid.py',
}


ARGUMENTS = [
    '--official-full34-root', str(BASE / 'full34-dr25-authbus-r2/quarantine/original-closure'),
    '--official-full34-summary-sha256', OFFICIAL_SHA,
    '--binary-source', 'x230:' + LINUX_ROOT + '/artifacts/heptabao-server',
    '--expected-binary-sha256', LINUX_SHA,
    '--node-binary', ','.join(('hepta-mac-local', 'hepta-mac-local:' + str(BASE / 'build-test-4bde9-r1/artifacts/heptabao-server'), MAC_SHA, PRODUCT_COMMIT, PRODUCT_TREE)),
    '--native-build-receipt', 'x230,x230:' + LINUX_ROOT + '/provenance/native-build.public.json,' + LINUX_RECEIPT_SHA,
    '--native-build-receipt', 'ai395,x230:' + LINUX_ROOT + '/provenance/native-build.public.json,' + LINUX_RECEIPT_SHA,
    '--native-build-receipt', 'hepta-mac-local,hepta-mac-local:' + str(BASE / 'ha-native-build-projection-20261106-r1/native-build.public.json') + ',' + MAC_RECEIPT_SHA,
    '--source-commit', PRODUCT_COMMIT, '--source-tree', PRODUCT_TREE,
    '--node', 'x230,192.168.0.13,/home/qian/heptabao-native-ha-4bde9-authbus-20261107-r4',
    '--node', 'ai395,192.168.0.11,/home/qq/heptabao-native-ha-4bde9-authbus-20261107-r4',
    '--node', 'hepta-mac-local,192.168.0.8,' + str(BASE / 'native-ha-4bde9-authbus-node-r4'),
    '--api-port', '31040', '--raft-port', '31041',
    '--mesh-local-port-base', '55200', '--mesh-reverse-port-base', '55300', '--mesh-api-port-base', '55400',
    '--work-root', str(WORK), '--allow-private-lan',
    '--darwin-watchdog-python', PYTHON, '--darwin-watchdog-python-sha256', PYTHON_SHA,
]

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def ident(value):
    return tuple(str(getattr(value, k)) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read(path, maximum, private=False):
    path = Path(path)
    need(path.resolve(strict=True) == path, 'canonical_input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid in ((501,) if private else (0, 501))
             and before.st_nlink == 1 and not before.st_mode & (0o077 if private else 0o022)
             and 0 <= before.st_size <= maximum, 'bounded_owned_regular_input')
        data = bytearray()
        while len(data) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        need(len(data) == before.st_size and ident(before) == ident(os.fstat(fd)) == ident(path.lstat()), 'whole_stable_input')
        return bytes(data), ident(before)
    finally:
        os.close(fd)

def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(count > 0, 'private_write_progress')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def snapshot():
    need(len(PINS) > 0, 'assembled_pins_required')
    result = {}
    for relative, pin in PINS.items():
        need(not relative.startswith('/') and '..' not in Path(relative).parts, 'repository_relative_dependency')
        raw, identity = read(SOURCE / relative, pin['bytes'])
        need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'qa_dependency_exact')
        result[relative] = identity
    return result

def runtime_snapshot():
    result = {}
    for path, (size, pin) in STDLIB_PINS.items():
        raw, identity = read(path, size)
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == pin, 'actual_stdlib_exact')
        result[path] = identity
    return result

def diagnostic_snapshot():
    need(set(PAYLOADS) == PAYLOAD_NAMES, 'exact_three_new_diagnostic_sources')
    result = {}
    for name, entry in PAYLOADS.items():
        raw, identity = read(CONTROL / name, entry['bytes'], private=True)
        need(len(raw) == entry['bytes'] and hashlib.sha256(raw).hexdigest() == entry['sha256'], 'diagnostic_source_exact')
        result[name] = identity
    return result

def main():
    os.umask(0o077)
    sys.dont_write_bytecode = True
    started = time.monotonic()
    report = {'schema': 'heptabao.current-ha128-observed-launch.r1', 'ok': False,
              'qaCommit': QA_COMMIT, 'qaTree': QA_TREE, 'productCommit': PRODUCT_COMMIT,
              'productTree': PRODUCT_TREE, 'arguments': ARGUMENTS,
              'productionChanged': False, 'productionAuthority': False,
              'providerRequests': 0, 'fullReplacementQualified': False,
              'automaticRetry': False, 'harnessEntered': False,
              'originalProductBudgetsChanged': False, 'outerSupervisorSeconds': 1800, 'observerOnlyChange': True,
              'gitOperations': [], 'sourceBeforeAfterExact': False}
    created = False
    raw_summary = None
    before = None
    owner = None
    try:
        need(sys.platform == 'darwin' and platform.machine() == 'arm64' and os.geteuid() == 501, 'actual_mac_owner')
        raw_python, _ = read(PYTHON, 1048576)
        need(hashlib.sha256(raw_python).hexdigest() == PYTHON_SHA and Path(sys.executable).resolve(strict=True) == Path(PYTHON), 'fixed_python')
        for directory in (BASE, SOURCE, QA):
            s = directory.lstat()
            need(directory.resolve(strict=True) == directory and stat.S_ISDIR(s.st_mode) and s.st_uid == 501 and not s.st_mode & 0o022, 'owned_source_directory')
        need(not CONTROL.exists() and not CONTROL.is_symlink() and not WORK.exists() and not WORK.is_symlink(), 'new_owned_launch_and_work_roots')
        before = snapshot()
        runtime_before = runtime_snapshot()
        os.mkdir(CONTROL, 0o700)
        created = True
        need(set(PAYLOADS) == PAYLOAD_NAMES, 'exact_three_new_diagnostic_sources')
        for name, entry in PAYLOADS.items():
            raw = base64.b64decode(entry['base64'], validate=True)
            need(len(raw) == entry['bytes'] and hashlib.sha256(raw).hexdigest() == entry['sha256'], 'embedded_diagnostic_source_exact')
            create(CONTROL / name, raw)
        diagnostic_before = diagnostic_snapshot()
        report['diagnosticSourcePins'] = {name: {'bytes': entry['bytes'], 'sha256': entry['sha256']} for name, entry in PAYLOADS.items()}
        sys.path.insert(0, str(QA))
        import kv2_dr_process_custody as custody
        import native_v6_ha_official_history_live as official
        sys.path.insert(0, str(CONTROL))
        import ha128_transport_observed_r4 as diagnostic
        need(Path(diagnostic.__file__).resolve() == CONTROL / 'ha128_transport_observed_r4.py'
             and Path(diagnostic.observer.__file__).resolve() == CONTROL / 'ha_http_transport_observer_formal_r1.py'
             and diagnostic.official is official and diagnostic.custody is custody, 'fixed_diagnostic_import_origins')
        import urllib.request, http.client
        need(set((str(Path(urllib.request.__file__).resolve()), str(Path(http.client.__file__).resolve())))
             == set(STDLIB_PINS), 'fixed_actual_stdlib_import_origins')
        need(Path(custody.__file__).resolve() == QA / 'kv2_dr_process_custody.py'
             and Path(official.__file__).resolve() == QA / 'native_v6_ha_official_history_live.py', 'fixed_import_origins')
        need((len(official.direct.DIRECT_CHECKS), len(official.EXTRA_CHECKS), len(official.OfficialHistoryRun.required_checks)) == (98, 30, 128), 'original_128_check_definition')
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/qianqi', 'LC_ALL': 'C', 'LANG': 'C',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
               'GIT_OPTIONAL_LOCKS': '0', 'PYTHONDONTWRITEBYTECODE': '1'}
        def freeze(label):
            deadline = time.monotonic() + 60
            observed = {}
            with custody.activated() as current_owner:
                for name, args in (
                    ('head', ['rev-parse', 'HEAD']),
                    ('tree', ['rev-parse', 'HEAD^{tree}']),
                    ('clean', ['status', '--porcelain=v1', '--untracked-files=all']),
                    ('product', ['diff', '--quiet', PRODUCT_COMMIT, QA_COMMIT, '--', '.', ':(exclude)qa', ':(exclude)docs']),
                ):
                    left = deadline - time.monotonic()
                    need(left > 0, 'source_observation_deadline')
                    result = subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', *args], cwd=SOURCE,
                        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(15, left), start_new_session=True)
                    need(len(result.stdout) <= 1048576 and len(result.stderr) <= 1048576, 'bounded_git_output')
                    row = {'stage': label, 'name': name, 'exitCode': result.returncode,
                           'stdoutBytes': len(result.stdout), 'stderrBytes': len(result.stderr),
                           'stdoutSha256': hashlib.sha256(result.stdout).hexdigest(), 'stderrSha256': hashlib.sha256(result.stderr).hexdigest()}
                    report['gitOperations'].append(row)
                    create(CONTROL / (label + '-' + name + '.stdout'), result.stdout)
                    create(CONTROL / (label + '-' + name + '.stderr'), result.stderr)
                    need(result.returncode == 0, 'source_git_known_zero')
                    observed[name] = result.stdout
                current_owner.assert_retired()
            report[label + 'GitCustody'] = current_owner.receipt()
            need(current_owner.receipt()['passed_process_custody'], 'git_children_closed')
            need(observed['head'].decode().strip() == QA_COMMIT and observed['tree'].decode().strip() == QA_TREE
                 and observed['clean'] == b'' and observed['product'] == b'', 'clean_exact_source_and_product')
        freeze('before')
        need(snapshot() == before and runtime_snapshot() == runtime_before
             and diagnostic_snapshot() == diagnostic_before, 'source_stable_before_entry')
        create(CONTROL / 'admission.public.json', (json.dumps({**report, 'admitted': True, 'dependencyCount': len(before)}, sort_keys=True) + '\n').encode())
        report['harnessEntered'] = True
        report['harnessExitCode'] = diagnostic.main(ARGUMENTS)
        raw_summary, _ = read(WORK / 'summary.json', 16 * 1024 * 1024, private=True)
        summary = json.loads(raw_summary)
        need(summary.get('schema') == 'heptabao.native-v6-direct-lan-official271-history.v1', 'original_summary_schema')
        report['summaryBytes'] = len(raw_summary)
        report['summarySha256'] = hashlib.sha256(raw_summary).hexdigest()
        freeze('after')
        need(snapshot() == before and runtime_snapshot() == runtime_before
             and diagnostic_snapshot() == diagnostic_before, 'all_source_dependencies_unchanged')
        report['sourceBeforeAfterExact'] = True
        required = official.OfficialHistoryRun.required_checks
        checks = summary.get('checks', [])
        need(report['harnessExitCode'] == 0 and summary.get('status') == 'passed'
             and len(checks) == len(required) == 128 and {r.get('case') for r in checks} == required
             and all(r.get('passed') is True for r in checks)
             and summary.get('official_history_chain_qualified') is True
             and summary.get('native_ha_backup_verified') is True
             and not summary.get('cleanup_failure') and not summary.get('failure_code'), 'original_ha128_result_qualified')
        need(summary.get('observerOriginalRequiredCheckCount') == 128
             and summary.get('observerChangesOriginalWorkload') is False
             and summary.get('observerChangesFormalDenominator') is False
             and summary.get('observerChangesOriginalBudgets') is False
             and isinstance(summary.get('transportObservations'), list)
             and 0 < len(summary['transportObservations']) <= 2048,
             'original_ha128_transport_observation_bound')
        report['ok'] = True
    except BaseException as error:
        report['errorType'] = type(error).__name__
        report['errorCode'] = str(error) if isinstance(error, Refused) else 'original_launch_or_harness_failed'
    report['elapsedSeconds'] = time.monotonic() - started
    report['dependencyCount'] = len(before) if before is not None else 0
    raw = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if created:
        create(CONTROL / 'result.public.json', raw)
    print(raw.decode(), end='', flush=True)
    if raw_summary is not None:
        # This is the harness's own secret-safe public report, copied unchanged.
        sys.stdout.buffer.write(raw_summary)
        sys.stdout.buffer.flush()
    return 0 if report['ok'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
