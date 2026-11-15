#!/usr/bin/env python3
"""Stage one exact Mac source without compiling or touching an existing service."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

os.umask(0o077)
BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
ROOT = BASE / 'continuation-20261106-kv2-ha-convergence-r1'
SOURCE = ROOT / 'source'
OLD = BASE / 'continuation-20261105-same-root-publication-normal-r2/source'
OUT = ROOT / 'control/source-stage-1d63-r1'
COMMIT = '1d63ec98ce0fc5cbc7d74a37f6307be148dd5aeb'
TREE = 'cae7f371ee07d90f7ac9d50d1c205ca77bfd3902'
OLD_COMMIT = '4e808d0ecb1bcded22870a7ec960dfb2491cf6ec'
OLD_TREE = 'eba5e650bd080b8ad41ea52a2bc68867f541d255'
PYTHON_SHA = 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
START = time.monotonic()
UNTIL = START + 600
CHILDREN = []
PROTECTED = 0
PENDING = None
ENV = {k: os.environ[k] for k in ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ') if k in os.environ}
ENV.update(PATH='/opt/homebrew/bin:/usr/bin:/bin', GIT_TERMINAL_PROMPT='0', GIT_TRACE='0', GIT_CURL_VERBOSE='0')
REPORT = dict(schema='heptabao.mac-independent-source-stage.r1', status='failed',
              source_commit=COMMIT, source_tree=TREE, source=str(SOURCE),
              original_source=str(OLD), stage_budget_seconds=600, steps=[],
              compiler_started=False, service_started=False, production_changed=False,
              inherited_success_claim=False, automatic_retry=False)


class Failed(RuntimeError):
    pass


class Cancelled(BaseException):
    pass


def need(value, label):
    if not value:
        raise Failed(label)


def interrupted(signum, _frame):
    global PENDING
    PENDING = signum
    if not PROTECTED:
        raise Cancelled()


for number in (signal.SIGTERM, signal.SIGINT):
    signal.signal(number, interrupted)


def sha(path):
    p = Path(path)
    before = p.stat()
    with p.open('rb') as stream:
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = p.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'input_changed_during_hash')
    return value


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def members(pgid):
    raw = subprocess.check_output(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,stat='], timeout=5, text=True)
    found = []
    for line in raw.splitlines():
        parts = line.split()
        need(len(parts) >= 4 and all(s.isdecimal() for s in parts[:3]), 'ps_numeric_shape')
        if int(parts[2]) == pgid:
            found.append(dict(pid=int(parts[0]), ppid=int(parts[1]), pgid=int(parts[2]), state=parts[3]))
    return found


def retire(process):
    # Same ownership rule as the successful Mac61 runner: never signal a
    # reaped numeric PGID. Any surviving group refuses stage qualification.
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    return members(process.pid)


def run(label, command, cap, cwd=ROOT):
    global PROTECTED
    until = min(UNTIL - 30, time.monotonic() + cap)
    need(time.monotonic() < until, 'original_stage_deadline')
    row = dict(label=label, argv=command, cap_seconds=cap, timed_out=False)
    child = None
    print(json.dumps(dict(event='stage-step-started', label=label)), flush=True)
    with (OUT / (label + '.stdout')).open('xb') as so, (OUT / (label + '.stderr')).open('xb') as se:
        try:
            PROTECTED += 1
            try:
                child = subprocess.Popen(command, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                                         stdout=so, stderr=se, start_new_session=True)
                CHILDREN.append((label, child))
            finally:
                PROTECTED -= 1
            if PENDING is not None:
                raise Cancelled()
            try:
                child.wait(timeout=max(0.001, until - time.monotonic()))
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
        finally:
            if child is not None:
                row.update(pid=child.pid, remaining=retire(child), exit_code=child.returncode,
                           direct_child_reaped=child.returncode is not None)
            so.flush(); se.flush(); os.fsync(so.fileno()); os.fsync(se.fileno())
    row.update(stdout_sha256=sha(OUT / (label + '.stdout')), stderr_sha256=sha(OUT / (label + '.stderr')),
               completed_before_step_deadline=time.monotonic() < until)
    REPORT['steps'].append(row); write(OUT / (label + '.public.json'), row)
    need(child is not None and row['exit_code'] == 0 and not row['timed_out']
         and row['direct_child_reaped'] and not row['remaining']
         and row['completed_before_step_deadline'], label + '_failed')
    return (OUT / (label + '.stdout')).read_text().strip()


def git(label, args, cap=30, cwd=ROOT):
    return run(label, ['/usr/bin/git', '--no-optional-locks', '-c', 'core.hooksPath=/dev/null', *args], cap, cwd)


def freeze(label, source):
    return dict(commit=git(label + '-head', ['-C', str(source), 'rev-parse', 'HEAD']),
                tree=git(label + '-tree', ['-C', str(source), 'rev-parse', 'HEAD^{tree}']),
                status=git(label + '-clean', ['-C', str(source), 'status', '--porcelain=v1', '--untracked-files=all']))


def retained():
    selection = json.loads((ROOT / 'build-test-r1/test-selection.public.json').read_text())
    result = {}
    for name, value in selection['old_retained_artifacts'].items():
        p = Path(value['path'])
        need(p.is_file() and not p.is_symlink(), 'retained_regular_file')
        result[name] = dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p))
        need(result[name]['bytes'] == value['bytes'] and result[name]['sha256'] == value['sha256'], 'retained_artifact_changed')
    return result


need(os.uname().sysname == 'Darwin' and os.uname().machine == 'arm64' and os.getuid() == 501, 'native_mac_required')
need(ROOT.resolve(strict=True) == ROOT and ROOT.stat().st_dev == 16777244
     and stat.S_IMODE(ROOT.stat().st_mode) == 0o700, 'private_t5_root_required')
need(sha(sys.executable) == PYTHON_SHA, 'python_pin')
need(not OUT.exists() and not OUT.is_symlink() and not SOURCE.exists() and not SOURCE.is_symlink(), 'fresh_stage_required')
OUT.mkdir(mode=0o700)
REPORT['controller_sha256'] = sha(__file__)
write(OUT / 'intent.public.json', REPORT)
try:
    REPORT['old_retained_before'] = retained()
    REPORT['old_source_before'] = freeze('00-old', OLD)
    need(REPORT['old_source_before'] == dict(commit=OLD_COMMIT, tree=OLD_TREE, status=''), 'old_source_binding')
    git('10-independent-clone', ['clone', '--no-hardlinks', '--no-checkout', '--', str(OLD), str(SOURCE)], 120)
    need((SOURCE / '.git').is_dir() and not (SOURCE / '.git').is_symlink()
         and not (SOURCE / '.git/objects/info/alternates').exists(), 'independent_git_directory')
    git('11-fetch-published-exact', ['fetch', '--no-tags', 'https://github.com/TrillionniumFoundation/HeptaBao.git', COMMIT], 240, SOURCE)
    need(git('12-canonical-tree', ['rev-parse', COMMIT + '^{tree}'], cwd=SOURCE) == TREE, 'canonical_tree')
    need(git('13-canonical-parent', ['rev-parse', COMMIT + '^'], cwd=SOURCE) == '4be17241395952b01890d30545b537a28ac2c06c', 'canonical_parent')
    git('14-checkout-exact', ['checkout', '--detach', COMMIT], cwd=SOURCE)
    need(git('15-complete-history', ['rev-parse', '--is-shallow-repository'], cwd=SOURCE) == 'false', 'complete_history_required')
    git('16-full-fsck', ['fsck', '--full', '--strict'], 60, SOURCE)
    REPORT['source_after'] = freeze('17-new', SOURCE)
    need(REPORT['source_after'] == dict(commit=COMMIT, tree=TREE, status=''), 'new_source_binding')
    REPORT['status'] = 'prepared'
except BaseException as error:
    REPORT['failure'] = str(error) if isinstance(error, Failed) else type(error).__name__
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        need(PENDING is None and time.monotonic() < UNTIL - 30, 'preservation_observation_deadline')
        REPORT['old_retained_after'] = retained()
        REPORT['old_source_after'] = freeze('98-old-final', OLD)
        need(REPORT['old_retained_after'] == REPORT.get('old_retained_before'), 'retained_final_binding')
        need(REPORT['old_source_after'] == REPORT.get('old_source_before'), 'old_source_final_binding')
    except BaseException as error:
        REPORT['status'] = 'failed'; REPORT['preservation_failure'] = type(error).__name__
    REPORT['cleanup'] = []
    for label, child in reversed(CHILDREN):
        try:
            remaining = retire(child)
            REPORT['cleanup'].append(dict(label=label, pid=child.pid, exit_code=child.returncode,
                                          direct_child_reaped=child.returncode is not None, remaining=remaining))
        except BaseException as error:
            REPORT['cleanup'].append(dict(label=label, remaining=None, error_type=type(error).__name__))
            REPORT['status'] = 'failed'
    REPORT['all_owned_stopped'] = all(row.get('direct_child_reaped') and row.get('remaining') == [] for row in REPORT['cleanup'])
    REPORT['within_original_stage_budget'] = time.monotonic() < UNTIL
    if PENDING is not None or not REPORT['all_owned_stopped'] or not REPORT['within_original_stage_budget']:
        REPORT['status'] = 'failed'
    REPORT['elapsed_seconds'] = time.monotonic() - START
    write(OUT / 'result.public.json', REPORT)
    print(json.dumps(dict(status=REPORT['status'], receipt=str(OUT / 'result.public.json'),
                          sha256=sha(OUT / 'result.public.json'), compiler_started=False)), flush=True)
sys.exit(0 if REPORT['status'] == 'prepared' else 1)
