import base64
import hashlib
import json
import os
import pathlib
import subprocess
import time

start = time.monotonic()
end = start + 150
os.umask(0o077)
root = pathlib.Path('/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1')
old = root / 'source-868-r7'
fresh = root / 'source-09c14-r8'
out = root / 'control/source-09c14-r8-prep'
bundle = out / 'candidate.bundle'
BUNDLE_B64 = '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'
COMMIT = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'
TREE = 'dfb0df97a2c74b1c0154f45342f3debb0ce438ab'
PARENT = '868439e6df9f12291842898763ccba581e346bfb'
OLD_TREE = 'c211d66343235fbb8a220744f3e97768559007c8'
OLD_RECEIPT = root / 'build-test-r7/result.public.json'
OLD_RECEIPT_SHA = '423799fbc2e69b08e8bc2f29f9813b1365f017765f9292394a48ce1b7d068a9e'
env = {k: os.environ[k] for k in ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ') if k in os.environ}
env.update(PATH='/usr/bin:/bin', GIT_OPTIONAL_LOCKS='0')
report = {'schema': 'heptabao.fresh-clean-source-preparation.v1', 'status': 'running',
          'source_commit': COMMIT, 'source_tree': TREE, 'old_source_preserved': False,
          'cooperative_lock_removed': False, 'compiler_started': False,
          'production_changed': False, 'original_preparation_seconds': 150, 'steps': []}


def run(label, args, cwd=root, cap=30):
    remaining = min(cap, end - time.monotonic())
    assert remaining > 0, 'original_preparation_deadline_expired'
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, timeout=remaining)
    (out / (label + '.stdout')).write_bytes(result.stdout)
    (out / (label + '.stderr')).write_bytes(result.stderr)
    report['steps'].append({'label': label, 'argv': args, 'exit_code': result.returncode,
                            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                            'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
    assert result.returncode == 0, label
    return result.stdout


def old_identity(tag):
    assert old.is_dir() and not old.is_symlink(), 'old_source_directory'
    identity = old.lstat()
    head = run(tag + '-head', ['/usr/bin/git', 'rev-parse', 'HEAD'], old).decode().strip()
    tree = run(tag + '-tree', ['/usr/bin/git', 'rev-parse', 'HEAD^{tree}'], old).decode().strip()
    clean = run(tag + '-clean', ['/usr/bin/git', 'status', '--porcelain'], old)
    assert head == PARENT and tree == OLD_TREE and not clean.strip(), 'old_source_identity'
    receipt = OLD_RECEIPT.read_bytes()
    assert hashlib.sha256(receipt).hexdigest() == OLD_RECEIPT_SHA, 'failed_receipt_changed'
    return {'head': head, 'tree': tree, 'clean': True, 'failed_receipt_sha256': OLD_RECEIPT_SHA,
            'directory_identity': [identity.st_dev, identity.st_ino, identity.st_uid, identity.st_gid, identity.st_mode]}


assert not fresh.exists() and not fresh.is_symlink(), 'new_source_exists'
out.mkdir(mode=0o700)
try:
    raw = base64.b64decode(BUNDLE_B64, validate=True)
    assert len(raw) == 2001 and hashlib.sha256(raw).hexdigest() == '1343cc508548e8cad01f0ba5271d563fbf17725fd8a264f232db1ccdded0cc0d'
    with bundle.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    report['old_before'] = old_identity('00-before')
    run('01-clone', ['/usr/bin/git', '-c', 'gc.auto=0', 'clone', '--no-hardlinks', '--no-checkout', str(old), str(fresh)], cap=60)
    run('02-bundle-verify', ['/usr/bin/git', 'bundle', 'verify', str(bundle)], fresh)
    run('03-fetch', ['/usr/bin/git', '-c', 'gc.auto=0', 'fetch', str(bundle), 'HEAD'], fresh)
    run('04-checkout', ['/usr/bin/git', 'checkout', '--detach', COMMIT], fresh)
    assert run('05-head', ['/usr/bin/git', 'rev-parse', 'HEAD'], fresh).decode().strip() == COMMIT
    assert run('06-tree', ['/usr/bin/git', 'rev-parse', 'HEAD^{tree}'], fresh).decode().strip() == TREE
    assert run('06-parent', ['/usr/bin/git', 'rev-parse', 'HEAD^'], fresh).decode().strip() == PARENT
    assert not run('07-clean', ['/usr/bin/git', 'status', '--porcelain'], fresh).strip()
    run('08-fsck', ['/usr/bin/git', 'fsck', '--full', '--strict'], fresh, 60)
    report['old_after'] = old_identity('09-after')
    assert report['old_before'] == report['old_after'], 'old_source_changed'
    assert time.monotonic() < end, 'original_preparation_deadline_expired'
    report.update(status='passed', old_source_preserved=True, new_source=str(fresh), new_source_clean=True)
except BaseException as error:
    report.update(status='failed', failure_type=type(error).__name__, failure=str(error))
    raise
finally:
    report['elapsed_seconds'] = time.monotonic() - start
    with (out / 'result.public.json').open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(report), flush=True)
