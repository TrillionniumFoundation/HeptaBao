import base64
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import time

start = time.monotonic()
end = start + 150
os.umask(0o077)
root = pathlib.Path('/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1')
old = root / "source-4bde9-r9"
fresh = root / "source-4bde9-diagnostic-r11"
out = root / "control/source-4bde9-diagnostic-r11-prep"
target = root / "target-4bde9-diagnostic-r11"
build_output = root / "build-test-4bde9-diagnostic-r11"
cargo_home = pathlib.Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home')
bundle = out / 'candidate.bundle'
BUNDLE_B64 = "IyB2MiBnaXQgYnVuZGxlCi0wOWMxNGVhZTdhM2I1MmRlZThjZTNhZjMxNzVkYWQ1OTAwYWM1OWVjIHRlc3QoYXV0aCk6IGNvcnJlY3QgbmF0aXZlIEpXVCBmaXh0dXJlIHByZWNvbmRpdGlvbnMgYW5kIHByb3ZlbmFuY2UgY29udHJvbHMKNGJkZTlhZWUwM2ZjZDI3YzU5ZTEzNjA3ZTUyOWIxY2VlNTk0YjI0OSBIRUFECgpQQUNLAAAAAgAAAAaZInicrY/BbtswEETv+oo9NkgsUKIlmkEQJJccEqCnAj2vyZVNhOIK5DJA/j60UxT9gF5ndmfeSCaCRR32VuOolwOhmrVRRs/TMOrhME+EdlbmaKyibsNMSUBZN+wJyaA+TqMnOjjSuOjBTB79ZJVCN1lyHVY5c4aXjOm9VM8rJngYW7hRgx1v/9WfaqFc+sSZtvjZn4Kc67F3vD7CYKy2ZrDzHnZqUqpr6hpE6P8nd0JFflywb+7hGJKHhBI+CF5//4LMkQCdcC4gDLQs5K6mpwVrFNg4BheodN0b0QZy/mvtrtYn8BpKCZwAC2AzUyAPa5VW0kTHSVpJD8+lIUvXbmvzsWFE5nfyu7rBn6RCUu5gy9QuG0LdPArdXiZ/c3qKdAm96y7vbTpngdKKaoEFQ6ztE1CukJzDKSSM4DBGyj385JbMvjoBd8Z0otJ/AbL5usjxAt+w35eix0scAVT0U0Lz3rsM5DireJzbxL6JfUMSo4jd59X5T/dZtJubHY7y1ihsjyhc7bW5jNGGCQDuLw1i8QKGIr1aGoStqoJK3dc3b56DQ+PdpXicWy20WmjDN3aRlIbQO3vbGB7G3Y6/vnXuw8YqNo7Jm7k4FBkBC6wOmvACrqSOPwT3m+S/zQhSjnFWbBWnYWF4nDvFdIppgzCjyBv+koxrxuWOJ5oN+uo52JRuT++cPFmdURkAza0MLfcC3wzhYRmrK+087jyitzMz/QbRssB4nAEnANj/9dwC9dwCsF9uFNFx2f4wWOvu1w5eSigdSpvhYSHRkyFwGLOLbuo/oVQTrv89F6ChsKkciEl2IOF9aTKfivrvzpJ4nJ1SzWsTQRSHoKTWj1q08aOtfdktSyKbFAqKJGy9mFpFQTz0YIhhs3lJN93MxJlJYhApHqx4EJR38yB48F7NyVvvHupJFP8Qr+5ukiUkt+5h2GV/8/t67+2P2OHv2MGH+JxeVMJ2dsuO7XkoSv338ZtLdEtfuNwr85ZyOZOpFvdcx0VpghJtpCf6yqnoJ61kl9dHgBwYRUMqUTJnYfgwXq5izW57qhyiejmocO4RgwQt6sv0/cUF+qO/m5/CUWP1MR0lU4sjcq1kQkNyloz8pPtfV7chLriHYAEl7gNd+3LuRPBNn29cop/x2Yf+e7bCq72iVrWVrZWK2hhf5HLA62MGFjQTNGYrt4OZRldppXQITOfpMH71wTSj4rvIysfhpX93NvfW1uCRQImig6B2EFrC5QJsRwWnBBsY1sNL4HCm/HS56VatYDKhrM8msMk7KGEIAewgA7cGroIuCgR83gqsKq/nQ5+tt1EqrILLBuohH3iuVNmQ0EMFTVdKl9VHorRV2Mo3bWbXUYAVpa1lB010XbUz9BXtkDFeAjmF5J4JNduTmL6dj2T8WLJd5ceh1PxCM8HkM4xnApLJrifkanm/3VRYshkUgo7fQToooRiJp4yJ3KMFpEpBpyPryowxLIFeWRfPTCTU6LyVoL/W2RljmGsa9c1HbW4k6eP+/MnQCx3sb/tbf5rg9cLS+OZHFgf2X/Z/FT7F5ibnsnHvev/N3djT/4ZUT5bU0Wdek2ejLo66En7pINp8RFWD6Q=="
COMMIT = "4bde9aee03fcd27c59e13607e529b1cee594b249"
TREE = "f08493a23f8ea0637073651231865ea9607b790e"
PARENT = "09c14eae7a3b52dee8ce3af3175dad5900ac59ec"
OLD_HEAD = COMMIT
OLD_TREE = TREE
OLD_RECEIPT = root / "build-test-4bde9-r10/result.public.json"
OLD_RECEIPT_SHA = "7454046d5ac8fb764a458d28a9964df01485e15d17468ce92a14ee00a465a71b"
env = {k: os.environ[k] for k in ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'TZ') if k in os.environ}
env.update(PATH='/usr/bin:/bin', GIT_OPTIONAL_LOCKS='0')
report = {'schema': 'heptabao.fresh-diagnostic-source-preparation.v1', 'status': 'running',
          'source_commit': COMMIT, 'source_tree': TREE, 'old_source_preserved': False,
          'cooperative_lock_removed': False, 'compiler_started': False,
          'production_changed': False, 'original_preparation_seconds': 150, 'steps': [],
          'legacy_preservation': False, 'machine_acceptance': 'HOLD',
          'rollback_qualified': False, 'dr_qualified': False, 'cutover_qualified': False,
          'new_cold_target_created_empty': False}


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
    assert head == OLD_HEAD and tree == OLD_TREE and not clean.strip(), 'old_source_identity'
    receipt = OLD_RECEIPT.read_bytes()
    assert hashlib.sha256(receipt).hexdigest() == OLD_RECEIPT_SHA, 'failed_receipt_changed'
    return {'head': head, 'tree': tree, 'clean': True, 'failed_receipt_sha256': OLD_RECEIPT_SHA,
            'directory_identity': [identity.st_dev, identity.st_ino, identity.st_uid, identity.st_gid, identity.st_mode]}



def directory(path):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'regular_directory_required'
    assert info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'owned_private_directory_required'
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def fixed_existing_directories():
    result = {name: directory(path) for name, path in (
        ('root', root), ('cargo_home', cargo_home), ('base_source', old))}
    for name, inode in (('root', 31507989), ('cargo_home', 31604578), ('base_source', 35944842)):
        assert result[name]['device'] == 66306 and result[name]['inode'] == inode and result[name]['uid'] == 1000, 'observed_directory_identity_changed'
    return result


assert all(not path.exists() and not path.is_symlink() for path in (fresh, target, build_output)), 'new_diagnostic_path_exists'
out.mkdir(mode=0o700)
try:
    report['existing_directories_before'] = fixed_existing_directories()
    raw = base64.b64decode(BUNDLE_B64, validate=True)
    assert len(raw) == 1393 and hashlib.sha256(raw).hexdigest() == "9808cfef28ce90733b636e81aed122aeeaf4fe81e0f34b1b84dde7e0ab0e11cd"
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
    report['existing_directories_after'] = fixed_existing_directories()
    assert report['existing_directories_before'] == report['existing_directories_after'], 'existing_directory_changed'
    assert not build_output.exists() and not build_output.is_symlink(), 'diagnostic_build_output_appeared'
    target.mkdir(mode=0o700)
    assert not any(target.iterdir()), 'new_target_not_empty'
    report['directories_after'] = {name: directory(path) for name, path in (
        ('root', root), ('source', fresh), ('cargo_home', cargo_home), ('target', target))}
    assert time.monotonic() < end, 'original_preparation_deadline_expired'
    report.update(status='prepared_diagnostic_legacy_hold', old_source_preserved=True,
                  new_source=str(fresh), new_source_clean=True, new_cold_target_created_empty=True)
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
