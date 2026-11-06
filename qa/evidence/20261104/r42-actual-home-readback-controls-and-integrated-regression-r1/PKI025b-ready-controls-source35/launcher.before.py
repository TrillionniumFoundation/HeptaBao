#!/usr/bin/env python3
"""Preserve prior evidence and admit one frozen native JWT and PKI build and exact regression matrix."""
from pathlib import Path
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import time

BINDING_READY = False
assert BINDING_READY, 'formatted source and published controls need separate exact admission'
FINAL_COMMIT = '025b05a340de841b8161c1120344e86eae30eb97'
FINAL_TREE = '1d8160c9385f8053b9a683cc1834da0f912e2d37'
SOURCE_STAGE_ROOT = Path('/home/qian-qi/heptabao-native-jwt-pki-source-025b05a3-20261106-r1')
SOURCE_STAGE_SCHEMA = 'heptabao.native-jwt-independent-source-stage.v1'
GROUPS_SHA256 = '35153ff5e90b582f83e4fbbb66ff5c9fb295e95153f08df152cefedecdb50869'
OUTER_STARTED = time.monotonic()
ORIGINAL_OUTER_SECONDS = 12000
OUTER_UNTIL = OUTER_STARTED + ORIGINAL_OUTER_SECONDS
os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('--host', choices=('rog',), required=True)
for name in ('commit', 'tree', 'stage-sha256', 'runner-sha256', 'groups-sha256', 'controls-sha256'):
    parser.add_argument('--' + name, required=True)
for name in ('r9-resume-sha256', 'r9-resume-terminal-sha256', 'r9-resume-authority-sha256'):
    parser.add_argument('--' + name)
args = parser.parse_args()
assert args.commit == FINAL_COMMIT and args.tree == FINAL_TREE
for name in ('r9_resume_sha256', 'r9_resume_terminal_sha256', 'r9_resume_authority_sha256'):
    value = getattr(args, name)
    if args.host == 'mac':
        assert re.fullmatch('[0-9a-f]{64}', value or '')
    else:
        assert value is None
for name in ('commit', 'tree'):
    assert re.fullmatch('[0-9a-f]{40}', getattr(args, name))
for name in ('stage_sha256', 'runner_sha256', 'groups_sha256', 'controls_sha256'):
    assert re.fullmatch('[0-9a-f]{64}', getattr(args, name))

if args.host == 'mac':
    BASE = Path('/Volumes/T5/hepta-vnext-recovery-20261013')
    ROOT = BASE / 'continuation-20261104-native-http-r10'
    R9 = BASE / 'continuation-20261104-native-http-r9'
    OLD = BASE / 'continuation-20261104-native-ssh-http-r8'
    OLD_SOURCE = OLD / 'source'
    OLD_COMMIT = '2d9a2efd4cfc3a9ee60a450eee58866828a3f5ad'
    OLD_BUILD = OLD / 'build-normal-r1/result.public.json'
    OLD_BUILD_SHA = '31e5bb7905b11a4bad1bf9df34360cc0443f70455a047ac06914208d2bfe3a54'
    OLD_NATIVE = OLD / 'build-normal-r1/native-build.public.json'
    OLD_NATIVE_SHA = 'c372ef673bd3dd70daaf2791f4d0ba18893fb7235137c2ad0ce452b6b3fad5bd'
    OLD_TEST = OLD / 'normal-exact33-r1/result.public.json'
    OLD_TEST_SHA = 'fc6677c0f65ba0e2050f0fe20d25356cba33a20ab2c287de5e0e0c7d4dd56557'
    OLD_LIBTEST = OLD / 'mac-tls-einval-diagnostic-r1/retained-r8-libtest'
    OLD_LIBTEST_SHA = '648236a59ebf23aee2ebd02039e6045fb491cebff80ac8d4e564b78b3e316aab'
    OLD_LIBTEST_BYTES = 154048544
    OLD_STATUS = 'failed'
    TARGET = BASE / 'continuation-20261029-joint2dbb-full6-r1/runtime.noindex/target-native-full-r2'
    TOOLCHAIN = '/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin'
    CARGO_HOME = str(BASE / 'r13-full-native-cargo-home-r1')
    PYTHON = '/opt/homebrew/bin/python3'
    RUNNER_NAME = 'mac_normal_exact_tests_r10.py'
    expected_system, expected_uid = ('Darwin', 'arm64'), 501
else:
    BASE = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1')
    ROOT = Path('/home/qian-qi/heptabao-native-jwt-pki-controls-20261106-r2')
    R9 = BASE / 'r9-http-routing-r1'
    OLD = BASE / 'normal-release-tests-r8-r1'
    OLD_SOURCE = BASE / 'source-r8-test-fixtures-r1'
    OLD_COMMIT = '384c957612186d64c5a530044af0ae62c568cc3d'
    OLD_BUILD = OLD / 'normal-release-result.public.json'
    OLD_BUILD_SHA = '2dad4d882854850cbe05825785e77532656da255a11ce7a551969bd7439456a5'
    OLD_NATIVE = OLD / 'native-build.public.json'
    OLD_NATIVE_SHA = 'f96740372ada668a566aa1b90b2cd8daf463c009de8eed5ba86cb20a2883b8f9'
    OLD_TEST = OLD / 'result.public.json'
    OLD_TEST_SHA = '8fa3a928de5c705e6da80d9dd6fc64c5252035226013650c37941105e4069715'
    OLD_LIBTEST = OLD / 'retained-heptabao-server-libtest'
    OLD_LIBTEST_SHA = '9f498c4c2c14f2198dcbe746be81be1cf0c7caabca28671bba83fb003a65b46a'
    OLD_LIBTEST_BYTES = 188077176
    OLD_STATUS = 'passed'
    TARGET = Path('/home/qian-qi/heptabao-cold-h2-normal-20261105-r1/target-normal-r3')
    TOOLCHAIN = '/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin'
    CARGO_HOME = '/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home'
    PYTHON = '/usr/bin/python3'
    RUNNER_NAME = 'native_jwt_build.py'
    expected_system, expected_uid = ('Linux', 'x86_64'), 1000

SOURCE = SOURCE_STAGE_ROOT / 'source'
SOURCE_STAGE_CONTROL = SOURCE_STAGE_ROOT / 'control'
CONTROL = ROOT
PRIOR_DF026_ROOT = Path('/home/qian-qi/heptabao-cold-h2-normal-20261105-r1')
REVISION_CONTROL = PRIOR_DF026_ROOT / 'control-r3'
ADMISSION = ROOT / 'build-control-r1'
OUTPUT = ROOT / 'build-tests-r1'
OLD_TREE = 'd5a0f91a4d47f7c8d5f34170ea167d10dc036e04'
R9_SOURCE = R9 / 'source'
R9_COMMIT = '1d12abc45a83d4b32e7185d01a876eb93110b1e2'
R9_TREE = 'e1faeaa3ed49d26fb01a7617a8879cb693a12907'
FAILED_ROOT = Path('/home/qian-qi/heptabao-phaseb-fresh-ingress-observer-normal-20261104-r1')
FAILED_SOURCE = FAILED_ROOT / 'source'
FAILED_COMMIT = 'bf0aaec1dcafbf476c0ab3a75544bb0eafaeff24'
FAILED_TREE = 'ac4027db88fec69381ea0c6bba953d9a99c4e82a'
FAILED_AUTHORITY_NAME = 'prior-observer-build-authority.public.json'
FAILED_AUTHORITY_SHA = '820a3243ba5be87f4d8fdf3d47d68361a2f2d6a95043d38c0086afab1cf559b6'
FAILED_FILES = {
    'control/stage-result.public.json': (6838, 'bb2bd7b46974dc18bcb87325ea55c46383e17f2f8a521f2eaa77b1fc9fba8d2b'),
    'build-control-r1/launch-preflight.public.json': (12914, '91b8fe2e1d6e34d1e0b885a9bbb81c27e83e1d6f3f07cb4235cb2314b27e29d4'),
    'normal-release-tests-r1/intent.public.json': (7838, 'ad7adbf410217af34555e9b9135505cb8f70309facfa748f4fb1c3f0614eedb2'),
    'normal-release-tests-r1/result.public.json': (9233, '2947b177c2b7ca145a499175567aec632c76d12641c8afa4276ae900dda3a122'),
    'normal-release-tests-r1/normal-release-build.public.json': (710, '654c0e9dd676855d585746275be3dc92188c843e576d873d6b3607141fb9f412'),
    'normal-release-tests-r1/normal-release-build.stderr': (27914, 'd47156c8828983229eccec58c9a4cd5f1535b653c7d59fab9ddf4db72839ee3e'),
    'normal-release-tests-r1/normal-release-build.stdout': (384196, '324a6b59e740e1ed2dc0c447ce638557d5cbd53cdec2c5b3afaa0a701cee3c92'),
    'control/stage_source_phaseb_observer.py': (18774, '2cfc47c230d7a4780e758ee8736e4cd6f1412a2f65174c5581be48038581b32a'),
    'control/launch_normal_phaseb_observer.py': (22961, '56c7b06d4329e4fdb72079a089ad2f1509e856357328d849d58844236b86fd63'),
    'control/normal_phaseb_observer_build.py': (20791, 'c46efcee52b0b836f8c6539e86a02114c10828b0a295f4571178643dcc0f0273'),
    'control/normal-test-groups.public.json': (6249, '0566f7f98ea16a4c1df43ebaf992172646ad91623c18f68fcc59f7c08b53d1f1'),
    'source/crates/heptabao-server/src/ha_native_v6_runtime.rs': (61578, 'cf0e9e69bf295591d3a904458500bfcf7b01acaa0987ae1da8761f76b9ee136d'),
}

R9_MAC_STAGE_FENCES = {
    'stage-result.public.json': '1f60d0bbdab00feee4e0d5d1593fa3543b74ff05fae8ec60f9d17b3ddd381166',
    '021-git-fetch.public.json': '89e4865c8bb30bc500b05cd1fd0a79d0d39bb49fbe1830250d155f9797ff19a5',
    '021-git-fetch.stderr': 'dbcc4dce38066a3223043b215a80a7acdd2dd1e2f52063de42801d63d931e5ff',
    '021-git-fetch.stdout': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}



EARLY_NORMAL_FILES = {
    'prior-normal-early-failure.authority.original.json': (726, '9188213431c349616ecd8dd329f930d909fb3b973ff27848ae3afb7957e2bfae'),
    'prior-normal-early-failure.stderr': (693, 'bb032403580f205d6e15f90da809c666b4accec08a0acf00f0a83611ecbbe01e'),
    'prior-normal-target-metadata.stdout.json': (13741, 'e4e062eacfb4b6080f973d053d301504b90b27d0782172c227745488ec826a6a'),
    'prior-normal-target-metadata.authority.original.json': (733, '70a9289777c626b8ea795ae017161f923638a74459b79c350f94b5650ef72752'),
}

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_bound(path, expected_sha, cap, retain=True):
    assert path.resolve(strict=True) == path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
        assert 0 <= before.st_size <= cap
        digest, parts, count = hashlib.sha256(), [], 0
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            count += len(part)
            assert count <= cap
            digest.update(part)
            if retain:
                parts.append(part)
        assert count == before.st_size and digest.hexdigest() == expected_sha
        assert identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
        return b''.join(parts), {'path': str(path), 'bytes': count, 'sha256': expected_sha,
                               'identity': list(identity(before))}
    finally:
        os.close(fd)


def freeze(path):
    def git(*command):
        return subprocess.check_output(['/usr/bin/git', '-C', str(path), *command],
                                       text=True, timeout=30).strip()
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'status': git('status', '--porcelain=v1', '--untracked-files=all')}


def public(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def preserve_r9():
    r9_before = freeze(R9_SOURCE)
    assert r9_before == {'commit': R9_COMMIT, 'tree': R9_TREE, 'status': ''}
    evidence = {'source_before': r9_before, 'prior_failures_replayed': False}
    if args.host == 'rog':
        output = R9 / 'normal-release-tests-r1'
        build_raw, evidence['normal_release'] = read_bound(
            output / 'normal-release-result.public.json',
            '103bbb68367a13ec3df53a8b437f6e33bd44c75a4ad23a6a792692ef858deb3d', 30000)
        native_raw, evidence['native_build'] = read_bound(
            output / 'native-build.public.json',
            '771f53ae44858d9bb73809b997103edfd69bc564e152d9ee40f3a45ca7f854d5', 5000)
        tests_raw, evidence['failed_exact44'] = read_bound(
            output / 'result.public.json',
            'b4d3f25c0694dfa7cc24dd3d2a8bdf780ec9eb43716abb61a4581b26c8cc676f', 40000)
        build, native, tests = map(json.loads, (build_raw, native_raw, tests_raw))
        assert all(x['source_commit'] == R9_COMMIT and x['source_tree'] == R9_TREE
                   for x in (build, native, tests))
        assert build['build_exit_code'] == 0 and build['build_finished_success']
        assert build['source_freeze_verified'] and not build['timed_out'] and not build['owned_group_survivors_after_wait']
        assert tests['status'] == 'failed' and tests['test_count'] == 44
        assert [(x['label'], x['tests']['exit_code']) for x in tests['group_results']] == [
            ('ssh25', 0), ('mount1', 0), ('redirect5', 0), ('actor2', 0), ('ordinary5', 0), ('no_forward6', 101)]
        assert all(not x['tests']['timed_out'] for x in tests['group_results'])
        assert all(x['direct_child_reaped'] and x['remaining'] == [] and not x.get('cleanup_error_type')
                   for x in tests['cleanup'])
        assert sorted(build['artifacts']) == ['heptabao-seed', 'heptabao-server']
        evidence['retained_artifacts'] = []
        for value in build['artifacts'].values():
            path = Path(value['path'])
            assert path == output / 'artifacts' / path.name and not path.is_relative_to(TARGET)
            assert sorted(value['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
            _, pin = read_bound(path, value['sha256'], value['bytes'], retain=False)
            assert pin['bytes'] == value['bytes']
            evidence['retained_artifacts'].append(pin)
        libtest = output / 'retained-heptabao-server-libtest'
        libtest_sha = '9b871dd8d12c063e6ea042d5bb4415d9a042da0e4d18d83fca3e184396879cf4'
        libtest_bytes = 188176568
        assert tests['binary']['path'] == str(libtest)
        assert tests['binary']['sha256'] == libtest_sha and tests['binary']['bytes'] == libtest_bytes
        _, pin = read_bound(libtest, libtest_sha, libtest_bytes, retain=False)
        assert pin['bytes'] == libtest_bytes and stat.S_IMODE(libtest.stat().st_mode) == 0o500
        assert not libtest.is_relative_to(TARGET)
        evidence['retained_artifacts'].append(pin)
    else:
        evidence['failed_stage_fences'] = {}
        for name, sha256 in R9_MAC_STAGE_FENCES.items():
            _, pin = read_bound(R9 / 'control' / name, sha256, 2 * 1024 * 1024)
            evidence['failed_stage_fences'][name] = pin
        resume_path = R9 / 'control/canonical-resume-r2/result.public.json'
        resume_raw, evidence['canonical_resume'] = read_bound(resume_path, args.r9_resume_sha256, 150000)
        terminal_raw, evidence['canonical_resume_terminal'] = read_bound(
            CONTROL / 'r9-canonical-resume-r2.terminal.public.json', args.r9_resume_terminal_sha256, 150000)
        authority_raw, evidence['canonical_resume_authority'] = read_bound(
            CONTROL / 'r9-canonical-resume-r2.authority.public.json', args.r9_resume_authority_sha256, 20000)
        resume, terminal, authority = map(json.loads, (resume_raw, terminal_raw, authority_raw))
        assert resume['schema'] == 'heptabao.r9.offline-canonical-controller.v2'
        assert resume['status'] == 'prepared' and resume['action'] == 'resume-mac'
        assert resume['canonical_commit'] == R9_COMMIT and resume['canonical_tree'] == R9_TREE
        assert resume['source_after']['head'] == R9_COMMIT and resume['source_after']['tree'] == R9_TREE and resume['source_after']['clean']
        assert resume['canonical_proof']['commit_count'] == 3751 and resume['canonical_proof']['full_fsck_passed']
        assert resume['all_owned_stopped'] and resume['deadline_before_receipt_passed']
        assert terminal['status'] == terminal['receipt_candidate_status'] == 'prepared'
        assert terminal['action'] == 'resume-mac' and terminal['receipt'] == str(resume_path)
        assert terminal['canonical_commit'] == R9_COMMIT and terminal['canonical_tree'] == R9_TREE
        assert terminal['publication_within_original_deadline'] and terminal['all_owned_stopped']
        assert authority['state'] == 'succeeded' and authority['exit_code'] == 0
        assert authority['output_complete'] and authority['output_durable'] and authority['terminal_publication_confirmed']
        assert not authority['timed_out'] and not authority['cancelled']
        assert all(value is False for value in authority['log_truncated'].values())
        assert all(value is None for value in authority['log_errors'].values())
        evidence['r9_build_artifacts_required'] = False
        evidence['no_r9_artifact_claim'] = True
    assert freeze(R9_SOURCE) == r9_before
    evidence['source_after'] = r9_before
    return evidence


def preserve_r10():
    root = Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1')
    source = root / 'source'
    output = root / 'normal-release-tests-r1'
    before = freeze(source)
    assert before == {'commit': '49503322c7f446e5eb41e7744f1fdbd7f1192ecc',
                      'tree': '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9', 'status': ''}
    evidence = {'source_before': before, 'prior_failures_replayed': False}
    build_raw, evidence['normal_release'] = read_bound(output / 'normal-release-result.public.json',
        '75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee', 30000)
    native_raw, evidence['native_build'] = read_bound(output / 'native-build.public.json',
        '0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77', 5000)
    tests_raw, evidence['exact44'] = read_bound(output / 'result.public.json',
        '409b8a02557cc5d2985d15f01ff28ff64a6fb43c4a8b1e0f50f03bb748fcbeee', 40000)
    build, native, tests = map(json.loads, (build_raw, native_raw, tests_raw))
    assert all(x['source_commit'] == before['commit'] and x['source_tree'] == before['tree']
               for x in (build, native, tests))
    assert build['source_freeze_verified'] and build['build_exit_code'] == 0 and build['build_finished_success']
    assert not build['timed_out'] and not build['owned_group_survivors_after_wait']
    assert tests['status'] == 'passed' and tests['test_count'] == 44
    assert tests['binary']['sha256'] == '248dac36e0ba89732ef6c3c0055dab38a6458d762171b4883cbdbd50286467bf'
    assert tests['binary']['bytes'] == 187607928
    retained = []
    for name in ('heptabao-server', 'heptabao-seed'):
        item = build['artifacts'][name]
        path = output / 'artifacts' / name
        assert item['path'] == str(path) and not path.is_relative_to(TARGET)
        _, fact = read_bound(path, item['sha256'], item['bytes'], retain=False)
        assert fact['bytes'] == item['bytes']
        assert sorted(item['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
        retained.append(fact)
    _, fact = read_bound(output / 'retained-heptabao-server-libtest',
        tests['binary']['sha256'], tests['binary']['bytes'], retain=False)
    assert fact['bytes'] == tests['binary']['bytes']
    retained.append(fact)
    assert freeze(source) == before
    evidence.update(source_after=before, retained=retained, all_unchanged=True)
    return evidence


def preserve_successful_observer():
    root = Path('/home/qian-qi/heptabao-phaseb-fresh-ingress-observer-normal-20261104-r3')
    source = root / 'source'
    output = root / 'normal-release-tests-r1'
    before = freeze(source)
    assert before == {'commit': '3cb873919170cc77101b27f6a3ab9e98f41f8d93',
                      'tree': '7f4d48a647a81ca96e8a24a0a057c2c829459060', 'status': ''}
    evidence = {'source_before': before, 'prior_failures_replayed': False}
    build_raw, evidence['normal_release'] = read_bound(output / 'normal-release-result.public.json',
        '6313b4eaad68ac882d0891e14bd9d1632e138e635e3626b1b2b774e6be8f243f', 30000)
    native_raw, evidence['native_build'] = read_bound(output / 'native-build.public.json',
        '51d0d83956a82e532b1f576a904bd1d5708ccc8991eaa6572b7435d8e57aebce', 5000)
    tests_raw, evidence['exact44'] = read_bound(output / 'result.public.json',
        '8899a7acc647505c230430b35771ae1eccaf48cc5aea27a034906d513fd0b0f7', 40000)
    build, native, tests = map(json.loads, (build_raw, native_raw, tests_raw))
    assert all(x['source_commit'] == before['commit'] and x['source_tree'] == before['tree']
               for x in (build, native, tests))
    assert build['source_freeze_verified'] and build['build_exit_code'] == 0 and build['build_finished_success']
    assert not build['timed_out'] and not build['owned_group_survivors_after_wait']
    assert tests['status'] == 'passed' and tests['test_count'] == 44
    assert tests['binary']['sha256'] == '94e2daa8448807079472264fb19d39d00619ac6a046c59ac7849aa39a70161fa'
    assert tests['binary']['bytes'] == 187656088
    assert tests['original_44_status'] == 'passed'
    assert tests['ingress_observer_regression']['status'] == 'passed'
    assert tests['ingress_observer_regression']['test_count'] == 7
    assert len(tests['cleanup']) == 28
    assert all(x['direct_child_reaped'] and x['remaining'] == [] and not x.get('cleanup_error_type') for x in tests['cleanup'])
    retained = []
    for name in ('heptabao-server', 'heptabao-seed'):
        item = build['artifacts'][name]
        path = output / 'artifacts' / name
        assert item['path'] == str(path) and not path.is_relative_to(TARGET)
        _, fact = read_bound(path, item['sha256'], item['bytes'], retain=False)
        assert fact['bytes'] == item['bytes']
        assert sorted(item['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
        retained.append(fact)
    _, fact = read_bound(output / 'retained-heptabao-server-libtest',
        tests['binary']['sha256'], tests['binary']['bytes'], retain=False)
    assert fact['bytes'] == tests['binary']['bytes']
    retained.append(fact)
    assert freeze(source) == before
    evidence.update(source_after=before, retained=retained, all_unchanged=True)
    return evidence



def preserve_failed_observer():
    before = freeze(FAILED_SOURCE)
    assert before == {'commit': FAILED_COMMIT, 'tree': FAILED_TREE, 'status': ''}
    rows, loaded = {}, {}
    for relative, (size, expected_sha) in FAILED_FILES.items():
        path = FAILED_ROOT / relative
        info = path.lstat()
        raw, _ = read_bound(path, expected_sha, size)
        assert len(raw) == size
        assert identity(info) == identity(path.lstat())
        rows[relative] = {'path': str(path), 'bytes': size, 'sha256': expected_sha,
                          'identity': list(identity(info))}
        if relative in ('normal-release-tests-r1/result.public.json',
                        'normal-release-tests-r1/normal-release-build.public.json'):
            loaded[relative] = json.loads(raw)
    authority_path = SOURCE_STAGE_CONTROL / FAILED_AUTHORITY_NAME
    authority_info = authority_path.lstat()
    authority_raw, _ = read_bound(authority_path, FAILED_AUTHORITY_SHA, 726)
    assert len(authority_raw) == 726
    assert identity(authority_info) == identity(authority_path.lstat())
    authority = json.loads(authority_raw)
    assert authority['job_id'] == '1a1a87f578a-fc05-2ee0'
    assert authority['state'] == 'failed' and authority['exit_code'] == 1
    assert authority['output_complete'] and authority['output_durable']
    assert authority['terminal_publication_confirmed']
    assert not authority['timed_out'] and not authority['cancelled'] and not authority['automatic_retry']
    assert all(value is False for value in authority['log_truncated'].values())
    assert all(value is None for value in authority['log_errors'].values())
    failed = loaded['normal-release-tests-r1/result.public.json']
    child = loaded['normal-release-tests-r1/normal-release-build.public.json']
    assert failed['source_commit'] == FAILED_COMMIT and failed['source_tree'] == FAILED_TREE
    assert failed['status'] == 'failed' and failed['failure_type'] == 'AssertionError'
    assert failed['failure'] == 'normal production binary compilation failed'
    assert failed['runtime_tests_started'] is False and failed['group_results'] == []
    assert failed['test_count'] == 44 and failed['normal_release_build'] == child
    assert child['exit_code'] == 101 and not child['timed_out']
    assert child['outer_cap_seconds'] == 1800 and child['elapsed_seconds'] < 1800
    assert child['direct_child_reaped'] and child['remaining'] == []
    assert len(failed['cleanup']) == 1
    assert all(row['direct_child_reaped'] and row['remaining'] == []
               and row['exit_code'] == 101 and not row.get('cleanup_error_type')
               for row in failed['cleanup'])
    assert freeze(FAILED_SOURCE) == before
    return {'source_before': before, 'source_after': before, 'files': rows,
            'authority': {'path': str(authority_path), 'bytes': 726,
                          'sha256': FAILED_AUTHORITY_SHA,
                          'identity': list(identity(authority_info)),
                          'source': 'exact cached authoritative terminal receipt'},
            'prior_failed_build_replayed': False}



def preserve_current_early_failure():
    facts, values = {}, {}
    for name, (size, sha256) in EARLY_NORMAL_FILES.items():
        assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired during early-failure fences'
        raw, fact = read_bound(REVISION_CONTROL / name, sha256, size)
        assert len(raw) == size
        facts[name] = fact
        if name.endswith('.json'):
            values[name] = json.loads(raw)
    failed = values['prior-normal-early-failure.authority.original.json']
    diagnostic = values['prior-normal-target-metadata.authority.original.json']
    assert failed['job_id'] == '1a1a9d78f65-fc05-3884' and failed['state'] == 'failed' and failed['exit_code'] == 1
    assert diagnostic['job_id'] == '1a1a9e48b01-fc05-392b' and diagnostic['state'] == 'succeeded' and diagnostic['exit_code'] == 0
    for authority in (failed, diagnostic):
        assert authority['output_complete'] and authority['output_durable'] and authority['terminal_publication_confirmed']
        assert not authority['timed_out'] and not authority['cancelled'] and not authority['automatic_retry']
        assert all(value is False for value in authority['log_truncated'].values())
        assert all(value is None for value in authority['log_errors'].values())
    metadata = values['prior-normal-target-metadata.stdout.json']
    assert metadata['complete'] and metadata['publication_within_original_deadline']
    assert metadata['children_started'] == 0 and metadata['files_written'] == 0
    assert metadata['all_opened_descriptors_closed']
    _, facts['original_rejected_launcher'] = read_bound(
        PRIOR_DF026_ROOT / 'control/launch_normal_cold_h2.py',
        '7c3dbf522f51931aaa5c1947ec0742883bdcc1405913d45f8b43f217983acb98', 31963)
    assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired after early-failure fences'
    return {'files': facts, 'original_job_replayed': False,
            'historical_missing_target_recreated': False,
            'target_removal_cause_known': False}



def holders():
    if args.host == 'mac':
        observed = subprocess.run(['/usr/sbin/lsof', '-t', str(TARGET / 'release/.cargo-lock')],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        assert observed.returncode in (0, 1)
        return [int(value) for value in observed.stdout.split()]
    matches = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            comm = (directory / 'comm').read_text().strip()
            if comm not in ('cargo', 'rustc', 'rustdoc'):
                continue
            env = (directory / 'environ').read_bytes().split(b'\0')
            target_values = [x.split(b'=', 1)[1] for x in env if x.startswith(b'CARGO_TARGET_DIR=')]
            argv = (directory / 'cmdline').read_bytes().split(b'\0')
            cwd = str((directory / 'cwd').resolve(strict=True))
            if str(TARGET).encode() in target_values or any(str(TARGET).encode() in x for x in argv) or cwd in (str(SOURCE), str(OLD_SOURCE), str(R9_SOURCE)):
                matches.append({'pid': int(directory.name), 'comm': comm, 'cwd': cwd})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return matches


assert (os.uname().sysname, os.uname().machine) == expected_system
assert os.getuid() == expected_uid == ROOT.stat().st_uid
assert ROOT.resolve(strict=True) == ROOT
assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_native_jwt_build.py'
assert TARGET.resolve(strict=True) == TARGET
assert identity(TARGET.stat())[:5] == (66306, 31606588, 1000, 1000, 16832)
assert not ADMISSION.exists() and not ADMISSION.is_symlink()
assert not OUTPUT.exists() and not OUTPUT.is_symlink()
stage_raw, stage_pin = read_bound(SOURCE_STAGE_CONTROL / 'stage-result.public.json', args.stage_sha256, 150000)
stage = json.loads(stage_raw)
assert stage['schema'] == SOURCE_STAGE_SCHEMA
assert stage['status'] == 'prepared' and stage['source_commit'] == args.commit and stage['source_tree'] == args.tree
assert stage['source_clean'] and stage['independent_git_directory'] and stage['old_source_unchanged']
assert all(x['direct_child_reaped'] and not x['remaining'] for x in stage['cleanup'])
assert stage['full_strict_fsck_passed'] and stage['no_alternates'] and stage['no_shared_object_links']
assert stage['source'] == str(SOURCE) and stage['root'] == str(SOURCE_STAGE_ROOT)
assert stage['within_new_stage_deadline'] and not stage['compiler_started'] and not stage['rust_tests_executed']
assert not stage['formatter_executed'] and not stage['historical_controls_executed']
runner = CONTROL / RUNNER_NAME
_, runner_pin = read_bound(runner, args.runner_sha256, 40000)
groups_raw, groups_pin = read_bound(CONTROL / 'jwt-test-groups.public.json', args.groups_sha256, 20000)
groups = json.loads(groups_raw)
assert stage['controls'][FAILED_AUTHORITY_NAME] == {'bytes': 726, 'sha256': FAILED_AUTHORITY_SHA}
assert stage['failed_observer_before'] == stage['failed_observer_after']
assert args.groups_sha256 == GROUPS_SHA256
assert [(g['label'], g['libtest_profile'], len(g['tests'])) for g in groups] == [
    ('native-jwt-pki-file17', 'file', 17), ('native-jwt-pki-default17', 'default', 17),
    ('legacy-jwt-default63', 'default', 63), ('native-auth-identity-default69', 'default', 69)]
assert all(set(g) == {'label', 'libtest_profile', 'tests', 'runtime_seconds'}
           and g['runtime_seconds'] == 600 and len(g['tests']) == len(set(g['tests'])) for g in groups)
assert groups[0]['tests'] == groups[1]['tests']
assert sum(len(g['tests']) for g in groups) == 166
assert len({name for g in groups for name in g['tests']}) == 149
controls_raw, controls_pin = read_bound(CONTROL / 'inert-stage.result.public.json',
                                      args.controls_sha256, 65536)
controls = json.loads(controls_raw)
assert controls['schema'] == 'heptabao.native-jwt-pki-build-controls-inert.v1'
assert controls['status'] == 'prepared' and controls['python_compile_only'] is True
assert all(controls[name] is False for name in
           ('source_executed', 'git_started', 'compiler_started', 'service_started', 'artifact_transfer_started'))
assert len(controls['files']) == 3
control_rows = {Path(row['path']).name: row for row in controls['files']}
assert set(control_rows) == {'native_jwt_build.py', 'launch_native_jwt_build.py', 'jwt-test-groups.public.json'}
_, launcher_pin = read_bound(CONTROL / 'launch_native_jwt_build.py',
                            control_rows['launch_native_jwt_build.py']['sha256'], 40000)
for name, observed in [('native_jwt_build.py', runner_pin),
                       ('launch_native_jwt_build.py', launcher_pin),
                       ('jwt-test-groups.public.json', groups_pin)]:
    row = control_rows[name]
    assert row['path'] == str(CONTROL / name) and row['mode'] == '0600'
    assert row['publication'] in ('created', 'existing_exact', 'existing_after_race')
    assert row['bytes'] == observed['bytes'] and row['sha256'] == observed['sha256']
    assert row['identity'] == observed['identity']
    assert observed['identity'][2:6] == [expected_uid, expected_uid, 0o100600, 1]
assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired after current control admission'
ADMISSION.mkdir(mode=0o700)
result = {'schema': 'heptabao.native-jwt-pki-target-admission.v1', 'status': 'failed',
          'host': args.host, 'source_commit': args.commit, 'source_tree': args.tree,
          'stage': stage_pin, 'runner': runner_pin, 'groups': groups_pin,
          'controls_receipt': controls_pin, 'launcher': launcher_pin,
          'target': str(TARGET), 'production_changed': False, 'normal_runner_started': False,
          'fresh_cache': False, 'inherits_prior_cache_performance': False,
          'reuses_existing_df026_target': True, 'target_identity_before': list(identity(TARGET.stat())),
          'started_ns': time.time_ns()}
public(ADMISSION / 'launch-intent.public.json', result)
lock_fd = None
try:
    before, old_before = freeze(SOURCE), freeze(OLD_SOURCE)
    assert before == {'commit': args.commit, 'tree': args.tree, 'status': ''}
    assert old_before == {'commit': OLD_COMMIT, 'tree': OLD_TREE, 'status': ''}
    result.update(source_before=before, old_source_before=old_before)
    build_raw, result['old_build_receipt'] = read_bound(OLD_BUILD, OLD_BUILD_SHA, 30000)
    native_raw, result['old_native_receipt'] = read_bound(OLD_NATIVE, OLD_NATIVE_SHA, 5000)
    test_raw, result['old_exact_test_receipt'] = read_bound(OLD_TEST, OLD_TEST_SHA, 40000)
    build, native, old_test = map(json.loads, (build_raw, native_raw, test_raw))
    assert build['source_commit'] == native['source_commit'] == old_test['source_commit'] == OLD_COMMIT
    assert build['source_tree'] == native['source_tree'] == old_test['source_tree'] == OLD_TREE
    assert build['source_freeze_verified'] and build['build_exit_code'] == 0 and build['build_finished_success'] and not build['timed_out'] and not build['owned_group_survivors_after_wait']
    assert old_test['status'] == OLD_STATUS and old_test['test_count'] == 33
    assert old_test['binary']['sha256'] == OLD_LIBTEST_SHA and old_test['binary']['bytes'] == OLD_LIBTEST_BYTES
    assert sorted(build['artifacts']) == ['heptabao-seed', 'heptabao-server']
    retained = []
    for value in build['artifacts'].values():
        _, artifact_pin = read_bound(Path(value['path']), value['sha256'], value['bytes'], retain=False)
        assert artifact_pin['bytes'] == value['bytes']
        assert sorted(value['features']) == ['default', 'native-v6-ha', 'native-v6-storage']
        assert not Path(value['path']).is_relative_to(TARGET)
        retained.append(artifact_pin)
    _, libtest_pin = read_bound(OLD_LIBTEST, OLD_LIBTEST_SHA, OLD_LIBTEST_BYTES, retain=False)
    assert libtest_pin['bytes'] == OLD_LIBTEST_BYTES and not OLD_LIBTEST.is_relative_to(TARGET)
    retained.append(libtest_pin)
    assert freeze(SOURCE) == before and freeze(OLD_SOURCE) == old_before
    result['retained_r9_evidence'] = preserve_r9()
    result['retained_r10_evidence'] = preserve_r10()
    result['retained_successful_observer'] = preserve_successful_observer()
    result['retained_failed_observer'] = preserve_failed_observer()
    assert result['retained_failed_observer'] == stage['failed_observer_after']
    assert freeze(SOURCE) == before and freeze(OLD_SOURCE) == old_before
    result['retained_current_early_failure'] = preserve_current_early_failure()
    assert identity(TARGET.stat())[:5] == tuple(result['target_identity_before'][:5])
    result['compiler_holders_before_lock'] = holders()
    assert not result['compiler_holders_before_lock']
    lock_fd = os.open(TARGET / 'release/.cargo-lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(lock_fd)
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result['compiler_holders_under_lock'] = holders()
    if args.host == 'mac':
        # lsof also observes this controller's own temporary lock descriptor.
        assert all(pid == os.getpid() for pid in result['compiler_holders_under_lock'])
    else:
        assert not result['compiler_holders_under_lock']
    result['target_lock'] = {'identity': list(identity(info)), 'nonblocking_exclusive_probe': True}
    assert preserve_current_early_failure() == result['retained_current_early_failure']
    assert identity(TARGET.stat())[:5] == tuple(result['target_identity_before'][:5])
    assert freeze(SOURCE) == before and freeze(OLD_SOURCE) == old_before
    argv = [PYTHON, '-I', '-S', '-B', str(runner), '--source', str(SOURCE),
            '--output', str(OUTPUT), '--commit', args.commit, '--tree', args.tree,
            '--toolchain', TOOLCHAIN, '--cargo-home', CARGO_HOME, '--target', str(TARGET),
            '--groups', str(CONTROL / 'jwt-test-groups.public.json'),
            '--groups-sha256', args.groups_sha256,
            '--outer-started-monotonic', repr(OUTER_STARTED), '--launcher-pid', str(os.getpid())]
    assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before exec admission'
    result.update(status='admitted', retained_r8_artifacts=retained,
                  prior_r8_failure_replayed=False, source_and_retained_artifacts_unchanged=True,
                  normal_runner_argv=argv, original_release_build_cap_seconds=1800,
                  original_libtest_build_cap_seconds=1800 if args.host == 'mac' else 3600,
                  each_listing_cap_seconds=30, each_runtime_group_cap_seconds=600,
                  unique_test_count=149, profile_instance_test_count=166,
                  new_jwt_test_names=15, new_jwt_profile_instances=30,
                  new_pki_test_names=2, new_pki_profile_instances=4,
                  existing_auth_identity_test_names=132, compile_profiles=['file', 'default'],
                  default_features_do_not_qualify_distributed_jwt_ha=True,
                  compile_gate_shared_cap_seconds=3600, compile_deadline_reset=False,
                  original_supervisor_seconds=ORIGINAL_OUTER_SECONDS,
                  outer_started_monotonic=OUTER_STARTED, outer_until_monotonic=OUTER_UNTIL)
except BaseException as error:
    result.update(error_type=type(error).__name__, error=str(error))
finally:
    result['terminal_ns'] = time.time_ns()
    public(ADMISSION / 'launch-preflight.public.json', result)
    if lock_fd is not None:
        os.close(lock_fd)
if result['status'] != 'admitted':
    print(json.dumps({'status': 'refused', 'receipt': str(ADMISSION / 'launch-preflight.public.json'),
                      'error_type': result.get('error_type')}), flush=True)
    raise SystemExit(1)
print(json.dumps({'status': 'preflight-admitted', 'source_commit': args.commit,
                  'source_tree': args.tree, 'unique_test_count': 149, 'profile_instance_test_count': 166,
                  'retained_r8_artifacts_verified': True, 'retained_r9_evidence_verified': True,
                  'retained_r10_evidence_verified': True,
                  'retained_failed_observer_verified': True,
                  'retained_successful_observer_verified': True,
                  'original_budgets_preserved': True}), flush=True)
assert time.monotonic() < OUTER_UNTIL, 'original outer deadline expired before same-PID exec'
os.execv(argv[0], argv)
