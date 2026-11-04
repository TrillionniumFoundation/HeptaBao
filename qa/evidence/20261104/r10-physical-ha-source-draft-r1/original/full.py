"""Freeze normal 33cafa artifacts and invoke the original full128 driver once."""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib
import json
import os
import shlex
import stat
import subprocess
import sys
import time

os.umask(0o077)
sys.dont_write_bytecode = True
ROOT = Path('/home/qian-qi/heptabao-ha-closure-20261103-r1')
CONTROL = ROOT / 'normal-33cafa-full128-control-r2'
WORK = ROOT / 'formal-33cafa-normal-full128-r2'
SOURCE = ROOT / 'ha-root-pull-response-final-source-r1'
COMMIT = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
MAC = '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-root-pull-response-r1/build-normal-r1'
LINUX = str(ROOT / 'ha-root-pull-response-normal-build-rog-r1')
PROBE = CONTROL / 'probe_normal_build_r1.py'
QA_PINS = {
    'ha_multihost_live.py': '0e7362d3e579f8a13d63ad1573745fb8cda71aeba75f40288db3927204e408de',
    'native_v6_ha_multihost_live.py': '330cc6fe8eccb02711e897753ef70d9f3f46717f581f6e80a7b814f7603c638c',
    'native_v6_ha_direct_lan_live.py': '8b82b66555f0190eeb0eaf40ad2a19006de932297fa01b512b22b73675995197',
    'native_v6_ha_official_history_live.py': '758e5d6cc93900fd6c5de328446fce069f167fe1eb7c63fc1f2a8310231e04d5',
    'native_fixture_recovery.py': '4c71ef73947ba30a1f4f24344a9840f38f78350c223a4cc80c2b3cb53d777af3',
}
BUILDS = {'linux': {'abi': 'x86_64-unknown-linux-gnu',
           'actual_native_build_host': 'rog',
           'alias': 'rog-ts',
           'build': '/home/qian-qi/heptabao-ha-closure-20261103-r1/ha-root-pull-response-normal-build-rog-r1',
           'files': {'artifacts/heptabao-seed': '4d3f0be9e527b5b36a7cfb45bbb0fadcd9c8c2c2f3e7a72e14bab90ab1ed68c3',
                     'artifacts/heptabao-server': '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba',
                     'cargo.jsonl': 'ddd53e4eed2cb9e3807ac06e25c7e49b275159cc7a3060be82c22c0d95323a3a',
                     'native-build.public.json': '2fa263744917e1d71658daa4f34e09ea448fe77ec0b2c0f8ec22c01e2cd84e8e',
                     'result.public.json': '7fa76585e94fe2e60bbc3ce754f37e4d9d433e4cf576fcc2e39a1e95771f3f42'},
           'python': '/usr/bin/python3',
           'source': '/home/qian-qi/heptabao-ha-closure-20261103-r1/ha-root-pull-response-final-source-r1'},
 'mac': {'abi': 'aarch64-apple-darwin',
         'actual_native_build_host': 'mac',
         'alias': 'mac-ts',
         'build': '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-root-pull-response-r1/build-normal-r1',
         'files': {'artifacts/heptabao-seed': '2f2d8453a7c6c6d39ae3a233411f79d7607ab92db5358c5687bfb2cde86bf2d2',
                   'artifacts/heptabao-server': 'd8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20',
                   'cargo.jsonl': '9b17bfa1aac1e1682f306e8a1562328cf7e1dd963dbc6bc810ed264d8f44161a',
                   'native-build.public.json': '0e0980a9915ece82a051f828e5740562c1832d1a920b95995af0bada00eb3cff',
                   'result.public.json': 'b53967aac8d06547473f68f907047fd34a89f4ab6295cb9765b24f2202853f33'},
         'python': '/opt/homebrew/bin/python3',
         'source': '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-ha-root-pull-response-r1/source'}}
COMPARISON_PINS = {
  "/home/qian-qi/heptabao-ha-closure-20261103-r1/combined-blocker-closure-build-control-r1/import-failure-boundary.public.json": "352d797c58371547ccfd125d4ceed7ca54baf5f756ebf81a2dd81224951e5a90",
  "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-36076-normal-full128-r1/summary.json": "6c0c51c2e155db952dfb154b5d5418e2a66beb21b3548f63d1b25f4787deab8b",
  "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-33cafa-normal-full128-r1/summary.json": "41af5de59863ec2d430674d0b6272b040276d2777dda383a25a2e195cdab9f44",
  "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-33cafa-full128-control-r1/normal-original128-assessment.public.json": "30f3f88667cfb876833d4c84347c40ca9c20fc91c08e4f1d812cdf41b11cda4f",
  "/home/qian-qi/heptabao-ha-closure-20261103-r1/e171-private-cold-phase-full128-live-r1/summary.json": "53a17ce7169e412e30099b7232dd3e2ba3b064a6bd39d47fc58753883476c91e",
  "/home/qian-qi/heptabao-ha-closure-20261103-r1/e171-private-cold-phase-full128-live-r2/summary.json": "f928c1d74bd1f8b4bad8530b6f2ad9d96ea8ff8020ac5f4384a136c833241d1d"
}


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(path, raw):
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def write_json(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def build_probes():
    probes = {}
    probe_code = PROBE.read_text()
    for name, config in BUILDS.items():
        config = dict(config, commit=COMMIT, tree=TREE)
        if config['alias'] == 'local':
            argv = [sys.executable, str(PROBE)]
        else:
            argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', config['alias'],
                    config['python'] + ' -c ' + shlex.quote(probe_code)]
        p = subprocess.run(argv, input=json.dumps(config).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if p.returncode:
            raise RuntimeError('normal_build_probe_failed_' + name + '_' + hashlib.sha256(p.stderr).hexdigest())
        value = json.loads(p.stdout)
        assert value['source_commit'] == COMMIT and value['source_tree'] == TREE
        assert value['source_clean'] is True and value['private_diagnostic_feature_enabled'] is False
        probes[name] = value
    return probes


def args():
    v = [sys.executable, str(SOURCE / 'qa/openbao-acceptance/native_v6_ha_official_history_live.py'),
        '--binary-source', 'rog-ts:' + LINUX + '/artifacts/heptabao-server',
        '--expected-binary-sha256', BUILDS['linux']['files']['artifacts/heptabao-server'],
        '--node-binary', 'mac-ts,mac-ts:' + MAC + '/artifacts/heptabao-server,' + BUILDS['mac']['files']['artifacts/heptabao-server'] + ',' + COMMIT + ',' + TREE,
        '--source-commit', COMMIT, '--source-tree', TREE]
    for alias, platform in [('mac-ts', 'mac'), ('rog-ts', 'linux'), ('pocket4-ts', 'linux')]:
        v += ['--native-build-receipt', alias + ',local:' + str(CONTROL / (platform + '-native-build.public.json')) + ',' + BUILDS[platform]['files']['native-build.public.json']]
    v += ['--node', 'mac-ts,192.168.0.8,/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261103-ha-closure-r1/33cafa-normal-full128-node1-r2',
          '--node', 'rog-ts,192.168.0.10,/home/qian-qi/heptabao-ha-closure-20261103-r1/33cafa-normal-full128-node2-r2',
          '--node', 'pocket4-ts,192.168.0.9,/home/alex/heptabao-ha-closure-20261103-r1/33cafa-normal-full128-node3-r2',
          '--api-port', '46230', '--raft-port', '46231', '--allow-private-lan', '--work-root', str(WORK),
          '--darwin-watchdog-python', '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14',
          '--darwin-watchdog-python-sha256', 'cbf84109626aa1013bbe408fbb9590bd0f1c1548f038b2221c6b8b87de26ca43',
          '--official-full34-root', '/home/qian-qi/heptabao-unified-ha-20261103-r1/official-full34-mac-input-r1',
          '--official-full34-summary-sha256', '0b6ccb83c43517b9a66fd5971b9a890809a79c773668bc97cfeeeb5dd738c8d7']
    return v


parser = argparse.ArgumentParser()
action = parser.add_mutually_exclusive_group(required=True)
action.add_argument('--prepare-only', action='store_true')
action.add_argument('--run-once', action='store_true')
parser.add_argument('--prepared-sha256')
option = parser.parse_args()
assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_normal_33cafa_full128_r2.py'
assert CONTROL.resolve(strict=True) == CONTROL
assert CONTROL.stat().st_uid == os.getuid() and stat.S_IMODE(CONTROL.stat().st_mode) == 0o700
assert not WORK.exists() and not WORK.is_symlink()
for name, expected in QA_PINS.items():
    assert sha(SOURCE / 'qa/openbao-acceptance' / name) == expected
assert all(sha(path) == pin for path, pin in COMPARISON_PINS.items())
probes = build_probes()
launcher_sha, probe_sha = sha(__file__), sha(PROBE)
prepared_path = CONTROL / 'prepared.public.json'
if option.prepare_only:
    assert option.prepared_sha256 is None and not prepared_path.exists()
    for name, probe in probes.items():
        for field, filename in [('native_raw_base64', 'native-build.public.json'), ('result_raw_base64', 'result.public.json')]:
            raw = base64.b64decode(probe[field], validate=True)
            assert hashlib.sha256(raw).hexdigest() == BUILDS[name]['files'][filename]
            write(CONTROL / (name + '-' + filename), raw)
    sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))
    module = importlib.import_module('native_v6_ha_official_history_live')
    module.parsed_arguments(args()[2:])
    assert len(module.direct.DIRECT_CHECKS) == 98 and len(module.EXTRA_CHECKS) == 30
    assert len(module.OfficialHistoryRun.required_checks) == 128
    prepared = {'schema': 'heptabao.33cafa-normal-original128-prepared.v1',
        'source_commit': COMMIT, 'source_tree': TREE, 'qa_pins': QA_PINS,
        'comparison_pins': COMPARISON_PINS, 'prior_receipts_unchanged': True,
        'launcher_sha256': launcher_sha, 'probe_sha256': probe_sha, 'build_pins': BUILDS,
        'build_probes': probes, 'argv': args(), 'required_checks': 128,
        'original_98_preserved': True, 'original_extra_30_preserved': True,
        'source_admission_and_actual_argument_parser_passed': True,
        'native_large_import_http_seconds': 5, 'ordinary_http_seconds': 15,
        'native_admission_seconds': 8, 'fixture_started': False,
        'production_changed': False, 'private_diagnostic_feature_enabled': False,
        'formal_qualification': False, 'prepared_unix': time.time()}
    write_json(prepared_path, prepared)
    print(json.dumps({'prepared': str(prepared_path), 'bytes': prepared_path.stat().st_size,
        'sha256': sha(prepared_path), 'fixture_started': False, 'required_checks': 128}, sort_keys=True))
    raise SystemExit(0)

assert option.prepared_sha256 and sha(prepared_path) == option.prepared_sha256
prepared = json.loads(prepared_path.read_text())
assert prepared['launcher_sha256'] == launcher_sha and prepared['probe_sha256'] == probe_sha
assert prepared['build_probes'] == probes and prepared['argv'] == args()
assert prepared['comparison_pins'] == COMPARISON_PINS
for name, config in BUILDS.items():
    for filename in ('native-build.public.json', 'result.public.json'):
        assert sha(CONTROL / (name + '-' + filename)) == config['files'][filename]
write_json(CONTROL / 'launch.public.json', {'schema': 'heptabao.normal-original128-launch.v1',
    'source_commit': COMMIT, 'source_tree': TREE, 'argv': args(), 'prepared_sha256': option.prepared_sha256,
    'launcher_sha256': launcher_sha, 'probe_sha256': probe_sha, 'started_unix': time.time(),
    'production_changed': False, 'private_diagnostic_feature_enabled': False})
with (CONTROL / 'stdout.private.log').open('xb') as out, (CONTROL / 'stderr.private.log').open('xb') as err:
    result = subprocess.run(args(), cwd=SOURCE, stdout=out, stderr=err,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), timeout=2400)
post = build_probes()
frozen = {name: post[name] == probes[name] for name in probes}
report = {'schema': 'heptabao.normal-original128-exit.v1', 'exit_code': result.returncode,
    'summary': str(WORK / 'summary.json'), 'finished_unix': time.time(),
    'fresh_build_source_files_unchanged': frozen,
    'controller_unchanged': sha(__file__) == launcher_sha and sha(PROBE) == probe_sha,
    'runner_unchanged': all(sha(SOURCE / 'qa/openbao-acceptance' / name) == pin for name, pin in QA_PINS.items()),
    'prior_receipts_unchanged': all(sha(path) == pin for path, pin in COMPARISON_PINS.items()),
    'private_diagnostic_feature_enabled': False}
write_json(CONTROL / 'exit.public.json', report)
print(json.dumps(report, sort_keys=True))
raise SystemExit(result.returncode if all(frozen.values()) and report['controller_unchanged'] and report['runner_unchanged'] and report['prior_receipts_unchanged'] else 1)
