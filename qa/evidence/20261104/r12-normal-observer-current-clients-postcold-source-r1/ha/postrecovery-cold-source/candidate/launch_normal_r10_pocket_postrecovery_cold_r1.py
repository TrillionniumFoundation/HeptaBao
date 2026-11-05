"""New fresh Direct98 plus separate post-recovery cold12; exact R10 product, private QA overlay."""
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
CONTROL = ROOT / 'normal-r10-pocket3-mac1-postrecovery-cold-control-r1'
WORK = ROOT / 'formal-r10-pocket3-mac1-postrecovery-cold-r1'
SOURCE = ROOT / 'normal-r10-validation-source-r1'
COMMIT = '49503322c7f446e5eb41e7744f1fdbd7f1192ecc'
TREE = '1d4211f91e1b34a2ed087a3bbef2e2884bac88e9'
MAC = '/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/normal-release-tests-r1'
LINUX = '/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1/normal-release-tests-r1'
PROBE = CONTROL / 'probe_normal_build_r10_r1.py'
RUNNER = CONTROL / 'native_v6_pocket_source_postrecovery_cold_r10_r1.py'
RUNNER_SHA256 = '06acd60952d5804dd8bd7b67f399216f26df8e04a24d58e2bea7e82383c9ac47'
NUMERIC_HELPER = CONTROL / 'read_stopped_postrecovery_frontier_r1.py'
NUMERIC_HELPER_SHA256 = 'e951cca69fdc9e85dfd68b4af46b2a0cb01f7caae9ba24b9f0d16c985d476f43'
CIPHER_HELPER = CONTROL / 'read_stopped_recovered_cipher_r1.py'
CIPHER_HELPER_SHA256 = '096792825beee8577a9cbd33fe039e08a284a2186ce485131ac6b74ee56cc956'
DEADLINE_QA = CONTROL / 'deadline_qa'
DEADLINE_QA_PINS = {
    "ha_multihost_live.py": "e37e39459f290c8b9121039196038c9021607e86ed4112def8060d20b1233460",
    "native_v6_ha_multihost_live.py": "6fb8f2dbac97730bea706503fb07e9fd5de60e794475d52f32290e374f86d429",
    "native_v6_ha_direct_lan_live.py": "bc99f154d89dfbe8a82babb8c50bcda3accaf8c486c51750db48bfc4003932ea",
    "native_ha_foreground_watchdog.py": "04189572097f5f7ac1f4ea3eaf53afaa3bf9854043cec9e190b9fd96d628ef89"
}
POSTCOLD_CHECKS = [
    "postcold.inputs_and_history_bound",
    "postcold.all_three_owned_processes_stopped",
    "postcold.mac_persisted_frontier_retained",
    "postcold.same_recovered_cipher_reference_retained",
    "postcold.new_processes_sealed",
    "postcold.real_sealed_leader_elected",
    "postcold.all_three_unsealed_once",
    "postcold.all_local_frontiers_retained",
    "postcold.leader_retained_history_exact",
    "postcold.all_metadata_and_retired_states_exact",
    "postcold.all_hosts_small_readindex",
    "postcold.shared_deadline_completed"
]
QA_PINS = {
    'ha_multihost_live.py': '0e7362d3e579f8a13d63ad1573745fb8cda71aeba75f40288db3927204e408de',
    'native_v6_ha_multihost_live.py': '330cc6fe8eccb02711e897753ef70d9f3f46717f581f6e80a7b814f7603c638c',
    'native_v6_ha_direct_lan_live.py': '8b82b66555f0190eeb0eaf40ad2a19006de932297fa01b512b22b73675995197',
    'native_v6_ha_official_history_live.py': '758e5d6cc93900fd6c5de328446fce069f167fe1eb7c63fc1f2a8310231e04d5',
    'native_fixture_recovery.py': '4c71ef73947ba30a1f4f24344a9840f38f78350c223a4cc80c2b3cb53d777af3',
}
BUILDS = {
    "linux": {
        "abi": "x86_64-unknown-linux-gnu",
        "actual_native_build_host": "rog",
        "alias": "rog-ts",
        "build": "/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1/normal-release-tests-r1",
        "source": "/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1/source",
        "python": "/usr/bin/python3",
        "cargo": "/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo",
        "build_driver_sha256": "7aa39562fde6d96eeca9b1d0e53f600c9629de09613d052fad8e68e9c734d176",
        "files": {
            "artifacts/heptabao-seed": "6befec74076fb891e12a9dd3a1b2563c995ec7f7f1c7df18dc787d1163e0e018",
            "artifacts/heptabao-server": "67ebb1cd97605fcbebf69d6c2caa730a811900586139f63c0031f933c704d113",
            "normal-release-build.stdout": "47694694edb5ef1e5c10aec8d24d12de44f5537c18488ec2c879f6031f2fbe0f",
            "native-build.public.json": "0e3d1ae800820d33f0d5369968cbccbab8fa62b077b142f87c9f52b31cd09c77",
            "normal-release-result.public.json": "75f858b280249dcc981eee3e4340982a58027e8ca40217244ae029bb8e9011ee"
        }
    },
    "mac": {
        "abi": "aarch64-apple-darwin",
        "actual_native_build_host": "mac",
        "alias": "mac-ts",
        "build": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/normal-release-tests-r1",
        "source": "/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261104-native-http-r10/source",
        "python": "/opt/homebrew/bin/python3",
        "cargo": "/Users/qianqi/.rustup/toolchains/1.98.0-aarch64-apple-darwin/bin/cargo",
        "build_driver_sha256": "f925684275b42215300fa91f9b90478c75b822ce2d6f2e4be165b5e8e44e353d",
        "files": {
            "artifacts/heptabao-seed": "cbfbb57a63a971ce35701a5629d07f2e54e461c7774e4b27d56c8a34a0d26cf4",
            "artifacts/heptabao-server": "bc1fc6b8ded5a43a60ab4c562cd5e092e63ae9df77afd654c9af8c096c128c98",
            "normal-release-build.stdout": "8eefe497192295e5e8016ba3a1938ac534e4bf3746853164e9616c37b0eb6442",
            "native-build.public.json": "16fa488ed8d7a9a46541b5aea5007e27b538e5c37f9246c14de0e5fe24b05ad1",
            "normal-release-result.public.json": "f5746eaf7fd79c8001ac927c9738922297d6e5e575cbd12bc092aafa2c13f544"
        }
    }
}
COMPARISON_PINS = {
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/combined-blocker-closure-build-control-r1/import-failure-boundary.public.json": "352d797c58371547ccfd125d4ceed7ca54baf5f756ebf81a2dd81224951e5a90",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/e171-private-cold-phase-full128-live-r1/summary.json": "53a17ce7169e412e30099b7232dd3e2ba3b064a6bd39d47fc58753883476c91e",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/e171-private-cold-phase-full128-live-r2/summary.json": "f928c1d74bd1f8b4bad8530b6f2ad9d96ea8ff8020ac5f4384a136c833241d1d",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-33cafa-normal-full128-r1/summary.json": "41af5de59863ec2d430674d0b6272b040276d2777dda383a25a2e195cdab9f44",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-33cafa-normal-full128-r2/summary.json": "8f7285ffad498ec0b6eeaca48e255790776a15ec62c218e195cf5e7ce0f2e8f1",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-36076-normal-full128-r1/summary.json": "6c0c51c2e155db952dfb154b5d5418e2a66beb21b3548f63d1b25f4787deab8b",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-r10-normal-full128-r1/summary.json": "99b78fe5021248cd9f00af681df8a176442a59c54d446fa3d9f5f0adab414d76",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-r10-normal-full128-r2/summary.json": "9a23e1b4cce8638f7b5c8ea37d41929864c8b4ef35e0bef47292695d4703405e",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-r10-pocket3-mac1-direct98-r2/summary.json": "bd7cc8949faca6bebcad6c847f2f1506526a6329ed6392f865892f253cf0c912",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-33cafa-full128-control-r1/normal-original128-assessment.public.json": "30f3f88667cfb876833d4c84347c40ca9c20fc91c08e4f1d812cdf41b11cda4f",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-33cafa-full128-control-r2/normal-original128-assessment.public.json": "66df7dbd422004f7f4569fb9e44a5835f929a5c7f5d19a08b484cc3ecf0cb318",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-full128-control-r1/exit.public.json": "d9c9b628ceb135ace41d6c7990668dce2cd73c0784d028b1361b42346e7c504c",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-full128-control-r1/launch_normal_r10_full128_r1.py": "0c249a8d0cdec7912346394084ba0da638e3b83f41a1bbd70fdfe924eab21a3a",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-full128-control-r1/prepared.public.json": "64855330cb0beb840869fe601c707a4f2897e7bf3688af85dfdddc5e4ab9e01c",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-full128-control-r2/exit.public.json": "ec20a5bd20c3808ee55890ea00044e6ab92b24d290e55b7b50fe268b0ea774ef",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-full128-control-r2/launch_normal_r10_full128_r2.py": "1c7f6b254a5a4acde704fff145b315b9fbe7ade186513dc0411c7e1a64506817",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-full128-control-r2/prepared.public.json": "ef5b7e46b8632b354652ecc709e81ed6e2ce41cfdc8870d54c1891a13214c524",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-pocket3-mac1-direct98-control-r2/exit.public.json": "2836b3e3e79fe0b2f531eca2b1e25394e79c156de2efafc78cfaad7e0e1e03da",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-pocket3-mac1-direct98-control-r2/launch_normal_r10_pocket_direct98_r2.py": "7a40c9ce4c646f850c611fc29317cc2c0662d5823a10c7d52d7d43dcaa97ade9",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-pocket3-mac1-direct98-control-r2/prepared.public.json": "a583880730e5c3dfa24b8d31c714af44b11434f05bdd660a1f0e434a46c0387c",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/formal-r10-pocket3-mac1-direct98-r3/summary.json": "db362c9c2041636912ccfc95076c6ec7948ec7918efc17032af856875e61cd41",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-pocket3-mac1-direct98-control-r3/exit.public.json": "4e109b8c40a8503bcb128fc33e8ae4ad1134795e2107bf85f1a83a0b4aeb3b29",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-pocket3-mac1-direct98-control-r3/launch_normal_r10_pocket_direct98_r3.py": "5b25448423abba0a18a9317e645fb7bffe392355efe7809e9c76c480f3f3c5b4",
    "/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-r10-pocket3-mac1-direct98-control-r3/prepared.public.json": "deac7add8e45d56099c1e126b2f547ddc0f39e0b5ef9ff15f086f2dfca01e565"
}

def require_bound_artifact_pins():
    def exact_digest(value):
        return (isinstance(value, str) and len(value) == 64
                and all(char in '0123456789abcdef' for char in value))
    assert all(exact_digest(pin) for config in BUILDS.values()
               for pin in config['files'].values()), 'actual_R10_build_pins_not_bound'
    assert all(isinstance(config['cargo'], str)
               and Path(config['cargo']).is_absolute()
               and Path(config['cargo']).name == 'cargo'
               for config in BUILDS.values()), 'actual_R10_cargo_paths_not_bound'
    assert all(exact_digest(pin) for pin in COMPARISON_PINS.values()), 'prior_receipt_pins_not_bound'



def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(path, raw):
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def write_json(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def verify_new_qa_sources():
    assert DEADLINE_QA.resolve(strict=True) == DEADLINE_QA and not DEADLINE_QA.is_symlink()
    assert DEADLINE_QA.stat().st_uid == os.getuid() and stat.S_IMODE(DEADLINE_QA.stat().st_mode) == 0o700
    files = {DEADLINE_QA / name: pin for name, pin in DEADLINE_QA_PINS.items()}
    files[CIPHER_HELPER] = CIPHER_HELPER_SHA256
    for path, pin in files.items():
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        assert info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
        assert 0 < info.st_size < 128 * 1024 and sha(path) == pin
    return True


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
    v = [sys.executable, str(RUNNER), '--candidate-source', str(SOURCE),
        '--binary-source', 'rog-ts:' + LINUX + '/artifacts/heptabao-server',
        '--expected-binary-sha256', BUILDS['linux']['files']['artifacts/heptabao-server'],
        '--node-binary', 'mac-ts,mac-ts:' + MAC + '/artifacts/heptabao-server,' + BUILDS['mac']['files']['artifacts/heptabao-server'] + ',' + COMMIT + ',' + TREE,
        '--source-commit', COMMIT, '--source-tree', TREE]
    for alias, platform in [('mac-ts', 'mac'), ('rog-ts', 'linux'), ('pocket4-ts', 'linux')]:
        v += ['--native-build-receipt', alias + ',local:' + str(CONTROL / (platform + '-native-build.public.json')) + ',' + BUILDS[platform]['files']['native-build.public.json']]
    v += ['--node', 'mac-ts,192.168.0.8,/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261103-ha-closure-r1/r10-pocket3-mac1-postrecovery-cold-node1-r1',
          '--node', 'rog-ts,192.168.0.10,/home/qian-qi/heptabao-ha-closure-20261103-r1/r10-pocket3-mac1-postrecovery-cold-node2-r1',
          '--node', 'pocket4-ts,192.168.0.9,/home/alex/heptabao-ha-closure-20261103-r1/r10-pocket3-mac1-postrecovery-cold-node3-r1',
          '--api-port', '46230', '--raft-port', '46231', '--allow-private-lan', '--work-root', str(WORK),
          '--darwin-watchdog-python', '/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14',
          '--darwin-watchdog-python-sha256', 'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13']
    return v


parser = argparse.ArgumentParser()
action = parser.add_mutually_exclusive_group(required=True)
action.add_argument('--prepare-only', action='store_true')
action.add_argument('--run-once', action='store_true')
parser.add_argument('--prepared-sha256')
option = parser.parse_args()
require_bound_artifact_pins()
assert Path(__file__).resolve(strict=True) == CONTROL / 'launch_normal_r10_pocket_postrecovery_cold_r1.py'
assert CONTROL.resolve(strict=True) == CONTROL
assert CONTROL.stat().st_uid == os.getuid() and stat.S_IMODE(CONTROL.stat().st_mode) == 0o700
assert not WORK.exists() and not WORK.is_symlink()
for name, expected in QA_PINS.items():
    assert sha(SOURCE / 'qa/openbao-acceptance' / name) == expected
assert all(sha(path) == pin for path, pin in COMPARISON_PINS.items())
assert sha(RUNNER) == RUNNER_SHA256
assert NUMERIC_HELPER.resolve(strict=True) == NUMERIC_HELPER
assert NUMERIC_HELPER.is_file() and not NUMERIC_HELPER.is_symlink()
assert NUMERIC_HELPER.stat().st_uid == os.getuid() and NUMERIC_HELPER.stat().st_nlink == 1
assert stat.S_IMODE(NUMERIC_HELPER.stat().st_mode) == 0o600
assert sha(NUMERIC_HELPER) == NUMERIC_HELPER_SHA256
assert verify_new_qa_sources()
probes = build_probes()
launcher_sha, probe_sha = sha(__file__), sha(PROBE)
prepared_path = CONTROL / 'prepared.public.json'
if option.prepare_only:
    assert option.prepared_sha256 is None and not prepared_path.exists()
    for name, probe in probes.items():
        for field, filename in [('native_raw_base64', 'native-build.public.json'), ('result_raw_base64', 'normal-release-result.public.json')]:
            raw = base64.b64decode(probe[field], validate=True)
            assert hashlib.sha256(raw).hexdigest() == BUILDS[name]['files'][filename]
            write(CONTROL / (name + '-' + filename), raw)
    sys.path.insert(0, str(SOURCE / 'qa/openbao-acceptance'))
    module = importlib.import_module('native_v6_ha_official_history_live')
    module.direct.parsed_arguments(args()[4:])
    contract_result = subprocess.run([sys.executable, str(RUNNER), '--candidate-source', str(SOURCE), '--describe-contract'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert contract_result.returncode == 0
    contract = json.loads(contract_result.stdout)
    assert contract['required_check_count'] == 98 and contract['fixture_started'] is False
    assert contract['required_extra_check_count'] == 12 and contract['required_extra_checks'] == POSTCOLD_CHECKS
    assert contract['deadline_qa_pins'] == DEADLINE_QA_PINS
    assert contract['new_shared_postrecovery_seconds'] == 300 and contract['original_controller_seconds'] == 2400
    assert contract['extra_phase_before_original_finish_application'] is True
    assert contract['canonical_qa_unchanged'] is True
    assert contract['reference_captured_in_original_recovered_scan'] is True
    assert contract['cipher_helper_sha256'] == CIPHER_HELPER_SHA256
    assert contract['readable_large_versions'] == 17 and contract['lifecycle_versions'] == 19
    assert contract['requested_cipher_source_node'] == 3 and contract['requested_actual_empty_leader_node'] == 1
    assert contract['numeric_helper_sha256'] == NUMERIC_HELPER_SHA256
    assert contract['controlled_stop_order'] == [2, 1, 3] and contract['original_stop_count_preserved'] == 3
    assert contract['new_role_prepare_seconds'] == 60 and contract['original_sealed_election_seconds'] == 60
    assert contract['new_numeric_read_seconds'] == 15 and contract['new_numeric_ssh_seconds'] == 45
    assert contract['canonical128_summary_sha256'] == COMPARISON_PINS[
        str(ROOT / 'formal-r10-normal-full128-r2/summary.json')]
    assert len(module.direct.DIRECT_CHECKS) == 98 and len(module.EXTRA_CHECKS) == 30
    assert len(module.direct.DirectLanRun.required_checks) == 98
    prepared = {'schema': 'heptabao.normal-r10-postrecovery-cold-prepared.v1',
        'required_extra_checks': POSTCOLD_CHECKS, 'required_extra_check_count': 12,
        'new_shared_postrecovery_seconds': 300, 'original_controller_seconds': 2400,
        'deadline_qa_pins': DEADLINE_QA_PINS, 'cipher_helper_sha256': CIPHER_HELPER_SHA256,
        'original98_extra12_separate': True, 'canonical_qa_files_unchanged': True,
        'source_commit': COMMIT, 'source_tree': TREE, 'qa_pins': QA_PINS,
        'comparison_pins': COMPARISON_PINS, 'prior_receipts_unchanged': True,
        'launcher_sha256': launcher_sha, 'probe_sha256': probe_sha, 'build_pins': BUILDS,
        'build_probes': probes, 'argv': args(), 'required_checks': 98,
        'runner_sha256': RUNNER_SHA256, 'numeric_helper_sha256': NUMERIC_HELPER_SHA256,
        'direction_contract': contract,
        'original_98_preserved': True, 'official30_repeated_in_this_scope': False,
        'source_admission_and_actual_argument_parser_passed': True,
        'ordinary_http_seconds': 15,
        'native_admission_seconds': 8, 'fixture_started': False,
        'production_changed': False, 'private_diagnostic_feature_enabled': False,
        'formal_qualification': False, 'prepared_unix': time.time()}
    write_json(prepared_path, prepared)
    print(json.dumps({'prepared': str(prepared_path), 'bytes': prepared_path.stat().st_size,
        'sha256': sha(prepared_path), 'fixture_started': False, 'required_checks': 98}, sort_keys=True))
    raise SystemExit(0)

assert option.prepared_sha256 and sha(prepared_path) == option.prepared_sha256
prepared = json.loads(prepared_path.read_text())
assert prepared['launcher_sha256'] == launcher_sha and prepared['probe_sha256'] == probe_sha
assert prepared['build_probes'] == probes and prepared['argv'] == args()
assert prepared['comparison_pins'] == COMPARISON_PINS
assert prepared['runner_sha256'] == RUNNER_SHA256
assert prepared['numeric_helper_sha256'] == NUMERIC_HELPER_SHA256
assert prepared['deadline_qa_pins'] == DEADLINE_QA_PINS
assert prepared['cipher_helper_sha256'] == CIPHER_HELPER_SHA256
assert prepared['required_extra_checks'] == POSTCOLD_CHECKS and prepared['required_extra_check_count'] == 12
assert verify_new_qa_sources()
for name, config in BUILDS.items():
    for filename in ('native-build.public.json', 'normal-release-result.public.json'):
        assert sha(CONTROL / (name + '-' + filename)) == config['files'][filename]
qa_started = time.monotonic()
qa_until = qa_started + 2400.0
write_json(CONTROL / 'launch.public.json', {'schema': 'heptabao.normal-r10-postrecovery-cold-launch.v1',
    'original_controller_seconds': 2400, 'controller_started_monotonic': qa_started,
    'controller_absolute_deadline': qa_until, 'new_shared_postrecovery_seconds': 300,
    'deadline_qa_pins': DEADLINE_QA_PINS, 'cipher_helper_sha256': CIPHER_HELPER_SHA256,
    'source_commit': COMMIT, 'source_tree': TREE, 'argv': args(), 'prepared_sha256': option.prepared_sha256,
    'launcher_sha256': launcher_sha, 'probe_sha256': probe_sha, 'started_unix': time.time(),
    'production_changed': False, 'private_diagnostic_feature_enabled': False})
with (CONTROL / 'stdout.private.log').open('xb') as out, (CONTROL / 'stderr.private.log').open('xb') as err:
    remaining_controller = qa_until - time.monotonic()
    assert remaining_controller > 0
    result = subprocess.run(args(), cwd=SOURCE, stdout=out, stderr=err,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                 HEPTABAO_SYNTHETIC_CONTROLLER_DEADLINE=repr(qa_until)), timeout=remaining_controller)
post = build_probes()
frozen = {name: post[name] == probes[name] for name in probes}
report = {'schema': 'heptabao.normal-r10-postrecovery-cold-exit.v1',
    'deadline_qa_unchanged': verify_new_qa_sources(), 'required_extra_check_count': 12,
    'original_controller_seconds': 2400, 'new_shared_postrecovery_seconds': 300, 'exit_code': result.returncode,
    'summary': str(WORK / 'summary.json'), 'finished_unix': time.time(),
    'fresh_build_source_files_unchanged': frozen,
    'controller_unchanged': sha(__file__) == launcher_sha and sha(PROBE) == probe_sha,
    'runner_unchanged': sha(RUNNER) == RUNNER_SHA256 and sha(NUMERIC_HELPER) == NUMERIC_HELPER_SHA256 and all(sha(SOURCE / 'qa/openbao-acceptance' / name) == pin for name, pin in QA_PINS.items()),
    'prior_receipts_unchanged': all(sha(path) == pin for path, pin in COMPARISON_PINS.items()),
    'private_diagnostic_feature_enabled': False}
write_json(CONTROL / 'exit.public.json', report)
print(json.dumps(report, sort_keys=True))
raise SystemExit(result.returncode if all(frozen.values()) and report['controller_unchanged'] and report['runner_unchanged'] and report['prior_receipts_unchanged'] and report['deadline_qa_unchanged'] else 1)
