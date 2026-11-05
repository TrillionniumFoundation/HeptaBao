"""Compose and compile the disabled Linux driver offline. Never execute it."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTROL = ROOT / 'control'
REVIEW = ROOT / 'review'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


baseline_raw = (REVIEW / 'mac-r5-driver-baseline.py').read_bytes()
assert sha(baseline_raw) == '6e1ba63d18d6133c4912228b2c1bc5662465155b578017c3278c8a008834477c'
baseline = baseline_raw.decode()
baseline_lines = baseline.splitlines(True)
nodes = {node.name: node for node in ast.parse(baseline).body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
names = ['need', 'sha', 'blob', 'identity', 'remaining', 'read_owned', 'hash_owned',
         'sync_dir', 'write_raw', 'write_json', 'interrupted', 'OwnedRunner',
         'source_state', 'artifact_events', 'retain_artifact']
inventory = json.loads((CONTROL / 'critical-tests.public.json').read_text())
assert inventory['test_count'] == 19 and len(inventory['tests']) == 19
critical = [entry['name'] for entry in inventory['tests']]
header = '''#!/usr/bin/env python3
"""Disabled-review Linux candidate controller; current admission pins are mandatory."""
import base64
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian-qi/heptabao-bao-acceptance-unified-61ff-20261104-r1')
SOURCE = ROOT / 'source'
TARGET = ROOT / 'cargo-target-normal'
CACHE = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target')
CARGO_HOME = Path('/home/qian-qi/heptabao-native-20261029-c1bd-r1/cargo-home')
TOOLCHAIN = Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
ATTEMPT = ROOT / 'linux-snapshot-61ff-20261105-r1'
CONTROL = ATTEMPT / 'control'
OUTPUT = ATTEMPT / 'normal'
BASE_COMMIT = '70714605c39014bea93545f7f6aa4217d2a23544'
BASE_TREE = 'ef0ae63704a06b7dda1038e02abcc3233a2a438f'
BASE_BRANCH = 'refs/heads/codex/heptabao-unified-61ff-20261104-r1'
REVIEW_COMMIT = 'f80d2d54800ba7e932d91572c084f930af3e5714'
INPUT_TREE = '667ae96b264c5e7f4b9290933612125d883b9e69'
BRANCH = 'codex/heptabao-linux-snapshot-61ff-20261105-r1'
BASE_FROZEN_SHA = 'ad59fb02e3affc08720c13f7349d93a99df646ca7616f9a10e41e1cc6ddbeff1'
GUARD_SHA = 'b00ff78b2a341a752d489c3a677f7a912f0f79b39c42601cfb030a29bea45b59'
ORIGINAL_UNKNOWN_PREFLIGHT_JOB = '1a1a93e525e-fc05-3335'
SHARED_SECONDS = 3600.0
NORMAL_PROFILE = {
    'CARGO_PROFILE_RELEASE_OPT_LEVEL': '3',
    'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '16',
    'CARGO_PROFILE_RELEASE_LTO': 'false',
    'CARGO_PROFILE_RELEASE_DEBUG': '0',
    'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS': 'true',
    'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS': 'true',
    'CARGO_PROFILE_RELEASE_PANIC': 'unwind',
}
FEATURES = ['default', 'native-v6-ha', 'native-v6-storage']
creating = False
pending_signal = None
work_started = False
'''
parts = [header, 'CRITICAL_TESTS = ' + repr(critical) + '\n']
mechanical = []
for name in names:
    node = nodes[name]
    original = ''.join(baseline_lines[node.lineno - 1:node.end_lineno])
    updated = original
    expected_uid_changes = name in ('read_owned', 'hash_owned', 'retain_artifact')
    if expected_uid_changes:
        assert original.count('== 501') == 1
        updated = original.replace('== 501', '== 1000')
        assert '501' not in updated
    mechanical.append({'name': name, 'before_sha256': sha(original.encode()),
                       'after_sha256': sha(updated.encode()),
                       'unchanged': original == updated,
                       'only_change': 'fixed operator UID 501 -> 1000' if expected_uid_changes else None})
    parts.append(updated)
tail = (CONTROL / 'linux_candidate_tail.py').read_text()
parts.append(tail)
driver = ('\n\n'.join(parts) + '\n').encode()
parsed = ast.parse(driver.decode(), filename='run_linux_candidate_r1.py')
compile(parsed, 'run_linux_candidate_r1.py', 'exec')
(CONTROL / 'run_linux_candidate_r1.py').write_bytes(driver)
new_nodes = {node.name: node for node in parsed.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
assert len(new_nodes) == len([n for n in parsed.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))])
driver_lines = driver.decode().splitlines(True)
owned_node = new_nodes['OwnedRunner']
owned_actual = ''.join(driver_lines[owned_node.lineno - 1:owned_node.end_lineno])
owned_base_node = nodes['OwnedRunner']
owned_base = ''.join(baseline_lines[owned_base_node.lineno - 1:owned_base_node.end_lineno])
assert owned_actual == owned_base
payload = json.loads((CONTROL / 'candidate-input.draft.public.json').read_text())
assert payload['execution_enabled'] is False and payload['mode'] is None
assert payload['process_request'] is None and payload['current_toolchain_pins'] is None
assert payload['authoritative_preflight_resolution'] is None
assert payload['current_resource_and_ownership_review'] is None
assert payload['unresolved_preflight_job'] == '1a1a93e525e-fc05-3335'
assert [x['name'] for x in payload['critical_tests']['tests']] == critical
payload['original_unknown_preflight_job'] = '1a1a93e525e-fc05-3335'
payload['original_unknown_preflight_resolution'] = None
input_raw = canonical(payload)
(CONTROL / 'candidate-input-r2.draft.public.json').write_bytes(input_raw)
control_draft = {
    'schema': 'heptabao.linux.candidate-controller-draft.v2',
    'execution_enabled': False, 'process_request': None, 'bootstrap': None,
    'unresolved_preflight_job': payload['unresolved_preflight_job'],
    'driver_source': driver.decode(), 'driver_sha256': sha(driver),
    'candidate_input': payload,
    'input_sha256': sha(input_raw),
    'new_shared_budget_seconds': 3600, 'supervisor_seconds': 3900,
}
control_raw = canonical(control_draft)
assert len(control_raw) <= 1024 * 1024
(CONTROL / 'candidate-controller.draft.public.json').write_bytes(control_raw)
report = {
    'schema': 'heptabao.linux.candidate-controller.local-syntax.v1',
    'scope': 'mechanical extraction, AST and compile only; packaged code not executed',
    'driver': {'path': 'control/run_linux_candidate_r1.py', 'bytes': len(driver), 'sha256': sha(driver)},
    'controller_draft': {'path': 'control/candidate-controller.draft.public.json', 'bytes': len(control_raw), 'sha256': sha(control_raw)},
    'input_draft': {'path': 'control/candidate-input-r2.draft.public.json', 'bytes': len(input_raw), 'sha256': sha(input_raw)},
    'baseline': {'commit': '5d0197ab72e4cf7e52df6e481fba5f42f8042ab9',
                 'path': 'qa/evidence/20261105/ha-mac-snapshot-api-attempt-61ff-r5/control/run_normal_attempt_r5.py',
                 'sha256': sha(baseline_raw)},
    'mechanical_helpers': mechanical,
    'owned_runner_class_byte_for_byte_unchanged': True,
    'new_linux_group_observation': 'proc stat only; an observation error cannot become an empty group',
    'ast_parse_passed': True, 'compile_passed': True,
    'duplicate_function_or_class_names': False,
    'test_count': len(critical), 'test_names_match_disabled_input': True,
    'executed': False, 'remote_process_submitted': False,
    'current_admission_missing': True, 'execution_enabled': False, 'process_request': None,
    'original_unknown_preflight_job': '1a1a93e525e-fc05-3335',
    'original_unknown_preflight_resolution': None,
    'full_replacement_qualified': False,
}
(REVIEW / 'controller-local-syntax.public.json').write_bytes(canonical(report))
print(json.dumps({'driver': report['driver'], 'controller_draft': report['controller_draft'],
                  'owned_runner_unchanged': True, 'syntax': True, 'executed': False}, sort_keys=True))
