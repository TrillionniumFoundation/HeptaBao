"""Reconcile retained original Mac custody evidence without running tests."""
from pathlib import Path
import hashlib
import json
import re
import sys

root = Path(__file__).resolve().parent
load = lambda name: json.loads((root / name).read_text())
sha = lambda value: hashlib.sha256(value).hexdigest()
terminal = load('runtime-terminal.original.json')
logs = load('runtime-read.original.json')
selection = load('selection.public.json')
report = load('result.public.json')
binding = load('input-binding.public.json')
request = load('runtime-launch-request.json')
start = load('runtime-start.original.json')

assert terminal['job_id'] == start['job']['id'] == logs['job_id'] == '1a1b0f0b31e-fc05-7438'
assert start['job']['host'] == request['host'] == report['host'] == 'mac'
assert start['job']['args'] == request['args']
assert start['job']['idempotency_key'] == request['idempotency_key']
assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
assert terminal['output_complete'] and terminal['output_durable']
assert terminal['terminal_publication_confirmed'] and not terminal['timed_out']
for stream in ('stdout', 'stderr'):
    original = bytes.fromhex(logs[stream]['bytes_hex'])
    assert original == logs[stream]['text'].encode('utf-8') == (root / (stream + '.original')).read_bytes()
    assert len(original) == logs[stream]['size'] == logs[stream]['next_offset']
    assert logs[stream]['offset'] == 0 and logs[stream]['eof']
    assert terminal['log_bytes'][stream]['seen'] == terminal['log_bytes'][stream]['stored'] == len(original)
for row in load('runtime-file-read.original.json')['files']:
    original = (root / Path(row['path']).name).read_bytes()
    assert original == row['text'].encode('utf-8')
    assert len(original) == row['size'] and sha(original) == row['sha256'] and row['eof']
assert report == json.loads((root / 'stdout.original').read_text().splitlines()[1])
actual = re.findall(r'^test_[^ ]+ \(([^)]+)\) \.\.\. ok$', (root / 'stderr.original').read_text(), flags=re.M)
assert sorted(actual) == selection['tests'] and len(actual) == 18
assert sorted(row['test'] for row in report['outcomes']) == selection['tests']
assert all(row['outcome'] == 'passed' for row in report['outcomes'])
assert report['status'] == 'passed' and report['tests_run'] == report['passed'] == 18
assert report['failed'] == report['errors'] == report['skipped'] == 0
assert report['expected_failures'] == report['unexpected_successes'] == 0
assert report['exact_names_matched'] and report['no_direct_children_after_tests']
assert report['original_hooks_and_handlers_restored'] and report['source_and_copied_inputs_unchanged']
assert report['original_test_child_timeouts_unchanged'] and request['timeout_seconds'] == report['outer_seconds'] == 60
assert selection['inputs'] == report['inputs'] == binding['inputs']
for row in selection['inputs']:
    original = (root / 'inputs' / row['relative']).read_bytes()
    assert len(original) == row['bytes'] and sha(original) == row['sha256']
assert sha((root / 'runner.py').read_bytes()) == binding['runner_sha256']
assert sha((root / 'launcher.py').read_bytes()) == binding['launcher_sha256']
assert (root / 'launcher.py').read_text() == request['args'][-1]
assert not report['product107_or_dr_executed'] and not report['formal_storage_or_physical_ha_qualified']
assert not report['production_changed']
print(json.dumps({'verified': True, 'job_id': terminal['job_id'], 'host': 'mac',
                  'source_commit': report['source_commit'], 'actual_named_tests': 18,
                  'passed': 18, 'failed': 0, 'errors': 0, 'skipped': 0,
                  'raw_streams_and_independent_remote_files_match': True,
                  'same_helper_hash_complete_module_qualified': True,
                  'product_or_physical_ha_qualified': False}, sort_keys=True))
