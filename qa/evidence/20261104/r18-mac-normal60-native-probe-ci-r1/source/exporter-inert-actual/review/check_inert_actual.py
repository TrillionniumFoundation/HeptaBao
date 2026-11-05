#!/usr/bin/env python3
"""Verify captured original public receipts offline; no host or candidate execution."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
c = json.loads((root / 'inert-actual-input.json').read_text())
request = c['request']
ack = json.loads(c['ack_raw'])
authority = json.loads(c['authority_raw'])
streams = json.loads(c['streams_raw'])
files = json.loads(c['files_raw'])
source_info = json.loads(c['source_info_raw'])
receipt_info = json.loads(c['receipt_info_raw'])
assert request['host'] == ack['job']['host'] == 'rog'
for name in ('args', 'cwd', 'executable', 'idempotency_key'):
    assert request[name] == ack['job'][name]
assert request['timeout_seconds'] == 60
assert ack['reused'] is False and ack['launch']['ok'] is True
assert ack['job']['launch_state'] == 'launched'
assert authority['job_id'] == streams['job_id'] == ack['job']['id']
assert authority['state'] == 'succeeded' and authority['exit_code'] == 0
assert not authority['timed_out'] and not authority['cancelled']
assert authority['output_complete'] and authority['output_durable']
assert authority['terminal_publication_confirmed']
for name in ('stdout', 'stderr'):
    row = streams[name]
    raw = bytes.fromhex(row['bytes_hex'])
    assert raw == row['text'].encode()
    assert row['offset'] == 0 and row['eof'] and row['next_offset'] == row['size'] == len(raw)
    assert authority['log_bytes'][name] == {'seen': len(raw), 'stored': len(raw)}
    assert authority['log_synced'][name] and not authority['log_truncated'][name]
    assert authority['log_errors'][name] is None
assert streams['stderr']['text'] == ''
assert files['truncated'] is False and len(files['files']) == 2
source, receipt = files['files']
assert source['text'] == c['expected_source']
for item, info in ((source, source_info), (receipt, receipt_info)):
    raw = item['text'].encode()
    assert item['eof'] and item['path'] == info['path']
    assert len(raw) == item['size'] == info['size']
    assert hashlib.sha256(raw).hexdigest() == item['sha256'] == info['sha256']
    assert item['version'] == info['version']
    assert info['mode'] == info['metadata']['mode'] == 0o600
    assert info['metadata']['uid'] == info['metadata']['gid'] == 1000
    assert info['metadata']['link_count'] == 1
core = json.loads(receipt['text'])
assert core == json.loads(streams['stdout']['text'])
assert core['status'] == 'prepared' and core['python_compile_only'] is True
for flag in ('artifact_transfer_started', 'compiler_started', 'git_started', 'service_started', 'source_executed'):
    assert core[flag] is False
assert core['stdin_bytes'] == len(request['stdin'].encode())
assert core['stdin_sha256'] == hashlib.sha256(request['stdin'].encode()).hexdigest()
assert len(core['files']) == 1
made = core['files'][0]
assert made['publication'] == 'created' and made['mode'] == '0600'
assert made['path'] == source['path'] and made['bytes'] == source['size']
assert made['sha256'] == source['sha256']
assert made['identity'][2:7] == [1000, 1000, 0o100600, 1, source['size']]
assert ':'.join(str(made['identity'][i]) for i in (0, 1, 6, 7, 8)) == source_info['version']
elapsed = core['terminal_ns'] - core['started_ns']
assert 0 < elapsed < 60_000_000_000
result = {'schema': 'heptabao.df026-export-inert-actual-check.v1', 'status': 'passed_inert_only',
          'job_id': ack['job']['id'], 'source_sha256': source['sha256'],
          'source_bytes': source['size'], 'receipt_sha256': receipt['sha256'],
          'source_version': source['version'], 'receipt_version': receipt['version'],
          'integer_comparison': 'Python exact arbitrary-precision integers from original JSON strings',
          'elapsed_nanoseconds': str(elapsed), 'stdout_bytes': streams['stdout']['size'],
          'stderr_bytes': 0, 'original_core_stdout_equal': True,
          'source_complete_bytes_equal': True, 'authority_success_complete_durable': True,
          'source_executed': False, 'product_runtime_qualification': False,
          'host_operations_during_this_offline_check': 0}
raw = json.dumps(result, indent=2, sort_keys=True) + '\n'
(root / 'inert-actual-check.public.json').write_text(raw)
print(raw, end='')
