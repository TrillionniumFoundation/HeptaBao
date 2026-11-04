#!/usr/bin/env python3
"""Independently check the retained partial observer result without replay."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def sha(data):
    return hashlib.sha256(data).hexdigest()

def read(name, expected):
    data = (ROOT / name).read_bytes()
    assert sha(data) == expected, name
    return json.loads(data)

r = read('normal33-live-r2-result.public.json', '12cdeb32dc89a7f0af5d1950a2c14a02581a8e98cefd3719c0673a0bd38e68d4')
a = read('normal33-live-r2-partial-wire-assessment.public.json', '3172100f22faa9f23992bf8c6f806ead6c20ff8b68f5821203745c86424c74db')
job = json.loads((ROOT / 'normal33-wire-r2-job-status.public.json').read_text())
assert job['job_id'] == '1a1a66d4440-fc05-2504'
assert job['state'] == 'failed' and job['exit_code'] == 1 and job['output_complete'] and not job['timed_out']

files = [a['result'], a['roles_before']]
for boundary in a['boundaries']:
    files.extend([boundary['intent'], boundary['outcome']])
assert len(files) == 136
for embedded in files:
    raw = (json.dumps(embedded['json'], sort_keys=True, indent=2) + '\n').encode()
    assert len(raw) == embedded['bytes'] and sha(raw) == embedded['sha256'], embedded['path']
assert a['result']['json'] == r
assert r['status'] == 'failed' and r['failure_code'] == 'node2_snapshot_invalid_restore_safe_exact_leader_location'
assert r['checks_total'] == len(r['checks']) == 43
assert r['checks_passed'] == sum(x['passed'] for x in r['checks']) == 42
assert [x['name'] for x in r['checks'] if not x['passed']] == [r['failure_code']]
assert r['http_intents'] == r['http_outcomes'] == len(a['boundaries']) == 67
assert r['http_unknown'] == 0 and r['intent_sequences_without_terminal_outcome'] == []
assert r['all_owned_stopped'] and len(r['owned_cleanup']) == 4 and len(r['client_cleanup']) == 67
assert all(x['owned_stopped'] and not x['remaining'] for x in r['owned_cleanup'] + r['client_cleanup'])
assert r['source_and_fences_after'] == {k: r['prepared'][k] for k in ['old_fences', 'source_clean', 'source_commit', 'source_tree']}
assert r['artifacts_after'] == r['prepared']['artifacts']
assert r['controller_sha256_after'] == r['prepared']['controller_sha256'] == '365258018813269701fc9332bde852db93ce55153da9e5b9b50a2f4e82ae28c6'
assert r['prepared']['source_tree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
assert r['prepared']['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
assert r['prepared']['http_seconds'] == 15 and r['prepared']['readiness_seconds'] == 45 and r['prepared']['election_seconds'] == 60
assert not r['prepared']['redirect_following'] and not r['production_services_touched'] and r['valid_restore_bodies'] == 0

preconnect = []
for sequence, boundary in enumerate(a['boundaries'], 1):
    intent, outcome = boundary['intent']['json'], boundary['outcome']['json']
    assert boundary['sequence'] == intent['sequence'] == outcome['sequence'] == sequence
    assert intent['http_seconds'] == 15 and intent['redirect_following'] is False
    assert outcome['child_reaped'] and not outcome['child_remaining'] and not outcome['caller_timed_out']
    assert not outcome['outcome_unknown']
    if outcome['request_sent'] is False:
        preconnect.append(sequence)
        assert outcome['child_returncode'] == 2 and outcome['error_type'] == 'ConnectionRefusedError'
        assert outcome['phase'] == 'before_connect' and outcome['response_complete'] is False
    else:
        assert outcome['child_returncode'] == 0 and outcome['response_complete']
assert preconnect == [10]
assert len(a['partial_snapshot_cases']) == 12 and not a['case_matrix_complete']
assert not a['roles_after_exists'] and not a['wire_observations_terminal_exists']
last = a['boundaries'][-1]['outcome']['json']
assert last['status'] == 307 and last['location_present'] and last['location_node'] is None
assert last['location_matches_enrolled_origin_and_exact_target'] is False
assert last['header_names'] == ['location'] and last['content_length'] is None and last['response_bytes'] == 0
assert 'response_header_strict_termination' not in last

review = {
    'schema': 'heptabao-normal33-failed-standby-wire-root-review.v1',
    'result_sha256': sha((ROOT / 'normal33-live-r2-result.public.json').read_bytes()),
    'partial_assessment_sha256': sha((ROOT / 'normal33-live-r2-partial-wire-assessment.public.json').read_bytes()),
    'authoritative_job': {'host': 'desktop', 'id': job['job_id'], 'exit_code': 1, 'output_complete': True, 'timed_out': False},
    'embedded_public_json_files_byte_hash_verified': 136,
    'checks_passed': 42, 'checks_total': 43, 'matrix_complete': False,
    'http_intents': 67, 'recorded_outcomes': 67,
    'old_observer_reported_complete_http': 66, 'definite_preconnect_failures': 1,
    'old_observer_reported_unknown': 0,
    'strict_http_wire_completion_proven': False,
    'strict_completion_correction': 'The frozen observer used http.client, which accepts EOF before the CRLFCRLF header terminator. Its response_complete and zero-unknown fields are parser reports, not independent proof of strict wire completion. Original receipts are retained unchanged.',
    'failed_sequence': 67, 'failed_invariant': r['failure_code'],
    'failed_sequence_observation': {'status': 307, 'location_present': True, 'exact_enrolled_leader_origin_and_target': False, 'raw_location_saved': False, 'strict_header_terminator_saved': False, 'header_names': ['location'], 'body_bytes': 0},
    'cause_proven': False,
    'unproven_alternatives': ['incorrect target', 'duplicate header', 'partial header or response truncation', 'role changed after roles_before'],
    'immutable_source_binary_controller_and_five_prior_evidence_fences_unchanged': True,
    'all_four_owned_servers_and_67_request_children_stopped': True,
    'original_deadlines_retained': {'http_seconds': 15, 'readiness_seconds': 45, 'election_seconds': 60},
    'single_physical_host_three_loopback_nodes': True,
    'production_changed': False, 'unknown_request_replayed': False, 'full_replacement_qualification': False,
    'root_review_script_sha256': sha(Path(__file__).read_bytes()),
}
out = ROOT / 'normal33-wire-r2-root-review.public.json'
out.write_text(json.dumps(review, sort_keys=True, indent=2) + '\n')
print(json.dumps({'path': str(out), 'bytes': out.stat().st_size, 'sha256': sha(out.read_bytes()), 'status': 'retained_failure_verified_with_strict_completion_limitation'}))
