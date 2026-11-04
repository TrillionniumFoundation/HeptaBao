#!/usr/bin/env python3
"""Verify the fresh strict-header failure and all recorded operation boundaries."""
from pathlib import Path
import hashlib
import json

R = Path(__file__).resolve().parent
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(R / 'normal33-live-r3-full-boundary-assessment.public.json') == '11f241b66f63a5f12d983827750576dee4f87b8456e9f873e13ff5cc6ac7b93a'
a = json.loads((R / 'normal33-live-r3-full-boundary-assessment.public.json').read_text())
r = json.loads((R / 'normal33-live-r3-result.public.json').read_text())
job = json.loads((R / 'normal33-wire-r3-job-status.public.json').read_text())
assert job['job_id'] == '1a1a68b95a0-fc05-26ba' and job['state'] == 'failed' and job['exit_code'] == 1
assert job['output_complete'] and job['output_durable'] and not job['timed_out']
files = [a['result'], a['roles_before'], a['raft_before']]
for b in a['boundaries']:
    files.extend([b['intent'], b['outcome']])
assert len(files) == 121
for x in files:
    raw = (json.dumps(x['document'], sort_keys=True, indent=2) + '\n').encode()
    assert len(raw) == x['bytes'] and hashlib.sha256(raw).hexdigest() == x['sha256'], x['path']
assert a['result']['document'] == r
assert sha(R / 'normal33-live-r3-result.public.json') == 'f5a44d25e6f33e562b492e050242f36cc2744417a13a01db4beab1c0422ae590'
assert r['status'] == 'failed' and r['failure_code'] == 'single_exchange_outcome_unknown_no_replay'
assert r['checks_total'] == r['checks_passed'] == len(r['checks']) == 41
assert all(x['passed'] for x in r['checks'])
assert r['http_intents'] == r['http_outcomes'] == len(a['boundaries']) == 59
assert r['complete_http_responses'] == 56 and r['preconnect_failures'] == 2 and r['http_unknown'] == 1
assert r['operation_boundary_complete'] is False and r['intent_sequences_without_terminal_outcome'] == []
assert r['all_owned_stopped'] and len(r['owned_cleanup']) == 4 and len(r['client_cleanup']) == 59
assert all(x['owned_stopped'] and not x['remaining'] for x in r['owned_cleanup'] + r['client_cleanup'])
assert r['source_and_fences_after'] == {k: r['prepared'][k] for k in ['old_fences', 'source_clean', 'source_commit', 'source_tree']}
assert len(r['prepared']['old_fences']) == 7 and r['artifacts_after'] == r['prepared']['artifacts']
assert r['prepared']['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
assert r['controller_sha256_after'] == r['prepared']['controller_sha256'] == 'f6770eea97846adaf67aa0672d9f50596a1800b13d00c074aa16bef6f886765d'
assert (r['prepared']['http_seconds'], r['prepared']['readiness_seconds'], r['prepared']['election_seconds']) == (15, 45, 60)
assert not r['production_services_touched'] and r['valid_restore_bodies'] == 0

heads = {h['sequence']: h for h in a['private_header_integrity_only']}
assert len(heads) == 57
preconnect, unknown, fixed, empty = [], [], [], []
for seq, b in enumerate(a['boundaries'], 1):
    i, o = b['intent']['document'], b['outcome']['document']
    assert seq == b['sequence'] == i['sequence'] == o['sequence']
    assert i['http_seconds'] == 15 and not i['redirect_following'] and not i['valid_restore_body']
    assert o['child_reaped'] and not o['child_remaining'] and not o['caller_timed_out']
    if o['request_sent'] is False:
        assert o['phase'] == 'before_connect' and o['child_returncode'] == 2
        assert not o['response_complete'] and not o['outcome_unknown'] and seq not in heads
        preconnect.append(seq)
        continue
    h = heads[seq]
    assert h['matches_public_size_sha256'] and h['single_link_owned'] and h['mode'] == '0o600'
    assert h['raw_header_not_exported']
    other_names = set(o.get('header_names', [])) - set(h['known_complete_field_counts'])
    assert other_names <= {'x-vault-index', 'content-disposition'}
    assert h['unknown_complete_field_count'] == len(other_names)
    assert h['sha256'] == o['response_header_sha256'] and h['bytes'] == o['response_header_bytes']
    if o['outcome_unknown']:
        unknown.append(seq)
        assert not o['response_complete'] and o['child_returncode'] == 2
        continue
    assert o['response_complete'] and o['child_returncode'] == 0
    assert o['response_header_strict_termination'] and h['ends_crlf_crlf']
    assert not o['response_header_eof_during_headers'] and not o['response_header_capture_bound_exceeded']
    # A strict head alone does not prove fixed-length body completion.
    # Verify the actual retained body byte counts separately for every reply.
    if o['content_length'] is not None:
        assert o['content_length'].isdecimal() and int(o['content_length']) == o['response_bytes']
        assert h['known_complete_field_counts']['content-length'] == 1
        assert 'transfer-encoding' not in o['header_names']
        fixed.append(seq)
    else:
        assert o['status'] == 204 and o['response_bytes'] == 0
        assert 'content-length' not in o['header_names'] and 'transfer-encoding' not in o['header_names']
        empty.append(seq)
assert preconnect == [10, 11] and unknown == [59] and len(fixed) == 54 and empty == [5, 33]

last = a['boundaries'][-1]['outcome']['document']
intent = a['boundaries'][-1]['intent']['document']
literal = b'HTTP/1.1 307 Temporary Redirect\r\nLocation: '
assert intent['method'] == 'POST' and intent['node'] == 2 and intent['body_bytes'] == 22
assert last['status'] == 307 and last['phase'] == 'response_headers'
assert last['http_client_accepted_headers'] and last['response_header_eof_during_headers']
assert not last['response_header_strict_termination'] and last['response_header_bytes'] == len(literal) == 43
assert last['response_header_sha256'] == hashlib.sha256(literal).hexdigest() == '784faf9483052fa127c456e1fd7e1296a8ec358523780ac0a124d91d4d6f9aff'
assert last['location_header_count'] == 1 and last['location_projections'][0]['value_bytes'] == 0
assert heads[59]['equals_initial_redirect_write_literal'] and heads[59]['known_complete_field_counts'] == {}
assert not heads[59]['ends_crlf'] and not heads[59]['ends_crlf_crlf']
assert a['roles_before']['document']['actual_leader'] == 1
assert a['raft_before']['document']['healthy'] and len(a['raft_before']['document']['observed_servers']) == 3

review = {'schema': 'heptabao.normal33-strict-wire-r3-root-review.v1',
    'status': 'retained_failure_verified', 'job': job['job_id'], 'host': 'desktop', 'terminal_exit': 1,
    'result_sha256': sha(R / 'normal33-live-r3-result.public.json'),
    'full_boundary_sha256': sha(R / 'normal33-live-r3-full-boundary-assessment.public.json'),
    'embedded_public_files_byte_hash_verified': 121,
    'http_intents': 59, 'recorded_outcomes': 59, 'strict_complete_http': 56,
    'body_completion_independently_verified': {'single_content_length_exact_bytes': 54, '204_no_body': 2},
    'definite_preconnect_failures': 2, 'strict_unknown': 1,
    'checks_completed_before_request_failure': 41, 'fixed_qualification_denominator_claimed': False,
    'complete_case_matrix': False, 'failure_sequence': 59,
    'response_truncation_proven': True, 'received_header_bytes': 43,
    'received_header_sha256': hashlib.sha256(literal).hexdigest(),
    'header_equals_first_fixed_redirect_write_fragment': True,
    'location_has_no_received_value': True, 'strict_head_terminator_received': False,
    'unique_transport_root_cause_proven': False, 'tcp_reset_proven': False,
    'zero_existing_write_failure_markers_proves_all_writes_succeeded': False,
    'private_raw_headers_kept_private': 57,
    'original_source_binary_controller_and_seven_evidence_fences_unchanged': True,
    'all_owned_servers_stopped': 4, 'all_owned_request_children_stopped': 59,
    'unknown_request_replayed': False, 'valid_restore_bodies': 0,
    'original_budget_seconds': {'http': 15, 'readiness': 45, 'election': 60},
    'not_observed': a['scope']['not_observed'],
    'production_changed': False, 'full_replacement_qualified': False,
    'root_review_script_sha256': sha(Path(__file__))}
out = R / 'normal33-wire-r3-root-review.public.json'
out.write_text(json.dumps(review, indent=2, sort_keys=True) + '\n')
print(json.dumps({'path': str(out), 'bytes': out.stat().st_size, 'sha256': sha(out)}))
