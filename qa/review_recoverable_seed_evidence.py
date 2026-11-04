#!/usr/bin/env python3
"""Recompute the public, source-bound Mac seed recovery evidence; no remote I/O."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E = ROOT / 'qa/evidence/20261104'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(name, pin=None):
    raw = (E / name).read_bytes()
    if pin is not None:
        assert sha(raw) == pin, name
    return json.loads(raw)


def main():
    r1 = read('recoverable-seed-r1-result.public.json',
              '1fac5c29c563841aa0b85b28146197565ab0e794c7dbb33d149dc2b41b60cc9f')
    r2 = read('recoverable-seed-r2-result.public.json',
              '5856a6c7308d4f73b796ee4a14a58d6406727f50b1756b654d5826f24122cc34')
    r3 = read('recoverable-seed-r3-result.public.json',
              'ef640ced21b11be8cfd2dd8cac9342cff5cc0406e1ee17f0bb07cf85c37d7ecb')
    native = read('recoverable-seed-r3-report-read.original-sdk.json',
                  '7a89821a979e992a3aad8cba4998aa90c7d06a6993aa270ad4f8737d5d06c64a')
    assert native['isError'] is False
    fetched = json.loads(native['content'][0]['text'])
    assert fetched['truncated'] is False and len(fetched['files']) == 1
    original = fetched['files'][0]
    raw = original['text'].encode()
    assert original['eof'] is True and original['size'] == len(raw) == 39007
    assert sha(raw) == original['sha256'] == sha((E / 'recoverable-seed-r3-result.public.json').read_bytes())
    terminal_native = read('recoverable-seed-r3-terminal.original-sdk.json',
                           'f52ca4d7c9ddd6e048065ac46a1e14a2dc72c789864a9d68e963659282873e55')
    terminal = read('recoverable-seed-r3-terminal.public.json')
    assert json.loads(terminal_native['content'][0]['text']) == terminal
    assert terminal['job_id'] == '1a1a70e188f-fc05-2a02'
    assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
    assert all(terminal[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
    assert not terminal['timed_out'] and not terminal['cancelled']
    for stream in ('stdout', 'stderr'):
        assert terminal['log_synced'][stream] and not terminal['log_truncated'][stream]
        assert terminal['log_errors'][stream] is None

    pins = {
        'tools/production/prepare_recoverable_seed.py': 'b7b14b6fcbf767d76873b215ce10119fe58beb50ec3fbd164b4925ceb188cfea',
        'tools/production/resume_recoverable_seed.py': '6d1e1bedaa771e7235ddff4c5efe7dddce84be2c37ab8b97bbe5be7cdbc1651d',
        'tools/production/reconcile_recoverable_seed.py': 'fb7772f3c4490e434e6481754d099db94ee23c20298f4f016d4be5e33af28fea',
        'qa/evidence/20261104/recoverable-seed-retained-source/prepare_recoverable_seed.py': '6a2687be3f83583d8730353c72f36bf6c79e24e64211b8a617ba57088f910000',
        'qa/evidence/20261104/recoverable-seed-retained-source/resume_recoverable_seed.py': '6d1e1bedaa771e7235ddff4c5efe7dddce84be2c37ab8b97bbe5be7cdbc1651d',
    }
    for path, expected in pins.items():
        assert sha((ROOT / path).read_bytes()) == expected, path
    assert r3['source'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
    assert r3['tree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
    assert r3['binary_sha256'] == 'd8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20'
    assert r3['source_helper_sha256'] == pins['tools/production/prepare_recoverable_seed.py']
    assert r1['failure'] == 'seed-initial.expected_seed_storage_format' and not r1['ok']
    assert len(r1['requests']) == 7 and all(x['outcome'] == 'response_received' for x in r1['requests'])
    assert r2['failure'] == 'fixed_seed_api_response_framing' and not r2['ok']
    assert len(r2['requests']) == 8 and all(x['outcome'] == 'response_received' for x in r2['requests'][:-1])
    uncertain = r2['requests'][-1]
    assert uncertain['outcome'] == 'unknown' and uncertain['nonce'] == '0f2be8fc31a9430c91f67d784ae8e5b3'
    assert uncertain['method'] == 'POST' and uncertain['path'] == 'sys/mounts/heptabao-seed-recovery-61ff'
    assert r3['ok'] and r3['all_owned_children_stopped'] and r3['r2_unknown_mount_reconciled']
    assert len(r3['checks']) == 66 and all(c['passed'] is True for c in r3['checks'])
    assert len({c['case'] for c in r3['checks']}) == 66
    assert r3['boundary_before'] == r3['boundary_after']
    assert r3['cluster_id'] == '0c56fad8-4061-349e-84a8-0a4cbc7ca12a'
    assert r3['secret_shares'] == 3 and r3['secret_threshold'] == 2
    assert r3['cold_recovery_pairs_verified'] == [[1, 2], [1, 3], [2, 3]]
    requests = r3['requests']
    assert len(requests) == 40 and len({x['nonce'] for x in requests}) == 40
    assert all(x['outcome'] == 'response_received' and x['replayed'] is False and x['http_seconds'] == 12 for x in requests)
    assert not any(x['path'] == 'sys/init' or (x['method'] == 'POST' and x['path'].startswith('sys/mounts/')) for x in requests)
    indexed = {x['label']: x for x in requests}
    assert indexed['reconcile-unknown-mount-read-only']['status'] == 200
    assert indexed['reconcile-no-prior-cas-write']['status'] == 404
    assert all(indexed['dedicated-cas-write-' + str(v)]['status'] == 200 for v in (1, 2))
    assert indexed['dedicated-cas-read']['status'] == 200
    for x in requests:
        assert x['complete_header_bytes'] > 0 and len(bytes.fromhex(x['complete_header_sha256'])) == 32
        assert x['observed_status'] == x['status']
        if x['status'] == 204:
            assert x['response_bytes'] == 0 and x['framing'] == 'status_204_header_boundary'
        else:
            assert x['framing'] in ('exact_content_length', 'canonical_chunked_terminal_boundary')
    for a, b in ((1, 2), (1, 3), (2, 3)):
        prefix = f'cold-recovery-{a}{b}'
        expected = ['initial-status', f'share-{a}', f'share-{b}', 'health', 'root-lookup', 'capacity', 'mounts', 'seal']
        group = [x for x in requests if x['label'].startswith(prefix + '-')]
        assert [x['label'] for x in group] == [prefix + '-' + suffix for suffix in expected]
        assert [x['status'] for x in group] == [200] * 7 + [204]
    assert len(r3['processes']) == 4
    for p in r3['processes']:
        assert p['owned_popen'] and p['stopped'] and p['returncode'] == -15 and not p['forced_kill']
    reconciliation = r3['mount_reconciliation']
    assert reconciliation['original_request_nonce'] == uncertain['nonce']
    assert reconciliation['original_outcome_retained'] == 'unknown' and reconciliation['new_mount_request_sent'] is False
    # r2's mount already produced V5. r3 confirms that effect before its two new CAS writes.
    assert all(c['state_storage_format'] == 'heptabao-state-records-v5' and c['profile'] == 'bounded-record-state-v5'
               and c['native_kv2_reader_format'] is None for c in r3['capacity_observations'])
    for key in ('initialization_repeated', 'prior_unknown_mount_replayed', 'production_node_state_populated',
                'production_service_started', 'production_start_qualified', 'native_v6_activated', 'client_changed',
                'credential_source_changed', 'j3160_contacted', 'shares_distributed', 'split_custody_qualified'):
        assert r3[key] is False, key
    components = read('recoverable-seed-components-http-v2-green.public.json',
                      'f8293ca508a86f65ec84b754e306d8d896418c4a99810f9b5772dac5cc950a1b')
    assert components['ok'] and len(components['cases']) == 13 and all(c['passed'] for c in components['cases'])
    assert components['source_sha256'] == r3['source_helper_sha256']
    assert components['production_http_budget_seconds'] == 12
    assert components['real_heptabao_executed'] is False and components['remote_hosts_contacted'] is False
    report = {
        'schema': 'heptabao.root-reviewed-recoverable-seed.v1', 'ok': True,
        'source': r3['source'], 'tree': r3['tree'], 'binary_sha256': r3['binary_sha256'],
        'job': 'mac/' + terminal['job_id'], 'terminal_exit': 0,
        'result_sha256': original['sha256'], 'original_sdk_sha256': sha((E / 'recoverable-seed-r3-report-read.original-sdk.json').read_bytes()),
        'dynamic_checks': 66, 'http_intents': 40, 'http_outcomes': 40, 'unknown_outcomes': 0,
        'r2_original_unknown_mount_outcome_retained': True, 'r2_mount_readonly_reconciled_on_exact_cold_clone': True,
        'unknown_mount_replayed': False, 'initialization_repeated': False,
        'cold_recovery_pairs': r3['cold_recovery_pairs_verified'], 'actual_cluster_id': r3['cluster_id'],
        'seed_archive': r3['seed_archive'], 'owned_processes_reaped': 4,
        'original_r1_r2_ciphertext_and_receipts_unchanged': True, 'production_boundary_unchanged': True,
        'local_tls_signal_component_tests': 13, 'live_http_budget_seconds': 12,
        'seed_storage_format': 'heptabao-state-records-v5',
        'promotion_sequence': 'r1 fresh V4; r2 mount response unknown; r3 reads exact cold clone as V5 with mount present, then new CAS0/CAS1 and unmount',
        'v6_activation_qualified_by_this_run': False, 'production_start_qualified': False,
        'split_share_custody_qualified': False, 'provider_credentials_qualified': False,
        'full_openbao_271_replacement_qualified': False, 'source_pins': pins,
    }
    output = E / 'recoverable-seed-root-review.public.json'
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'ok': True, 'review_sha256': sha(output.read_bytes()), 'checks': 66,
                      'requests': 40, 'pairs': 3, 'owned_processes_reaped': 4}))


if __name__ == '__main__':
    main()
