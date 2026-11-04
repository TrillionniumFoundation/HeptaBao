#!/usr/bin/env python3
"""Recompute the exact Mac-to-ROG seed proof, without reading any secret."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E = ROOT / 'qa/evidence/20261104'
R = E / 'cross-os-seed-r2'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def native(path):
    result = read(path)
    assert result.get('isError') is not True
    return json.loads(next(c['text'] for c in result['content'] if c['type'] == 'text'))


def terminal(path, job):
    value = native(path)
    assert value['job_id'] == job and value['state'] == 'succeeded' and value['exit_code'] == 0
    for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'):
        assert value[key] is True
    for key in ('cancelled', 'automatic_retry', 'timed_out'):
        assert value[key] is False
    return value


def main():
    pins = {
        'prepare_recoverable_seed.py': 'b7b14b6fcbf767d76873b215ce10119fe58beb50ec3fbd164b4925ceb188cfea',
        'recover_seed_linux.py': '908e477fbd2470b2f7824caee35841a508b4c4a5d3afc66c495cacc9a7264a65',
        'verify_seed_cross_os.py': '3357566596695c88e06fde82aab7b9ce09eb635b49c571cb17590c986bf104e8',
        'stage_cross_os_helpers.py': 'eaf63f498cd7e26e3e11b766e648939fb990082667f9e64db968ea61c93b2578',
    }
    for name, expected in pins.items():
        assert sha(ROOT / 'tools/production' / name) == expected, name
    report_pins = {
        'controller-result.public.json': '56b93b8f8a7021bc414152a526aff07958148678dd423d56c9d31aaa9084599e',
        'linux-result.public.json': '1534b4075dba60731f4b651ee4ca350a2e24625bd7a4feeea5ffd1d011d2e1ce',
        'direct-linux-result.public.json': '1534b4075dba60731f4b651ee4ca350a2e24625bd7a4feeea5ffd1d011d2e1ce',
        'identity-verified.public.json': '4f2ba4bebef9f34c27035ca1cfd8e70ea640e3a6c53bfb222ea3fb8dbff9d149',
        'linux-intent.public.json': '2637d8bf39c7b4098f7192f6be37732ebf96827b32df0fabfd1209ff4b67d430',
        'mac-intent.public.json': '3051546d860af802132da086a047ea30fe22b81ec26c928f4833a8c5d3b04b9c',
    }
    for name, expected in report_pins.items():
        assert sha(R / name) == expected, name
    for name in ('public-reports-read.original-sdk.json', 'direct-linux-reports.original-sdk.json',
                 'direct-mac-identity.original-sdk.json'):
        response = native(R / name)
        assert response['truncated'] is False
        for item in response['files']:
            raw = item['text'].encode()
            assert item['eof'] and len(raw) == item['size']
            assert hashlib.sha256(raw).hexdigest() == item['sha256']
            assert item['sha256'] in report_pins.values()
    stage_jobs = {'mac': '1a1a742f9db-fc05-2abe', 'rog': '1a1a743436b-fc05-2ac1'}
    stages = read(E / 'cross-os-seed-r2-stage-control.public.json')
    for host, job in stage_jobs.items():
        terminal(E / f'cross-os-seed-r2-stage-{host}-status.original-sdk.json', job)
        request = read(R / f'cross-os-seed-stage-{host}-r2-original-request.json')
        assert request['host'] == host and request['idempotency_key'] == stages[host]['idempotency_key']
        assert stages[host]['job_id'] == job and stages[host]['reused'] is False
        assert (ROOT / 'tools/production/stage_cross_os_helpers.py').read_text() in request['args']
        packet = json.loads(request['stdin'])
        output = json.loads((E / f'cross-os-seed-r2-stage-{host}-stdout.txt').read_bytes())
        assert packet['node'] == host and output['ok'] is True and output['service_started'] is False
        assert set(packet['files']) == set(output['pins'])
        for filename, content in packet['files'].items():
            assert hashlib.sha256(content.encode()).hexdigest() == output['pins'][filename]
            assert output['pins'][filename] in pins.values()
    live_job = '1a1a7467b63-fc05-2acc'
    terminal(R / 'live-status.original-sdk.json', live_job)
    start = native(R / 'live-start.original-sdk.json')
    request = read(R / 'cross-os-seed-r2-live-original-request.json')
    control = read(R / 'live-control.public.json')
    assert start['job']['id'] == control['job_id'] == live_job
    assert start['job']['host'] == request['host'] == control['host'] == 'mac'
    assert start['job']['idempotency_key'] == request['idempotency_key'] == control['idempotency_key']
    assert start['job']['request_digest'] == control['request_digest']
    assert start['reused'] is False and start['launch']['ok'] is True
    assert start['job']['args'] == request['args'] and start['job']['executable'] == request['executable']
    assert request['timeout_seconds'] == 360
    assert pins['verify_seed_cross_os.py'] in request['args'][-1]
    assert "exec(compile(raw,str(p),'exec')" in request['args'][-1]
    output = native(R / 'live-read.original-sdk.json')
    assert output['job_id'] == live_job and output['stdout']['eof'] and output['stderr']['size'] == 0
    stdout = bytes.fromhex(output['stdout']['bytes_hex'])
    assert stdout.decode() == output['stdout']['text'] and len(stdout) == 362
    summary = json.loads(stdout)
    assert summary['ok'] and summary['sha256'] == report_pins['controller-result.public.json']
    mac, linux = read(R / 'controller-result.public.json'), read(R / 'linux-result.public.json')
    identity = read(R / 'identity-verified.public.json')
    assert (R / 'linux-result.public.json').read_bytes() == (R / 'direct-linux-result.public.json').read_bytes()
    nonce = mac['nonce']
    assert all(v['nonce'] == nonce for v in (linux, identity, read(R / 'linux-intent.public.json'), read(R / 'mac-intent.public.json')))
    assert identity['ready'] and identity['uid'] == 1000
    assert identity['helper_sha256'] == mac['linux_receiver_sha256'] == linux['source_helper_sha256'] == pins['recover_seed_linux.py']
    assert identity['transport_sha256'] == mac['transport_source_sha256'] == linux['transport_source_sha256'] == pins['prepare_recoverable_seed.py']
    assert mac['remote_result_sha256'] == report_pins['linux-result.public.json']
    assert mac['remote_outcome'] == 'confirmed_success' and mac['remote_readonly_reconciliation_required'] is False
    assert mac['owned_ssh_stopped'] and mac['owned_ssh_returncode'] == 0
    assert mac['boundary_before'] == mac['boundary_after'] and linux['boundary_before'] == linux['boundary_after']
    assert mac['source_seed_verified_unchanged'] and mac['same_connection_identity_verified_before_secret_transfer']
    assert mac['receiver_executed_from_verified_source_bytes'] and linux['actual_same_directory_cold_restart']
    assert linux['source'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
    assert linux['tree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
    assert linux['binary_sha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
    assert linux['cluster_id'] == mac['actual_cluster_id'] == '0c56fad8-4061-349e-84a8-0a4cbc7ca12a'
    assert linux['archive_sha256'] == mac['source_archive_sha256'] == 'c50dbae852e748763038d0e0dcdfe2eae7dbc2a254f2b29642dec47c3117e64b'
    assert linux['source_mac_result_sha256'] == mac['source_result_sha256'] == 'ef640ced21b11be8cfd2dd8cac9342cff5cc0406e1ee17f0bb07cf85c37d7ecb'
    assert linux['secret_shares'] == 3 and linux['secret_threshold'] == 2
    assert linux['recovery_shares_received_in_memory'] == 2 and linux['recovery_shares_persisted_on_linux'] is False
    assert linux['ok'] and mac['ok'] and linux['all_owned_children_stopped']
    processes = linux['processes']
    assert len(processes) == 2 and len({p['pid'] for p in processes}) == 2
    assert all(p['name'] == 'restored' and p['stopped'] and p['owned_popen']
               and p['returncode'] == -15 and not p['forced_kill'] for p in processes)
    expected = [('GET', 'sys/seal-status', 200), ('POST', 'sys/unseal', 200),
                ('POST', 'sys/unseal', 200), ('GET', 'sys/health', 200),
                ('GET', 'auth/token/lookup-self', 200), ('GET', 'sys/internal/capacity', 200),
                ('GET', 'sys/mounts', 200), ('POST', 'sys/seal', 204)] * 2
    requests = linux['requests']
    assert len(requests) == len({v['nonce'] for v in requests}) == 16
    assert [(v['method'], v['path'], v['status']) for v in requests] == expected
    for item in requests:
        assert item['outcome'] == 'response_received' and item['replayed'] is False and item['http_seconds'] == 12
        assert item['complete_header_bytes'] > 0 and len(item['complete_header_sha256']) == 64
        assert item['status'] == item['observed_status']
        assert item['framing'] == ('status_204_header_boundary' if item['status'] == 204 else 'exact_content_length')
    checks = linux['checks']
    assert all(c['passed'] for c in checks) and len(checks) == len({c['case'] for c in checks})
    substantive = [c for c in checks if not c['case'].startswith('no_plaintext_secret_')]
    scans = len(checks) - len(substantive)
    assert len(substantive) == 20 and scans == 47
    for name in ('journal.hbj', 'seal.json', 'state.hbs'):
        assert linux['first_stopped_state_inventory'][name] == linux['final_stopped_state_inventory'][name]
    assert linux['first_stopped_state_inventory']['ledger.hbl'] != linux['final_stopped_state_inventory']['ledger.hbl']
    for key in ('initialization_repeated', 'j3160_contacted', 'production_start_qualified'):
        assert linux[key] is False and mac[key] is False
    for key in ('production_service_started', 'production_node_state_populated', 'native_v6_activated',
                'shares_distributed', 'split_custody_qualified', 'client_changed'):
        assert linux[key] is False
    for key in ('credentials_exported_to_control_plane', 'production_started', 'client_changed',
                'native_v6_qualification', 'full_34_mib_qualification', 'source_seed_modified', 'automatic_retry'):
        assert mac[key] is False
    report = {
        'schema': 'heptabao.root-review.mac-to-rog-seed-recovery.v1', 'ok': True,
        'reviewer_sha256': sha(Path(__file__)), 'source_pins': pins, 'public_report_pins': report_pins,
        'job': 'mac/' + live_job, 'stage_jobs': stage_jobs, 'terminal_exit': 0,
        'same_report_received_via_verified_ssh_and_direct_runtime_read': True,
        'source': linux['source'], 'tree': linux['tree'], 'linux_normal_binary_sha256': linux['binary_sha256'],
        'mac_normal_binary_sha256': mac['boundary_before']['binary_sha256'],
        'actual_cluster_id': linux['cluster_id'], 'source_archive_sha256': linux['archive_sha256'],
        'substantive_dynamic_checks': len(substantive), 'owned_file_plaintext_scan_checks': scans,
        'known_http_outcomes': 16, 'unknown_outcomes': 0, 'replayed_requests': 0,
        'actual_same_directory_cold_restart': True, 'owned_linux_servers_reaped': processes,
        'owned_ssh_returncode': 0, 'source_mac_seed_and_receipts_unchanged': True,
        'private_same_connection_identity_verified_before_transfer': True,
        'shares_received_in_linux_memory': 2, 'shares_persisted_on_linux': False,
        'scope': {'storage_format': 'V5 seed', 'native_v6': False, 'full_34_mib_dataset': False,
                  'new_unified_candidate': False, 'split_custody': False, 'production_start': False,
                  'production_client_change': False, 'full_openbao_271_replacement': False},
        'r1_source_stage_transport_unknown_preserved': True,
    }
    destination = R / 'root-review.public.json'
    destination.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'ok': True, 'root_review_sha256': sha(destination), 'http_outcomes': 16,
                      'substantive_checks': len(substantive), 'owned_file_scan_checks': scans}))


if __name__ == '__main__':
    main()
