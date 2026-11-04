#!/usr/bin/env python3
"""Review immutable public receipts only. Never contacts or mutates a node."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[3]
SOURCE = '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE = 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(name):
    return json.loads((ROOT / name).read_bytes())


pins = read('readback-pins.public.json')
for pin in pins:
    assert sha((ROOT / pin['name']).read_bytes()) == pin['sha256'], pin['name']
cohort = read('mac-result.public.json')
terminal = read('cohort-terminal-status.public.json')
assert terminal['job_id'] == '1a1a691e2c2-fc05-2707'
assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
assert terminal['timed_out'] is False and terminal['automatic_retry'] is False
assert cohort['ok'] and cohort['source_commit'] == SOURCE and cohort['source_tree'] == TREE
assert cohort['identity_before_key_transfer_verified'] is True and len(cohort['peers']) == 3
assert cohort['replication_key_sha256'] == 'db454a095add7561be656adc01494fb3748080b94a00e0f3a320b6cdceff54a7'
assert all(cohort[k] is False for k in ['service_started', 'service_loaded', 'seed_initialized',
                                      'activation_created', 'traffic_cutover', 'ca_key_exported',
                                      'node_private_keys_exported', 'firewall_or_routing_changed'])
for host, node_id in [('rog', 2), ('pocket4', 3)]:
    peer = read(host + '-cohort-prepared.public.json')
    certificate = read(host + '-certificates-installed.public.json')
    correction = read(host + '-state-path-correction.public.json')
    service = read(host + '-service-prepared.public.json')
    handshake = read('mac-' + host + '-identity-verified.public.json')
    assert peer['source_commit'] == SOURCE and peer['source_tree'] == TREE
    assert peer['cluster_id'] == cohort['cluster_id'] == service['cluster_id']
    assert peer['node_id'] == node_id and peer['identity_before_key_transfer_verified'] is True
    assert sha((ROOT / (host + '-cohort-prepared.public.json')).read_bytes()) == cohort['linux_receipts'][host]['receipt_sha256']
    assert peer['files'] == cohort['linux_receipts'][host]['files']
    assert peer['files']['tls/replication.key'] == cohort['replication_key_sha256']
    assert peer['files']['control/peer-registry.private.json'] == cohort['mac_files']['control/peer-registry.private.json']
    assert cohort['peers'][str(node_id)]['certificate_sha256'] == certificate['certificate_der_sha256']
    assert certificate['chain_server_client_san_verified'] and certificate['local_private_key_matches']
    assert correction['ok'] and correction['old_config_preserved'] and correction['initialized_data_present'] is False
    assert handshake['ready'] is True and handshake['node_id'] == node_id and handshake['uid'] == 1000
    assert handshake['hostname'] == peer['hostname'] and handshake['root'] == peer['root']
    for field, filename in [('prepared_sha256', host + '-prepared-csr.public.json'),
                            ('certificate_receipt_sha256', host + '-certificates-installed.public.json'),
                            ('repair_receipt_sha256', host + '-state-path-correction.public.json')]:
        assert handshake[field] == sha((ROOT / filename).read_bytes())
    assert service['ok'] and service['exact_guard_check_passed'] and service['systemd_analyze_user_verify_passed']
    assert service['missing_activation_serve_refused'] is True
    assert service['cohort_receipt_sha256'] == cohort['linux_receipts'][host]['receipt_sha256']
    assert service['script_sha256'] == sha((REPOSITORY / 'tools/production/prepare_linux_node_service.py').read_bytes())
    assert service['guard_sha256'] == sha((REPOSITORY / 'tools/production/heptabao_linux_node_start.py').read_bytes())
    assert all(service[k] is False for k in ['service_loaded', 'service_started', 'seed_initialized',
                                           'activation_created', 'traffic_cutover', 'production_client_changed'])
mac = read('mac-state-path-correction.public.json')
assert mac['ok'] and mac['actual_plist_lint_and_guard_check'] and mac['python_codesign_strict_verified']
assert mac['shared_homebrew_installation_modified'] is False
assert mac['python_original_expected_sha256'] != mac['python_original_observed_sha256']
assert mac['python_replacement_sha256'] == '7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
assert sha((ROOT / 'executed_prepare_linux_node_stage_r1.py').read_bytes()) == 'bf2227937626aaa8efa3738afdb1c63c59b9ed198e4345b9eb58230e3c07fce6'
report = {
    'schema': 'heptabao.root-review.offline-three-node-preparation.v1', 'ok': True,
    'source_commit': SOURCE, 'source_tree': TREE, 'cluster_id_prepared': cohort['cluster_id'],
    'verified_public_readback_files': len(pins), 'physical_hosts': ['mac', 'rog', 'pocket4'],
    'three_native_state_paths_corrected': True, 'same_connection_identity_before_key_release': True,
    'private_keys_exported': False, 'actual_mac_guard_and_plist_checked': True,
    'actual_linux_guards_and_systemd_templates_checked': True, 'linux_missing_activation_serve_refused': True,
    'shared_homebrew_installation_modified': False, 'seed_initialized': False, 'service_started': False,
    'cohort_cluster_id_bound_to_initialized_seed': False, 'production_clients_switched': False,
    'full_openbao_271_replacement_qualified': False, 'old_installations_deleted': False,
}
(ROOT / 'root-review.public.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps(report, sort_keys=True))
