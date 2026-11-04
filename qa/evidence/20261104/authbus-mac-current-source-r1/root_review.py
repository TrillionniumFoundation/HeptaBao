#!/usr/bin/env python3
"""Verify the full public Mac real-source chain and its precise qualification scope."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
E = ROOT / 'evidence'
R = E / 'raw'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def main():
    review = E / 'agent-review.public.json'
    expected = 'a1f6db158dea1c8ae7324a2fc025923b98f90b6471051bdb50a339344ec1c509'
    assert sha(review) == expected
    completed = subprocess.run([sys.executable, str(ROOT / 'review_evidence.py')],
                               capture_output=True, text=True, check=True, timeout=30)
    assert not completed.stderr and json.loads(completed.stdout)['ok'] is True
    assert sha(review) == expected
    agent = read(review)
    stage = read(R / 'stage.public.json')
    root = stage['root']
    packet = read(ROOT / 'stage-input.json')
    assert packet['root'] == root and len(packet['copies']) == 8
    verified_sources = {}
    for item in packet['copies']:
        local = ROOT / 'original' / Path(item['target']).name
        assert sha(local) == item['sha256'] == stage['pins'][root + '/' + item['target']]
        verified_sources[str(local.relative_to(ROOT))] = item['sha256']
    for target, content in packet['embedded'].items():
        # The packet stores exact source text, never initialization or provider secrets.
        assert isinstance(content, str)
        pin = hashlib.sha256(content.encode()).hexdigest()
        assert pin == stage['pins'][root + '/' + target]
        if target == 'controller.py':
            assert (ROOT / 'controller.py').read_text() == content
        elif target == 'scripts/authbus_current_stage_custody.py':
            assert (ROOT / 'custody.py').read_text() == content
        verified_sources['embedded:' + target] = pin
    original_custody = (ROOT / 'original/authbus_current_stage_custody.py').read_text().splitlines()
    used_custody = (ROOT / 'custody.py').read_text().splitlines()
    assert original_custody[3:] == used_custody[4:]
    assert used_custody[2] == 'root=Path(sys.argv[1])'
    assert "root.parent.name == 'authbus-current-source-61ff8bef-20261104-r1'" in used_custody[3]
    driver = (ROOT / 'original/authbus_current_credential_stage.py').read_text()
    assert "WHERE ' + key + '=?', ('primary',)" in driver
    addendum = read(E / 'scope-addendum.public.json')
    assert addendum['capturedExpiredOAuthProfileRecords'] == 12
    for key in ('nonPrimaryAuthRowsQualified', 'otherDatabaseTablesQualified',
                'completeDatabaseBackupRecoveryQualified', 'uniqueProviderAccountsCountQualified',
                'providerCredentialValidityFromRowMigrationQualified', 'freshProviderRequestPerformed',
                'productionGatewayRecoveryQualified'):
        assert addendum[key] is False
    archive = E / 'complete-public-evidence-r1.tar.gz'
    assert sha(archive) == '8d8f43cafa85271c609fbfb5385b0f01e2839d1d611a18183396ea33a654158b'
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        assert len(members) == 15 and len({m.name for m in members}) == 15
        assert {m.name for m in members} == {str(p.relative_to(R)) for p in R.rglob('*') if p.is_file()}
        for member in members:
            path = Path(member.name)
            assert member.isfile() and not path.is_absolute() and '..' not in path.parts
            raw = package.extractfile(member).read()
            assert len(raw) == member.size and raw == (R / path).read_bytes()
    control = read(E / 'durable-control-evidence.public.json')
    start = json.loads(control['liveStart']['content'][0]['text'])
    assert start['job']['id'] == agent['liveJob'] == '1a1a6eccc77-fc05-2986'
    assert start['job']['host'] == 'mac' and start['reused'] is False
    assert control['liveStatus'] == read(E / 'terminal-status.public.json')
    outer = read(R / 'result.public.json')
    assert outer['sourcePins'] == stage['pins'] and len(stage['pins']) == 52
    assert sum(agent['assertions'].values()) == 330
    selector = read(R / 'native-profile2-selector-r1/result.public.json')
    assert selector['sourceNativeSha256'] != selector['selectedCredentialSha256']
    assert selector['providerReadPerformedThisRun'] is False
    assert selector['singleCurrentAccountValidated'] is False
    assert selector['actualBridgeProviderReady'] is False
    report = {
        'schema': 'heptabao.root-review.mac-real-source-authbus.v1', 'ok': True,
        'job': 'mac/' + agent['liveJob'], 'terminal_exit': 0,
        'source': agent['sourceCommit'], 'tree': agent['sourceTree'], 'binary_sha256': agent['binarySha256'],
        'dynamic_assertions': 330, 'phase_assertions': agent['assertions'],
        'public_raw_files': 14, 'archive_members_with_manifest': 15,
        'complete_public_archive_sha256': sha(archive), 'agent_review_sha256': expected,
        'executed_source_files_locally_verified': verified_sources,
        'runtime_source_pins_checked_by_actual_controller': 52,
        'actual_current_primary_auth_row_migration': True, 'configured_agents': 5,
        'oauth_profile_records': 12, 'expired_oauth_profile_records': 12,
        'provider_validity_proven_from_these_rows': False, 'unique_account_count_proven': False,
        'native_file_sha256': selector['sourceNativeSha256'],
        'selected_credential_sha256': selector['selectedCredentialSha256'],
        'installed_sdk_default_resolver_on_private_native_profile2_copy': True,
        'complete_sdk_logical_store_rollbacks': 2, 'whole_database_backup_recovery': False,
        'actual_server_process_cold_restart': True, 'os_service_manager_restart_this_run': False,
        'prior_provider_generation_exactly_linked': True, 'fresh_provider_read': False,
        'provider_refresh': False, 'new_provider_login': False, 'model_request': False,
        'production_bridge_ready': False, 'bridge_guard': 'geoip_disagreement',
        'exact_selector_runtime_options_refused': True,
        'production_gateway_selection_qualified': False, 'production_traffic_rollback_qualified': False,
        'production_files_and_relays_unchanged': True, 'all_owned_servers_stopped': True,
        'j3160_contacted': False, 'full_openbao_271_replacement_qualified': False,
    }
    output = ROOT / 'root-review.public.json'
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'ok': True, 'sha256': sha(output), 'dynamic_assertions': 330,
                      'public_archive_members': 15, 'local_executed_source_pins': len(verified_sources)}))


if __name__ == '__main__':
    main()
