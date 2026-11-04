#!/usr/bin/env python3
"""Verify the additional two inventories and retain the four-host baseline."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
E = ROOT.parent
PROJECT = E.parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def native(path):
    value = read(path)
    assert value.get('isError') is not True
    return json.loads(next(c['text'] for c in value['content'] if c['type'] == 'text'))


def main():
    old_path = ROOT / 'root-review.public.json'
    assert sha(old_path) == '9070de4809e7f79388b8837bc7450e6e6da0cb70aea000f58c010c1a80b0a0a1'
    old = read(old_path)
    assert sha(PROJECT / 'tools/production/inventory_retirement_boundaries.py') == old['script_sha256']
    specs = {
        'desktop': ('1a1a72bccd9-fc05-2a72', 'b401226088d1255f6c041608f7f2270d696fb2e7b4645ab6f2727276f4120368', 29, 12),
        'ai395': ('1a1a72be711-fc05-2a75', 'd288a235bee7e4e98c368e2446981df15693604993994cbcc6f49f316a67f7a4', 0, 0),
    }
    added = []
    for host, (job, expected, services, backups) in specs.items():
        status = native(E / f'retirement-{host}-status.original-sdk.json')
        assert status == read(E / f'retirement-{host}-terminal.public.json')
        assert status['job_id'] == job and status['state'] == 'succeeded' and status['exit_code'] == 0
        for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'):
            assert status[key] is True
        for key in ('timed_out', 'automatic_retry', 'cancelled'):
            assert status[key] is False
        pages = [E / f'retirement-{host}-read0.original-sdk.json']
        if host == 'desktop':
            pages.append(E / 'retirement-desktop-read16384.original-sdk.json')
        body = b''
        for path in pages:
            page = native(path)
            assert page['job_id'] == job and page['stderr']['size'] == 0
            stream = page['stdout']
            chunk = bytes.fromhex(stream['bytes_hex'])
            assert stream['offset'] == len(body) and chunk.decode() == stream['text']
            body += chunk
            assert stream['next_offset'] == len(body)
        assert stream['eof'] and len(body) == stream['size'] == status['log_bytes']['stdout']['stored']
        assert body == (E / f'retirement-{host}-stdout.txt').read_bytes()
        assert hashlib.sha256(body).hexdigest() == expected
        report = json.loads(body)
        assert report == read(E / f'retirement-{host}-report.public.json')
        assert report['changes'] == [] and report['errors'] == []
        for key in ('credential_files_read', 'process_arguments_read', 'process_environment_read',
                    'complete_asset_inventory', 'all_clients_migrated', 'committed_backup_qualified',
                    'retirement_authorized_by_this_report'):
            assert report[key] is False
        assert len(report['service_files']) == services
        assert sum(len(p['selected']) for p in report['backup_path_candidates']) == backups
        entry = {
            'host': host, 'job': host + '/' + job, 'exit_code': 0, 'stdout_sha256': expected,
            'report_sha256': sha(E / f'retirement-{host}-report.public.json'),
            'service_path_candidates': services, 'nonrecursive_backup_path_candidates': backups,
            'configured_agent_ids': report.get('configured_agent_ids'),
            'authbus': report.get('authbus'), 'scope_errors': report['errors'],
            'docker_probe': report['docker_listing'],
        }
        if host == 'desktop':
            assert len(report['configured_agent_ids']) == 8
            assert report['client_config_metadata_stable']
            assert report['client_config']['sha256'] == '7dc5e5412ddc6da4977d44743261376e24c0d644dabd3b082c8c57f3647ed1d3'
            assert report['authbus']['enabled'] is True
            address = report['authbus']['address']
            assert address['scheme'] == 'https' and address['hostname'] == '127.0.0.1' and address['port'] == 18200
            rows = [r for p in report['manager_observations'] for r in p['matched_rows']]
            required = {
                'hepta-openbao-private-ci.service': 'running',
                'hepta-openbao-leaf-renewal.timer': 'waiting',
                'openclaw-gateway.service': 'running',
            }
            for unit, state in required.items():
                assert any(unit in r and 'active' in r and state in r for r in rows)
            entry['active_provider_gateway_and_renewal_observed'] = True
            entry['runtime_version_of_provider_qualified'] = False
        else:
            assert 'configured_agent_ids' not in report and 'authbus' not in report
            assert report['client_config'] == {'path': '/home/qq/.openclaw/openclaw.json', 'unavailable': 'FileNotFoundError'}
            entry['observed_client_config'] = report['client_config']
            entry['absence_scope'] = 'Only configured operator home, common paths and filtered manager observations; not a whole-machine absence proof.'
        added.append(entry)
    all_hosts = old['hosts'] + added
    report = {
        'schema': 'heptabao.root-reviewed-six-host-retirement-inventory.v1', 'ok': True,
        'reviewer_sha256': sha(Path(__file__)), 'prior_four_host_review_sha256': sha(old_path),
        'script_sha256': old['script_sha256'], 'hosts': all_hosts,
        'observed_physical_hosts': 6, 'mac_main_alias_deduplicated': True,
        'service_path_candidates': sum(h['service_path_candidates'] for h in all_hosts),
        'nonrecursive_backup_path_candidates': sum(h['nonrecursive_backup_path_candidates'] for h in all_hosts),
        'candidate_counts_are_not_service_or_backup_qualification_counts': True,
        'desktop_eight_agent_local_provider_migration_required': True,
        'preserve_openbao271_x230_oracle': True,
        'docker_listing_failed_hosts_not_claimed_empty': ['rog', 'pocket4'],
        'complete_asset_inventory': False, 'credential_values_read': False,
        'all_clients_migrated': False, 'all_backup_restore_paths_migrated': False,
        'retirement_qualified': False, 'old_installations_deleted': False, 'changes': [],
    }
    assert report['service_path_candidates'] == 53 and report['nonrecursive_backup_path_candidates'] == 91
    destination = ROOT / 'six-host-root-review.public.json'
    destination.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'ok': True, 'sha256': sha(destination), 'physical_hosts': 6,
                      'service_path_candidates': 53, 'backup_path_candidates': 91}))


if __name__ == '__main__':
    main()
