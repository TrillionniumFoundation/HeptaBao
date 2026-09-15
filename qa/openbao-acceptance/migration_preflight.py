#!/usr/bin/env python3
"""Observe migration prerequisites over verified HTTPS, without copying assets.

The collector sends only fixed GET/LIST requests. Audit writes and finite-token
consumption may still occur. It never proves a complete inventory, freezes a
writer, copies secrets, changes a consumer pin, or authorizes a cutover.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

from bao_http import BaoError, Client, SafeArgumentParser, digest, private_json, private_read, private_write
from capacity_live import validate_observation
from core_isolation import ScenarioFailure

CATALOGS = {
    'mounts': ('GET', '/v1/sys/mounts'),
    'auth': ('GET', '/v1/sys/auth'),
    'policies': ('LIST', '/v1/sys/policies/acl'),
    'entities': ('LIST', '/v1/identity/entity/id'),
    'groups': ('LIST', '/v1/identity/group/id'),
    'token_accessors': ('LIST', '/v1/auth/token/accessors'),
    'lease_prefixes': ('LIST', '/v1/sys/leases/lookup/'),
    'namespaces': ('LIST', '/v1/sys/namespaces'),
}
KNOWN_TYPES = {'kv', 'cubbyhole', 'identity', 'system', 'transit', 'pki', 'ssh',
               'database', 'totp', 'kubernetes', 'openldap', 'rabbitmq', 'token',
               'userpass', 'approle', 'jwt', 'oidc', 'ldap', 'cert', 'radius', 'kerberos'}
MAX_CATALOG_ITEMS = 10000


def require_private_new_output(path: Path) -> None:
    """Reject ambiguous output parents before any network access."""
    if not hasattr(os, 'geteuid') or not hasattr(os, 'O_NOFOLLOW'):
        raise BaoError('private_files_require_posix')
    if not path.is_absolute() or any(part == '..' for part in path.parts):
        raise BaoError('output_absolute_canonical_path_required')
    current = Path(path.anchor)
    for part in path.parent.parts[1:]:
        current /= part
        if current.is_symlink():
            raise BaoError('output_symlink_component_rejected')
    info = path.parent.stat()
    if not path.parent.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise BaoError('output_directory_requires_owner_only_mode')
    if os.path.lexists(path):
        raise BaoError('output_already_exists')


def _catalog(response, family: str) -> dict:
    # A 404 might mean an empty collection or an unimplemented route. Never
    # promote that ambiguity into an observed empty/complete inventory.
    if response.status != 200:
        return {'status': 'unobserved', 'http_status': response.status}
    data = response.data()
    if family in ('mounts', 'auth'):
        if not data or len(data) > MAX_CATALOG_ITEMS:
            raise BaoError('catalog_empty_or_oversized')
        counts = {}
        for item in data.values():
            if not isinstance(item, dict) or not isinstance(item.get('type'), str):
                raise BaoError('catalog_type_missing')
            name = item['type']
            # Arbitrary plugin names, mount paths and descriptions do not cross
            # the report boundary. Even safe-looking custom types are redacted.
            label = name if name in KNOWN_TYPES else 'other'
            counts[label] = counts.get(label, 0) + 1
        return {'status': 'observed', 'http_status': 200, 'count': len(data),
                'types': dict(sorted(counts.items()))}
    keys = data.get('keys')
    if (not isinstance(keys, list) or len(keys) > MAX_CATALOG_ITEMS
            or any(not isinstance(k, str) or not k or len(k) > 8192 for k in keys)
            or len(keys) != len(set(keys))):
        raise BaoError('catalog_keys_invalid')
    return {'status': 'observed', 'http_status': 200, 'count': len(keys),
            'recursive': False}


def collect(source: Client, target: Client, planned_additional_bytes: int | None = None) -> dict:
    if (planned_additional_bytes is not None
            and (type(planned_additional_bytes) is not int or not 0 <= planned_additional_bytes <= 2**63 - 1)):
        raise BaoError('invalid_capacity_estimate')
    left, right = source.health(), target.health()
    if source.address == target.address or left['cluster_id'] == right['cluster_id']:
        raise BaoError('same_endpoint_or_cluster_rejected')
    if left['version'] != '2.6.2' or not right['version'].startswith('HeptaBao-'):
        raise BaoError('migration_product_version_mismatch')
    report = {
        'schema': 'heptabao.migration-preflight.v1',
        'status': 'blocked_full_instance_migration',
        'source_binding': digest({'endpoint': source.address, 'namespace': source.namespace, **left}),
        'target_binding': digest({'endpoint': target.address, 'namespace': target.namespace, **right}),
        'source_version': left['version'], 'target_version': right['version'],
        'source_catalogs': {}, 'target_capacity': {'status': 'unobserved'},
        'planned_additional_bytes': planned_additional_bytes,
        'blockers': [], 'inventory_complete': False, 'source_writes_frozen': False,
        'atomic_cutover_proven': False, 'migration_authority': False,
        'independent_admission': False, 'hepta_consumer_requalified': False,
        'full_openbao_compatibility': False, 'read_methods_only': True,
        'read_requests_can_consume_token_uses_and_audit': True,
    }
    for family, (method, path) in CATALOGS.items():
        observation = _catalog(source.request(method, path), family)
        report['source_catalogs'][family] = observation
        if observation['status'] != 'observed':
            report['blockers'].append('catalog_unobserved:' + family)
    capacity_response = target.request('GET', '/v1/sys/internal/capacity')
    if capacity_response.status == 200:
        capacity = capacity_response.data()
        try:
            validate_observation(capacity)
        except ScenarioFailure:
            raise BaoError('target_capacity_invalid') from None
        if capacity.get('profile') != 'bounded-single-record-v1' or capacity.get('scope') != 'serving-leader-local':
            raise BaoError('target_capacity_profile_unknown')
        fields = ('state_bytes', 'state_limit_bytes', 'state_remaining_bytes', 'generation',
                  'retained_operations', 'operation_limit', 'operations_remaining',
                  'journal_bytes', 'journal_limit_bytes')
        report['target_capacity'] = {'status': 'observed', **{k: capacity[k] for k in fields},
                                     'admission_reserved': False}
        if capacity['operations_remaining'] == 0:
            report['blockers'].append('target_operation_identity_budget_exhausted')
        if planned_additional_bytes is not None and planned_additional_bytes > capacity['state_remaining_bytes']:
            report['blockers'].append('target_state_estimate_exceeds_current_capacity')
    else:
        report['target_capacity'] = {'status': 'unobserved', 'http_status': capacity_response.status}
        report['blockers'].append('target_capacity_unobserved')
    # Reading metadata does not establish a stable asset snapshot or a safe
    # serialization-size bound. Partial runtime engines are not import adapters.
    for label in ('transit', 'pki', 'ssh', 'database', 'totp', 'other'):
        if report['source_catalogs']['mounts'].get('types', {}).get(label, 0):
            report['blockers'].append('asset_adapter_not_qualified:' + label)
    report['blockers'].extend([
        'recursive_asset_inventory_and_version_history_missing',
        'capacity_estimate_not_serialized_admission_or_reservation',
        'source_freeze_and_single_writer_cutover_not_proven',
        'auth_identity_policy_and_active_lease_conversion_not_qualified',
        'rollback_and_external_revocation_reconciliation_not_qualified',
        'independent_migration_and_hepta_consumer_requalification_required',
    ])
    report['blockers'] = sorted(set(report['blockers']))
    return report


def client_from_config(value: dict) -> Client:
    required = {'address', 'ca_file', 'token_file', 'namespace'}
    if not isinstance(value, dict) or set(value) != required or any(not isinstance(v, str) for v in value.values()):
        raise BaoError('endpoint_config_invalid')
    for key in ('ca_file', 'token_file'):
        p = Path(value[key])
        if not p.is_absolute() or '..' in p.parts:
            raise BaoError('credential_path_absolute_required')
        current = Path(p.anchor)
        for part in p.parts[1:]:
            current /= part
            if current.is_symlink():
                raise BaoError('credential_symlink_component_rejected')
    token = private_read(value['token_file'], 8192).decode('ascii').strip()
    trust = private_read(value['ca_file'], 1024 * 1024)
    return Client(value['address'], value['ca_file'], token, value['namespace'], trusted_ca_pem=trust)


def main(argv=None) -> int:
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--allow-read', action='store_true')
    args = parser.parse_args(argv)
    if not args.allow_read:
        parser.error('explicit metadata read permission required')
    import json
    try:
        output = Path(args.output).absolute()
        require_private_new_output(output)
        config = private_json(args.config)
        if not isinstance(config, dict) or set(config) != {'source', 'target', 'planned_additional_bytes'}:
            raise BaoError('preflight_config_invalid')
        estimate = config['planned_additional_bytes']
        if estimate is not None and (type(estimate) is not int or not 0 <= estimate <= 2**63 - 1):
            raise BaoError('invalid_capacity_estimate')
        report = collect(client_from_config(config['source']), client_from_config(config['target']), estimate)
        private_write(output, report, replace=False)
        print(json.dumps({'status': report['status'], 'blocker_count': len(report['blockers']),
                          'migration_authority': False}))
        return 3  # Deliberately not a successful migration or a cutover permit.
    except (BaoError, OSError, UnicodeError, ValueError) as exc:
        reason = exc.code if isinstance(exc, BaoError) else type(exc).__name__
        print(json.dumps({'status': 'failed_preflight', 'reason': reason, 'migration_authority': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
