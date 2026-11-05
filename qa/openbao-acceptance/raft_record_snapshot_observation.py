"""Inspect a synthetic format-3 Raft artifact without exporting stored content.

This validates framing, the typed descriptor graph and metadata. It does not
possess the server keys and cannot verify AEAD, HMAC IDs or plaintext key order.
The HA fixture separately requires the recovered voter to serve every value as
leader and compares each value with its pre-fault canonical hash.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
import stat
import zlib
from raft_snapshot_observation import MAGIC, MAX_ARTIFACT_BYTES

MIB = 1024 * 1024
MAX_APPLICATION_BYTES = 47 * MIB
MAX_OBJECTS = 131072
MAX_CHILDREN = 256
MAX_DEPTH = 18
KINDS = frozenset({'Block', 'Value', 'Leaf', 'Branch', 'OwnerChunk', 'PackedLeaf'})
REF_FIELDS = frozenset({'id', 'kind', 'encoded_bytes', 'record_count', 'payload_bytes'})
STATE_FIELDS = frozenset({'last_applied_log', 'last_membership', 'client_status', 'records_v5'})


class SnapshotPending(Exception):
    """No snapshot at the required frontier exists yet; not a corruption result."""


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def bounded_int(value, maximum, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def exact_fields(value, fields):
    return isinstance(value, dict) and set(value) == fields


def encoded_size(value):
    return sum(len(part.encode('utf-8')) for part in json.JSONEncoder(
        ensure_ascii=False, separators=(',', ':'), allow_nan=False).iterencode(value))


def strict_json(encoded):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'snapshot_duplicate_json_key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('snapshot_invalid_json_number')
    try:
        return json.loads(encoded, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError('snapshot_invalid_json') from None


def compact_bytes(value, limit):
    require(isinstance(value, str) and value.isascii() and '=' not in value
            and len(value) <= (limit * 4 + 2) // 3, 'snapshot_invalid_compact_encoding')
    try:
        decoded = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError('snapshot_invalid_compact_encoding') from None
    require(len(decoded) <= limit and base64.b64encode(decoded).decode().rstrip('=') == value,
            'snapshot_noncanonical_compact_encoding')
    return decoded


def object_id(value):
    require(isinstance(value, list) and len(value) == 32
            and all(bounded_int(byte, 255) for byte in value), 'record_invalid_id')
    return bytes(value).hex()


def reference(value):
    require(exact_fields(value, REF_FIELDS), 'record_invalid_reference_fields')
    ident = object_id(value['id'])
    require(isinstance(value['kind'], str) and value['kind'] in KINDS and bounded_int(value['encoded_bytes'], MIB, 25)
            and bounded_int(value['record_count'], 2**64 - 1)
            and bounded_int(value['payload_bytes'], 2**64 - 1), 'record_invalid_reference')
    return ident


def envelope(value):
    require(isinstance(value, str) and value.isascii() and value.startswith('hbr3:'),
            'record_invalid_envelope')
    length, separator, rest = value[5:].partition(':')
    require(bool(separator) and re.fullmatch(r'[0-9]{1,3}', length) is not None
            and 1 <= int(length) <= 128, 'record_invalid_envelope')
    size = int(length)
    operation, suffix = rest[:size], rest[size:]
    require(re.fullmatch(r'[a-zA-Z0-9_.:\-]{1,128}', operation) is not None and suffix.startswith(':'),
            'record_invalid_envelope')
    digest, separator, sealed = suffix[1:].partition(':')
    require(bool(separator) and re.fullmatch(r'[0-9a-f]{64}', digest) is not None
            and digest != '0' * 64 and bool(compact_bytes(sealed, MIB)), 'record_invalid_envelope')


def legacy_status_digest(status):
    require(isinstance(status, str) and status.isascii(), 'prepared_invalid_status')
    if status.startswith(('hbr2:', 'hbr3:')):
        version = status[:5]
        length, separator, rest = status[5:].partition(':')
        require(bool(separator) and re.fullmatch(r'[0-9]+', length) is not None, 'prepared_invalid_status')
        significant = length.lstrip('0')
        require(0 < len(significant) <= 3 and 1 <= int(significant) <= 128, 'prepared_invalid_status')
        size = int(significant); operation, suffix = rest[:size], rest[size:]
        require(suffix.startswith(':'), 'prepared_invalid_status')
        digest, separator, sealed = suffix[1:].partition(':')
        require(bool(separator), 'prepared_invalid_status')
    elif status.startswith('hbr1:'):
        version = 'hbr1:'; parts = status[5:].split(':')
        require(len(parts) == 3, 'prepared_invalid_status')
        operation, digest, sealed = parts
    else:
        raise ValueError('prepared_invalid_status')
    require(re.fullmatch(r'[a-zA-Z0-9_.:\-]{1,128}', operation) is not None
            and re.fullmatch(r'[0-9a-fA-F]{64}', digest) is not None and digest != '0'*64,
            'prepared_invalid_status')
    if version == 'hbr3:':
        require(bool(compact_bytes(sealed, MIB)), 'prepared_invalid_status')
    else:
        require(0 < len(sealed) <= 2*MIB and len(sealed) % 2 == 0
                and re.fullmatch(r'[0-9a-fA-F]+', sealed) is not None, 'prepared_invalid_status')
    return digest.lower()


def log_index(log):
    require(isinstance(log, dict) and bounded_int(log.get('index'), 2**64 - 1),
            'snapshot_invalid_log_index')
    return log['index']


def inspect_state(state):
    require(exact_fields(state, STATE_FIELDS), 'record_state_fields_mismatch')
    log_index(state['last_applied_log'])
    require(isinstance(state['last_membership'], dict)
            and encoded_size([state['last_applied_log'], state['last_membership']]) <= MIB - 1024,
            'record_metadata_budget_exceeded')
    statuses = state['client_status']
    require(isinstance(statuses, dict) and all(isinstance(k, str) and isinstance(v, str)
            for k, v in statuses.items()), 'record_invalid_legacy_statuses')
    legacy_bytes = 2 + sum(encoded_size(k) + encoded_size(v) + 2 for k, v in statuses.items())
    record = state['records_v5']
    require(isinstance(record, dict) and set(record) in (
        {'objects', 'published'}, {'objects', 'published', 'legacy_migration_prepared'}),
        'record_state_invalid_fields')
    objects, published = record['objects'], record['published']
    prepared = record.get('legacy_migration_prepared')
    if prepared is not None:
        require(exact_fields(prepared, {'digest', 'status_sha256'}) and published is None,
                'prepared_invalid_identity')
        expected_digest = object_id(prepared['digest'])
        expected_status = object_id(prepared['status_sha256'])
        require(expected_digest != '0'*64 and expected_status != '0'*64, 'prepared_zero_identity')
        legacy_status = statuses.get('heptabao-production-ha')
        require(legacy_status_digest(legacy_status) == expected_digest
                and hashlib.sha256(legacy_status.encode()).hexdigest() == expected_status,
                'prepared_legacy_identity_mismatch')
    require(isinstance(objects, dict) and len(objects) <= MAX_OBJECTS, 'record_object_count_exceeded')
    direct = []
    if published is not None:
        require(exact_fields(published, {'base', 'envelope', 'direct_refs'}), 'record_publication_invalid')
        base = published['base']
        if base != 'Empty':
            require(isinstance(base, dict) and len(base) == 1 and next(iter(base)) in ('Legacy', 'RecordsV5'),
                    'record_invalid_publication_base')
            object_id(next(iter(base.values())))
        envelope(published['envelope'])
        direct = published['direct_refs']
        require(isinstance(direct, list) and len(direct) <= MAX_CHILDREN
                and encoded_size(published) + 128 <= MIB, 'record_publication_bound_exceeded')
        for child in direct:
            reference(child)
            require(child['kind'] in ('OwnerChunk', 'Leaf', 'PackedLeaf', 'Branch'), 'record_invalid_direct_kind')
    charged = 128 + encoded_size(published) + encoded_size(prepared) + legacy_bytes
    sealed_total = 0
    for key, item in objects.items():
        require(isinstance(key, str) and re.fullmatch(r'[0-9a-f]{64}', key) is not None
                and exact_fields(item, {'reference', 'children', 'sealed'}), 'record_invalid_object_fields')
        ref, children = item['reference'], item['children']
        require(reference(ref) == key, 'record_object_id_mismatch')
        require(isinstance(children, list) and len(children) <= MAX_CHILDREN, 'record_children_bound_exceeded')
        for child in children: reference(child)
        raw = compact_bytes(item['sealed'], MIB)
        require(0 < len(raw) <= ref['encoded_bytes'] + 256, 'record_ciphertext_size_invalid')
        sealed_total += len(raw)
        child_records = sum(child['record_count'] for child in children)
        child_payload = sum(child['payload_bytes'] for child in children)
        require(child_records <= 2**64 - 1 and child_payload <= 2**64 - 1,
                'record_aggregate_overflow')
        kind = ref['kind']
        if kind in ('Block', 'OwnerChunk'):
            valid = (not children and ref['record_count'] == 0 and ref['payload_bytes'] <= 256 * 1024
                     and ref['encoded_bytes'] == 25 + ref['payload_bytes'])
        elif kind == 'Value':
            valid = (len(children) <= 64 and ref['record_count'] == 1 and ref['payload_bytes'] <= 16 * MIB
                     and all(c['kind'] == 'Block' for c in children) and child_payload == ref['payload_bytes']
                     and ref['encoded_bytes'] == 27 + 53 * len(children))
        elif kind == 'PackedLeaf':
            # Structural metadata only: ciphertext does not prove plaintext
            # entry order, value bytes or application authentication.
            inline_count = ref['record_count'] - child_records
            inline_payload = ref['payload_bytes'] - child_payload
            valid = (27 <= ref['encoded_bytes'] <= 32 * 1024
                     and 1 <= ref['record_count'] <= 256
                     and all(c['kind'] == 'Value' and c['record_count'] == 1 for c in children)
                     and 1 <= inline_count <= 256
                     and 0 <= inline_payload <= inline_count * 1024
                     and inline_payload <= ref['encoded_bytes'] - 27)
        else:
            valid = (bool(children) and ref['encoded_bytes'] <= 32 * 1024
                     and child_records == ref['record_count'] and child_payload == ref['payload_bytes']
                     and (all(c['kind'] == 'Value' for c in children) if kind == 'Leaf' else
                          (all(c['kind'] == 'Branch' for c in children)
                           or all(c['kind'] in ('Leaf', 'PackedLeaf') for c in children))))
        require(valid, 'record_kind_or_aggregate_mismatch')
        item_bytes = encoded_size(item)
        require(item_bytes + 128 <= MIB, 'record_proposal_budget_exceeded')
        charged += encoded_size(key) + item_bytes + 2
        require(charged <= MAX_APPLICATION_BYTES, 'record_application_budget_exceeded')
    def dependency(ref):
        key = reference(ref)
        require(key in objects and objects[key]['reference'] == ref, 'record_dependency_mismatch')
        return key
    for child in direct: dependency(child)
    depths, active = {}, set()
    def depth(key, level=1):
        require(level <= MAX_DEPTH, 'record_graph_depth_exceeded')
        if key in depths: return depths[key]
        require(key not in active, 'record_graph_cycle')
        active.add(key)
        result = 1 + max((depth(dependency(child), level + 1) for child in objects[key]['children']), default=0)
        require(result <= MAX_DEPTH, 'record_graph_depth_exceeded')
        active.remove(key); depths[key] = result
        return result
    for key in objects: depth(key)
    require(charged <= MAX_APPLICATION_BYTES or (prepared is not None and not objects and published is None),
            'record_application_budget_exceeded')
    reachable, pending = set(), [dependency(child) for child in direct]
    while pending:
        key = pending.pop()
        if key in reachable: continue
        reachable.add(key)
        pending.extend(dependency(child) for child in objects[key]['children'])
    return {'publication_present': published is not None, 'legacy_migration_prepared': prepared is not None, 'object_count': len(objects), 'reachable_object_count': len(reachable),
            'staged_unreachable_object_count': len(objects) - len(reachable),
            'maximum_graph_depth': max(depths.values(), default=0), 'ciphertext_bytes': sealed_total,
            'charged_application_bytes': charged, 'application_byte_limit': MAX_APPLICATION_BYTES,
            'published_direct_ref_count': len(direct),
            'published_record_count': sum(c['record_count'] for c in direct if c['kind'] != 'OwnerChunk'),
            'published_payload_bytes': sum(c['payload_bytes'] for c in direct if c['kind'] != 'OwnerChunk')}


def inspect_record_bundle(path: Path, *, minimum_index: int) -> dict:
    require(bounded_int(minimum_index, 2**64 - 1), 'snapshot_invalid_required_frontier')
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= MAX_ARTIFACT_BYTES,
            'snapshot_artifact_not_bounded_regular_file')
    with path.open('rb') as stream: encoded = stream.read(MAX_ARTIFACT_BYTES + 1)
    require(20 <= len(encoded) <= MAX_ARTIFACT_BYTES and encoded[:8] == MAGIC, 'snapshot_artifact_bad_frame')
    payload = encoded[16:-4]
    require(int.from_bytes(encoded[8:16], 'little') == len(payload), 'snapshot_artifact_bad_length')
    require(int.from_bytes(encoded[-4:], 'little') == zlib.crc32(payload), 'snapshot_artifact_bad_checksum')
    bundle = strict_json(payload)
    require(isinstance(bundle, dict) and bounded_int(bundle.get('format_version'), 3, 1)
            and bounded_int(bundle.get('generation'), 2**64 - 1, 1)
            and bounded_int(bundle.get('journal_format', 0), 1), 'snapshot_bundle_header_invalid')
    state = bundle.get('state')
    require(isinstance(state, dict), 'snapshot_bundle_state_invalid')
    current = inspect_state(state) if bundle['format_version'] == 3 else None
    if current is None:
        require('records_v5' not in state, 'snapshot_missing_bundle_version_fence')
    snapshot = bundle.get('current_snapshot')
    if snapshot is None: raise SnapshotPending('snapshot_not_created')
    require(isinstance(snapshot, dict) and isinstance(snapshot.get('meta'), dict), 'snapshot_invalid_metadata')
    meta = snapshot['meta']; index = log_index(meta.get('last_log_id'))
    require(log_index(state.get('last_applied_log')) >= index, 'snapshot_newer_than_bundle_state')
    data = snapshot.get('data')
    if isinstance(data, list):
        require(bundle['format_version'] in (1, 3) and len(data) <= MAX_ARTIFACT_BYTES
                and all(bounded_int(v, 255) for v in data), 'snapshot_invalid_legacy_encoding')
        decoded = bytes(data)
    else:
        require(bundle['format_version'] != 1, 'snapshot_invalid_bundle_encoding')
        decoded = compact_bytes(data, MAX_ARTIFACT_BYTES)
    wrapper = strict_json(decoded)
    require(isinstance(wrapper, dict), 'snapshot_state_not_object')
    typed = 'format_version' in wrapper
    if typed:
        require(exact_fields(wrapper, {'format_version', 'state'}) and type(wrapper['format_version']) is int
                and wrapper['format_version'] == 3 and current is not None and isinstance(data, str),
                'snapshot_missing_typed_version_fence')
        snapshot_state = wrapper['state']; snapshot_graph = inspect_state(snapshot_state)
    else:
        snapshot_state, snapshot_graph = wrapper, None
        require('records_v5' not in snapshot_state, 'snapshot_missing_typed_version_fence')
    require(snapshot_state.get('last_applied_log') == meta.get('last_log_id')
            and snapshot_state.get('last_membership') == meta.get('last_membership'), 'snapshot_metadata_mismatch')
    if index < minimum_index: raise SnapshotPending('snapshot_before_required_frontier')
    require(current is not None and snapshot_graph is not None, 'required_snapshot_is_not_typed_records')
    require(current['publication_present'] and snapshot_graph['publication_present'],
            'required_snapshot_has_no_published_root')
    return {'format_version': 3, 'snapshot_wire_format': 3, 'snapshot_index': index,
            'artifact_bytes': len(encoded), 'artifact_sha256': hashlib.sha256(encoded).hexdigest(),
            'snapshot_bytes': len(decoded), 'canonical_representation': True, 'checksum_verified': True,
            'metadata_matches_snapshot': True, 'current_state': current, 'snapshot_state': snapshot_graph,
            'cryptographic_authenticity_verified': False, 'plaintext_key_order_verified': False}
