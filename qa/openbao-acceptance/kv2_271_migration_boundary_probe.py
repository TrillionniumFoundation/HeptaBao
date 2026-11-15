#!/usr/bin/env python3
"""Run the existing raw decoder on public synthetic, valid protobuf histories.

This is a local boundary reproduction. It never launches a server, sends an
HTTP request, changes decoder limits, or establishes OpenBao compatibility.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024

def load(name, relative):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def varint(value):
    raw = bytearray()
    while value > 127:
        raw.append((value & 127) | 128)
        value >>= 7
    raw.append(value)
    return bytes(raw)

def integer(field, value):
    return varint(field << 3) + varint(value)

def binary(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value

def synthetic_records(live_count, payload_bytes):
    """Two retired small versions plus N retained versions in one KV2 key."""
    root = 'logical/11111111-1111-4111-8111-111111111111/'
    key, salt = 'synthetic/history', b'public-fixture-salt'
    created = integer(1, 1792320000)
    deleted = integer(1, 1792320001)
    total = live_count + 2
    metadata = binary(1, key.encode())
    records = [(root + 'config', integer(1, total + 4)), (root + 'salt', salt)]
    for version in range(1, total + 1):
        destroyed = version == 2
        vm = binary(1, created)
        if version == 1:
            vm += binary(2, deleted)
        if destroyed:
            vm += integer(3, 1)
        metadata += binary(2, integer(1, version) + binary(2, vm))
        if destroyed:
            continue
        payload = {'version': version, 'payload': 'X' * (32 if version == 1 else payload_bytes)}
        data = json.dumps(payload, separators=(',', ':')).encode()
        record = binary(1, data) + binary(2, created)
        digest = hashlib.sha256(salt + (key + '|' + str(version)).encode()).hexdigest()
        records.append((root + 'versions/' + digest[:3] + '/' + digest[3:], record))
    metadata += integer(3, total) + integer(4, 1)
    metadata += binary(5, created) + binary(6, created) + integer(7, total + 4)
    records.append((root + 'metadata/public-fixture', metadata))
    return records

def probe():
    decoder = load('kv2_lossless_raw', 'tools/migration/kv2_lossless_raw.py')
    migration = load('openbao270_kv2_migrate', 'tools/migration/openbao270_kv2_migrate.py')
    decoder = sys.modules['kv2_lossless_raw']
    leaf = load('kv2_http_once', 'tools/migration/kv2_http_once.py')
    files = [Path(m.__file__) for m in (decoder, migration, leaf)]
    files += [ROOT / 'crates/heptabao-server/src/service_kv2_import.rs',
              ROOT / 'crates/heptabao-server/src/engine_kv2_import.rs']
    cases = []
    control = decoder.decode_records(synthetic_records(2, 512 * 1024))
    versions = control['entries']['synthetic/history']['versions']
    assert versions['1']['data']['payload'] == 'X' * 32
    assert versions['1']['deletion_time'] and not versions['1']['destroyed']
    assert versions['2']['data'] is None and versions['2']['destroyed']
    cases.append({'case': 'valid_small_raw_history_control', 'status': 'passed',
                  'retained_live_versions': 2, 'deleted_payload_retained': True,
                  'destroyed_payload_absent': True})
    records = synthetic_records(1, 2 * MIB)
    maximum = max(len(raw) for _, raw in records)
    try:
        decoder.decode_records(records)
    except decoder.DecodeError as error:
        assert str(error) == 'record bound'
        cases.append({'case': 'valid_2mib_record_rejected', 'status': 'reproduced',
                      'maximum_raw_record_bytes': maximum, 'error': str(error)})
    else:
        raise AssertionError('2 MiB blocker has changed; update this reproduction')
    records = synthetic_records(68, 512 * 1024)
    projected = decoder.decode_records(records)
    raw = decoder.dumps_lossless(projected).encode()
    assert sum(len(v['data']['payload']) for k, v in projected['entries']['synthetic/history']['versions'].items()
               if int(k) > 2) == 34 * MIB
    assert max(len(v) for _, v in records) < MIB
    try:
        migration.parse_json(raw, migration.MAX_BUNDLE)
    except decoder.DecodeError as error:
        assert str(error) == 'JSON byte bound'
        cases.append({'case': 'valid_34mib_small_record_bundle_rejected', 'status': 'reproduced',
                      'retained_payload_bytes': 34 * MIB, 'raw_total_bytes': sum(len(v) for _, v in records),
                      'maximum_raw_record_bytes': max(len(v) for _, v in records),
                      'bundle_bytes': len(raw), 'bundle_sha256': hashlib.sha256(raw).hexdigest(),
                      'decoder_completed': True, 'error': str(error)})
    else:
        raise AssertionError('34 MiB bundle blocker has changed; update this reproduction')
    engine = files[-1].read_text()
    service = files[-2].read_text()
    assert 'Backend::Kv2Native(_)' in engine
    assert '501,' in engine and 'native KV2 aggregate import requires a dedicated graph import writer' in engine
    assert 'crate::MAX_APPLICATION_STATE_BYTES' in service and 'crate::MAX_APPLICATION_STATE_BYTES' in engine
    return {
        'schema': 'heptabao.kv2-large-migration-boundary-reproduction.v1',
        'status': 'blockers_reproduced', 'two_process_migration_executed': False,
        'native_import_executed': False, 'server_501_basis': 'source_guard_not_live_response',
        'official_openbao_271_executed': False, 'production_authority': False,
        'source_file_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        'caps': {'raw_record_bytes': decoder.MAX_RECORD, 'raw_aggregate_bytes': decoder.MAX_TOTAL,
                 'bundle_bytes': migration.MAX_BUNDLE, 'migration_response_bytes': migration.MAX_RESPONSE,
                 'http_leaf_input_bytes': leaf.MAX_INPUT, 'http_leaf_response_bytes': leaf.MAX_RESPONSE},
        'native_import_guard': {'path': 'crates/heptabao-server/src/engine_kv2_import.rs',
                                'method': 'EngineState::stage_openbao_kv2_import',
                                'backend': 'Backend::Kv2Native', 'status': 501,
                                'message': 'native KV2 aggregate import requires a dedicated graph import writer'},
        'legacy_import_bounds': {'route': 'Service::kv2_import_route',
                                'limit_symbol': 'crate::MAX_APPLICATION_STATE_BYTES',
                                'checks': ['whole incoming bundle', 'whole staged EngineState']},
        'cases': cases,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = probe()
    with args.output.open('x') as out:
        json.dump(report, out, indent=2, sort_keys=True)
        out.write('\n')
    print(json.dumps({'status': report['status'], 'cases': len(report['cases']),
                      'two_process_migration_executed': False}))

if __name__ == '__main__':
    main()
