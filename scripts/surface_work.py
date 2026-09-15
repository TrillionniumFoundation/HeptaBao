#!/usr/bin/env python3
"""Validate or inspect per-surface work. Existing profile executables remain owners.

This tool does not grant admission, run a shell, or turn an available fixture into
whole-surface completion. Exit 0 validates the work inventory only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'planning/HEPTABAO_SURFACE_WORK_V1.json'
FIELDS = {'api_or_protocol', 'required_positive_and_hostile_behavior', 'remaining_semantics_and_effect_checks',
          'crash_reopen', 'isolation', 'migration_upgrade'}
EVIDENCE = {'positive_and_hostile_behavior', 'side_effect_readback', 'crash_reopen',
            'namespace_and_authority_isolation', 'format_upgrade_or_explicit_migration',
            'exact_head_and_prospective_merge', 'independent_admission'}


def read_json(path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    return json.loads(path.read_text(), object_pairs_hook=unique)


def source_path(root, value):
    if not isinstance(value, str) or Path(value).is_absolute() or '..' in Path(value).parts:
        raise ValueError('source path outside repository')
    path = root / value
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents) if p != root.parent):
        raise ValueError('source must be an existing nonsymlink file')
    return path


def validate(root=ROOT):
    errors = []
    try:
        doc = read_json(root / MANIFEST)
        if (doc['schema'] != 'heptabao.surface-work.v1' or doc['target'] != 'OpenBao 2.6.2'
                or doc['subordinate_to'] != 'HEPTABAO-PLAN-2026-09-07-V2.1'
                or doc['compatibility_claim'] is not False or doc['production_authority'] is not False):
            raise ValueError('invalid work scope or self-issued claim')
        if set(doc['required_completion_evidence']) != EVIDENCE or len(doc['required_completion_evidence']) != len(EVIDENCE):
            raise ValueError('completion evidence dimensions missing or duplicated')
        if doc['corpus_path'] != 'qa/openbao-acceptance/complete_surface_corpus_v1.json':
            raise ValueError('corpus may not be substituted')
        path = source_path(root, doc['corpus_path'])
        if hashlib.sha256(path.read_bytes()).hexdigest() != doc['corpus_sha256']:
            raise ValueError('work inventory must be reviewed after corpus changes')
        corpus = read_json(path)
        expected = {s['surface_id']: s for s in corpus['surfaces']}
        rows = doc['surfaces']
        ids = [s['surface_id'] for s in rows]
        if len(ids) != len(set(ids)) or set(ids) != set(expected):
            raise ValueError('surface denominator missing, duplicated or expanded')
        profiles = doc['profile_definitions']
        for name, profile in profiles.items():
            if profile['scope'] != 'repository_controlled_bounded_profile_not_whole_surface':
                raise ValueError('profile scope inflated')
            source_path(root, profile['script'])
            if not isinstance(profile['arguments'], list) or any(not isinstance(arg, str) for arg in profile['arguments']):
                raise ValueError('invalid typed profile argv')
        for row in rows:
            original = expected[row['surface_id']]
            if row['category'] != original['category'] or row['fixture_case_ids'] != original['fixture_case_ids']:
                raise ValueError('work catalog cannot change fixed fixture bindings')
            if row['whole_surface_admitted'] is not False:
                raise ValueError('work catalog cannot self-admit a surface')
            if row['implementation_status'] not in ('runtime_partial', 'tooling_partial', 'not_implemented'):
                raise ValueError('unrecognized implementation status')
            if set(row['technical_contract']) != FIELDS or any(not isinstance(v, str) or len(v.strip()) < 20 for v in row['technical_contract'].values()):
                raise ValueError('missing per-surface technical contract')
            names = row['available_scoped_profiles']
            if len(names) != len(set(names)) or not set(names) <= set(profiles):
                raise ValueError('duplicate or missing executable profile')
            if row['runtime_source'] is not None:
                source_path(root, row['runtime_source'])
            if row['implementation_status'] == 'runtime_partial' and row['runtime_source'] is None:
                raise ValueError('runtime claim needs current source owner')
    except (OSError, ValueError, TypeError, KeyError) as error:
        errors.append('surface work: ' + str(error))
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--surface', help='Exact HB-SURFACE identifier to inspect')
    args = parser.parse_args(argv)
    errors = validate()
    if errors:
        print('\n'.join(errors))
        return 1
    doc = read_json(ROOT / MANIFEST)
    if args.surface:
        matches = [r for r in doc['surfaces'] if r['surface_id'] == args.surface]
        if not matches:
            parser.error('unknown surface ID')
        result = {'surface': matches[0], 'profiles': {name: doc['profile_definitions'][name] for name in matches[0]['available_scoped_profiles']}}
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps({'status': 'valid_work_inventory_not_completion', 'surface_count': len(doc['surfaces']),
                          'available_profiles': len(doc['profile_definitions']), 'compatibility_claim': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
