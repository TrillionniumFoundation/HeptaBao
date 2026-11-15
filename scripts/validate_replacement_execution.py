#!/usr/bin/env python3
"""Validate/render the existing plan's per-surface execution requirements.

This is a source/navigation drift check, not execution or independent admission.
"""
from __future__ import annotations

import argparse
import json
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = 'planning/HEPTABAO_REPLACEMENT_EXECUTION_V2.json'
GUIDE = 'docs/compatibility/HEPTABAO_REPLACEMENT_EXECUTION.md'
CORPUS = 'qa/openbao-acceptance/complete_surface_corpus_v1.json'
AXES = {'protocol', 'authorization', 'effect_readback', 'crash_replay',
        'expiry_revocation', 'migration_upgrade', 'capacity_operations', 'independent_admission'}
STATES = {'RUNTIME_COMPLETE_LOCAL', 'PARTIAL_RUNTIME', 'CONTRACT_ONLY', 'NOT_IMPLEMENTED'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member')
        result[key] = value
    return result


def load(path: Path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_object)


def local_file(root: Path, value) -> bool:
    if not isinstance(value, str) or not value or '\\' in value:
        return False
    path = Path(value)
    if path.is_absolute() or any(part in ('..', '.') for part in path.parts):
        return False
    full = root / path
    return full.is_file() and not any((root / Path(*path.parts[:i])).is_symlink()
                                      for i in range(1, len(path.parts) + 1))


def render(matrix: dict) -> str:
    lines = [
        '# Per-surface OpenBao replacement execution requirements', '',
        'Subordinate to `HEPTABAO-PLAN-2026-09-07-V2.1`; not a new global plan.',
        f'Edit `{MATRIX}` and run `python scripts/validate_replacement_execution.py --write`.',
        'The fixed corpus remains the denominator; this table neither adds a pass receipt nor reduces its scope.',
        'A listed profile is an executable entry point, not coverage of all requirements in its row.',
        '`RUNTIME_COMPLETE_LOCAL` means repository-local runtime behavior is executable but later migration, physical fault, full differential and independent-admission phases remain open. `PARTIAL_RUNTIME` means real bounded code; `CONTRACT_ONLY` means a separate model/interface; none alone means full compatibility.', '',
        '## Common acceptance dimensions', '',
    ]
    for key, value in matrix['acceptance_axes'].items():
        lines.extend([f'### {key}', '', value, ''])
    lines.extend(['## Exact surface requirements', ''])
    for row in matrix['surfaces']:
        lines.extend([
            f"### {row['surface_id']}", '',
            f"Implementation: `{row['implementation']}`. Original work packages: " + ', '.join('`'+w+'`' for w in row['owner_work_packages']) + '.',
            'API families: ' + '; '.join('`'+v+'`' for v in row['api_families']) + '.',
            'Runtime source: ' + (', '.join('`'+v+'`' for v in row['runtime_sources']) or 'none claimed') + '.',
            'Separate contracts: ' + (', '.join('`'+v+'`' for v in row['contract_sources']) or 'none claimed') + '.',
            'Guides: ' + ', '.join('`'+v+'`' for v in row['guides']) + '.', '',
            '**Positive:** ' + row['positive'] + '.', '',
            '**Hostile:** ' + row['hostile'] + '.', '',
            '**Lifecycle:** ' + row['lifecycle'] + '.', '',
            '**Remaining scope:** ' + row['remaining_scope'], '',
            'Existing bounded profiles: ' + (', '.join('`'+v+'`' for v in row['executable_profiles']) or 'none bound yet; executable fixtures must be implemented') + '.', '',
        ])
    lines.extend([
        '## Hard-problem exits, without scope reduction', '',
        'Capacity: local persistence now publishes independently serialized authoritative owners under one authenticated V4 manifest, while the active replay ledger and HA logical-state path remain bounded. '
        'The capacity endpoint and before-entry journal compaction do not eliminate those remaining limits. '
        'The next scalable-storage exit is to carry owner/record deltas through the HA state-machine boundary, '
        'keep replay fences across ledger retirement, reject unsafe old-binary fallback, and '
        'measure large-state memory, I/O, latency and recovery costs. See `docs/operations/HEPTABAO_CAPACITY_AND_GROWTH.md`.', '',
        'Transit: retain current domain/AAD protections. An adapter must explicitly bind the source and destination '
        'domains, inventory every key/version/ciphertext, decrypt with authorized source ownership, re-encrypt under '
        'the destination, and verify readback. Similar `vault:vN:` text is not interoperability.', '',
        'Database: the fixed provider-role SQL profile is real but does not replace the OpenBao statement/static-role '
        'contract. Extend real providers with durable intent and provider-side idempotency/ownership; test DDL, '
        'rollback and session revocation on the actual database. A wire model is not that evidence.', '',
        'Snapshot: preserve original OpenBao bytes; do not mutate raft.db or reset revocation state. Require a '
        'separate typed, versioned conversion and exact source/target/seal binding. Native HeptaBao backups '
        'do not become OpenBao snapshots by sharing an endpoint.', '',
        'Migration and Hepta integration: run the inventory preflight before any planned copy, then the bounded '
        'copy/readback and source-freeze/single-writer cutover exits separately. Requalify the real Hepta consumer '
        'with both exact binaries before updating its external pin. Never advance the pin from repository CI alone.', '',
        'External security, isolated custody and physical multi-host/disk/power testing require authentic evidence. '
        'The existing external-admission verifier owns that decision; this execution map never issues approval.', '',
    ])
    return '\n'.join(lines)


def validate(root: Path = ROOT, *, check_render: bool = True) -> list[str]:
    errors = []
    try:
        m, corpus = load(root/MATRIX), load(root/CORPUS)
        inventory = yaml.safe_load((root/'oracle/inventory/openbao-v2.6.2/surface-catalog.yaml').read_text())
        baseline = {v['id']: v for category in inventory['categories'] for v in category['items']}
        if (m['schema'] != 'heptabao.replacement-execution.v1'
                or m['plan_id'] != 'HEPTABAO-PLAN-2026-09-07-V2.1'
                or m['target_version'] != corpus['target']['version']
                or m['corpus_path'] != CORPUS or m['authority_effect'] != 'NONE'):
            errors.append('execution identity differs from active plan/corpus')
        if set(m['acceptance_axes']) != AXES or any(not isinstance(v, str) or len(v) < 40 for v in m['acceptance_axes'].values()):
            errors.append('all acceptance dimensions must remain substantive')
        rows = m['surfaces']
        ids = [v['surface_id'] for v in rows]
        if ids != [v['surface_id'] for v in corpus['surfaces']] or len(ids) != len(set(ids)):
            errors.append('execution map must retain each exact corpus surface once in order')
        for row in rows:
            sid = row['surface_id']
            original = baseline.get(sid, {})
            if row['owner_work_packages'] != original.get('owner_work_packages') or row['public_baseline_reference'] != original.get('source_reference'):
                errors.append(sid + ': work package or baseline reference differs from original inventory')
            if row['implementation'] not in STATES:
                errors.append(sid + ': unknown implementation classification')
            if row.get('full_surface_verified') is not False or row.get('independently_admitted') is not False:
                errors.append(sid + ': requirements cannot self-issue completion')
            for key in ('positive', 'hostile', 'lifecycle', 'remaining_scope'):
                if not isinstance(row[key], str) or len(row[key]) < 20:
                    errors.append(sid + ': missing substantive ' + key)
            if not isinstance(row['public_baseline_reference'], str) or not row['public_baseline_reference'].startswith(('public-docs://', 'public-source-surface://', 'public-product-surface://', 'heptabao-plan://', 'heptabao-spec://')):
                errors.append(sid + ': unbound public baseline reference')
            by_id = {v['surface_id']: v for v in corpus['surfaces']}
            if sid not in by_id or row['category'] != by_id[sid]['category']:
                errors.append(sid + ': category differs from corpus')
            if (by_id[sid].get('fixture_state') == 'IMPLEMENTED_SCOPED'
                    and row['implementation'] == 'NOT_IMPLEMENTED'):
                errors.append(sid + ': fixed corpus has scoped implementation but execution map says not implemented')
            for key in ('api_families', 'owner_work_packages', 'guides'):
                values = row[key]
                if not isinstance(values, list) or not values or any(not isinstance(v,str) or not v for v in values):
                    errors.append(sid + ': missing ' + key)
            for key in ('runtime_sources', 'contract_sources', 'guides', 'executable_profiles'):
                values = row[key]
                if not isinstance(values, list) or len(values) != len(set(values)):
                    errors.append(sid + ': duplicate/invalid ' + key)
                    continue
                for value in values:
                    if not local_file(root, value):
                        errors.append(sid + ': missing or unsafe source ' + str(value))
            if (row['implementation'] in {'PARTIAL_RUNTIME', 'RUNTIME_COMPLETE_LOCAL'}) != bool(row['runtime_sources']):
                errors.append(sid + ': runtime classification lacks concrete entry')
            if row['implementation'] == 'RUNTIME_COMPLETE_LOCAL':
                evidence = row.get('implementation_evidence')
                if not isinstance(evidence, dict) or set(evidence) != {'source_paths', 'test_anchors', 'local_dimensions'}:
                    errors.append(sid + ': local runtime completion lacks executable evidence')
                else:
                    if set(evidence.get('local_dimensions', [])) != {'protocol_framing', 'authorization_before_effect', 'effect_readback', 'crash_reopen'}:
                        errors.append(sid + ': local runtime completion dimensions are incomplete')
                    for value in evidence.get('source_paths', []):
                        if not local_file(root, value):
                            errors.append(sid + ': missing completion source ' + str(value))
                    seen = set()
                    for anchor in evidence.get('test_anchors', []):
                        if not isinstance(anchor, dict) or set(anchor) != {'path', 'name'} or not local_file(root, anchor.get('path')):
                            errors.append(sid + ': invalid completion test anchor')
                            continue
                        key = (anchor['path'], anchor['name'])
                        if key in seen or f"fn {anchor['name']}" not in (root/anchor['path']).read_text():
                            errors.append(sid + ': absent or duplicated completion test anchor')
                        seen.add(key)
            elif 'implementation_evidence' in row:
                errors.append(sid + ': non-complete execution row carries completion evidence')
            if row['implementation'] == 'CONTRACT_ONLY' and not row['contract_sources']:
                errors.append(sid + ': contract classification lacks source')
        if check_render and (root/GUIDE).read_text(encoding='utf-8') != render(m):
            errors.append('execution guide differs from machine-readable requirements')
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as exc:
        errors.append('execution inputs invalid: ' + type(exc).__name__)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    if args.write:
        (ROOT/GUIDE).write_text(render(load(ROOT/MATRIX)), encoding='utf-8')
    problems = validate()
    for problem in problems:
        print('replacement-execution: ' + problem)
    if not problems:
        print(f"replacement-execution: PASS ({len(load(ROOT/MATRIX)['surfaces'])} requirement rows, not execution or admission)")
    return int(bool(problems))


if __name__ == '__main__':
    raise SystemExit(main())
