#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

import jsonschema
import yaml

REQUIRED = [
    'Purpose and non-goals', 'Maturity and authority boundary', 'Ownership and trust boundary',
    'Dependency contract', 'Public API index', 'State and invariants', 'Failure and retry semantics',
    'Persistent or wire formats', 'Concurrency and cancellation', 'Security and secret handling',
    'Testing and evidence', 'Extension workflow', 'Operations and diagnostics', 'Known gaps',
    'Traceability and maintenance',
]
FORBIDDEN = ('TODO', 'TBD', 'PLACEHOLDER', 'production_authority: true', 'qualification: true', 'authority_effect: GRANT')

class UniqueLoader(yaml.SafeLoader):
    pass

def construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f'duplicate YAML key: {key!r}')
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping

UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)

def load_yaml(path: Path):
    return yaml.load(path.read_text(encoding='utf-8'), Loader=UniqueLoader)

def validate(root: Path) -> list[str]:
    errors = []
    workspace = tomllib.loads((root / 'Cargo.toml').read_text(encoding='utf-8'))
    crates = []
    for member in workspace['workspace']['members']:
        manifest = tomllib.loads((root / member / 'Cargo.toml').read_text(encoding='utf-8'))
        crates.append(manifest['package']['name'])
    coverage_path = root / 'planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml'
    try:
        coverage = load_yaml(coverage_path)
    except Exception as exc:
        return [f'coverage YAML invalid: {exc}']
    entries = coverage.get('modules') or []
    names = [entry.get('crate') for entry in entries]
    if len(names) != len(set(names)):
        errors.append('duplicate module coverage entry')
    if sorted(names) != sorted(crates):
        errors.append(f'workspace/document coverage mismatch: workspace={sorted(crates)!r}, documented={sorted(names)!r}')
    if coverage.get('workspace_module_count') != len(crates) or coverage.get('documented_module_count') != len(crates):
        errors.append('module counts do not equal exact workspace count')
    expected_claims = {'qualification': False, 'compatibility_claim': False, 'production_authority': False, 'migration_authority': False, 'release_authority': False, 'authority_effect': 'NONE'}
    if coverage.get('claims') != expected_claims:
        errors.append('coverage authority boundary drifted')
    docs_seen = set()
    for entry in entries:
        name = entry.get('crate')
        rel = entry.get('document')
        if rel in docs_seen:
            errors.append(f'duplicate module document path: {rel}')
        docs_seen.add(rel)
        path = root / str(rel)
        if not path.is_file():
            errors.append(f'missing module document: {rel}')
            continue
        text = path.read_text(encoding='utf-8')
        if f'`{name}` developer guide' not in text:
            errors.append(f'module title mismatch: {rel}')
        for section in REQUIRED:
            if f'## {section}' not in text:
                errors.append(f'{rel} missing section {section!r}')
        for token in FORBIDDEN:
            if token in text:
                errors.append(f'{rel} contains forbidden placeholder/authority token {token!r}')
        if entry.get('required_sections') != REQUIRED:
            errors.append(f'{rel} required section registry drifted')
    module_files = {str(path.relative_to(root)) for path in (root / 'docs/modules').glob('heptabao-*.md')}
    if module_files != docs_seen:
        errors.append(f'unindexed or missing module guide files: files={sorted(module_files)!r}, index={sorted(docs_seen)!r}')
    for required in ('docs/modules/README.md', 'docs/modules/MODULE_DOCUMENTATION_STANDARD_V1.md'):
        if not (root / required).is_file():
            errors.append(f'missing {required}')
    readme = (root / 'README.md').read_text(encoding='utf-8')
    for token in ('V1.4.4', '19 / 19', 'not production-deployable', 'HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml'):
        if token not in readme:
            errors.append(f'README missing current-truth token {token!r}')
    manifest_path = root / 'planning/HEPTABAO_NORMATIVE_DOCUMENT_MANIFEST_V1_4_4.yaml'
    schema_path = root / 'schemas/heptabao_normative_document_manifest_v1_4_4.schema.json'
    try:
        manifest = load_yaml(manifest_path)
        schema = json.loads(schema_path.read_text(encoding='utf-8'))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(manifest, schema)
    except Exception as exc:
        errors.append(f'manifest/schema invalid: {exc}')
    else:
        paths = [item.get('path') for item in manifest.get('documents') or []]
        if len(paths) != len(set(paths)):
            errors.append('manifest contains duplicate paths')
        for rel in paths:
            if not (root / str(rel)).is_file():
                errors.append(f'manifest path missing: {rel}')
        if not docs_seen.issubset(set(paths)):
            errors.append('manifest does not include every module guide')
    status = load_yaml(root / 'planning/HEPTABAO_V1_4_4_MODULE_DOCUMENTATION_STATUS.yaml')
    blocker = load_yaml(root / 'planning/HEPTABAO_BLOCKER_REGISTER_V1_4_4.yaml')
    expected_full = {'qualification': False, 'compatibility_claim': False, 'selected_candidates': [], 'selection_effect': 'NONE', 'production_authority': False, 'migration_authority': False, 'release_authority': False, 'authority_effect': 'NONE'}
    if status.get('claims') != expected_full or blocker.get('claims') != expected_full:
        errors.append('status/blocker authority boundary drifted')
    blocker_ids = [item.get('id') for item in blocker.get('added_blockers') or []]
    if blocker_ids != ['HB-BLK-REPO-037', 'HB-BLK-REPO-038', 'HB-BLK-REPO-039', 'HB-BLK-REPO-040']:
        errors.append('V1.4.4 blocker set drifted')
    return errors

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', default='.')
    args = parser.parse_args()
    errors = validate(Path(args.root).resolve())
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print('V1.4.4 module documentation validation: PASS')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
