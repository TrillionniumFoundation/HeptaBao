#!/usr/bin/env python3
"""Validate the frozen V1.4.4 documentation baseline inside an evolving workspace."""
from __future__ import annotations

import argparse
import glob
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
HISTORICAL_MODULE_COUNT = 19


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


def current_workspace_crates(root: Path) -> list[str]:
    workspace = tomllib.loads((root / 'Cargo.toml').read_text(encoding='utf-8'))
    crates = []
    for member in workspace['workspace']['members']:
        if Path(member).is_absolute() or '..' in Path(member).parts:
            raise ValueError(f'workspace member escapes repository: {member}')
        if glob.has_magic(member):
            roots = sorted(
                path for path in root.glob(member)
                if path.is_dir() and (path / 'Cargo.toml').is_file()
            )
            if not roots:
                raise ValueError(f'workspace member glob matched no crates: {member}')
        else:
            roots = [root / member]
        for crate_root in roots:
            manifest_path = crate_root / 'Cargo.toml'
            if not manifest_path.is_file():
                raise ValueError(f'missing workspace manifest: {manifest_path.relative_to(root)}')
            manifest = tomllib.loads(manifest_path.read_text(encoding='utf-8'))
            crates.append(manifest['package']['name'])
    if len(crates) != len(set(crates)):
        raise ValueError('current workspace contains duplicate package names')
    return crates


def validate(root: Path) -> list[str]:
    errors = []
    coverage_path = root / 'planning/HEPTABAO_MODULE_DOCUMENTATION_COVERAGE_V1_4_4.yaml'
    try:
        coverage = load_yaml(coverage_path)
        crates = current_workspace_crates(root)
    except Exception as exc:
        return [f'coverage/workspace invalid: {exc}']
    entries = coverage.get('modules') or []
    names = [entry.get('crate') for entry in entries]
    if len(names) != len(set(names)):
        errors.append('duplicate module coverage entry')
    missing_crates = sorted(set(names) - set(crates))
    if missing_crates:
        errors.append(f'historical V1.4.4 crates are absent from current workspace: {missing_crates!r}')
    if (
        len(names) != HISTORICAL_MODULE_COUNT
        or coverage.get('workspace_module_count') != HISTORICAL_MODULE_COUNT
        or coverage.get('documented_module_count') != HISTORICAL_MODULE_COUNT
    ):
        errors.append('V1.4.4 historical module counts drifted')
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
    module_files = {
        str(path.relative_to(root))
        for path in (root / 'docs/modules').glob('heptabao-*.md')
    }
    missing_guides = sorted(docs_seen - module_files)
    if missing_guides:
        errors.append(f'historical module guides are missing: {missing_guides!r}')
    for required in ('docs/modules/README.md', 'docs/modules/MODULE_DOCUMENTATION_STANDARD_V1.md'):
        if not (root / required).is_file():
            errors.append(f'missing {required}')
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
            errors.append('manifest does not include every historical module guide')
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
    print('V1.4.4 historical module documentation validation: PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
