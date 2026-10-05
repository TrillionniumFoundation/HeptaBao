#!/usr/bin/env python3
"""Eight real mechanical Cargo probes. Behavioral qualification is never inferred."""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Reuse reviewed byte-exact input isolation and low-level execution, not V1 receipts.
import types

def load(relative, digest):
    path = ROOT / relative
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('reviewed helper changed: ' + relative)
    module = types.ModuleType(relative)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module

common = load('scripts/h02_openraft_fault_lab_evidence_v2.py', '3193a7f8fd9bae8268ce5d746fb1597a797eae1ecf92e70dc34675cd4f0a5e68')
legacy = load('scripts/h02_dependency_probe_v1.py', 'c63c57472d176a02529a82ecba72a4f72aa476cb19119f0234d364c545c520ce')
require, sha, file_sha, read, write, canonical = common.require, common.sha, common.file_sha, common.strict_json, common.write, common.canonical
PROFILE = 'HB-H02-MECHANICAL-PROBE-CURRENT-V2'
SCHEMA = 'heptabao.dependency-mechanical-evidence.v2'
TARGET = 'x86_64-unknown-linux-gnu'
STAGES = ('rustc', 'cargo', 'lock', 'metadata', 'dependency-tree', 'package-features', 'check', 'test')
PLAN = 'planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V2.yaml'
LEGACY_PLAN = 'planning/HEPTABAO_H02_CANDIDATE_PROBE_MATRIX_V1.yaml'


def profiles():
    result = copy.deepcopy(legacy.profiles(legacy.load_yaml(ROOT / LEGACY_PLAN)))
    for item in result.values():
        item['probe_toolchains'][-1] = '1.99.0'
    return result


def entries():
    return {(p['profile_id'] + '-' + compiler): (p, compiler)
            for p in profiles().values() for compiler in p['probe_toolchains']}


def policy(item):
    return 'GENERATE_REAL_LOCK_ONCE_THEN_LOCKED' if item['package'] == 'tokio' else 'COMMITTED_LOCK_UNCHANGED'


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)


def snapshot(root, item):
    manifest = item['probe_manifest']
    lock = str(Path(manifest).with_name('Cargo.lock'))
    exists = git(root, 'ls-tree', 'HEAD', '--', lock).strip()
    return {'repository': 'TrillionniumFoundation/HeptaBao', 'commit': git(root, 'rev-parse', 'HEAD').decode().strip(),
            'tree': git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'clean_tree': git(root, 'status', '--porcelain', '--untracked-files=all') == b'',
            'manifest_sha256': sha(git(root, 'show', 'HEAD:' + manifest)),
            'committed_lock_sha256': sha(git(root, 'show', 'HEAD:' + lock)) if exists else None}


def commands(item, compiler, work):
    require(compiler in item['probe_toolchains'], 'compiler outside profile')
    cargo = ['rustup', 'run', compiler, 'cargo']
    tail = ['--manifest-path', str(work / 'Cargo.toml')]
    return {'rustc': ['rustup', 'run', compiler, 'rustc', '--version', '--verbose'],
            'cargo': cargo + ['--version'],
            'lock': cargo + ['generate-lockfile'] + tail if policy(item).startswith('GENERATE') else None,
            'metadata': cargo + ['metadata', '--locked', '--format-version', '1'] + tail,
            'dependency-tree': cargo + ['tree', '--locked', '--edges', 'normal,build', '--target', 'all', '--prefix', 'depth', '--format', '{p}|{f}', '--color', 'never'] + tail,
            'package-features': cargo + ['tree', '--locked', '--edges', 'normal,build', '--target', 'all', '--prefix', 'none', '--format', '{p}|{f}', '--color', 'never'] + tail,
            'check': cargo + ['check', '--locked', '--all-targets', '--target', TARGET] + tail,
            'test': cargo + ['test', '--locked', '--all-targets', '--target', TARGET] + tail}


def context(item, compiler, work, source, run_id, attempt, runner, base, source_root=ROOT):
    require(re.fullmatch(r'[1-9][0-9]*', run_id) and re.fullmatch(r'[1-9][0-9]*', attempt) and runner, 'run identity')
    env = common.controlled_environment(work, compiler, base)
    return {'schema': 'heptabao.h02-mechanical-context.v2', 'execution_profile_id': PROFILE,
            'profile_id': item['profile_id'], 'profile_digest_sha256': legacy.profile_digest(item),
            'toolchain': compiler, 'target': TARGET, 'run_id': run_id, 'run_attempt': attempt, 'runner_name': runner,
            'source_before': source, 'source_after': None, 'lock_policy': policy(item),
            'source_root': str(source_root), 'cwd': str(work), 'environment': env, 'environment_sha256': sha(canonical(env)),
            'configuration_paths': common.cargo_configuration_paths(work, Path(env['CARGO_HOME'])),
            'argv': commands(item, compiler, work), 'return_codes': dict.fromkeys(STAGES),
            'configuration_checks': dict.fromkeys(STAGES), 'lock_before_sha256': None, 'lock_after_sha256': None,
            'setup_error': None, 'package_error': None}


def materialize(root, work, item, commit):
    prefix = str(Path(item['probe_manifest']).parent)
    paths = [prefix]
    if item['package'] == 'rustls': paths.append('probes/h02/rustls-public-fixtures.rs')
    work.mkdir(parents=True)
    for record in filter(None, git(root, 'ls-tree', '-rz', commit, '--', *paths).split(b'\0')):
        header, name = record.split(b'\t', 1)
        mode, kind, object_id = header.decode().split(); name = name.decode()
        require(kind == 'blob' and mode in {'100644', '100755'}, 'nonregular committed input')
        relative = Path(name).relative_to(prefix) if name.startswith(prefix + '/') else Path('../rustls-public-fixtures.rs')
        destination = work / relative
        payload = git(root, 'show', commit + ':' + name)
        require(hashlib.sha1(b'blob ' + str(len(payload)).encode() + b'\0' + payload).hexdigest() == object_id, 'blob binding')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload); destination.chmod(int(mode[-3:], 8))


def declarations(manifest):
    """Normalize declarative identities, not Cargo resolution or cfg evaluation."""
    result = []
    groups = [(None, manifest)] + list(manifest.get('target', {}).items())
    for target, group in groups:
        for section, kind in [('dependencies', None), ('build-dependencies', 'build'), ('dev-dependencies', 'dev')]:
            for alias, raw in group.get(section, {}).items():
                dep = {'version': raw} if isinstance(raw, str) else raw
                require(isinstance(dep, dict) and 'workspace' not in dep, 'unresolved workspace declaration')
                require(not any(key in dep for key in ('path', 'git', 'registry')), 'unsupported non-registry direct declaration')
                result.append({'source': 'registry+https://github.com/rust-lang/crates.io-index', 'name': dep.get('package', alias), 'alias': alias.replace('-', '_'), 'kind': kind,
                               'target': target, 'optional': dep.get('optional', False), 'features': sorted(dep.get('features', [])),
                               'uses_default_features': dep.get('default-features', True), 'req': dep.get('version', '*')})
    return result


def requirement_text(value):
    require(isinstance(value, str) and bool(value), 'missing declared version requirement')
    # Cargo reports a bare TOML requirement as a caret requirement. We compare
    # declarations, without implementing an independent version resolver.
    return '^' + value if value[0].isdigit() else value


def metadata_declarations(package):
    require(isinstance(package.get('dependencies'), list), 'missing dependency declarations')
    result = []
    for dep in package['dependencies']:
        require(type(dep.get('optional')) is bool and type(dep.get('uses_default_features')) is bool, 'invalid dependency boolean')
        require(dep.get('kind') in (None, 'build', 'dev') and (dep.get('target') is None or isinstance(dep['target'], str)), 'invalid dependency kind/target')
        require(isinstance(dep.get('features'), list) and all(isinstance(f, str) for f in dep['features']), 'invalid requested features')
        result.append({'source': dep.get('source'), 'name': dep['name'], 'alias': (dep.get('rename') or dep['name']).replace('-', '_'), 'kind': dep['kind'],
                       'target': dep['target'], 'optional': dep['optional'], 'features': sorted(dep['features']),
                       'uses_default_features': dep['uses_default_features'], 'req': dep['req']})
    return result


def bind_declarations(package, manifest):
    expected, actual = declarations(manifest), metadata_declarations(package)
    for values in (expected, actual):
        for dep in values: dep['req'] = requirement_text(dep['req'])
    require(sorted(canonical(x) for x in actual) == sorted(canonical(x) for x in expected), 'metadata declarations differ from authenticated manifest')


def locked_identity(package):
    return (package['name'], package['version'], package.get('source'))


def lock_edges(lock):
    packages = lock['package']; identities = {locked_identity(p): p for p in packages}
    require(len(identities) == len(packages), 'duplicate locked package')
    edges = {}
    for identity, package in identities.items():
        children = set()
        for ref in package.get('dependencies', []):
            match = re.fullmatch(r'([^ ]+)(?: ([^ ()]+))?(?: \(([^)]+)\))?', ref)
            require(match is not None, 'invalid locked dependency reference')
            name, version, source = match.groups()
            choices = [key for key in identities if key[0] == name and (version is None or key[1] == version) and (source is None or key[2] == source)]
            require(len(choices) == 1, 'ambiguous/unresolved locked dependency')
            require(choices[0] not in children, 'duplicate locked dependency'); children.add(choices[0])
        edges[identity] = children
    return identities, edges


def metadata_graph(value, item, work, lock, candidate_manifest=None):
    packages, resolve = value['packages'], value['resolve']
    require(isinstance(packages, list) and packages and isinstance(resolve, dict), 'missing resolved metadata')
    by_id = {p['id']: p for p in packages}; nodes = {n['id']: n for n in resolve['nodes']}
    require(len(by_id) == len(packages) and len(nodes) == len(resolve['nodes']) and set(nodes) == set(by_id), 'duplicate/unresolved graph node')
    identities = {locked_identity(p): p['id'] for p in packages}
    require(len(identities) == len(packages), 'duplicate metadata package identity')
    locked, locked_children = lock_edges(lock)
    require(set(identities) <= set(locked), 'metadata package not in actual lock')
    root = resolve['root']
    require(root in nodes and by_id[root]['manifest_path'] == str(work / 'Cargo.toml') and by_id[root]['source'] is None, 'wrong graph root')
    require(value['workspace_members'] == [root], 'unexpected workspace members')
    root_manifest = tomllib.loads((ROOT / item['probe_manifest']).read_text())
    require(not any(d['kind'] == 'dev' for d in declarations(root_manifest)), 'this normal/build projection profile does not admit root dev dependencies')
    bind_declarations(by_id[root], root_manifest)
    patches = root_manifest.get('patch', {}).get('crates-io', {})
    for node_id, node in nodes.items():
        require(isinstance(node.get('deps'), list) and isinstance(node.get('dependencies'), list) and isinstance(node.get('features'), list), 'missing typed resolved graph fields')
        require(all(isinstance(f, str) for f in node['features']) and len(set(node['features'])) == len(node['features']), 'invalid resolved features')
        require(all(dep['pkg'] in nodes for dep in node['deps']), 'unresolved dependency edge')
        children = {d['pkg'] for d in node['deps']}
        require(len(children) == len(node['deps']) and set(node['dependencies']) == children and len(node['dependencies']) == len(children), 'dependency/deps graph mismatch')
        package = by_id[node_id]; declared = metadata_declarations(package)
        observed = set()
        for edge in node['deps']:
            child = by_id[edge['pkg']]
            require(locked_identity(child) in locked_children[locked_identity(package)], 'resolve edge missing from actual lock')
            require(isinstance(edge.get('dep_kinds'), list) and bool(edge['dep_kinds']), 'missing edge kind')
            for kind in edge['dep_kinds']:
                require(set(kind) == {'kind', 'target'} and kind['kind'] in (None, 'build', 'dev'), 'invalid edge kind/target')
                key = (edge['name'], kind['kind'], kind['target'])
                require(key not in observed, 'duplicate dependency kind edge'); observed.add(key)
                matches = [d for d in declared if (d['alias'], d['kind'], d['target']) == key and d['name'] == child['name']]
                require(len(matches) == 1, 'edge lacks matching dependency declaration')
                dep = matches[0]
                require(dep['kind'] != 'dev' or node_id == root, 'transitive dev edge in resolved graph')
                raw = next(d for d in package['dependencies'] if (d.get('rename') or d['name']).replace('-', '_') == dep['alias'] and d['kind'] == dep['kind'] and d['target'] == dep['target'])
                source = raw.get('source')
                patched = patches.get(child['name'])
                if patched and child.get('source', '').startswith('git+'):
                    expected = 'git+' + patched['git'] + '?rev=' + patched['rev'] + '#' + patched['rev']
                    require(child['source'] == expected, 'patched git revision/source drift')
                else: require(source == child.get('source'), 'declared/resolved dependency source mismatch')
                # Every observed edge's version is independently fixed by its
                # parent's exact Cargo.lock reference. Exact root/candidate pins
                # also have a directly checkable declaration constraint.
                req = requirement_text(dep['req'])
                if req.startswith('='): require(child['version'] == req[1:].strip(), 'exact dependency version drift')
                require(set(dep['features']) <= set(nodes[edge['pkg']]['features']), 'requested dependency features absent')
        mandatory = {(d['alias'], d['kind'], d['target']) for d in declared if not d['optional'] and (d['kind'] != 'dev' or node_id == root)}
        require(mandatory <= observed, 'mandatory dependency omitted from resolved graph')
    visited = set(); pending = [root]
    while pending:
        node_id = pending.pop()
        if node_id in visited: continue
        visited.add(node_id); pending.extend(nodes[node_id]['dependencies'])
    require(visited == set(nodes), 'unreachable resolved package')
    selected = [p for p in packages if p['name'] == item['package'] and p['version'] == item['version']]
    require(len(selected) == 1, 'candidate missing/ambiguous in graph'); selected = selected[0]
    require(selected['id'] in set(nodes[root]['dependencies']), 'candidate not root direct dependency')
    require(selected['source'] == 'registry+https://github.com/rust-lang/crates.io-index', 'wrong candidate source')
    features = set(nodes[selected['id']]['features'])
    require(set(item['features']) <= features and not features.intersection(item['forbidden_feature_expansion']), 'resolved feature expansion/drift')
    require(locked[locked_identity(selected)].get('checksum') == item['expected_registry_checksum_sha256'], 'locked candidate checksum')
    if candidate_manifest is not None: bind_declarations(selected, candidate_manifest)
    return selected, legacy.summarize_metadata(value)


def tree_package(text, packages):
    match = re.fullmatch(r'([^ ]+) v([^ ]+)( \(proc-macro\))?(?: \((.+)\))?', text)
    require(match is not None, 'unrecognized Cargo package row')
    name, version, macro, source = match.groups()
    candidates = [p for p in packages if p['name'] == name and p['version'] == version]
    require(len(candidates) == 1, 'ambiguous/unknown tree package identity')
    package = candidates[0]
    require(bool(macro) == any('proc-macro' in t['kind'] for t in package['targets']), 'tree proc-macro kind mismatch')
    identity = package.get('source')
    if identity is None:
        require(source == str(Path(package['manifest_path']).parent), 'tree local source mismatch')
    elif identity == 'registry+https://github.com/rust-lang/crates.io-index':
        require(source is None, 'unexpected registry tree source')
    elif identity.startswith('git+'):
        expected_url, expected_commit = identity[4:].rsplit('#', 1)
        require(source is not None and '#' in source, 'missing git tree revision')
        actual_url, actual_commit = source.rsplit('#', 1)
        require(actual_url == expected_url and re.fullmatch(r'[0-9a-f]{7,40}', actual_commit) and expected_commit.startswith(actual_commit), 'tree git source/revision mismatch')
    else:
        raise ValueError('unsupported tree source representation')
    return package['id']


def tree_observation(text, metadata, *, depth):
    packages, nodes = metadata['packages'], {n['id']: n for n in metadata['resolve']['nodes']}
    features, edges, stack = {}, set(), []
    rows = text.splitlines(); require(bool(rows) and all(rows), 'empty tree/projection row')
    roots = 0
    for row in rows:
        if row.endswith(' (*)'): row = row[:-4]
        level = None
        if depth:
            match = re.fullmatch(r'([0-9]+)(.+)', row); require(match is not None, 'tree depth prefix missing')
            level, row = int(match[1]), match[2]
            require(level <= len(stack), 'tree depth discontinuity')
        parts = row.split('|'); require(len(parts) == 2, 'tree package/features delimiter')
        package_id = tree_package(parts[0], packages)
        observed = parts[1].split(',') if parts[1] else []
        require(len(set(observed)) == len(observed) and set(observed) <= set(nodes[package_id]['features']), 'tree unknown/duplicate resolved feature')
        features.setdefault(package_id, set()).update(observed)
        if depth:
            if level == 0:
                roots += 1; require(package_id == metadata['resolve']['root'], 'wrong tree root')
            else: edges.add((stack[level-1], package_id))
            stack[level:] = [package_id]
    require(set(features) == set(nodes), 'tree/projection package coverage differs from resolved metadata')
    require(all(features[node_id] == set(node['features']) for node_id, node in nodes.items()), 'tree/projection feature union differs from resolved metadata')
    if depth:
        require(roots == 1, 'tree root count')
        expected = {(node['id'], dep['pkg']) for node in nodes.values() for dep in node['deps']
                    if any(kind['kind'] in (None, 'build') for kind in dep['dep_kinds'])}
        require(edges == expected, 'tree/metadata edge disagreement')
    return features


def bind_trees(entry, metadata):
    dependency = tree_observation((entry / 'dependency-tree.stdout').read_text(), metadata, depth=True)
    projection = tree_observation((entry / 'package-features.stdout').read_text(), metadata, depth=False)
    require(dependency == projection, 'package-feature projection disagrees with dependency tree')


def inspect_archive(path, item, actual_source=None):
    require(file_sha(path) == item['expected_registry_checksum_sha256'], 'actual crate checksum mismatch')
    prefix = item['package'] + '-' + item['version']
    with tempfile.TemporaryDirectory(prefix='h02-crate-scan-') as tmp:
        root = Path(tmp)
        with tarfile.open(path, 'r:gz') as archive:
            members = archive.getmembers()
            require(sum(m.size for m in members) < 64 * 1024 * 1024, 'oversize candidate archive')
            seen = set()
            expected_files = set()
            for member in members:
                relative = Path(member.name)
                require(not relative.is_absolute() and '..' not in relative.parts and relative.parts[0] == prefix, 'unsafe archive path')
                require(member.name not in seen, 'duplicate archive path'); seen.add(member.name)
                if member.isdir(): continue
                require(member.isfile(), 'nonregular archive member')
                relative = Path(*relative.parts[1:]); expected_files.add(relative.as_posix()); payload = archive.extractfile(member).read()
                if actual_source is not None:
                    source = actual_source / relative
                    require(not source.is_symlink() and source.is_file() and source.read_bytes() == payload, 'cached source differs from actual crate')
                target = root / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(payload)
        if actual_source is not None:
            require(all(not ancestor.is_symlink() for ancestor in (actual_source, *actual_source.parents)), 'symlinked cached-source ancestor')
            files = list(actual_source.rglob('*'))
            require(all(not path.is_symlink() for path in files), 'symlinked cached-source input')
            actual_files = {path.relative_to(actual_source).as_posix() for path in files if path.is_file()}
            require(actual_files - {'.cargo-ok', '.cargo-checksum.json'} == expected_files - {'.cargo-ok', '.cargo-checksum.json'}, 'extra/missing cached source input')
        vcs = read(root / '.cargo_vcs_info.json')
        require(vcs['git']['sha1'] == item['expected_release_commit_sha'], 'actual crate VCS commit mismatch')
        return {'archive_sha256': file_sha(path), 'vcs': vcs, 'manifest': tomllib.loads((root / 'Cargo.toml').read_text()), 'scan': legacy.scan_source_tree(root)}


def capture_package(entry, ctx, item):
    metadata = read(entry / 'metadata.stdout')
    lock = tomllib.loads((entry / 'Cargo.lock').read_text())
    selected, _ = metadata_graph(metadata, item, Path(ctx['cwd']), lock)
    home = Path(ctx['environment']['CARGO_HOME'])
    source = Path(selected['manifest_path']).parent
    require(source.is_relative_to(home / 'registry/src') and not source.is_symlink(), 'candidate outside isolated registry')
    relative = source.relative_to(home / 'registry/src')
    require(len(relative.parts) == 2 and relative.name == item['package'] + '-' + item['version'], 'registry source path')
    archive = home / 'registry/cache' / relative.parts[0] / (relative.name + '.crate')
    require(not archive.is_symlink(), 'symlinked crate')
    binding = inspect_archive(archive, item, source)
    metadata_graph(metadata, item, Path(ctx['cwd']), lock, binding['manifest'])
    shutil.copyfile(archive, entry / 'package.crate')


def collect(entry, ctx, item):
    problems = []
    if ctx['setup_error']: problems.append('setup: ' + ctx['setup_error'])
    if ctx['package_error']: problems.append('package: ' + ctx['package_error'])
    if canonical(ctx['source_before']) != canonical(ctx['source_after']) or ctx['source_before']['clean_tree'] is not True: problems.append('source changed/dirty')
    expected_stages = [s for s in STAGES if ctx['argv'][s] is not None]
    for stage in expected_stages:
        if ctx['return_codes'][stage] != 0: problems.append(stage + ': not executed successfully')
        if ctx['configuration_checks'][stage] != {'before': True, 'after': True}: problems.append(stage + ': Cargo configuration uncertainty')
        for suffix in ('stdout', 'stderr'):
            if not (entry / (stage + '.' + suffix)).is_file(): problems.append(stage + ': missing output')
    compiler = ctx['toolchain']
    rustc = (entry / 'rustc.stdout').read_text() if (entry / 'rustc.stdout').is_file() else ''
    cargo = (entry / 'cargo.stdout').read_text() if (entry / 'cargo.stdout').is_file() else ''
    if not (re.search(r'^release: ' + re.escape(compiler) + r'$', rustc, re.M) and re.search(r'^host: ' + TARGET + r'$', rustc, re.M) and re.match(r'rustc ' + re.escape(compiler) + r' \(', rustc)): problems.append('actual rustc identity')
    if not re.match(r'cargo ' + re.escape(compiler) + r' \(', cargo): problems.append('actual cargo identity')
    lock_hash = file_sha(entry / 'Cargo.lock')
    if not lock_hash or lock_hash != ctx['lock_before_sha256'] or lock_hash != ctx['lock_after_sha256']: problems.append('actual lock absent/changed')
    if policy(item) == 'COMMITTED_LOCK_UNCHANGED' and lock_hash != ctx['source_before']['committed_lock_sha256']: problems.append('committed graph mismatch')
    if policy(item).startswith('GENERATE') and ctx['source_before']['committed_lock_sha256'] is not None: problems.append('unexpected committed generated-policy lock')
    if file_sha(entry / 'Cargo.toml') != ctx['source_before']['manifest_sha256']: problems.append('manifest changed')
    graph = package = None
    try:
        lock = tomllib.loads((entry / 'Cargo.lock').read_text())
        package = inspect_archive(entry / 'package.crate', item)
        _, graph = metadata_graph(read(entry / 'metadata.stdout'), item, Path(ctx['cwd']), lock, package['manifest'])
        bind_trees(entry, read(entry / 'metadata.stdout'))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        problems.append('graph/package: ' + common.diagnostic(exc))
    artifacts = {}
    for path in sorted(entry.iterdir()):
        if path.name == 'evidence.json': continue
        require(path.is_file() and not path.is_symlink(), 'nonregular evidence artifact')
        artifacts[path.name] = {'sha256': file_sha(path), 'byte_length': path.stat().st_size}
    return {'schema': SCHEMA, 'execution_profile_id': PROFILE, 'profile_id': item['profile_id'],
            'profile_digest_sha256': legacy.profile_digest(item), 'toolchain': compiler,
            'graph_scope': 'ALL_TARGET_ENABLED_NORMAL_BUILD_OBSERVATION',
            'feature_artifact_kind': 'RESOLVED_PACKAGE_FEATURE_PROJECTION',
            'mechanical_status': 'EXECUTED_PASS' if not problems else 'EXECUTED_FAIL' if any(type(code) is int and code != 0 for code in ctx['return_codes'].values()) else 'BLOCKED',
            'source': ctx['source_before'], 'run_id': ctx['run_id'], 'run_attempt': ctx['run_attempt'],
            'runner_name': ctx['runner_name'], 'context_sha256': sha(canonical(ctx)), 'artifacts': artifacts,
            'graph_summary': graph, 'package_binding': package, 'problems': problems,
            'behavioral_cases': [{'case_id': case, 'status': 'UNEXECUTED'} for case in item['required_cases']],
            'qualification': False, 'selection_effect': 'NONE', 'authority_effect': 'NONE'}


def run(args):
    root, evidence, execution = args.source_root.resolve(), args.evidence_root.resolve(), args.execution_root.resolve()
    require(root == ROOT and not evidence.exists() and not execution.exists(), 'exact source and fresh output roots required')
    require(not evidence.is_relative_to(root) and not execution.is_relative_to(root) and not evidence.is_relative_to(execution) and not execution.is_relative_to(evidence), 'separate external roots required')
    planned = entries()
    original_sources = {item['profile_id']: snapshot(root, item) for item, _ in planned.values()}
    require(all(value['commit'] == args.expected_commit and value['clean_tree'] for value in original_sources.values()), 'unexpected/dirty source')
    evidence.mkdir(parents=True); execution.mkdir(parents=True)
    for name in ('home', 'cargo-home', 'tmp'): (execution / name).mkdir()
    base = common.runtime_base_environment()
    for name, (item, compiler) in planned.items():
        before = original_sources[item['profile_id']]
        entry, work = evidence / name, execution / name / 'probe'; entry.mkdir()
        ctx = context(item, compiler, work, before, args.run_id, args.run_attempt, args.runner_name, base)
        try:
            require(canonical(snapshot(root, item)) == canonical(before), 'source changed before entry; execution blocked')
            materialize(root, work, item, before['commit'])
            require(file_sha(work / 'Cargo.toml') == before['manifest_sha256'], 'materialized manifest mismatch')
            require(file_sha(work / 'Cargo.lock') == before['committed_lock_sha256'], 'materialized lock mismatch')
        except (OSError, ValueError, subprocess.SubprocessError) as exc: ctx['setup_error'] = common.diagnostic(exc)
        if ctx['setup_error'] is None:
            for stage in STAGES:
                if stage in {'check', 'test'} and ctx['package_error'] is not None:
                    continue
                if ctx['argv'][stage] is not None: common.execute(ctx, stage, entry)
                if stage == 'lock': ctx['lock_before_sha256'] = file_sha(work / 'Cargo.lock')
                if stage == 'metadata':
                    try:
                        for filename in ('Cargo.toml', 'Cargo.lock'):
                            shutil.copyfile(work / filename, entry / filename)
                        capture_package(entry, ctx, item)
                    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
                        ctx['package_error'] = common.diagnostic(exc)
            ctx['lock_after_sha256'] = file_sha(work / 'Cargo.lock')
        for filename in ('Cargo.toml', 'Cargo.lock'):
            if (work / filename).is_file(): shutil.copyfile(work / filename, entry / filename)
        try: capture_package(entry, ctx, item)
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc: ctx['package_error'] = common.diagnostic(exc)
        try: ctx['source_after'] = snapshot(root, item)
        except (OSError, subprocess.SubprocessError): ctx['source_after'] = None
        write(entry / 'execution-context.json', ctx)
        write(entry / 'evidence.json', collect(entry, ctx, item))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'evidence-root', 'execution-root'): parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-commit', 'run-id', 'run-attempt', 'runner-name'): parser.add_argument('--' + name, required=True)
    return run(parser.parse_args())

if __name__ == '__main__': raise SystemExit(main())
