from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import copy
import shutil
import io
import json
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import h02_dependency_probe_v2 as p
import validate_h02_dependency_probe_v2 as v

BASE = {'PATH': '/usr/bin:/bin', 'RUSTUP_HOME': '/host/rustup'}
PACKAGE = {'archive_sha256': 'a' * 64, 'vcs': {'git': {'sha1': 'b' * 40}}, 'scan': {'classification': 'HEURISTIC_UNREVIEWED', 'qualification': False, 'authority_effect': 'NONE'}}

class ProbeV2Tests(unittest.TestCase):
    def fixture_lock(self, item):
        path = ROOT / Path(item['probe_manifest']).with_name('Cargo.lock')
        if path.exists(): return path.read_bytes()
        # A complete, explicitly synthetic generated Tokio graph from the exact
        # pinned packages already in the committed OpenRaft lock. Not a real run.
        raw = (ROOT / 'probes/h02/openraft-tokio/Cargo.lock').read_text()
        start = raw.index('[[package]]\nname = "heptabao-h02-probe-openraft-tokio"')
        end = raw.index('[[package]]', start + 12)
        return (raw[:start] + '[[package]]\nname = "heptabao-h02-probe-tokio-minimal"\nversion = "0.0.0"\ndependencies = ["tokio"]\n\n' + raw[end:]).encode()

    def fixture_manifest(self, item):
        locked, edges = p.lock_edges(tomllib.loads(self.fixture_lock(item).decode()))
        identity = next(k for k in locked if k[0] == item['package'] and k[1] == item['version'])
        return {'package': {'name': item['package'], 'version': item['version']},
                'features': {feature: (['tokio-rt', 'clap'] if feature == 'default' and item['profile_id'] == p.FULL_PROFILE else []) for feature in item.get('expected_resolved_features', item['features'])},
                'dependencies': {child[0]: {'version': '=' + child[1]} for child in sorted(edges[identity])}}

    def mock_archive(self, path, item, actual_source=None):
        return {**copy.deepcopy(PACKAGE), 'manifest': self.fixture_manifest(item)}

    def metadata_fixture(self, item, work, lock):
        locked, children = p.lock_edges(tomllib.loads(lock.decode()))
        root_identity = next(k for k in locked if k[2] is None)
        active = set(); pending = [root_identity]
        while pending:
            key = pending.pop()
            if key in active: continue
            active.add(key); pending.extend(children[key])
        ids = {key: key[0] + '@' + key[1] for key in active}
        packages, nodes = [], []
        root_manifest = tomllib.loads((ROOT / item['probe_manifest']).read_text())
        features = {key: set() for key in active}
        selected = next(k for k in active if k[0] == item['package'] and k[1] == item['version'])
        features[selected].update(item.get('expected_resolved_features', item['features']))
        for dep in p.declarations(root_manifest):
            for key in active:
                if key[0] == dep['name']: features[key].update(dep['features'])
        for key in sorted(active):
            name, version, source = key
            if key == root_identity: decls = p.declarations(root_manifest)
            else:
                decls = [{'name': child[0], 'alias': child[0].replace('-', '_'), 'kind': None, 'target': None,
                          'optional': False, 'features': [], 'uses_default_features': True, 'req': '=' + child[1]}
                         for child in sorted(children[key])]
            dependencies = [{**{k:d[k] for k in ('name','kind','target','optional','features','uses_default_features','req')},
                             'rename': None if d['alias'] == d['name'].replace('-', '_') else d['alias'],
                             'source': 'registry+https://github.com/rust-lang/crates.io-index'} for d in decls]
            if name == 'openraft-memstore' and item['profile_id'] == p.FULL_PROFILE:
                next(d for d in dependencies if d['name'] == 'openraft')['features'] = ['serde', 'type-alias']
            manifest_path = str(work / 'Cargo.toml') if source is None else '/registry/' + name + '-' + version + '/Cargo.toml'
            packages.append({'id': ids[key], 'name': name, 'version': version, 'source': source,
                             'manifest_path': manifest_path, 'targets': [], 'dependencies': dependencies, 'features': {f:(['tokio-rt', 'clap'] if f == 'default' and key == selected and item['profile_id'] == p.FULL_PROFILE else []) for f in features[key]}})
            deps = [{'name': child[0].replace('-', '_'), 'pkg': ids[child], 'dep_kinds':[{'kind':None,'target':None}]} for child in sorted(children[key])]
            nodes.append({'id':ids[key], 'features':sorted(features[key]), 'dependencies':[d['pkg'] for d in deps], 'deps':deps})
        return {'packages':packages, 'workspace_members':[ids[root_identity]], 'resolve':{'root':ids[root_identity], 'nodes':nodes}}

    def tree_fixture(self, metadata):
        packages={x['id']:x for x in metadata['packages']};nodes={x['id']:x for x in metadata['resolve']['nodes']}
        rows=[];seen=set()
        def visit(node_id, depth):
            pkg=packages[node_id];text=pkg['name']+' v'+pkg['version']
            if pkg['source'] is None:text+=' ('+str(Path(pkg['manifest_path']).parent)+')'
            elif pkg['source'].startswith('git+'):text+=' ('+pkg['source'][4:]+')'
            text+='|'+','.join(nodes[node_id]['features'])
            duplicate=node_id in seen
            if duplicate:text+=' (*)'
            rows.append((depth,text))
            if duplicate:return
            seen.add(node_id)
            for child in nodes[node_id]['dependencies']:visit(child,depth+1)
        visit(metadata['resolve']['root'],0)
        return ''.join(str(depth)+text+'\n' for depth,text in rows), ''.join(text+'\n' for depth,text in rows)

    def fixture(self, root):
        evidence, execution = root / 'evidence', root / 'work'; evidence.mkdir()
        for name, (item, compiler) in p.entries().items():
            entry = evidence / name; entry.mkdir(); work = execution / name / 'probe'
            manifest = (ROOT / item['probe_manifest']).read_bytes(); lock = self.fixture_lock(item)
            lock_path = ROOT / Path(item['probe_manifest']).with_name('Cargo.lock')
            source = {'repository': 'TrillionniumFoundation/HeptaBao', 'commit': '1' * 40, 'tree': '2' * 40, 'clean_tree': True,
                      'manifest_sha256': p.sha(manifest), 'committed_lock_sha256': p.sha(lock) if lock_path.exists() else None}
            ctx = p.context(item, compiler, work, source, '42', '1', 'runner', BASE)
            ctx['source_after'] = copy.deepcopy(source); ctx['lock_before_sha256'] = ctx['lock_after_sha256'] = p.sha(lock)
            for stage in p.STAGES:
                if ctx['argv'][stage] is not None:
                    ctx['return_codes'][stage] = 0;ctx['configuration_checks'][stage] = {'before': True, 'after': True}
                    (entry / (stage + '.stdout')).write_text('synthetic output\n');(entry / (stage + '.stderr')).write_text('')
            (entry / 'rustc.stdout').write_text('rustc ' + compiler + ' (abcdef 2026-01-01)\nrelease: ' + compiler + '\nhost: ' + p.TARGET + '\n')
            (entry / 'cargo.stdout').write_text('cargo ' + compiler + ' (abcdef 2026-01-01)\n')
            metadata=self.metadata_fixture(item,work,lock); p.write(entry / 'metadata.stdout',metadata)
            dep,feat=self.tree_fixture(metadata)
            (entry/'dependency-tree.stdout').write_text(dep);(entry/'package-features.stdout').write_text(feat)
            (entry / 'Cargo.toml').write_bytes(manifest);(entry / 'Cargo.lock').write_bytes(lock)
            (entry / 'package.crate').write_bytes(b'synthetic fixture; archive verifier separately tested')
            p.write(entry / 'execution-context.json',ctx)
            with patch.object(p,'inspect_archive',side_effect=self.mock_archive):p.write(entry / 'evidence.json',p.collect(entry,ctx,item))
        return evidence, execution

    def verify(self, evidence, execution, **kw):
        with patch.object(p, 'inspect_archive', side_effect=self.mock_archive):
            v.validate(evidence, execution, ROOT, '1' * 40, '2' * 40, '42', '1', 'runner', runtime_base=BASE, **kw)

    def test_source_contract(self): self.assertEqual(v.source_contract(), 8)

    def test_eight_synthetic_mechanical_passes_preserve_behavior_unexecuted(self):
        with tempfile.TemporaryDirectory() as tmp:
            e, x = self.fixture(Path(tmp)); self.verify(e, x, require_pass=True)
            for entry in e.iterdir():
                value = p.read(entry / 'evidence.json')
                self.assertFalse(value['qualification'])
                self.assertTrue(all(c['status'] == 'UNEXECUTED' for c in value['behavioral_cases']))

    def test_profile_digests_not_relabelled(self):
        for item in p.profiles().values():
            old = p.legacy.profiles(p.legacy.load_yaml(ROOT / p.LEGACY_PLAN))[item.get('historical_minimal_profile_id', item['profile_id'])]
            self.assertNotEqual(p.legacy.profile_digest(old), p.profile_digest(item))
            self.assertEqual(old['probe_toolchains'][-1], '1.98.0')

    def test_context_relabel_negative_set(self):
        mutations = [('run_id', '43'), ('run_attempt', '2'), ('runner_name', 'other'), ('toolchain', '1.98.0'), ('source_root', '/forged'), ('target', 'other'), ('cwd', '/other'), ('profile_digest_sha256', '0' * 64)]
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                e, x = self.fixture(Path(tmp)); entry = next(e.iterdir()); c = p.read(entry / 'execution-context.json'); c[field] = value; p.write(entry / 'execution-context.json', c)
                with self.assertRaises(ValueError): self.verify(e, x)

    def test_independent_source_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            e, x = self.fixture(Path(tmp))
            with patch.object(p, 'inspect_archive', side_effect=self.mock_archive), self.assertRaises(ValueError):
                v.validate(e, x, ROOT, '3' * 40, '2' * 40, '42', '1', 'runner', runtime_base=BASE)

    def test_environment_and_commands_are_independent(self):
        for field in ('environment', 'argv'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                e, x = self.fixture(Path(tmp)); entry = next(e.iterdir()); c = p.read(entry / 'execution-context.json')
                if field == 'environment': c[field]['RUSTFLAGS'] = '--cfg forged'
                else: c[field]['check'].remove('--locked')
                p.write(entry / 'execution-context.json', c)
                with self.assertRaises(ValueError): self.verify(e, x)

    def test_receipt_and_authority_tampering(self):
        for key, value in [('qualification', True), ('authority_effect', 'AUTHORIZED'), ('mechanical_status', 'UNKNOWN'), ('problems', ['forged'])]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                e, x = self.fixture(Path(tmp)); file = next(e.iterdir()) / 'evidence.json'; data = p.read(file); data[key] = value; p.write(file, data)
                with self.assertRaises((ValueError, Exception)): self.verify(e, x)

    def test_missing_extra_and_symlink_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            e, x = self.fixture(Path(tmp)); first = next(e.iterdir()); first.rename(e / 'wrong-entry')
            with self.assertRaises(ValueError): self.verify(e, x)

    def test_mutated_raw_bytes_cannot_pass(self):
        for filename in ('Cargo.lock', 'Cargo.toml', 'metadata.stdout', 'dependency-tree.stdout', 'package.crate', 'rustc.stdout'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                e, x = self.fixture(Path(tmp)); file = next(e.iterdir()) / filename; file.write_bytes(file.read_bytes() + b'changed')
                with self.assertRaises(ValueError): self.verify(e, x)

    def test_nonzero_tree_exit_preserved_and_gate_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            e, x = self.fixture(Path(tmp)); entry = next(e.iterdir()); c = p.read(entry / 'execution-context.json'); c['return_codes']['dependency-tree'] = 1
            p.write(entry / 'execution-context.json', c)
            with patch.object(p, 'inspect_archive', side_effect=self.mock_archive): data = p.collect(entry, c, p.entries()[entry.name][0])
            self.assertEqual(data['mechanical_status'], 'EXECUTED_FAIL'); p.write(entry / 'evidence.json', data)
            self.verify(e, x)
            with self.assertRaises(ValueError): self.verify(e, x, require_pass=True)

    def test_actual_compiler_release_and_cargo_mismatch(self):
        for file, text in [('rustc.stdout', 'rustc 1.99.0 (x)\nrelease: 1.98.0\nhost: x86_64-unknown-linux-gnu\n'), ('cargo.stdout', 'cargo 1.98.0 (x)')]:
            with self.subTest(file=file), tempfile.TemporaryDirectory() as tmp:
                e, x = self.fixture(Path(tmp)); entry = next(e.iterdir()); (entry / file).write_text(text)
                with patch.object(p, 'inspect_archive', side_effect=self.mock_archive): data = p.collect(entry, p.read(entry / 'execution-context.json'), p.entries()[entry.name][0])
                self.assertNotEqual(data['mechanical_status'], 'EXECUTED_PASS')

    def test_invalid_metadata_variants(self):
        transforms = [lambda m: {}, lambda m: {**m, 'packages': []}, lambda m: {**m, 'resolve': None}, lambda m: {**m, 'workspace_members': ['forged']},
                      lambda m: {**m, 'packages': m['packages'] * 2}, lambda m: {**m, 'resolve': {**m['resolve'], 'root': 'forged'}}]
        with tempfile.TemporaryDirectory() as tmp:
            e, _ = self.fixture(Path(tmp)); entry = next(e.iterdir()); original = p.read(entry / 'metadata.stdout'); ctx = p.read(entry / 'execution-context.json'); item = p.entries()[entry.name][0]
            for transform in transforms:
                with self.subTest(transform=transform):
                    p.write(entry / 'metadata.stdout', transform(copy.deepcopy(original)))
                    with patch.object(p, 'inspect_archive', side_effect=self.mock_archive): self.assertNotEqual(p.collect(entry, ctx, item)['mechanical_status'], 'EXECUTED_PASS')

    def test_dirty_source_empty_tree_and_config_fail_closed(self):
        for mutation in ('dirty', 'tree', 'config', 'missing-lock'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                e, _ = self.fixture(Path(tmp)); entry = next(e.iterdir()); ctx = p.read(entry / 'execution-context.json')
                if mutation == 'dirty': ctx['source_after']['clean_tree'] = False
                if mutation == 'tree': (entry / 'package-features.stdout').write_text('')
                if mutation == 'config': ctx['configuration_checks']['test']['after'] = False
                if mutation == 'missing-lock': (entry / 'Cargo.lock').unlink()
                with patch.object(p, 'inspect_archive', side_effect=self.mock_archive): self.assertNotEqual(p.collect(entry, ctx, p.entries()[entry.name][0])['mechanical_status'], 'EXECUTED_PASS')

    def test_boolean_exit_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            e, x = self.fixture(Path(tmp)); file = next(e.iterdir()) / 'execution-context.json'; c = p.read(file); c['return_codes']['check'] = False; p.write(file,c)
            with self.assertRaises(ValueError): self.verify(e,x)

    def archive(self, root, *, vcs='b' * 40, unsafe=False):
        archive = root / 'candidate.crate'
        with tarfile.open(archive, 'w:gz') as out:
            for name, raw in [('.cargo_vcs_info.json', json.dumps({'git': {'sha1': vcs}}).encode()), ('Cargo.toml', b'[package]\nname="fixture"\nversion="1.0"\n'), ('lib.rs', b'unsafe fn f() {}')]:
                info = tarfile.TarInfo('../escape' if unsafe else 'fixture-1.0/' + name); info.size = len(raw); out.addfile(info, io.BytesIO(raw))
        return archive, {'package': 'fixture','version':'1.0','expected_registry_checksum_sha256':p.file_sha(archive),'expected_release_commit_sha':'b'*40}

    def test_real_archive_checksum_vcs_and_heuristic_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, item = self.archive(Path(tmp)); result = p.inspect_archive(archive,item)
            self.assertEqual(result['scan']['heuristic_unsafe_occurrences'],1)
            self.assertFalse(result['scan']['qualification'])
            item['expected_registry_checksum_sha256']='0'*64
            with self.assertRaises(ValueError):p.inspect_archive(archive,item)

    def test_archive_vcs_and_path_negatives(self):
        for options in ({'vcs':'0'*40},{'unsafe':True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                archive,item=self.archive(Path(tmp),**options)
                with self.assertRaises(ValueError):p.inspect_archive(archive,item)

    def test_cached_source_archive_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive,item=self.archive(root);source=root/'source';source.mkdir()
            with self.assertRaises(ValueError):p.inspect_archive(archive,item,source)

    def test_duplicate_json_nonfinite_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'x.json'
            for raw in ['{"a":1,"a":2}', '{"a":NaN}', '{"a":1e9999}']:
                file.write_text(raw)
                with self.assertRaises(ValueError):p.read(file)
            link=Path(tmp)/'link';link.symlink_to(file)
            with self.assertRaises(ValueError):p.read(link)


    def test_cached_source_extra_build_and_symlinks_rejected(self):
        for mutation in ('extra-build', 'nested-extra', 'symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);archive,item=self.archive(root);source=root/'source';source.mkdir()
                (source/'.cargo_vcs_info.json').write_text(json.dumps({'git': {'sha1': 'b'*40}}))
                (source/'lib.rs').write_bytes(b'unsafe fn f() {}')
                (source/'Cargo.toml').write_bytes(b'[package]\nname="fixture"\nversion="1.0"\n')
                (source/'.cargo-ok').write_text('generated marker')
                p.inspect_archive(archive,item,source)
                if mutation == 'extra-build': (source/'build.rs').write_text('fn main() {}')
                elif mutation == 'nested-extra': (source/'src').mkdir(); (source/'src/extra.rs').write_text('')
                else: (source/'extra').symlink_to(source/'lib.rs')
                with self.assertRaises(ValueError): p.inspect_archive(archive,item,source)

    def test_ignored_ancestor_configuration_blocks_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); work=root/'entry/probe';work.mkdir(parents=True)
            ctx=p.context(next(iter(p.profiles().values())), '1.71.0', work, {}, '42','1','runner',BASE)
            self.assertTrue(p.common.configuration_absent(ctx))
            (root/'.cargo').mkdir();(root/'.cargo/config.toml').write_text('[build]\nrustflags=["--cfg","forged"]\n')
            self.assertFalse(p.common.configuration_absent(ctx))

    def test_runner_package_failure_skips_native_but_retains_eight(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); fixtures=root/'fixtures';fixtures.mkdir(); e,x=self.fixture(fixtures)
            entries=p.entries(); calls=[]
            source=root/'source';source.mkdir();(source/'planning').mkdir()
            shutil.copyfile(ROOT/p.FULL_CONTRACT,source/p.FULL_CONTRACT)
            args=argparse.Namespace(source_root=source,evidence_root=root/'out',execution_root=root/'exec',expected_commit='1'*40,run_id='42',run_attempt='1',runner_name='runner')
            def snap(_root,item):
                name=next(n for n,(i,c) in entries.items() if i['profile_id']==item['profile_id'])
                return p.read(e/name/'execution-context.json')['source_before']
            def materialize(_root,work,item,commit):
                work.mkdir(parents=True)
                fixture=e/work.parent.name
                shutil.copyfile(fixture/'Cargo.toml',work/'Cargo.toml')
                if item['package']!='tokio':shutil.copyfile(fixture/'Cargo.lock',work/'Cargo.lock')
            def execute(ctx,stage,entry):
                calls.append((entry.name,stage))
                for suffix in ('stdout','stderr'):shutil.copyfile(e/entry.name/(stage+'.'+suffix),entry/(stage+'.'+suffix))
                if stage=='lock':shutil.copyfile(e/entry.name/'Cargo.lock',Path(ctx['cwd'])/'Cargo.lock')
                ctx['return_codes'][stage]=0;ctx['configuration_checks'][stage]={'before':True,'after':True}
                return 0
            with patch.object(p,'ROOT',source),patch.object(p,'entries',return_value=entries),patch.object(p,'snapshot',side_effect=snap),patch.object(p,'materialize',side_effect=materialize),patch.object(p.common,'execute',side_effect=execute),patch.object(p.common,'runtime_base_environment',return_value=BASE),patch.object(p,'capture_package',side_effect=ValueError('hostile cached build.rs')):
                self.assertEqual(p.run(args),0)
            self.assertEqual(len(list(args.evidence_root.iterdir())),8)
            self.assertFalse(any(stage in {'check','test'} for _,stage in calls))
            self.assertTrue(all(p.read(entry/'evidence.json')['mechanical_status']!='EXECUTED_PASS' for entry in args.evidence_root.iterdir()))


    def test_review_pruned_two_node_graph_rejected_without_archive_mock(self):
        item=next(i for i in p.profiles().values() if i['package']=='openraft')
        lock=tomllib.loads(self.fixture_lock(item).decode());work=Path('/expected/probe')
        metadata=self.metadata_fixture(item,work,self.fixture_lock(item));root=metadata['resolve']['root']
        candidate=next(x['id'] for x in metadata['packages'] if x['name']=='openraft')
        metadata['packages']=[x for x in metadata['packages'] if x['id'] in {root,candidate}]
        metadata['resolve']['nodes']=[n for n in metadata['resolve']['nodes'] if n['id'] in {root,candidate}]
        for node in metadata['resolve']['nodes']:
            node['deps']=[d for d in node['deps'] if node['id']==root and d['pkg']==candidate]
            node['dependencies']=[d['pkg'] for d in node['deps']]
        with self.assertRaises(ValueError):p.metadata_graph(metadata,item,work,lock)

    def test_root_and_candidate_declaration_truncation_rejected(self):
        item=next(i for i in p.profiles().values() if i['package']=='openraft');work=Path('/expected/probe');raw=self.fixture_lock(item);lock=tomllib.loads(raw.decode())
        for name in ('heptabao-h02-probe-openraft-tokio','openraft'):
            with self.subTest(package=name):
                metadata=self.metadata_fixture(item,work,raw)
                package=next(x for x in metadata['packages'] if x['name']==name);package['dependencies']=package['dependencies'][1:]
                with self.assertRaises(ValueError):p.metadata_graph(metadata,item,work,lock,self.fixture_manifest(item))

    def test_dependency_ids_lock_edges_and_reachability_negatives(self):
        item=next(i for i in p.profiles().values() if i['package']=='openraft');work=Path('/expected/probe');raw=self.fixture_lock(item)
        for mutation in ('ids','lock-edge','unreachable','mandatory'):
            with self.subTest(mutation=mutation):
                lock=tomllib.loads(raw.decode());metadata=self.metadata_fixture(item,work,raw);root=next(n for n in metadata['resolve']['nodes'] if n['id']==metadata['resolve']['root'])
                if mutation=='ids':root['dependencies']=root['dependencies'][1:]
                elif mutation=='lock-edge':next(x for x in lock['package'] if x.get('source') is None)['dependencies']=[]
                elif mutation=='mandatory':root['deps']=root['deps'][1:];root['dependencies']=[d['pkg'] for d in root['deps']]
                else:
                    fake={'name':'unused','version':'1.0.0','source':'registry+https://github.com/rust-lang/crates.io-index'};lock['package'].append(fake)
                    metadata['packages'].append({**fake,'id':'unused','manifest_path':'/unused/Cargo.toml','targets':[],'dependencies':[],'features':{}})
                    metadata['resolve']['nodes'].append({'id':'unused','features':[],'dependencies':[],'deps':[]})
                with self.assertRaises(ValueError):p.metadata_graph(metadata,item,work,lock,self.fixture_manifest(item))

    def test_inactive_optional_lock_package_need_not_resolve(self):
        item=next(i for i in p.profiles().values() if i['package']=='openraft');work=Path('/expected/probe');raw=self.fixture_lock(item);lock=tomllib.loads(raw.decode());metadata=self.metadata_fixture(item,work,raw)
        fake={'name':'unused','version':'1.0.0','source':'registry+https://github.com/rust-lang/crates.io-index'};lock['package'].append(fake)
        leaf=next(p_ for p_ in metadata['packages'] if p_['name']=='autocfg')
        leaf['dependencies'].append({'name':'unused','rename':None,'kind':None,'target':None,'optional':True,'features':[],'uses_default_features':True,'req':'=1.0.0','source':fake['source']})
        next(p_ for p_ in lock['package'] if p_['name']=='autocfg')['dependencies']=['unused']
        p.metadata_graph(metadata,item,work,lock,self.fixture_manifest(item))

    def test_review_arbitrary_trees_rejected_after_recollection(self):
        for file in ('dependency-tree.stdout','package-features.stdout'):
            with self.subTest(file=file),tempfile.TemporaryDirectory() as tmp:
                e,x=self.fixture(Path(tmp));entry=next(e.iterdir());(entry/file).write_text('NOT A CARGO TREE\n')
                with patch.object(p,'inspect_archive',side_effect=self.mock_archive):value=p.collect(entry,p.read(entry/'execution-context.json'),p.entries()[entry.name][0])
                self.assertNotEqual(value['mechanical_status'],'EXECUTED_PASS');p.write(entry/'evidence.json',value)
                with self.assertRaises(ValueError):self.verify(e,x,require_pass=True)

    def test_review_numeric_clean_tree_rejected_all_eight(self):
        with tempfile.TemporaryDirectory() as tmp:
            e,x=self.fixture(Path(tmp))
            for entry in e.iterdir():
                c=p.read(entry/'execution-context.json');c['source_after']['clean_tree']=1;p.write(entry/'execution-context.json',c)
                with patch.object(p,'inspect_archive',side_effect=self.mock_archive):value=p.collect(entry,c,p.entries()[entry.name][0])
                self.assertNotEqual(value['mechanical_status'],'EXECUTED_PASS');p.write(entry/'evidence.json',value)
            with self.assertRaises(ValueError):self.verify(e,x,require_pass=True)

    def test_typed_tree_edge_feature_source_and_depth_negatives(self):
        item=next(i for i in p.profiles().values() if i['package']=='openraft');metadata=self.metadata_fixture(item,Path('/expected/probe'),self.fixture_lock(item));text,projection=self.tree_fixture(metadata)
        for mutation in (text.replace('0heptabao','2heptabao',1),text.replace('/expected/probe','/wrong/probe',1),text.replace('|','|unknown_feature,',1),text.splitlines()[0]+'\n',text.replace('7016fa5e072a86092928144b3a3040381e6964e9)','0000000)',1)):
            with self.subTest(mutation=mutation[:70]),self.assertRaises(ValueError):p.tree_observation(mutation,metadata,depth=True)
        p.tree_observation(text,metadata,depth=True);p.tree_observation(projection,metadata,depth=False)


    @classmethod
    def native_fixture(cls):
        if not hasattr(cls, '_native_fixture'):
            outer=json.loads((ROOT/'tests/platform/fixtures/h02_mechanical_hosted_37247651462.json').read_text())
            raw=gzip.decompress(base64.b64decode(outer['payload'],validate=True))
            assert len(raw)==outer['decompressed_bytes'] and hashlib.sha256(raw).hexdigest()==outer['decompressed_sha256']
            cls._native_fixture=json.loads(raw)
        return cls._native_fixture

    def native_item(self, record):
        return p.profiles()[p.FULL_PROFILE if record['profile_id']=='HB-H02-PROBE-OPENRAFT-TOKIO' else record['profile_id']]

    def test_native_all_eight_typed_views_and_original_failures_retained(self):
        fixture=self.native_fixture();self.assertEqual(fixture['source_commit'],'fe021e4995fda5c73ca11dcfbfea28409b015a23')
        self.assertEqual(fixture['original_zip_sha256'],'b9193de0c2529a18e550741341f53548951de3960ffb3aabeaf06ec0a275b8ec')
        statuses=[]
        for record in fixture['entries']:
            with self.subTest(entry=record['name']):
                metadata=json.loads(record['metadata_raw']);self.assertEqual(hashlib.sha256(record['metadata_raw'].encode()).hexdigest(),record['metadata_sha256'])
                p.tree_observation(record['dependency_tree'],metadata,depth=True)
                p.tree_observation(record['package_features'],metadata,depth=False)
                p.metadata_graph(metadata,self.native_item(record),Path(record['work']),tomllib.loads(record['lock_raw']))
                original=record['original_evidence'];statuses.append(original['mechanical_status']);self.assertFalse(original['qualification'])
                if 'OPENRAFT' in record['profile_id'] or 'TOKIO-MINIMAL' in record['profile_id']:
                    self.assertIsNone(record['return_codes']['check']);self.assertIsNone(record['return_codes']['test'])
        self.assertEqual(statuses.count('EXECUTED_PASS'),2);self.assertEqual(statuses.count('BLOCKED'),6)

    def test_native_tokio_comparator_whitespace_and_inequivalent_negatives(self):
        fixture=self.native_fixture();source=fixture['tokio_upstream_manifest'];raw=source['content'].encode()
        self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),source['sha'])
        manifest=tomllib.loads(source['content'])
        self.assertEqual(manifest['target']['cfg(all(tokio_unstable, target_has_atomic = "64"))']['dev-dependencies']['tracing-mock'],'= 0.1.0-beta.1')
        for record in fixture['entries']:
            if 'TOKIO-MINIMAL' not in record['profile_id']:continue
            metadata=json.loads(record['metadata_raw']);candidate=next(x for x in metadata['packages'] if x['name']=='tokio')
            p.bind_declarations(candidate,manifest)
            for replacement in ('<0.1.0-beta.1','=0.1.0-beta.2','=0.1 .0-beta.1'):
                forged=copy.deepcopy(candidate);next(d for d in forged['dependencies'] if d['name']=='tracing-mock')['req']=replacement
                with self.assertRaises(ValueError):p.bind_declarations(forged,manifest)
        self.assertEqual(p.requirement_text('= 0.1.0-beta.1'),'=0.1.0-beta.1')
        self.assertNotEqual(p.requirement_text('=0.1 .0-beta.1'),'=0.1.0-beta.1')

    def test_native_rustls_authenticated_manifest_binding(self):
        fixture=self.native_fixture();binding=fixture['authenticated_rustls_manifest']
        self.assertEqual(binding['crate_sha256'],'0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06')
        self.assertEqual(hashlib.sha256(binding['manifest_raw'].encode()).hexdigest(),binding['manifest_sha256'])
        manifest=tomllib.loads(binding['manifest_raw'])
        for record in fixture['entries']:
            if 'RUSTLS' not in record['profile_id']:continue
            metadata=json.loads(record['metadata_raw'])
            p.metadata_graph(metadata,self.native_item(record),Path(record['work']),tomllib.loads(record['lock_raw']),manifest)

    def test_native_weak_reference_does_not_admit_active_node_removal(self):
        record=next(x for x in self.native_fixture()['entries'] if 'AWS-LC' in x['profile_id'])
        metadata=json.loads(record['metadata_raw']);nodes,edges=p.projected_graph(metadata)
        self.assertEqual(len(metadata['packages']),34);self.assertEqual(len(nodes),20)
        for mode in ('weak-to-strong','optional-to-mandatory','drop-active-tree-row','drop-mandatory-metadata-edge'):
            with self.subTest(mode=mode):
                forged=copy.deepcopy(metadata);text=record['dependency_tree'];webpki=next(x for x in forged['packages'] if x['name']=='rustls-webpki')
                if mode=='weak-to-strong':webpki['features']['alloc']=[r.replace('ring?/','ring/') for r in webpki['features']['alloc']]
                elif mode=='optional-to-mandatory':next(d for d in webpki['dependencies'] if d['name']=='ring')['optional']=False
                elif mode=='drop-active-tree-row':text='\n'.join(row for row in text.splitlines() if 'rustls-webpki v' not in row)+'\n'
                else:
                    root=next(n for n in forged['resolve']['nodes'] if n['id']==forged['resolve']['root']);root['deps']=root['deps'][1:];root['dependencies']=[d['pkg'] for d in root['deps']]
                    with self.assertRaises(ValueError):p.metadata_graph(forged,self.native_item(record),Path(record['work']),tomllib.loads(record['lock_raw']))
                    continue
                with self.assertRaises(ValueError):p.tree_observation(text,forged,depth=True)

    def test_native_full_profile_is_distinct_and_minimal_remains_blocked(self):
        minimal=p.minimal_profiles()['HB-H02-PROBE-OPENRAFT-TOKIO'];full=p.profiles()[p.FULL_PROFILE]
        self.assertEqual(minimal['forbidden_feature_expansion'],['clap','runtime-stats']);self.assertNotEqual(p.profile_digest(minimal),p.profile_digest(full))
        for record in self.native_fixture()['entries']:
            if 'OPENRAFT' not in record['profile_id']:continue
            metadata=json.loads(record['metadata_raw']);lock=tomllib.loads(record['lock_raw'])
            with self.assertRaisesRegex(ValueError,'resolved feature expansion/drift'):p.metadata_graph(metadata,minimal,Path(record['work']),lock)
            p.metadata_graph(metadata,full,Path(record['work']),lock)
            for feature in ('runtime-stats','missing-clap'):
                changed=copy.deepcopy(metadata);candidate=next(x for x in changed['packages'] if x['name']=='openraft');node=next(n for n in changed['resolve']['nodes'] if n['id']==candidate['id'])
                if feature=='runtime-stats':node['features'].append(feature)
                else:node['features'].remove('clap')
                with self.assertRaises(ValueError):p.metadata_graph(changed,full,Path(record['work']),lock)

    def test_verified_archive_retained_before_contract_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive,item=self.archive(root);home=root/'cargo';source=home/'registry/src/index/fixture-1.0';source.mkdir(parents=True);cache=home/'registry/cache/index';cache.mkdir(parents=True)
            shutil.copyfile(archive,cache/'fixture-1.0.crate')
            (source/'.cargo_vcs_info.json').write_text(json.dumps({'git':{'sha1':'b'*40}}));(source/'Cargo.toml').write_bytes(b'[package]\nname="fixture"\nversion="1.0"\n');(source/'lib.rs').write_bytes(b'unsafe fn f() {}')
            entry=root/'entry';entry.mkdir();(entry/'Cargo.lock').write_text('version=3\n')
            p.write(entry/'metadata.stdout',{'packages':[{'name':'fixture','version':'1.0','source':'registry+https://github.com/rust-lang/crates.io-index','manifest_path':str(source/'Cargo.toml')}]})
            ctx={'environment':{'CARGO_HOME':str(home)},'cwd':str(root/'work')}
            with patch.object(p,'metadata_graph',side_effect=ValueError('later profile rejection')),self.assertRaisesRegex(ValueError,'later profile rejection'):p.capture_package(entry,ctx,item)
            self.assertEqual((entry/'package.crate').read_bytes(),archive.read_bytes())
            (entry/'package.crate').unlink();bad=dict(item,expected_registry_checksum_sha256='0'*64)
            with self.assertRaises(ValueError):p.capture_package(entry,ctx,bad)
            self.assertFalse((entry/'package.crate').exists())

    def test_missing_archive_is_not_reported_as_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'archive evidence missing'):p.inspect_archive(Path(tmp)/'missing.crate',{'expected_registry_checksum_sha256':'0'*64})


    def test_authenticated_explicit_and_implicit_feature_normalization(self):
        manifest={'features':{'logging':['log'],'hidden-group':['dep:hidden'],'weak':['other?/x'],'strong':['alias-name/x']},
                  'dependencies':{'log':{'version':'1','optional':True},'hidden':{'version':'1','optional':True},'other':{'version':'1','optional':True},'alias-name':{'package':'renamed-package','version':'1','optional':True}},
                  'target':{'cfg(unix)':{'build-dependencies':{'conditional':{'version':'1','optional':True}}}}}
        expected={'logging':['log'],'hidden-group':['dep:hidden'],'weak':['other?/x'],'strong':['alias-name/x'],
                  'log':['dep:log'],'other':['dep:other'],'alias-name':['dep:alias-name'],'conditional':['dep:conditional']}
        self.assertEqual(p.manifest_feature_definitions(manifest),expected)
        p.bind_feature_definitions({'features':expected},manifest)
        for key in ('log','other','alias-name','conditional'):
            forged=copy.deepcopy(expected);forged[key]=[]
            with self.assertRaises(ValueError):p.bind_feature_definitions({'features':forged},manifest)
        self.assertNotIn('hidden',expected)

    def test_review_native_log_erasure_rejected_after_recollection(self):
        fixture=self.native_fixture();manifest=tomllib.loads(fixture['authenticated_rustls_manifest']['manifest_raw'])
        self.assertNotIn('log',manifest['features'])
        self.assertEqual(p.manifest_feature_definitions(manifest)['log'],['dep:log'])
        for record in fixture['entries']:
            if 'RUSTLS-RING' not in record['profile_id']:continue
            with self.subTest(entry=record['name']),tempfile.TemporaryDirectory() as tmp:
                e,x=self.fixture(Path(tmp));entry=e/record['name'];item=self.native_item(record);metadata=json.loads(record['metadata_raw'])
                candidate=next(pkg for pkg in metadata['packages'] if pkg['name']=='rustls');candidate['features']['log']=[]
                dep='\n'.join(row for row in record['dependency_tree'].splitlines() if 'log v0.4.' not in row)+'\n'
                features='\n'.join(row for row in record['package_features'].splitlines() if 'log v0.4.' not in row)+'\n'
                with self.assertRaisesRegex(ValueError,'feature definitions differ'):
                    p.metadata_graph(metadata,item,Path(record['work']),tomllib.loads(record['lock_raw']),manifest)
                p.write(entry/'metadata.stdout',metadata);(entry/'dependency-tree.stdout').write_text(dep);(entry/'package-features.stdout').write_text(features)
                ctx=p.read(entry/'execution-context.json');ctx['cwd']=record['work'];p.write(entry/'execution-context.json',ctx)
                with patch.object(p,'inspect_archive',return_value={**PACKAGE,'manifest':manifest}):value=p.collect(entry,ctx,item)
                self.assertNotEqual(value['mechanical_status'],'EXECUTED_PASS')
                self.assertTrue(any('feature definitions differ' in problem for problem in value['problems']))

    def test_native_root_feature_definition_forgery_rejected(self):
        record=next(x for x in self.native_fixture()['entries'] if 'RUSTLS-RING' in x['profile_id'])
        metadata=json.loads(record['metadata_raw']);root=next(pkg for pkg in metadata['packages'] if pkg['id']==metadata['resolve']['root']);root['features']['forged']=[]
        with self.assertRaisesRegex(ValueError,'feature definitions differ'):
            p.metadata_graph(metadata,self.native_item(record),Path(record['work']),tomllib.loads(record['lock_raw']))

if __name__ == '__main__': unittest.main()
