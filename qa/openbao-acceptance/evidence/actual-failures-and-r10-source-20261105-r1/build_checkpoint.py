#!/usr/bin/env python3
"""Preserve the exact reviewed failure/source checkpoint with explicit gaps."""
from pathlib import Path
import gzip, hashlib, io, json, re, tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
files = {}
sha = lambda data: hashlib.sha256(data).hexdigest()

def add(path, name):
    path = Path(path)
    assert path.is_file() and not path.is_symlink()
    raw = path.read_bytes()
    assert re.search(rb'(?m)^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?$', raw) is None
    assert name not in files and not name.startswith('/') and '..' not in Path(name).parts
    files[name] = raw

def flat(relative, prefix):
    directory = ROOT / relative
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix in ('.json', '.py', '.patch', '.diff', '.rs', '.stderr', '.original'):
            add(path, prefix + '/' + path.name)

flat('r6_mac_build_prepare/recovered-original-evidence-r1', 'r6-original-failure')
flat('r8_mac_build_prepare/evidence', 'r8-original-failure')
flat('r9_compile_fix_prepare/evidence-r1', 'r9-original-failure')
flat('r9_pocket_build_prepare/live-initial-evidence-r1', 'r9-pocket-initial')
flat('r10_native128_readindex_prepare/parent-draft-r1', 'r10-parent-draft')
flat('original-native-adapter/r5-frozen-history204-r2', 'r5-strict-history-wire')
flat('r7_readindex_client_evidence/late-original-operation-readback', 'r7-late-read-operation')
for name in ['failure-bundle-original-sdk-payload-r1.json', 'failure-bundle-async-pages-r1.json',
             'root-original-evidence-review.public.json', 'root_review_original_evidence.py']:
    add(ROOT / 'r9_compile_fix_prepare' / name, 'r9-original-failure/' + name)
for name in ['worker-request.json', 'worker-started.json']:
    add(ROOT / 'r5_matched27_evidence' / name, 'r5-matched27-original-worker/' + name)
for part in ['parent', 'candidate']:
    name = 'crates/heptabao-server/src/http_response_framing_tests.rs'
    add(ROOT / 'r10_test_initializer_prepare' / part / name, 'r10-source-review/' + part + '/' + name)
flat('r10_test_initializer_prepare', 'r10-source-review')
for name in ['remote_commit.json', 'raw_commit.json', 'source-read-probe-first-failure.public.json']:
    add(ROOT / 'r10_publish_prepare' / name, 'r10-published-source/' + name)
add(HERE / 'build_checkpoint.py', 'build_checkpoint.py')

review = json.loads(files['r9-original-failure/root-original-evidence-review.public.json'])
assert review['r9_mac']['actual_terminal'] == 'failed' and review['r9_mac']['build_test_qualified'] is False
assert review['r9_pocket_initial_observation']['normal_terminal_observed_in_this_review'] is False
assert review['formal_dr25_executions'] == 0 and review['replacement_qualified'] is False
source = json.loads(files['r10-source-review/root-review.public.json'])
assert source['source_change_approved'] is True and source['build_test_qualification'] is False
gaps = [
    {'stage': 'R6 normal release', 'missing': 'full original Cargo stdout',
     'sha256': '29b3a9c6ed8c4fa1b0b49ec1a23f559d447d065d2fdf2801260d1c670e30f3d0'},
    {'stage': 'R8 normal release', 'missing': 'full original Cargo stdout',
     'sha256': '9012fc1a4dffcbc19b54d81a9fb8b79b54e01818efdd099cedfdcff02d437837'},
    {'stage': 'R9 normal release', 'missing': 'full original Cargo stdout',
     'sha256': '3d664fc4514c82465c5a515831d801f19864142ffc97897cf3881b2f43ba81f2'},
    {'stage': 'R9 normal server libtest', 'missing': 'full original Cargo stdout',
     'sha256': '9b9779d43d675df3a3b9760cd80d71553c196aa349daff5c7f8c3a09976466d7'},
    {'stage': 'R9 Pocket source stage', 'missing': 'complete original 527-byte executor stdout; initial retrieval timed out'},
    {'stage': 'R9 Pocket normal build', 'missing': 'terminal and result in this initial-observation checkpoint'},
    {'stage': 'R7 current Mac response control42', 'missing': 'actual test terminal and result; recovered async read failed as a read operation'},
]
scope = {'schema': 'heptabao.actual-failure-and-source-checkpoint.v1',
    'status': 'verified_original_bytes_with_explicit_remaining_gaps',
    'r6_mac_build': 'failed Cargo101, normal release',
    'r8_mac_build': 'failed Cargo101, normal release',
    'r9_mac_build': 'failed overall: normal release Cargo0; server libtest Cargo101 E0063',
    'r9_mac_normal_server_sha256': '50ecac89156c862e6111f1460ed8f73b4872c61a9ef7fd9a9e4bc640f5981b73',
    'r9_mac_runtime_tests_started': False,
    'r9_pocket_normal': 'original running observation only; no terminal or qualification in this checkpoint',
    'r10_source_commit': 'b33b8d0de9c7689ff89f8ed11cd2151726972f4f',
    'r10_source_tree': '89a8af5b7bcb1d7472e1f12e1dec7adb7d2cf726',
    'r10_exact_change': 'existing test initializer adds status: None; no assertion, production code or budget change',
    'r10_build_or_test_qualification': False,
    'r10_parent_adapter': 'DRAFT; unchanged function ASTs; actual new owner21 not submitted',
    'r5_matched27_original_worker_addendum': 'actual old worker request and started files; does not change failed matched27 outcome',
    'r5_original_strict_history_wire_recovered': True,
    'r7_async_read_failure_is_not_test_failure': True,
    'missing_originals_or_terminal_observations': gaps,
    'formal_dr25_executions': 0, 'formal_kv2_qualified': False, 'physical_ha_qualified': False,
    'authbus_qualified': False, 'production_changed': False, 'traffic_cutover': False,
    'old_assets_deleted': False, 'replacement_qualified': False}
scope_raw = (json.dumps(scope, sort_keys=True, indent=2) + '\n').encode()
(HERE / 'scope.public.json').write_bytes(scope_raw)
files['scope.public.json'] = scope_raw

def archive():
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600; info.mtime = 0
                info.uid = info.gid = 0; info.uname = info.gname = ''
                tar.addfile(info, io.BytesIO(raw))
    return output.getvalue()

raw = archive(); assert archive() == raw
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
    assert len(tar.getmembers()) == len(files)
    for member in tar.getmembers():
        assert member.isfile() and tar.extractfile(member).read() == files[member.name]
path = HERE / 'actual-failures-and-r10-source-checkpoint.tar.gz'; path.write_bytes(raw)
manifest = {'schema': 'heptabao.exact-checkpoint-manifest.v1', 'archive': path.name, 'bytes': len(raw),
    'sha256': sha(raw), 'deterministic_rebuild_equal': True, 'all_members_reextracted_and_byte_compared': True,
    'files': [{'path': k, 'bytes': len(v), 'sha256': sha(v)} for k, v in sorted(files.items())],
    'original_evidence_complete': False, 'scope_sha256': sha(scope_raw), 'replacement_qualified': False}
(HERE / 'manifest.public.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
print(json.dumps({'archive': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'members': len(files), 'complete': False}))
