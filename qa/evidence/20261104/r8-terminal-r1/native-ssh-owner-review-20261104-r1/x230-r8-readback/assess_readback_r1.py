from pathlib import Path
import hashlib
import json
import os

R = Path(__file__).resolve().parent
def sha(b): return hashlib.sha256(b).hexdigest()
def read(n): return json.loads((R / n).read_bytes())
def ref(n):
    b = (R / n).read_bytes()
    return {'path': n, 'bytes': len(b), 'sha256': sha(b)}
expected = {'commit': '384c957612186d64c5a530044af0ae62c568cc3d',
            'tree': 'd5a0f91a4d47f7c8d5f34170ea167d10dc036e04',
            'binary_sha256': '666370dba0a1e2df4cb2b3177f54b1e190bc2a281aa64fd8501c4625f30e74ed',
            'dirty_including_untracked': False}
rows = []
for label, job in [('full34', '1a1a73477dc-fc05-2a8f'), ('comparison69', '1a1a73831f6-fc05-2a9a')]:
    outer = read(label + '-result.public.json')
    summary = read(label + '-summary.public.json')
    intent = read(label + '-intent.public.json')
    terminal = read(label + '-status.public.json')
    assert outer['ok'] and outer['child_exit_code'] == 0
    assert outer['source_before'] == outer['source_after'] == expected and outer['source_unchanged']
    assert ref(label + '-summary.public.json')['sha256'] == outer['summary_sha256']
    assert ref(label + '-summary.public.json')['bytes'] == outer['summary_bytes']
    assert terminal['job_id'] == job and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
    assert terminal['output_complete'] and terminal['output_durable'] and terminal['terminal_publication_confirmed']
    assert not terminal['timed_out'] and not terminal['cancelled']
    assert (R / (label + '-run.stderr')).read_bytes() == b''
    if label == 'full34':
        checks = summary['checks']
        names = [c['case'] for c in checks]
        assert len(checks) == len(set(names)) == 31 and all(c['passed'] is True for c in checks)
        assert summary['status'] == 'passed' and summary['full34_qualified']
        assert summary['source_commit'] == expected['commit'] and summary['source_tree'] == expected['tree']
        assert summary['binary_sha256'] == expected['binary_sha256'] and not summary['source_dirty']
        assert summary['live_payload_bytes'] == 34 * 1024 * 1024 and summary['tls_verified']
        assert summary['target_storage_precision_qualified'] and summary['synthetic_only']
        assert not summary['production_authority'] and not summary['replacement_authority']
        assert 'owned_processes_stopped' in names and outer['owned_processes_stopped']
        assert intent['driver_sha256'] == '383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581'
        assert intent['original_http_seconds'] == 15 and intent['original_migration_seconds'] == 360
        counts = {'passed': 31, 'total': 31, 'case_names': names, 'live_payload_bytes': summary['live_payload_bytes']}
    else:
        assert summary['status'] == 'passed_scoped_cases' and summary['cases_match'] and not summary['mismatched_cases']
        assert summary['owned_cleanup_completed'] and not summary['cleanup_errors'] and summary['source_and_binary_unchanged']
        assert not summary['full_openbao_compatibility'] and not summary['production_qualified']
        assert summary['execution_binding']['candidate_source_sha'] == expected['commit']
        assert summary['execution_binding']['candidate_binary_sha256'] == expected['binary_sha256']
        assert summary['execution_binding']['runner_source_sha256'] == 'fd88ed0b8f1c1010e79f9393dfbf6464cabcac48ece8c6e448a64b7ccc45272e'
        oracle = summary['execution_binding']['official_oracle']
        assert oracle['version'] == '2.7.1' and oracle['tls_verified'] and oracle['archive_member_matches_executable']
        assert oracle['binary_sha256'] == '535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea'
        assert oracle['artifact_sha256'] == '0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243'
        assert summary['native_storage']['activation_status'] == 204 and not summary['native_storage']['fixture_options']
        scopes = ['approle', 'core', 'edge_tls', 'identity', 'kv', 'operations', 'pki', 'system', 'token', 'totp', 'transit', 'userpass', 'wrapping']
        assert summary['scope'] == intent['default_modules'] == scopes
        counts = {}
        for side in ['candidate_results', 'oracle_results']:
            cases = summary[side]['cases']
            assert len(cases) == 69 and all(c['result'] == 'passed' for c in cases.values())
            assert summary[side]['cleanup']['result'] == 'passed'
            counts[side] = {'total': 69, 'passed': 69, 'not_run': 0, 'failed': 0, 'case_names': sorted(cases)}
        assert counts['candidate_results']['case_names'] == counts['oracle_results']['case_names']
        counts['scope'] = scopes
        counts['ssh_covered'] = False
    rows.append({'label': label, 'job_id': job, 'counts': counts, 'elapsed_seconds': outer['elapsed_seconds'],
                 'authoritative_terminal_complete_durable': True, 'source_and_binary_unchanged': True,
                 'owned_cleanup_confirmed': True, 'originals': [ref(label + '-' + n) for n in
                 ['result.public.json','summary.public.json','intent.public.json','status.public.json','run.stdout','run.stderr']]})
out = {'schema': 'heptabao.r8-x230-original31-and69-readback.v1', 'host': 'x230', 'source_binding': expected,
       'qualification': rows, 'original_driver_predicates_and_inner_budgets_retained': True,
       'full34_http_seconds': 15, 'full34_migration_seconds': 360,
       'two_distinct_fresh_owned_loopback_runs': True, 'production_changed': False,
       'full_openbao_compatibility_qualified': False, 'cross_platform_r8_qualified': False,
       'actual_production_consumer_qualified': False, 'new_runtime_started_by_assessor': False,
       'read_transport_errors_are_not_runtime_outcomes': True}
b = (json.dumps(out, indent=2) + '\n').encode()
with (R / 'readback-assessment.public.json').open('xb') as f: f.write(b);f.flush();os.fsync(f.fileno())
print(json.dumps({'bytes': len(b), 'sha256': sha(b), 'full34': '31/31', 'comparison69': '69/69 each', 'full_replacement': False}))
