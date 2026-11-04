#!/usr/bin/env python3
"""Independent source/archive/control review of the exact ROG profile-1 r2 run."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
R = ROOT / 'evidence/raw'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def main():
    review = ROOT / 'evidence/agent-review.public.json'
    expected = '73c1b25e517cc68d314673b178fd444fa5bd84aaaa556e017fcf5c80dfe3e417'
    assert sha(review) == expected
    assert sha(ROOT / 'review_evidence.py') == '6ef2035f12bd8a9ae357cbaff26d09c3408f02632a8872af85901c2246d22c7e'
    execution = subprocess.run([sys.executable, str(ROOT / 'review_evidence.py')],
                               capture_output=True, check=True, timeout=30)
    assert not execution.stderr and execution.stdout == review.read_bytes()
    agent = json.loads(execution.stdout)
    packet = read(ROOT / 'stage-input.json')
    stage = read(R / 'control/stage.public.json')
    freeze = read(ROOT / 'source-freeze.public.json')
    assert sha(ROOT / 'stage-input.json') == freeze['payloadSha256'] == stage['payloadSha256']
    assert packet['root'] == freeze['root'] and len(stage['pins']) == 34
    embedded = {}
    for name, source in packet['embedded'].items():
        pin = hashlib.sha256(source.encode()).hexdigest()
        assert pin == freeze['embeddedPins'][name] == stage['pins'][packet['root'] + '/control/' + name]
        if name != 'prior-provider-proof.public.json':
            assert (ROOT / name).read_bytes() == source.encode()
        embedded[name] = pin
    assert len(packet['additionalPins']) == 4 and len(packet['expectedPins']) == 26
    assert packet['expectedPins'] == freeze['expectedPins']
    for name, pin in packet['expectedPins'].items():
        assert stage['pins'][name] == pin
    for name in packet['additionalPins']:
        assert len(stage['pins'][name]) == 64
    archive = ROOT / 'evidence/complete-public-evidence-r2.tar.gz'
    control = read(ROOT / 'evidence/control-retrieval.public.json')
    binary = json.loads(control['binary_read_original']['content'][0]['text'])
    assert base64.b64decode(binary['data_base64'], validate=True) == archive.read_bytes()
    assert binary['chunk_sha256'] == sha(archive)
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        assert len(members) == len({m.name for m in members}) == 11
        assert {m.name for m in members} == {str(p.relative_to(R)) for p in R.rglob('*') if p.is_file()}
        for member in members:
            path = Path(member.name)
            assert member.isfile() and not path.is_absolute() and '..' not in path.parts
            raw = package.extractfile(member).read()
            assert len(raw) == member.size and raw == (R / path).read_bytes()
    driver = (ROOT / 'driver.py').read_text()
    consumer = (ROOT / 'consumer.mjs').read_text()
    launcher = (ROOT / 'launcher.py').read_text()
    assert "call('formal_activation','POST','sys/storage/native-v6/activate',{},expected=204)" in driver
    assert "['data']['native_kv2_reader_format']==2" in driver
    assert "originalprocess.returncode==-9" in driver
    assert "source['rows']==fresh['rows']" in driver
    assert "if (digest(store) !== candidate.storeSha256) return false;" in consumer
    assert 'saveOptions: { preserveStateProfileIds: [plan.expectedProfileId] }' in consumer
    assert "forceRefresh: false" in consumer and 'report.defaultGatewaySelectionQualified = false' in consumer
    assert "'--unshare-net','--unshare-pid','--die-with-parent'" in launcher
    assert "--ro-bind','/','/'" in launcher
    live = read(R / 'run-r2/live/result.public.json')
    outer = read(R / 'run-r2/execution.result.public.json')
    assert len(live['checks']) + sum(len(p['checks']) for p in live['phases']) == 236
    assert len(agent['authoritativeJobs']) == 12
    assert agent['counts']['independentPostRollbackSdkReads'] == 2
    late = read(R / 'evidence-export-r2/source-second-read.public.json')
    assert late['sameCredentialGeneration'] and not late['wholeRowsExact']
    assert late['lateDriftCausalityNotAttributed'] and late['notUsedAsRollbackTarget']
    report = {
        'schema': 'heptabao.root-review.rog-current-profile1-authbus.v1', 'ok': True,
        'reviewer_sha256': sha(Path(__file__)), 'agent_review_sha256': expected,
        'agent_review_recomputed_exactly': True, 'archive_sha256': sha(archive), 'archive_members': 11,
        'embedded_executed_source_pins': embedded, 'frozen_runtime_pins': 34,
        'job': 'rog/1a1a719db42-fc05-2a20', 'terminal_exit': 0,
        'source': agent['sourceCommit'], 'tree': agent['sourceTree'],
        'normal_binary_sha256': agent['normalBinarySha256'],
        'selected_credential_sha256': agent['actualCurrentCredentialSha256'],
        'dynamic_assertions': 236, 'phase_counts': agent['counts'],
        'actual_formal_native_v6_activation_and_format2': True,
        'actual_sigkill_cold_sealed_unseal_and_two_sdk_imports': True,
        'tls_approle_kv_policy_renew_revoke_both_phases': True,
        'whole_logical_sdk_cas_rollbacks': 2, 'independent_post_rollback_sdk_reads': 2,
        'production_unit_and_frozen_inputs_unchanged_during_run': True,
        'original_order_usage_defaults_exclusions_preserved': True,
        'late_export_usage_drift_retained': agent['lateDrift'],
        'r1_sdk_usage_pruning_failure_retained': True,
        'all_owned_processes_stopped': outer['ownedServerStopped'] and outer['ownedNamespaceProcessExited'],
        'scope': {'host': 'rog', 'agent': 'main', 'selected_managed_profile_ordinal': 1,
                  'profile_records_in_source': 3, 'sql_auth_row_source_invariant': True,
                  'migrated_sdk_primary_logical_store': True, 'nonprimary_rows_migration': False,
                  'complete_database_backup': False, 'all_six_agents': False,
                  'default_gateway_selection': False, 'native_codex_factory_reopen': False,
                  'os_service_manager_restart': False, 'production_traffic_cutover': False,
                  'fresh_provider_call_this_run': False, 'oauth_refresh': False,
                  'model_request': False, 'j3160_contacted': False,
                  'full_openbao_271_replacement': False},
    }
    destination = ROOT / 'root-review.public.json'
    destination.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'ok': True, 'sha256': sha(destination), 'dynamic_assertions': 236,
                      'archive_members': 11, 'independent_sdk_reads': 2}))


if __name__ == '__main__':
    main()
