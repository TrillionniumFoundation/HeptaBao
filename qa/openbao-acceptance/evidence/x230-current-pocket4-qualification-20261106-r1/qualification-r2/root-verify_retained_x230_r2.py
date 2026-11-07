#!/usr/bin/env python3
"""Root verification of immutable original X230 receipts; no remote execution."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
QA = ROOT / 'HeptaBao-current-924b/qa/openbao-acceptance'
INPUT = ROOT / 'x230-migration-checkpoint/x230-current-pocket4/order-fix-r1'
assert hashlib.sha256((QA / 'x230_current_candidate_qualification.py').read_bytes()).hexdigest() == 'abb8adee9483696df7e38369dbb0436cd578721d4b6bde18a06dd0218ee1e0d0'
assert hashlib.sha256((QA / 'kv2_native_fresh_directory_dr_live.py').read_bytes()).hexdigest() == '01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67'
sys.path.insert(0, str(QA))
import x230_current_candidate_qualification as q
import kv2_native_fresh_directory_dr_live as dr
import acceptance

specs = {
    'qualification-r2.result.original.public.json': '7c055e9a364392382ac756bdfb117742251a51d9',
    'qualification-r2.full31.original.public.json': 'b516ab0bb6ff33c9bbdb425061522cb36ccdb863',
    'qualification-r2.comparison69.original.public.json': '4928a96d8ce472d10324eb29a9c52b9357e112e8',
    'qualification-r2.terminal.exact-tool-text.json': 'e9465092823544340703124fa8bb6089b053f332',
}
values, pins = {}, {}
for name, blob in specs.items():
    raw = (INPUT / name).read_bytes()
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob
    values[name] = json.loads(raw)
    pins[name] = {'gitBlob': blob, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
result, full, comparison, terminal = (values[n] for n in specs)
assert terminal['job_id'] == '1a1b290fcde-fc05-7eaa' and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
assert all(terminal[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
assert all(terminal[k] is False for k in ('timed_out', 'cancelled', 'automatic_retry'))
assert result['admitted'] is True and result['status'] == 'passed' and result['source_and_inputs_unchanged'] is True
assert result['source_commit'] == q.BUILD_COMMIT and result['source_tree'] == q.BUILD_TREE
assert dr.full34_complete(full) and len(full['checks']) == 31
assert full['source_commit'] == q.BUILD_COMMIT and full['source_tree'] == q.BUILD_TREE and full['source_dirty'] is False
assert full['binary_sha256'] == result['input_binding']['pins']['binary']['sha256']
q.validate_comparison(comparison, result['input_binding'], acceptance)
owner = result['process_custody']
assert owner['passed_process_custody'] is True and owner['original_count'] == len(owner['children']) == 414
assert owner['failed'] is False and owner['interrupted'] is False and owner['finished'] is True
assert all(r['original_wait_completed'] is True and r['no_live_members_before_reap'] is True and not r['gaps'] for r in owner['children'])
assert result['http_budget_seconds'] == 15 and result['migration_budget_seconds'] == 360
assert all(result[k] is False for k in ('production_changed', 'production_cutover', 'full_replacement_qualified', 'legacy_cleanup_qualified', 'automatic_retry'))
print(json.dumps({'schema': 'heptabao.root-retained-x230-r2-validation.r1', 'ok': True,
    'originalJobId': terminal['job_id'], 'originalPins': pins, 'full31Passed': 31,
    'candidateApi69Passed': 69, 'officialApi69Passed': 69, 'caseObjectsExactlyEqual': True,
    'allOriginalChildrenClosed': 414, 'originalHttpSeconds': 15, 'originalMigrationSeconds': 360,
    'sourceAndInputsUnchanged': True, 'newProductExecution': False,
    'newRemoteArtifactRehashClaimed': False, 'fullReplacementQualified': False}, sort_keys=True))
