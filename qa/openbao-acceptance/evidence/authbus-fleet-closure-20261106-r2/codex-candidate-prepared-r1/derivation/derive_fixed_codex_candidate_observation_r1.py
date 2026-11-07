#!/usr/bin/env python3
"""Extend exact actual R4 observer with two fixed private candidate files."""
from pathlib import Path
import ast
import difflib
import hashlib
import json

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / 'mac-finite-codex-selectors-r4-work/observe_finite_codex_selectors_r4.py'
raw = OLD.read_bytes()
manifest = json.loads((OLD.parent / 'selector-manifest.public.json').read_text())
assert len(raw) == 56720 and hashlib.sha256(raw).hexdigest() == manifest['sha256']
tree = ast.parse(raw)
node = next(n for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(x, ast.Name) and x.id == 'PAYLOAD' for x in n.targets))
payload = ast.literal_eval(node.value)
text = raw.decode()
old_assignment = ast.get_source_segment(text, node)
text = text.replace(old_assignment, 'PAYLOAD = __CANDIDATE_PAYLOAD__', 1)

def replace(old, new):
    global text
    assert text.count(old) == 1, old[:100]
    text = text.replace(old, new)

replace("ROOT = Path('/Users/qianqi/heptabao-authbus-finite-codex-selectors-20261107-r4')",
        "ROOT = Path('/Users/qianqi/heptabao-authbus-finite-codex-candidate-files-20261107-r1')")
replace("'schema': 'heptabao.finite-codex-selector-observation.r4'",
        "'schema': 'heptabao.finite-codex-candidate-file-observation.r1'")
replace("codes, descriptors, directories, received_signals = set(), [], {}, []",
        "codes, descriptors, directories, received_signals = set(), [], {}, []\ncandidate_inputs = None")
replace("need(name in ('selectors-first.private.json', 'selectors-second.private.json'),",
        "need(name in ('selectors-first.private.json', 'selectors-second.private.json',\n"
        "                  'candidate-files.private.json'),")
replace("need(len(raw) <= 131072, 'selector_bounded_private_packet')",
        "need(len(raw) <= (2 * 1048576 if name == 'candidate-files.private.json' else 131072),\n"
        "         'selector_bounded_private_packet')")
replace("need(set(PAYLOAD['sources']) == {'mac_owned_unreaped_r1.py', 'mac_native_process_observer_r1.py',\n"
        "         'mac_procargs_selectors_r4.py'}, 'selector_exact_three_source_modules')",
        "need(set(PAYLOAD['sources']) == {'mac_owned_unreaped_r1.py', 'mac_native_process_observer_r1.py',\n"
        "         'mac_codex_backend_procargs_r1.py', 'mac_codex_candidate_backend_r1.py',\n"
        "         'mac_codex_fixed_candidate_inputs_r1.py'}, 'candidate_exact_five_source_modules')")
replace('from mac_procargs_selectors_r4 import parse_procargs, SelectorRefused',
        'from mac_codex_backend_procargs_r1 import parse_procargs, SelectorRefused\n'
        '    from mac_codex_fixed_candidate_inputs_r1 import FixedCandidateInputs, InputsRefused\n'
        '    from mac_codex_candidate_backend_r1 import CandidateRefused')
replace("    second = []\n", """    def candidate_source_fence():
        remaining()
        need({path: pin_public(path, expected) for path, expected in pins.items()} == before_pins,
             'candidate_actual_public_code_generation_exact')
    candidate_inputs = FixedCandidateInputs(until=UNTIL, source_fence=candidate_source_fence,
        private_write=private_output)
    candidate_inputs.capture([{'private': row['private'], 'public': row['public']} for row in first])
    second = []
""")
replace("    after_pins = {path: pin_public(path, expected) for path, expected in pins.items()}\n",
        "    candidate_inputs.verify()\n"
        "    after_pins = {path: pin_public(path, expected) for path, expected in pins.items()}\n")
replace("    report['sourcePins'] = PAYLOAD['sourcePins']\n",
        "    report['sourcePins'] = PAYLOAD['sourcePins']\n"
        "    report['originalR4ActualEvidenceMap'] = PAYLOAD['originalR4ActualEvidenceMap']\n"
        "    report['currentMain3ComparisonPerformed'] = False\n"
        "    report['candidateFileObservationIsCurrentBackendProof'] = False\n")
replace("'RuntimeError','SelectorRefused','ObservationRefused','OSError','FileNotFoundError',",
        "'RuntimeError','SelectorRefused','ObservationRefused','InputsRefused','CandidateRefused','OSError','FileNotFoundError',")
replace("'SelectorRefused','ObservationRefused') and code.isascii()",
        "'SelectorRefused','ObservationRefused','InputsRefused','CandidateRefused') and code.isascii()")
replace("finally:\n    errors = []\n", """finally:
    errors = []
    if candidate_inputs is not None:
        try:
            report['candidateInputs'] = candidate_inputs.close()
            report['authFileContentsRead'] = report['candidateInputs']['authFileContentsRead']
            report['ok'] = bool(report['ok'] and report['candidateInputs']['ok']
                and report['candidateInputs']['allSourceDescriptorsClosedOnce']
                and report['candidateInputs'].get('closedSourceNamesStillExact') is True)
        except BaseException:
            errors.append('candidate_original_source_close_or_generation_unknown')
            report['ok'] = False
""")
payload['sources'].pop('mac_procargs_selectors_r4.py')
for name in ('mac_codex_backend_procargs_r1.py', 'mac_codex_candidate_backend_r1.py',
             'mac_codex_fixed_candidate_inputs_r1.py'):
    payload['sources'][name] = (HERE / name).read_text()
payload['sourcePins'] = {name: hashlib.sha256(source.encode()).hexdigest()
                        for name, source in payload['sources'].items()}
payload['originalR4ActualEvidenceMap'] = '51080acf27ed134ba96fc228e03461f20faa544d'
prepared = text.replace('__CANDIDATE_PAYLOAD__', repr(payload))
compile(prepared, 'observe_fixed_codex_candidate_files_r1.py', 'exec')
target = HERE / 'observe_fixed_codex_candidate_files_r1.py'
assert not target.exists()
target.write_text(prepared)
template = HERE / 'observe_fixed_codex_candidate_files_r1.template.py'
template.write_text(text)
prior_template = raw.decode().replace(old_assignment, 'PAYLOAD = __CANDIDATE_PAYLOAD__', 1)
(HERE / 'codex-selector-r4-to-candidate-r1.diff').write_text(''.join(difflib.unified_diff(
    prior_template.splitlines(True), text.splitlines(True), fromfile=OLD.name, tofile=target.name)))
result = {'schema': 'heptabao.fixed-codex-candidate-observer-prepared.r1',
    'source': target.name, 'bytes': len(prepared.encode()),
    'sha256': hashlib.sha256(prepared.encode()).hexdigest(), 'sourcePins': payload['sourcePins'],
    'originalR4Bytes': len(raw), 'originalR4Sha256': hashlib.sha256(raw).hexdigest(),
    'originalR4Unchanged': True, 'originalR4ActualEvidenceMap': payload['originalR4ActualEvidenceMap'],
    'parentSeconds': 20, 'supervisorSeconds': 30, 'actualProcessesObservedByThisSource': 0,
    'actualCandidateAuthFilesReadByThisSource': 0, 'sourceOnlyPrepared': True,
    'fixedCredentialCandidateFileCount': 1, 'fixedUserConfigurationCandidateFileCount': 1,
    'noCurrentMain3Read': True, 'noKeychainSqlProviderChildOrService': True,
    'candidateFileRelationshipDoesNotProveRuntimeBackend': True}
(HERE / 'fixed-codex-candidate-observer-prepared-r1.public.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
