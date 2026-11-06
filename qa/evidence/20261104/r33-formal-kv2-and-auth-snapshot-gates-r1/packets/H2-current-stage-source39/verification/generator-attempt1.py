#!/usr/bin/env python3
"""Offline source transform only. Never imports or executes the stage or QA."""
from pathlib import Path
import ast
import difflib
import hashlib
import json

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / 'input'
OUT = ROOT / 'proposal'
OUT.mkdir(exist_ok=True)
before = (INPUT / 'before-stage.py').read_text()
spec_raw = (INPUT / 'fixture-template.private.json').read_text()
spec = json.loads(spec_raw)
instrument = json.loads((INPUT / 'instrument12-map.public.json').read_text())
normal = json.loads((INPUT / 'current-normal5-table.public.json').read_text())
old_carrier = json.loads((INPUT / 'original-cli-carrier.json').read_text())
members = json.loads((INPUT / 'H2-product-eight-members.public.json').read_text())

def pin(raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

assert pin(before)['blob'] == '45ceb135688a2002e845f31e010ca5c010551517'
assert pin(spec_raw)['blob'] == '52ce20ef5c148ad5477b493ce43ac3b43d8569a8'
assert spec['ready_for_readonly_prepare'] is False
assert instrument['rows'][7]['independent_desktop_incoming_info'] is None
assert [r['index'] for r in instrument['rows'] if r['independent_desktop_incoming_info'] is None] == [7, 8, 9, 10, 11]

qa_names = tuple(spec['qa_files'])
payload_files = {name: (INPUT / 'qa' / name).read_text() for name in qa_names}
for name, text in payload_files.items():
    assert pin(text)['bytes'] == spec['qa_files'][name]['bytes']
    assert pin(text)['sha256'] == spec['qa_files'][name]['sha256']
for name in ('normal-release-tests-result.public.json', 'groups.json'):
    payload_files[name] = old_carrier['files'][name]
    actual = next(r for r in normal['files'] if r['name'] == name)
    assert pin(payload_files[name])['bytes'] == actual['bytes']
    assert pin(payload_files[name])['sha256'] == actual['sha256']
payload_files['binding.partially-resolved.json'] = spec_raw
payload = {'schema': 'heptabao.normal-native-h2-gate.local-source-carrier.v1', 'files': payload_files}
payload_raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n'
assert len(payload_raw.encode()) <= 1024 * 1024
file_pins = {name: {k: pin(text)[k] for k in ('bytes', 'sha256')} for name, text in payload_files.items()}

old_ast = ast.parse(before)
old_source_pins = ast.literal_eval(next(n.value for n in old_ast.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SOURCE_PINS' for t in n.targets)))
sizes = {path: row[0] for path, row in old_source_pins.items()}
sizes['Cargo.lock'] = instrument['rows'][5]['content']['bytes']
http_snapshot_raw = (INPUT / 'http_snapshot.rs').read_bytes()
assert pin(http_snapshot_raw)['blob'] == '4a5743d757b79493400b712bf57a5fa552b50bda'
sizes['crates/heptabao-server/src/http_snapshot.rs'] = len(http_snapshot_raw)
source_pins = {r['path']: (sizes[r['path']], r['expected_sha256']) for r in members['members']}

h2_copy = {}
for r in instrument['rows']:
    source, target = r['desktop_incoming_receiver'], r['h2_planned_target']
    assert source['bytes'] == target['bytes'] and source['sha256'] == target['sha256']
    h2_copy[r['role']] = (r['name'], source['bytes'], source['sha256'], source['mode'], target['mode'])

text = before
changes = []

def replace(old, new, reason):
    global text
    assert text.count(old) == 1, (reason, text.count(old))
    text = text.replace(old, new, 1)
    changes.append({'reason': reason, 'before': old, 'after': new})

replace('Create-only local Phase B source/artifact carrier; no product execution.',
        'Create-only local H2 source/artifact carrier; no product execution.', 'H2 carrier label only')
replace('CONTROL = BASE / "official271-native-cli-phaseb-r3-control-r4"\nWORK = BASE / "official271-native-cli-phaseb-r3-live-r4"',
        'CONTROL = BASE / "normal-native-h2-gate-control-r2"\nWORK = BASE / "normal-native-h2-gate-live-r2"', 'Fixed fresh H2 namespaces already in the unchanged binding')
replace('OFFICIAL = BASE / "official271-standby-oracle-control-r1/artifacts/bao"',
        'H2_INCOMING = BASE / "normal-native-h2-qa-shared-artifacts-r1/incoming"', 'Second fixed existing instrument incoming; no official CLI executable')
replace('PAYLOAD_SHA = "a2f1d6b11c206b8b10ec896fd857207e38f72efac24bffd556fa94349bc34915"\nPAYLOAD_BYTES = 302459',
        'PAYLOAD_SHA = ' + repr(pin(payload_raw)['sha256']) + '\nPAYLOAD_BYTES = ' + str(pin(payload_raw)['bytes']), 'Exact new eight-member H2 carrier bytes')
start = text.index("FILES = json.loads(r'''")
end = text.index("''')", start) + 4
replace(text[start:end], "FILES = json.loads(r'''" + json.dumps(file_pins, indent=2) + "''')", 'Five unchanged H2 QA, unchanged two current receipts, unchanged content-bound template')
start = text.index('QA_NAMES = (')
end = text.index('\n)\n', start) + 3
replace(text[start:end], 'QA_NAMES = (\n' + ''.join('    ' + repr(name) + ',\n' for name in qa_names) + ')', 'Exact five unchanged H2 QA names')
start = text.index('SOURCE_PINS = {')
end = text.index('\n}', start) + 2
new_source = 'H2_COPY = {\n' + ''.join('    ' + repr(role) + ': (' + repr(v[0]) + ', ' + str(v[1]) + ', ' + repr(v[2]) + ', ' + oct(v[3]) + ', ' + oct(v[4]) + '),\n' for role, v in h2_copy.items()) + '}\nSOURCE_PINS = {\n' + ''.join('    ' + repr(path) + ': (' + str(v[0]) + ', ' + repr(v[1]) + '),\n' for path, v in source_pins.items()) + '}'
replace(text[start:end], new_source, 'Closed twelve instrument roles plus existing H2 eight canonical source pins')
replace('schema = "heptabao.official271-native-cli-phaseb-r3.local-stage.v1"',
        'schema = "heptabao.normal-native-h2-gate.local-stage.v1"', 'H2 stage receipt schema')
replace('        self.rootfd = self.qafd = self.artfd = None',
        '        self.rootfd = self.qafd = self.artfd = self.h2fd = None', 'New owned h2qa FD in the existing ledger')
replace('        for name in ("qa", "artifacts"):',
        '        for name in ("qa", "artifacts", "h2qa"):', 'Create exactly one additional owned child directory')
replace('            if name == "qa":\n                self.qafd = fd\n            else:\n                self.artfd = fd',
        '            if name == "qa":\n                self.qafd = fd\n            elif name == "artifacts":\n                self.artfd = fd\n            else:\n                self.h2fd = fd', 'Register and route h2qa through the existing append-before-fstat and reverse-close path')
replace('        need(name in set(QA_NAMES) | {"groups.json", "normal-release-tests-result.public.json",\n                                    "binding.private.json", "stage.result.public.json",\n                                    "stage.failure.public.json"}, "closed_destination_filename")',
        '        need((fd == self.qafd and name in QA_NAMES)\n             or (fd == self.artfd and name in {"groups.json", "normal-release-tests-result.public.json"})\n             or (fd == self.rootfd and name in {"binding.private.json", "stage.result.public.json",\n                                               "stage.failure.public.json"}), "closed_destination_filename")', 'Exact write FD/name pairing; instrument destination only admitted by fixed copy route')
replace('    def copy(self, name, size, expected_sha, source_mode, target_mode):\n        self.check()\n        path = INCOMING / name',
        '    def copy(self, name, size, expected_sha, source_mode, target_mode, *, h2=False):\n        self.check()\n        need(type(h2) is bool, "fixed_copy_route")\n        member = (name, size, expected_sha, source_mode, target_mode)\n        need(member in (H2_COPY.values() if h2 else COPY), "fixed_copy_member")\n        incoming, directory, destination = ((H2_INCOMING, "h2qa", self.h2fd) if h2\n                                            else (INCOMING, "artifacts", self.artfd))\n        need(destination is not None, "owned_copy_destination_fd")\n        path = incoming / name', 'One existing copy implementation with two closed input/target routes')
start = text.index('    def copy(')
end = text.index('\n    def close(', start)
old_copy = text[start:end]
new_copy = old_copy.replace('dir_fd=self.artfd', 'dir_fd=destination').replace('CONTROL / "artifacts" / name', 'CONTROL / directory / name').replace('os.fsync(self.artfd)', 'os.fsync(destination)')
replace(old_copy, new_copy, 'Same copy I/O/hash/EOF/identity/close code using its fixed routed destination FD')
replace('payload["schema"] == "heptabao.official271-native-cli-phaseb-r3.local-source-carrier.v1"',
        'payload["schema"] == "heptabao.normal-native-h2-gate.local-source-carrier.v1"', 'Exact H2 carrier schema in original admission')
replace('    need(spec["candidate_commit"] == HEAD and spec["candidate_tree"] == TREE\n         and spec["ready_for_readonly_prepare"] is False, "original_partial_binding")',
        '    need(spec["schema"] == "heptabao.normal-native-h2-gate.binding.v2"\n         and spec["candidate_commit"] == HEAD and spec["candidate_tree"] == TREE\n         and spec["instrument_build_commit"] == "df026fe323dd7cf0f0ec57d7d2d9c5a79897053c"\n         and spec["instrument_build_tree"] == "424463ccd2310ddc1e7b2bbcd7b7af29ae58c825"\n         and spec["ready_for_readonly_prepare"] is False, "original_partial_binding")', 'Exact frozen product and instrument identities remain separate')
replace('    directory_fences = {str(path): directory_identity(path.lstat()) for path in (SOURCE, INCOMING)}',
        '    need(H2_INCOMING.resolve(strict=True) == H2_INCOMING and H2_INCOMING.is_dir()\n         and H2_INCOMING.lstat().st_uid == 1000\n         and stat.S_IMODE(H2_INCOMING.lstat().st_mode) == 0o500, "instrument_incoming_custody")\n    directory_fences = {str(path): directory_identity(path.lstat())\n                        for path in (SOURCE, INCOMING, H2_INCOMING)}', 'Apply the existing canonical owned read-only incoming guard and before/after directory fence to the fixed instrument source')
replace('    official = capture(OFFICIAL, 181760103, "535cf827b13753046757f5ec8b97ae0ef21f10a40ffe673f0d5e75616170f5ea", 181760103)\n', '', 'H2 has no official_cli executable dependency')
replace('    captured = [machine, *source_pins, *old_fences, official, *utilities.values()]',
        '    captured = [machine, *source_pins, *old_fences, *utilities.values()]', 'Remove only the nonexistent H2 official executable from the read-only list')
replace('        copied = [owned.copy(*item) for item in COPY]',
        '        copied = [owned.copy(*item) for item in COPY]\n        h2_copied = {role: owned.copy(*item, h2=True) for role, item in H2_COPY.items()}', 'Twelve instrument copies via the same owned copy method')
replace('        spec["official_cli"] = bind(official)',
        '        actual_h2 = {role: bind(entry["target"]) for role, entry in h2_copied.items()}\n        need(actual_h2 == spec["h2_client"], "actual_h2_targets_match_frozen_binding")\n        spec["h2_client"] = actual_h2', 'Bind h2_client only from actual target hash/mode/owner records; no official_cli field')
replace('        for item in [*captured, *[entry["source"] for entry in copied]]:',
        '        for item in [*captured, *[entry["source"] for entry in copied],\n                     *[entry["source"] for entry in h2_copied.values()]]:', 'Preserve the full before/after metadata fence for all instrument copy sources')
replace('             | {"groups.json", "normal-release-tests-result.public.json"}, "exact_created_artifact_members")',
        '             | {"groups.json", "normal-release-tests-result.public.json"}, "exact_created_artifact_members")\n        need(set(os.listdir(owned.h2fd)) == {item[0] for item in H2_COPY.values()},\n             "exact_created_h2_members")\n        need(set(os.listdir(owned.rootfd)) == {"qa", "artifacts", "h2qa", "binding.private.json"},\n             "exact_created_control_members")', 'Exact h2qa and owned-root final membership before the original result receipt')
replace('                      machine_id_sha256=MACHINE_SHA, copied=copied, qa_files=qarecords,',
        '                      machine_id_sha256=MACHINE_SHA, copied=copied, h2_copied=h2_copied, qa_files=qarecords,', 'Report the twelve actual instrument source/target identity records separately')

ast.parse(text)
compile(text, '<H2-stage-candidate-compile-only>', 'exec')
for rel, raw in [('stage_h2_r1.py', text), ('source-carrier.json', payload_raw), ('fixture-binding.CONTENT-BOUND.private.json', spec_raw)]:
    (OUT / rel).write_text(raw)
for name, raw in payload_files.items():
    (OUT / 'payload-files').mkdir(exist_ok=True)
    (OUT / 'payload-files' / name).write_text(raw)
diff = ''.join(difflib.unified_diff(before.splitlines(keepends=True), text.splitlines(keepends=True), fromfile='before/cli_stage45ceb.py', tofile='candidate/stage_h2_r1.py'))
(OUT / 'stage.review.diff').write_text(diff)
report = {'schema': 'heptabao.h2-stage.minimal-adaptation-source.v1', 'status': 'SOURCE_ONLY_UNBOUND_OBSERVATION_GATE',
          'base': pin(before), 'candidate': pin(text), 'payload': pin(payload_raw),
          'change_count': len(changes), 'diff_hunks': sum(line.startswith('@@ ') for line in diff.splitlines()),
          'changes': changes, 'five_QA_whole_unchanged': True,
          'missing_independent_incoming_info': [7, 8, 9, 10, 11],
          'stage_process_request_constructed': False, 'stage_dispatch_ready': False,
          'target_actual_count': 0, 'Runtime_calls': 0, 'module_executions': 0,
          'budgets': {'internal_seconds': 300, 'outer_seconds': 330, 'stdin_max_bytes': 1048576},
          'copy_product_count': 3, 'payload_product_count': 2, 'copy_instrument_count': 12, 'QA_count': 5}
(OUT / 'TRANSFORM.public.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'changes'}, sort_keys=True))
