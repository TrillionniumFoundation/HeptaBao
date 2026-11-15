"""Derive one new QA-only DR attempt from the retained original staging code."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OLD_WRAPPER_SHA = 'b92051069e399539ced31139c1b0c39ad3595b8b05bba88390bedc09c86d98bc'
NEW_COMMIT = '5ded017e1c858b8602a73678acc29df75386a84d'
NEW_TREE = '9d1d040a063504ede67559fadb556897591642f2'
BUNDLE_SHA = 'eef7fc4f17d9818ad53fda4cf57b1de2ca7a31661833fae61695d89ff5dfbab3'
MAIN_SHA = '01993e6c367bf8b896b4832c7723b1f36900fefbc20fcc05394ce401ec6b4f67'

source = (ROOT / 'stage.original.py').read_text()
assert hashlib.sha256(source.encode()).hexdigest() == '73a3ac958ab57a925661a365190edfa11533bf9de146dc87c2d5c57d11f065c0'
tree = ast.parse(source)
node = next(n for n in tree.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'WRAPPER_TEXT' for t in n.targets))
wrapper = ast.literal_eval(node.value)
assert hashlib.sha256(wrapper.encode()).hexdigest() == OLD_WRAPPER_SHA


def once(value, old, new):
    assert value.count(old) == 1, (old, value.count(old))
    return value.replace(old, new, 1)


for old, new in (
    ("SOURCE = ROOT / 'source-dr25-4bde9-r1'", "SOURCE = ROOT / 'source-dr25-authbus-r2'"),
    ("QA_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'", f"QA_COMMIT = '{NEW_COMMIT}'"),
    ("QA_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'", f"QA_TREE = '{NEW_TREE}'"),
    ("WORK = ROOT / 'full34-dr25-r1'", "WORK = ROOT / 'full34-dr25-authbus-r2'"),
    ("OUT = ROOT / 'dr25-execution-4bde9-r1'", "OUT = ROOT / 'dr25-execution-authbus-r2'"),
    ("BACKUP = Path('/Users/qianqi/heptabao-dr25-backups-20261106-r1')",
     "BACKUP = Path('/Users/qianqi/heptabao-dr25-backups-20261106-authbus-r2')"),
    ("KEYS = ROOT / 'dr25-key-custody'", "KEYS = ROOT / 'dr25-key-custody-authbus-r2'"),
    ("'388f763d810e1694ce9fe3d4ce52325318aad8ec4fa4d87ebbcd6cfbe7f1f5a0', 70045",
     f"'{MAIN_SHA}', 72065"),
):
    wrapper = once(wrapper, old, new)
wrapper_sha = hashlib.sha256(wrapper.encode()).hexdigest()
segment = ast.get_source_segment(source, node)
source = once(source, segment, 'WRAPPER_TEXT = ' + json.dumps(wrapper))

# Only control/source identities, output namespaces and source-byte pins change.
# Original 52/60 staging and 60/1740/1800 execution budgets remain unchanged.
for old, new in (
    ("CONTROL = ROOT / 'control/dr25-4bde9-r1'", "CONTROL = ROOT / 'control/dr25-authbus-r2'"),
    ("BASE = ROOT / 'source-09c14-r1'", "BASE = ROOT / 'source-4bde9-r1'"),
    ("SOURCE = ROOT / 'source-dr25-4bde9-r1'", "SOURCE = ROOT / 'source-dr25-authbus-r2'"),
    ("BUNDLE = ROOT / 'control/candidate-4bde9-from-09c14.bundle'", "BUNDLE = ROOT / 'control/candidate-5ded-from-4bde9.bundle'"),
    ("OLD_COMMIT = '09c14eae7a3b52dee8ce3af3175dad5900ac59ec'", "OLD_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'"),
    ("OLD_TREE = 'dfb0df97a2c74b1c0154f45342f3debb0ce438ab'", "OLD_TREE = 'f08493a23f8ea0637073651231865ea9607b790e'"),
    ("\nCOMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'", f"\nCOMMIT = '{NEW_COMMIT}'"),
    ("\nTREE = 'f08493a23f8ea0637073651231865ea9607b790e'", f"\nTREE = '{NEW_TREE}'"),
    ("BUNDLE_SHA = '9808cfef28ce90733b636e81aed122aeeaf4fe81e0f34b1b84dde7e0ab0e11cd'", f"BUNDLE_SHA = '{BUNDLE_SHA}'"),
    (f"WRAPPER_SHA = '{OLD_WRAPPER_SHA}'", f"WRAPPER_SHA = '{wrapper_sha}'"),
    ("    ROOT / 'full34-dr25-r1', ROOT / 'dr25-execution-4bde9-r1',", "    ROOT / 'full34-dr25-authbus-r2', ROOT / 'dr25-execution-authbus-r2',"),
    ("    Path('/Users/qianqi/heptabao-dr25-backups-20261106-r1'), ROOT / 'dr25-key-custody',",
     "    Path('/Users/qianqi/heptabao-dr25-backups-20261106-authbus-r2'), ROOT / 'dr25-key-custody-authbus-r2',"),
    ("\nNEW_TEST = ", "\nNEW_CODE_PINS = dict(CODE_PINS)\nNEW_CODE_PINS['qa/openbao-acceptance/kv2_native_fresh_directory_dr_live.py'] = '" + MAIN_SHA + "'\nNEW_TEST = "),
    ("REPORT['source_pins'] = {name: pin(SOURCE / name, value) for name, value in CODE_PINS.items()}",
     "REPORT['source_pins'] = {name: pin(SOURCE / name, value) for name, value in NEW_CODE_PINS.items()}"),
    ("len(wrapper) == 22623", f"len(wrapper) == {len(wrapper.encode())}"),
    ("pin(CONTROL / 'dr25_mac_fixed_wrapper.py', WRAPPER_SHA, 22623)",
     f"pin(CONTROL / 'dr25_mac_fixed_wrapper.py', WRAPPER_SHA, {len(wrapper.encode())})"),
):
    source = once(source, old, new)
assert source.count('pin(BUNDLE, BUNDLE_SHA, 1393)') == 2
source = source.replace('pin(BUNDLE, BUNDLE_SHA, 1393)', 'pin(BUNDLE, BUNDLE_SHA, 401428)')
compile(source, '<new-stage>', 'exec')
compile(wrapper, '<new-wrapper>', 'exec')
assert "PRODUCT_COMMIT = '4bde9aee03fcd27c59e13607e529b1cee594b249'" in wrapper
assert 'OUTER_SECONDS, PREPARE_SECONDS, WORK_SECONDS = 1800, 60, 1740' in wrapper
assert "dr.full.HTTP_SECONDS == 15 and dr.full.MIGRATION_SECONDS == 360" in wrapper
assert 'time.monotonic() - ENTRY < 52' in source
(ROOT / 'stage.authbus-r2.py').write_text(source)
(ROOT / 'wrapper.authbus-r2.py').write_text(wrapper)
proof = {'schema': 'heptabao.mac-dr25-fresh-qa-stage-binding.v1',
         'qa_commit': NEW_COMMIT, 'qa_tree': NEW_TREE,
         'product_commit': '4bde9aee03fcd27c59e13607e529b1cee594b249',
         'bundle_bytes': 401428, 'bundle_sha256': BUNDLE_SHA,
         'wrapper_sha256': wrapper_sha, 'wrapper_bytes': len(wrapper.encode()),
         'stage_sha256': hashlib.sha256(source.encode()).hexdigest(),
         'stage_bytes': len(source.encode()), 'old_failed_attempt_unchanged': True,
         'new_output_namespaces': True, 'same_process_entry': True,
         'http_seconds': 15, 'migration_seconds': 360,
         'stage_work_seconds': 52, 'stage_outer_seconds': 60,
         'prepare_seconds': 60, 'work_seconds_from_entry': 1740, 'runtime_outer_seconds': 1800,
         'actual_restore_qualified': False}
(ROOT / 'preparation.public.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
print(json.dumps(proof, sort_keys=True))
