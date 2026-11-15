#!/usr/bin/env python3
"""Keep the original first-empty separator; never infer it from an Apple key."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

NEW=Path(__file__).resolve().parent
OLD=NEW.parent/'mac-finite-codex-selectors-r3-work'
raw=(OLD/'observe_finite_codex_selectors_r3.py').read_bytes()
assert len(raw)==56585 and hashlib.sha256(raw).hexdigest()=='b4957acf9c647de833aac9303987a61f4c7392dc7835d2334cc01c2c0a6d30ef'
payload=next(ast.literal_eval(node.value) for node in ast.parse(raw).body if isinstance(node,ast.Assign)
    and any(isinstance(target,ast.Name) and target.id=='PAYLOAD' for target in node.targets))
old=payload['sources']['mac_procargs_selectors_r3.py']
assert hashlib.sha256(old.encode()).hexdigest()=='a69334d5446486e9fb29cc46c9a6bcbbfcc09fb0ffe1bb7531689b8988caa4a2'
before="""        segment_start = at
        value = take()
        if value.partition(b'=')[0] in APPLE_KEYS:
            at = segment_start
            break
        environ_count += 1"""
after="""        value = take()
        environ_count += 1"""
assert old.count(before)==1
source=old.replace(before,after)
before="""        'argc': argc, 'environmentEntriesReturned': environ_count,
        'appleAuxiliarySegmentsValidated': auxiliary_count,
        'environmentCountExcludesRecognizedAppleVector': True,"""
after="""        'argc': argc, 'preTailKeyValueEntriesReturned': environ_count,
        'environmentEntryCountUpperBound': environ_count,
        'environmentEntryCountExact': False,
        'appleAuxiliarySegmentsValidated': auxiliary_count,
        'firstEmptySegmentDefinesAuxiliaryTail': True,"""
assert source.count(before)==1
source=source.replace(before,after)
source=source.replace("    # saved strings can include the public apple[] vector after the environment.\n    # Validate every nonempty auxiliary segment; never skip an unknown tail.",
"    # saved strings can include the public apple[] vector. Only the first empty\n    # segment marks the tail: a public Apple key may also be an ordinary env key.\n    # The leading key/value count is therefore only an environment upper bound.\n    # Validate every nonempty auxiliary segment; never skip an unknown tail.")
ast.parse(source)
name='mac_procargs_selectors_r4.py'
del payload['sources']['mac_procargs_selectors_r3.py'];del payload['sourcePins']['mac_procargs_selectors_r3.py']
payload['sources'][name]=source;payload['sourcePins'][name]=hashlib.sha256(source.encode()).hexdigest()
template=(OLD/'observe_finite_codex_selectors_r3.template.py').read_text()
template=template.replace('finite-codex-selectors-20261107-r3','finite-codex-selectors-20261107-r4')
template=template.replace('finite-codex-selector-observation.r3','finite-codex-selector-observation.r4')
template=template.replace('mac_procargs_selectors_r3','mac_procargs_selectors_r4')
assert template.count('# PAYLOAD_PLACEHOLDER')==1
assembled=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD = '+repr(payload));ast.parse(assembled)
for filename,value in [(name,source),('observe_finite_codex_selectors_r4.template.py',template),
    ('observe_finite_codex_selectors_r4.py',assembled),('r3-to-r4-parser.diff',''.join(difflib.unified_diff(
        old.splitlines(True),source.splitlines(True),fromfile='failed-r3/parser',tofile='prepared-r4/parser')))]:
    target=NEW/filename;assert not target.exists();target.write_text(value)
original_test=(OLD/'qualify_procargs_selectors_r3.py').read_text().replace('mac_procargs_selectors_r3','mac_procargs_selectors_r4')
original_test=original_test.replace("['environmentEntriesReturned']","['preTailKeyValueEntriesReturned']")
(NEW/'qualify_procargs_selectors_r4.py').write_text(original_test)
manifest={'schema':'heptabao.finite-codex-selector-source.r4','bytes':len(assembled.encode()),
    'sha256':hashlib.sha256(assembled.encode()).hexdigest(),'parserSha256':payload['sourcePins'][name],
    'originalR3Sha256':hashlib.sha256(raw).hexdigest(),'originalR3FailureJob':'1a1b3b39303-fc05-845f',
    'actualStructureJob':'1a1b3a8d652-fc05-842a','readMaximumUnchanged':262148,
    'parentSeconds':20,'supervisorSeconds':30,'noCredentialFileReads':True,'actualExecuted':False,
    'onlyFirstEmptySeparatorDefinesTail':True,'noAppleKeyEarlyCutoff':True,'environmentCountIsUpperBoundOnly':True,
    'appleReference':{'repository':'apple-oss-distributions/xnu','path':'bsd/kern/kern_exec.c',
        'commit':'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea','blob':'47420f9f8f620233f112e87a51ed8f576caa3546'}}
(NEW/'selector-manifest.public.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
