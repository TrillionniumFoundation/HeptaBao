#!/usr/bin/env python3
from pathlib import Path
import ast, hashlib, json, difflib

ROOT=Path(__file__).resolve().parent
OLD=ROOT.parent/'mac-finite-codex-selectors-r2-work'
assembled=(OLD/'observe_finite_codex_selectors_r2.py').read_text()
assert hashlib.sha256(assembled.encode()).hexdigest()=='976c2331de6416ca25d3270794db824bc5de5aee67a232a8d95a37d4e17941eb'
tree=ast.parse(assembled)
payload=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PAYLOAD' for t in n.targets))
old=payload['sources']['mac_procargs_selectors_r1.py']
assert hashlib.sha256(old.encode()).hexdigest()=='d961308bfd86539f37aadf77f4be4d747f8a0efafc61393d4ed4160d81b2dc64'
insert='''# XNU kern_exec.c builds an additional apple[] string vector in p_argslen.
# Exact public source: blob 47420f9f8f620233f112e87a51ed8f576caa3546.
# Values can be scrubbed to NUL by the running process. No auxiliary value is
# retained, and unknown segments or later environment selectors still refuse.
APPLE_KEYS = frozenset((b'pfz', b'MallocNanoZone', b'stack_guard', b'malloc_entropy',
    b'ptr_munge', b'main_stack', b'executable_file', b'dyld_file', b'executable_cdhash',
    b'executable_boothash', b'dyld_flags', b'subsystem_root_path', b'ptrauth_disabled',
    b'arm64e_abi', b'th_port', b'vm_force_4k_pages', b'MallocExperiment',
    b'security_config', b'HardenedRuntime'))


def auxiliary_tail(raw):
    if not any(raw):
        return 0
    need(len(raw) <= 8192 and raw.endswith(b'\\0'), 'selector_bounded_complete_apple_vector')
    segments = [part for part in raw.split(b'\\0') if part]
    need(1 <= len(segments) <= len(APPLE_KEYS), 'selector_apple_vector_segment_count')
    seen = set()
    for part in segments:
        key, separator, value = part.partition(b'=')
        need(separator == b'=' and key in APPLE_KEYS and key not in seen,
             'selector_unknown_or_duplicate_apple_vector_segment')
        text(value)
        seen.add(key)
    return len(segments)


'''
new=old.replace('def parse_procargs(raw):',insert+'def parse_procargs(raw):')
new=new.replace("        value = take()\n        environ_count += 1", "        segment_start = at\n        value = take()\n        if value.partition(b'=')[0] in APPLE_KEYS:\n            at = segment_start\n            break\n        environ_count += 1")
oldtail='''    # XNU's restricted-process path can end immediately after argv. With a
    # returned environment section, every entry must terminate within the
    # returned buffer. Its last NUL may end the buffer; any remaining padding
    # must be zero. No heuristic reads beyond an ambiguous envelope.
    need(not any(raw[at:]), 'selector_procargs_zero_tail')'''
newtail='''    # Restricted processes may end immediately after argv. Otherwise the
    # saved strings can include the public apple[] vector after the environment.
    # Validate every nonempty auxiliary segment; never skip an unknown tail.
    auxiliary_count = auxiliary_tail(raw[at:])'''
assert oldtail in new
new=new.replace(oldtail,newtail)
new=new.replace("'argc': argc, 'environmentEntriesReturned': environ_count,", "'argc': argc, 'environmentEntriesReturned': environ_count,\n        'appleAuxiliarySegmentsValidated': auxiliary_count,\n        'environmentCountExcludesRecognizedAppleVector': True,\n        'auxiliaryValuesRetained': False,")
ast.parse(new)
name='mac_procargs_selectors_r3.py'
del payload['sources']['mac_procargs_selectors_r1.py'];del payload['sourcePins']['mac_procargs_selectors_r1.py']
payload['sources'][name]=new;payload['sourcePins'][name]=hashlib.sha256(new.encode()).hexdigest()
template=(OLD/'observe_finite_codex_selectors_r2.template.py').read_text()
template=template.replace('finite-codex-selectors-20261107-r2','finite-codex-selectors-20261107-r3').replace('finite-codex-selector-observation.r2','finite-codex-selector-observation.r3')
template=template.replace('mac_procargs_selectors_r1','mac_procargs_selectors_r3')
final=template.replace('# PAYLOAD_PLACEHOLDER','PAYLOAD = '+repr(payload));ast.parse(final)
(ROOT/name).write_text(new)
(ROOT/'observe_finite_codex_selectors_r3.template.py').write_text(template)
(ROOT/'observe_finite_codex_selectors_r3.py').write_text(final)
(ROOT/'r2-to-r3-parser.diff').write_text(''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='old-parser-r1',tofile='new-parser-r3')))
prior_test=(OLD/'qualify_procargs_selectors_r1.py').read_text().replace('mac_procargs_selectors_r1','mac_procargs_selectors_r3')
(ROOT/'qualify_procargs_selectors_r3.py').write_text(prior_test)
manifest={'schema':'heptabao.finite-codex-selector-source.r3','bytes':len(final.encode()),'sha256':hashlib.sha256(final.encode()).hexdigest(),'parserSha256':payload['sourcePins'][name],'originalR2Sha256':'976c2331de6416ca25d3270794db824bc5de5aee67a232a8d95a37d4e17941eb','originalR2FailureJob':'1a1b39a74ef-fc05-83cd','actualStructureJob':'1a1b3a8d652-fc05-842a','readMaximumUnchanged':262148,'parentSeconds':20,'supervisorSeconds':30,'noCredentialFileReads':True,'appleReference':{'repository':'apple-oss-distributions/xnu','path':'bsd/kern/kern_exec.c','commit':'f6217f891ac0bb64f3d375211650a4c1ff8ca1ea','blob':'47420f9f8f620233f112e87a51ed8f576caa3546'}}
(ROOT/'selector-manifest.public.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
