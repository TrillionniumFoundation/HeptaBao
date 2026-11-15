#!/usr/bin/env python3
import json
import struct
from mac_procargs_selectors_r4 import parse_procargs, SelectorRefused

prefix=struct.pack('=i',2)+b'/usr/bin/codex\0\0codex\0app-server\0HOME=/synthetic/home\0'
cases=[]
def run(name,suffix,ok,leading=1,auxiliary=None):
    try:
        value=parse_procargs(prefix+suffix)
        assert ok
        public=value['public']
        assert public['preTailKeyValueEntriesReturned']==public['environmentEntryCountUpperBound']==leading
        assert public['environmentEntryCountExact'] is False
        assert public['firstEmptySegmentDefinesAuxiliaryTail'] is True
        if auxiliary is not None:assert public['appleAuxiliarySegmentsValidated']==auxiliary
        assert value['private']['candidateHome']['path']=='/synthetic/home/.codex'
        assert public['auxiliaryValuesRetained'] is False
        assert 'NEVER-RETAIN' not in json.dumps(value)
    except SelectorRefused:
        assert not ok
    cases.append({'name':name,'passed':True})

run('aligned_public_apple_vector_scrubbed_values',b'\0\0ptr_munge=\0\0main_stack=\0security_config=0x0\0',True,auxiliary=3)
run('unaligned_public_keys_are_only_leading_count_upper_bound',b'pfz=0x12\0stack_guard=\0ptr_munge=NEVER-RETAIN\0\0',True,leading=4,auxiliary=0)
run('unknown_tail_key_refused',b'\0UNKNOWN=NEVER-RETAIN\0',False)
run('path_selector_after_aux_refused',b'\0ptr_munge=\0CODEX_HOME=/ambiguous\0',False)
run('duplicate_apple_key_refused',b'\0ptr_munge=\0ptr_munge=\0',False)
run('unterminated_aux_refused',b'\0ptr_munge=0x1',False)
raw=struct.pack('=i',1)+b'/usr/bin/codex\0\0codex\0MallocNanoZone=0\0UNRELATED=NEVER-RETAIN\0HOME=/synthetic/home\0\0ptr_munge=\0main_stack=\0'
value=parse_procargs(raw)
assert value['private']['candidateHome']['path']=='/synthetic/home/.codex'
assert value['public']['preTailKeyValueEntriesReturned']==3
assert value['public']['appleAuxiliarySegmentsValidated']==2
assert 'NEVER-RETAIN' not in json.dumps(value)
cases.append({'name':'ordinary_MallocNanoZone_does_not_cut_off_later_HOME','passed':True})
print(json.dumps({'schema':'heptabao.apple-separator-local7.r1','passed':len(cases),'cases':cases,
    'syntheticOnly':True,'actualMac':False,'processReads':0,'credentialReads':0},sort_keys=True))
