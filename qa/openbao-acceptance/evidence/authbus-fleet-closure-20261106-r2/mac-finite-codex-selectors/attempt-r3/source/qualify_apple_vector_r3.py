#!/usr/bin/env python3
import json, struct
from mac_procargs_selectors_r3 import parse_procargs, SelectorRefused

prefix=struct.pack('=i',2)+b'/usr/bin/codex\0\0codex\0app-server\0HOME=/synthetic/home\0'
cases=[]
def run(name, suffix, ok):
    try:
        value=parse_procargs(prefix+suffix)
        assert ok
        assert value['public']['environmentEntriesReturned']==1
        assert value['private']['candidateHome']['path']=='/synthetic/home/.codex'
        assert value['public']['auxiliaryValuesRetained'] is False
        assert 'NEVER-RETAIN' not in json.dumps(value)
    except SelectorRefused:
        assert not ok
    cases.append({'name':name,'passed':True})
run('aligned_public_apple_vector_scrubbed_values',b'\0\0ptr_munge=\0\0main_stack=\0security_config=0x0\0',True)
run('unaligned_public_apple_vector',b'pfz=0x12\0stack_guard=\0ptr_munge=NEVER-RETAIN\0\0',True)
run('unknown_tail_key_refused',b'\0UNKNOWN=NEVER-RETAIN\0',False)
run('path_selector_after_aux_refused',b'\0ptr_munge=\0CODEX_HOME=/ambiguous\0',False)
run('duplicate_apple_key_refused',b'\0ptr_munge=\0ptr_munge=\0',False)
run('unterminated_aux_refused',b'\0ptr_munge=0x1',False)
print(json.dumps({'schema':'heptabao.apple-vector-local6.r1','passed':6,'cases':cases,'syntheticOnly':True},sort_keys=True))
