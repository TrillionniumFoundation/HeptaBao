"""Strict one-shot fd0 UNIX controller for the opt-in native restore test binary.

No release/retry API: the successful test action is owned SIGKILL after exact
ready validation. Gate records are instrumentation evidence, not release-binary
attestation or independently verified application roots.
"""
from __future__ import annotations
import json
import re
import socket
import time

FEATURE='fixture-native-restore-faults'
PHASES=('before_root_publish','after_root_commit_before_local')
FIELDS=frozenset({'version','phase','nonce','pid','old_root','new_root','local_generation',
                  'leader_id','stage_count','stage_index','commit_index'})
MAX_PAYLOAD=510


def unsigned(value):return type(value) is int and 0<=value<=2**64-1


def validate_ready(value,*,phase,nonce,pid,node_id,generation):
    if not isinstance(value,dict) or set(value)!=FIELDS:raise ValueError('gate_ready_fields')
    if (phase not in PHASES or re.fullmatch('[0-9a-f]{64}',nonce) is None
            or type(value['version']) is not int or value['version']!=1
            or value['phase']!=phase or value['nonce']!=nonce
            or type(value['pid']) is not int or value['pid']!=pid
            or not unsigned(value['leader_id']) or value['leader_id']!=node_id
            or not unsigned(value['local_generation']) or value['local_generation']!=generation):
        raise ValueError('gate_ready_binding')
    for name in ('old_root','new_root'):
        if not isinstance(value[name],str) or re.fullmatch('[0-9a-f]{64}',value[name]) is None or value[name]=='0'*64:
            raise ValueError('gate_ready_root')
    if value['old_root']==value['new_root']:raise ValueError('gate_ready_same_root')
    count,index,commit=value['stage_count'],value['stage_index'],value['commit_index']
    if not unsigned(count) or (count==0)!=(index is None) or (index is not None and (not unsigned(index) or index==0)):
        raise ValueError('gate_ready_stage')
    if phase==PHASES[0]:
        if count==0 or commit is not None:raise ValueError('gate_p_requires_stage_before_commit')
    elif not unsigned(commit) or commit==0 or (index is not None and commit<=index):
        raise ValueError('gate_q_requires_commit_receipt')
    return {key:value[key] for key in FIELDS if key!='nonce'} | {'nonce_matched':True,
        'root_source':'feature_instrumentation','local_generation_matches_before':True}


def unique_fields(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('gate_duplicate_field')
        result[key]=value
    return result


class GateController:
    def __init__(self,phase,nonce):
        if phase not in PHASES or not isinstance(nonce,str) or re.fullmatch('[0-9a-f]{64}',nonce) is None:
            raise ValueError('gate_configuration')
        self.phase,self.nonce=phase,nonce
        self.parent,self.child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        self.consumed=False

    def arguments(self):
        return ['--fixture-native-restore-fd','0','--fixture-native-restore-phase',self.phase,
                '--fixture-native-restore-nonce',self.nonce]

    def child_started(self):
        self.child.close()

    def ready(self,*,pid,node_id,generation,deadline):
        if self.consumed:raise ValueError('gate_already_consumed')
        self.consumed=True
        def exact(length):
            output=bytearray()
            while len(output)<length:
                left=deadline-time.monotonic()
                if left<=0:raise TimeoutError('gate_ready_deadline')
                self.parent.settimeout(left)
                part=self.parent.recv(length-len(output))
                if not part:raise ValueError('gate_ready_eof')
                output.extend(part)
            return bytes(output)
        length=int.from_bytes(exact(2),'big')
        if not 1<=length<=MAX_PAYLOAD:raise ValueError('gate_ready_bound')
        payload=exact(length)
        value=json.loads(payload,object_pairs_hook=unique_fields)
        result=validate_ready(value,phase=self.phase,nonce=self.nonce,pid=pid,node_id=node_id,generation=generation)
        if time.monotonic()>=deadline:raise TimeoutError('gate_ready_deadline')
        return result

    def close(self):
        self.parent.close();self.child.close()
