#!/usr/bin/env python3
"""Narrow local checks of the new parent's wire, once and closure boundaries.

Pure injected process authority is explicitly not Mac runtime qualification.
The failure-close case uses original real anonymous pipe descriptors locally.
No production path, service, provider, SDK import or credential is accessed.
"""
import contextlib
import copy
import json
import os
from pathlib import Path
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mac_owned_refresh_parent_r1 as parent

cases = []


def case(name, action):
    try:
        action()
        cases.append({'name': name, 'passed': True})
    except BaseException as error:
        cases.append({'name': name, 'passed': False, 'errorType': type(error).__name__})


def rejected(action):
    try:
        action()
    except parent.ParentRefused:
        return
    raise AssertionError('expected fixed refusal')


nonce = 'a' * 64
request = {'schema': 'heptabao.refresh-writer-check.private.r1', 'nonce': nonce,
           'sequence': 0, 'ordinal': 0, 'stage': 'final-native-send'}


def parse(value):
    return parent.parse_request(value, nonce=nonce, ordinal=0, sequence=0)


case('canonical_original_authority_roundtrip', lambda: (
    parse(parent.encoded(request)) == request or (_ for _ in ()).throw(AssertionError())))
for name, delta in (('wrong_parent_nonce', {'nonce': 'b' * 64}),
                    ('another_owner_ordinal', {'ordinal': 1}),
                    ('repeated_or_skipped_sequence', {'sequence': 1}),
                    ('boolean_sequence_is_not_zero', {'sequence': False}),
                    ('unlisted_stage', {'stage': 'new-provider-request'}),
                    ('unlisted_authority_field', {'permission': True})):
    case(name, lambda d=delta: rejected(lambda: parse(parent.encoded({**request, **d}))))
case('duplicate_field_rejected', lambda: rejected(lambda: parse(
    parent.encoded(request).replace(b'"sequence":0', b'"sequence":0,"sequence":0'))))
case('two_responses_or_noncanonical_whitespace_rejected', lambda: rejected(lambda: parse(
    parent.encoded(request) + b'\n')))
case('false_does_not_coerce_to_authorized', lambda: (
    json.loads(parent.response(request, False))['allowed'] is False or (_ for _ in ()).throw(AssertionError())))
case('numeric_authorization_refused', lambda: rejected(lambda: parent.response(request, 1)))

capsule = {'schema': 'heptabao.actual-sdk-selected-owner-credentials.private.r1', 'host': 'mac',
    'ownerEntries': [{'ownerAgentDir': str(parent.OWNER), 'actualProvider': 'openai',
        'profileId': 'synthetic-%d' % n, 'credential': {'provider': 'openai', 'type': 'oauth',
                                                     'refresh': 'synthetic-refresh-%d' % n}}
        for n in range(3)]}
case('three_distinct_private_refresh_objects', lambda: (
    len(parent.capsule_scope(parent.encoded(capsule), 0)) == 3 or (_ for _ in ()).throw(AssertionError())))
duplicate = copy.deepcopy(capsule)
duplicate['ownerEntries'][2]['credential']['refresh'] = duplicate['ownerEntries'][0]['credential']['refresh']
case('distinct_profile_names_do_not_authorize_same_refresh_twice', lambda: rejected(
    lambda: parent.capsule_scope(parent.encoded(duplicate), 0)))
wrong_owner = copy.deepcopy(capsule)
wrong_owner['ownerEntries'][1]['ownerAgentDir'] = '/synthetic/unrelated/owner'
case('other_owner_never_enters_main_scope', lambda: rejected(
    lambda: parent.capsule_scope(parent.encoded(wrong_owner), 0)))


def local_parent():
    until = time.monotonic() + 120
    maintenance = types.SimpleNamespace(until=until, unknown=False, phase='safe-plist-published',
        verify_quiesced=lambda stage: True, bind_owned_refresh_child=lambda *a: None,
        retire_owned_refresh_child=lambda *a: None)
    stop_calls, publications = [], []
    def stop(child, custody):
        stop_calls.append(child)
        return {'ok': True, 'directChildReaped': True, 'allGroupRowsEmptyAfterReap': True}
    custody = types.SimpleNamespace(require_waitid=lambda: None, capture_child=lambda *a, **k: None,
        exit_observation=lambda *a: None, observed_returncode=lambda *a: 0, stop_once_unreaped=stop)
    signals = types.SimpleNamespace(pending=None, critical=contextlib.nullcontext)
    owner = parent.OwnedRefreshParent(maintenance=maintenance, reader=None, custody=custody,
        signals=signals, until=until, source_fence=lambda: None,
        read_private=lambda *a: (_ for _ in ()).throw(AssertionError('unexpected ledger read')),
        write_private=lambda *a: publications.append(a), write_closure=lambda *a: publications.append(a))
    return owner, stop_calls, publications


def close_failure_does_not_skip_other_pipe():
    owner, stop_calls, publications = local_parent()
    r, w = os.pipe()
    row = {'ordinal': 0, 'fds': [
        {'fd': r, 'closeAttempts': 0, 'closed': False},
        {'fd': w, 'closeAttempts': 0, 'closed': False}],
        'custody': None, 'libproc': None, 'stopAttempted': False,
        'complete': False, 'started': time.monotonic()}
    child = types.SimpleNamespace(returncode=0)
    close_calls = []
    def close(item):
        item['closeAttempts'] += 1
        close_calls.append(item['fd'])
        os.close(item['fd'])
        if item['fd'] == w:
            raise OSError('synthetic close result unknown after syscall')
        item['closed'] = True
    result = {}
    owner._retire_original(row, result, child, close, bytearray(), bytearray())
    assert len(stop_calls) == 1 and close_calls == [w, r]
    assert owner.blocked and result['allOriginalPipesClosedOnce'] is False and len(publications) == 3
    rejected(lambda: owner._retire_original(row, result, child, close, bytearray(), bytearray()))
    assert len(stop_calls) == 1 and close_calls == [w, r]
case('actual_local_pipe_close_failure_never_repeats_or_skips_other_end', close_failure_does_not_skip_other_pipe)


def unresolved_child_cannot_read_commit_or_advance():
    owner, _, _ = local_parent()
    result = {'allOriginalPipesClosedOnce': True, 'originalChildClosureKnown': False}
    row = {'ordinal': 0, 'complete': False}
    rejected(lambda: owner._accept_original(row, result, types.SimpleNamespace(returncode=None), b'{}', b''))
    assert owner.blocked and owner.maintenance.unknown and not owner.committed
    rejected(lambda: owner.run_one(ordinal=0, capsule_bytes=b'{}', capsule_identity=[0]*9,
                                  fresh_capture_fence=lambda: None))
case('unresolved_original_child_blocks_ledger_claim_and_next_launch', unresolved_child_cannot_read_commit_or_advance)


def original_context_cannot_skip_first_owner():
    owner, _, _ = local_parent()
    rejected(lambda: owner.run_one(ordinal=1, capsule_bytes=parent.encoded(capsule),
                                  capsule_identity=[0]*9, fresh_capture_fence=lambda: None))
    assert not owner.attempts
case('fresh_outer_cannot_skip_original_owner_order', original_context_cannot_skip_first_owner)

result = {'schema': 'heptabao.owned-refresh-parent.local-qualification.r1',
          'ok': all(c['passed'] for c in cases), 'checks': len(cases),
          'passed': sum(c['passed'] for c in cases), 'cases': cases,
          'actualMacQualified': False, 'providerDispatches': 0, 'productionChanges': 0,
          'processAuthoritySynthetic': True, 'realLocalPipeDescriptors': 2,
          'actualChildEventLoopQualified': False}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
raise SystemExit(0 if result['ok'] else 1)
