#!/usr/bin/env python3
"""Finite local scope/FS checks; not Mac SQL or provider qualification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
AUTHORITY = HERE.parent / 'main3-sdk-outer-r4-work/source-sdk-r4/main3_source_authority.py'
spec = importlib.util.spec_from_file_location('main3_source_authority', AUTHORITY)
authority = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = authority; spec.loader.exec_module(authority)
import mac_current_selected_main3_r1 as module

cases = []


def check(name, function):
    function()
    cases.append({'case': name, 'passed': True})


def refuses(function):
    try:
        function()
    except module.CurrentOwnersRefused:
        return
    raise AssertionError('expected refusal')


def document():
    return {'schema': 'heptabao.actual-sdk-selected-owner-credentials.private.r1', 'host': 'mac',
        'sourceSelectionAuthority': authority.SOURCE_SELECTION_AUTHORITY,
        'sdkSourcePins': authority.SDK_SOURCE_PINS,
        'configurationSha256': hashlib.sha256(b'{"synthetic":true}\n').hexdigest(),
        'ownerEntries': [{'profileId': 'synthetic-owner-%d' % i, 'ownerAgentDir': str(module.OWNER),
            'actualProvider': 'openai', 'credential': {'refresh': 'old-never-used-%d' % i}}
            for i in range(3)]}


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def scope(doc=None):
    return module.authorized_scope(encode(document() if doc is None else doc), b'{"synthetic":true}\n')


def fresh():
    return {'storeRowPresent': True, 'registeredMissingCount': 0,
        'profiles': {identifier: {'provider': 'openai', 'type': 'oauth', 'refresh': 'fresh-%d' % i}
                     for i, identifier in enumerate(scope())}}


def old_values_unused():
    value = document()
    for entry in value['ownerEntries']:
        entry['credential'] = None
    assert scope(value) == scope()
    result = module.current_entries(fresh(), scope(value))
    assert [row['credential']['refresh'] for row in result] == ['fresh-0', 'fresh-1', 'fresh-2']


check('historical-values-ignored-current-values-only', old_values_unused)
check('configuration-change-refused', lambda: refuses(lambda: module.authorized_scope(encode(document()), b'{}')))


def wrong_scope():
    for change in ('authority', 'owner', 'duplicate'):
        value = document()
        if change == 'authority':
            value['sourceSelectionAuthority'] = {}
        elif change == 'owner':
            value['ownerEntries'][0]['ownerAgentDir'] = '/synthetic/unregistered'
        else:
            value['ownerEntries'][1]['profileId'] = value['ownerEntries'][0]['profileId']
        refuses(lambda: scope(value))


check('authority-owner-and-duplicate-scope-refused', wrong_scope)


def missing_current():
    value = fresh(); del value['profiles'][scope()[0]]
    refuses(lambda: module.current_entries(value, scope()))
    value = fresh(); value['profiles']['synthetic-not-selected'] = {}
    refuses(lambda: module.current_entries(value, scope()))


check('missing-or-extra-current-profile-refused', missing_current)


def invalid_current():
    for change in ('duplicate', 'missing', 'provider'):
        value = fresh()
        row = value['profiles'][scope()[1]]
        if change == 'duplicate':
            row['refresh'] = value['profiles'][scope()[0]]['refresh']
        elif change == 'missing':
            row['refresh'] = ''
        else:
            row['provider'] = 'synthetic-unregistered-provider'
        refuses(lambda: module.current_entries(value, scope()))


check('shared-missing-or-wrong-provider-refresh-refused', invalid_current)


def filesystem_case(mutation=None):
    # This executor's /workspace is 0777. Keep production ancestor checks
    # unchanged; use one fresh 0700 directory beneath its owned 0755 root.
    with tempfile.TemporaryDirectory(prefix='heptabao-current-main3-local-', dir='/') as temporary:
        root = Path(temporary)
        live, original = root / 'live', root / 'scope'
        live.mkdir(mode=0o700); original.mkdir(mode=0o700)
        config, capsule = live / 'openclaw.json', original / 'selected.private.json'
        config.write_bytes(b'{"synthetic":true}\n'); config.chmod(0o600)
        capsule.write_bytes(encode(document())); capsule.chmod(0o600)
        saved = {name: getattr(module, name) for name in ('CONFIG', 'SCOPE', 'UID', 'GID', 'SYSTEM_UID')}
        module.CONFIG, module.SCOPE = config, capsule
        module.UID, module.GID = os.geteuid(), os.getegid()
        module.SYSTEM_UID = Path('/').stat().st_uid
        observer = None
        try:
            observer = module.ScopeInputs(until=time.monotonic()+10, source_fence=lambda: None)
            assert observer.read(capsule) == capsule.read_bytes()
            assert observer.read(config) == config.read_bytes()
            if mutation == 'replace':
                fresh_path = root / 'replacement'
                fresh_path.write_bytes(config.read_bytes()); fresh_path.chmod(0o600)
                fresh_path.replace(config)
                refuses(observer.verify)
            elif mutation == 'sameinode':
                with config.open('r+b') as target:
                    target.write(b'{"synthetic":null}\n')
                refuses(observer.verify)
            else:
                observer.verify()
                assert observer.close()['allOriginalDescriptorsClosedOnce']
                assert observer.closed_fence()
        finally:
            if observer is not None:
                assert observer.close()['allOriginalDescriptorsClosedOnce']
            for name, value in saved.items():
                setattr(module, name, value)


check('real-fs-private-two-inputs-and-full-closure', filesystem_case)
check('real-fs-same-bytes-replaced-inode-refused', lambda: filesystem_case('replace'))
check('real-fs-same-inode-modification-refused', lambda: filesystem_case('sameinode'))
result = {'schema': 'heptabao.current-three-selected-local-checks.r1', 'ok': True,
    'cases': cases, 'passed': len(cases), 'expected': 8,
    'scope': 'pure-scope-projection-and-real-local-filesystem-only',
    'actualMacSqlReaderExecuted': False, 'realCredentialsRead': False,
    'providerCalls': 0, 'productionEffects': 0, 'runningConsumerExclusionProven': False}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
