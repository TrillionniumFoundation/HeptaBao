#!/usr/bin/env python3
"""Boundaries of the readonly observer; no Mac, process or private source read."""
import copy
import json
import time
from unittest.mock import patch

import mac_current_gateway_observation_r2 as source

cases = []


def check(name, body):
    body()
    cases.append({'name': name, 'passed': True})


def refused(body):
    try:
        body()
    except source.ObservationRefused:
        return
    raise AssertionError('expected fixed refusal')


def raw(body):
    return (source.TARGET + ' = {\n' + body + '\n}\n').encode()


def environment_braces():
    result = source.scoped_environments(raw(
        '\tenvironment = {\n\t\tHOME => /Users/qianqi\n'
        '\t\tOPENCLAW_INCLUDE_ROOTS => {private-placeholder}\n'
        '\t\tUNRELATED_TOKEN => never-project-this\n\t}'))
    assert result == {'environment': {'HOME': '/Users/qianqi',
        'OPENCLAW_INCLUDE_ROOTS': '{private-placeholder}'}}


check('environment-values-with-braces-are-private-values', environment_braces)
check('duplicate-selected-environment-key-refused', lambda: refused(lambda:
    source.scoped_environments(raw('\tenvironment = {\nHOME => a\nHOME => b\n}'))))
check('duplicate-environment-layer-refused', lambda: refused(lambda:
    source.scoped_environments(raw('environment = {\n}\nenvironment = {\n}'))))
check('malformed-environment-entry-refused', lambda: refused(lambda:
    source.scoped_environments(raw('environment = {\nHOME = a\n}'))))


def conflicting_layers():
    projection = source.environment_projection(
        {'environment': {'OPENCLAW_CONFIG_PATH': str(source.CONFIG)},
         'inherited environment': {'OPENCLAW_CONFIG_PATH': '/private/other'}}, {})
    assert projection['selectionLayerConflicts'] == 1
    assert projection['registeredHomeStateConfigValuesConsistent'] is False
    assert projection['launchdEnvironmentIsJavaScriptMemoryProof'] is False
    assert '/private/other' not in json.dumps(projection)


check('conflicting-selector-layers-are-counted-without-value-export', conflicting_layers)
check('boolean-full9-refused', lambda: refused(lambda:
    source.normalize_full9([1, 2, 501, 20, 33152, 1, False, 8, 9])))
check('negative-full9-refused', lambda: refused(lambda:
    source.normalize_full9([1, -2, 501, 20, 33152, 1, 7, 8, 9])))


class FakeCommands:
    def __init__(self, unknown=False):
        self.calls = 0
        self.unknown = unknown

    def run(self, label, argv, *, until, maximum):
        self.calls += 1
        assert argv == ['/bin/launchctl', 'print', source.TARGET]
        assert maximum == 262144 and until <= time.monotonic() + 8
        return {'label': label, 'argv': argv, 'outcomeUnknown': self.unknown,
                'completeBeforeDeadline': not self.unknown, 'exitCode': 0,
                'stdoutSha256': 'synthetic-private-digest',
                'stderrSha256': 'synthetic-private-digest'}, raw('arguments = {\n/bin/sh\n}'), b''


def observer(commands):
    value = object.__new__(source.CurrentGatewayObservation)
    value.until = time.monotonic() + 20
    value.commands = commands
    value.runtime_fence = lambda: None
    value.private_queries = []
    value.query_sequence_blocked = False
    value.public_commands = []
    value.private_write = lambda name, value: None
    value.parse_print = lambda out, target: {}
    return value


def query_privacy():
    commands = FakeCommands()
    value = observer(commands)
    value.query(0)
    assert commands.calls == 1
    assert 'synthetic-private-digest' not in json.dumps(value.public_commands)
    assert value.private_queries[0]['original']['stdoutSha256'] == 'synthetic-private-digest'


check('original-command-digests-stay-private', query_privacy)


def unknown_once():
    commands = FakeCommands(unknown=True)
    value = observer(commands)
    refused(lambda: value.query(0))
    refused(lambda: value.query(0))
    refused(lambda: value.query(1))
    assert commands.calls == 1


check('unknown-original-query-is-not-replayed', unknown_once)


class FakeReader:
    def __init__(self):
        self.rows = {
            100: {'pid': 100, 'ppid': 1, 'pgid': 100, 'uid': 501,
                  'birthSec': 1, 'birthUsec': 1, 'executable': source.NODE},
            101: {'pid': 101, 'ppid': 100, 'pgid': 100, 'uid': 501,
                  'birthSec': 2, 'birthUsec': 1, 'executable': '/synthetic/private/child'},
        }
        self.links = {100: [101], 101: []}

    def read(self, pid):
        return copy.deepcopy(self.rows[pid])

    def children(self, pid):
        return list(self.links[pid])


def family_changed(field):
    value = observer(FakeCommands())
    value.reader = FakeReader()
    rows, relations = value.family(100)
    if field == 'birth':
        value.reader.rows[101]['birthUsec'] = 2
    else:
        value.reader.links[100] = []
    refused(lambda: value.verify_family(rows, relations))


check('same-pid-new-birth-refused', lambda: family_changed('birth'))
check('descendant-set-drift-refused', lambda: family_changed('children'))


def close_failure_attempts_every_returned_fd_once():
    value = source.FixedPlist(lambda: None)
    value.rows = [{'fd': number, 'closeAttempts': 0, 'closed': False}
                  for number in (10, 11, 12)]
    calls = []

    def close(fd):
        calls.append(fd)
        if fd == 11:
            raise OSError('synthetic')

    with patch.object(source.os, 'close', close):
        value.close()
        value.close()
    assert calls == [12, 11, 10]
    assert value.public()['allOwnedDescriptorsClosedOnce'] is False
    assert value.public()['closeErrorCount'] == 1


check('one-close-failure-does-not-leak-or-retry-other-handles',
      close_failure_attempts_every_returned_fd_once)

print(json.dumps({'schema': 'heptabao.current-gateway-observer-local-boundaries.r2',
                  'ok': True, 'passed': len(cases), 'cases': cases,
                  'macExecuted': False, 'gatewayObserved': False,
                  'serviceActions': 0, 'providerCalls': 0}, sort_keys=True))
