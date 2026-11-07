#!/usr/bin/env python3
"""Verify the original recovery receipts without private keys or responses."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def read(name):
    return json.loads((HERE / name).read_bytes())


raw = (HERE / 'execution.stdout.original.json').read_bytes()
assert len(raw) == 118589
assert hashlib.sha256(raw).hexdigest() == '966c46522dcef9c4eefcc6d844033930b6060e34f7ff97e3d1be1b6aef35dcac'
report = json.loads(raw)
terminal = read('execution-terminal.original.json')
launch = read('execution-launch.original.json')
intent = read('dispatch-intent.public.json')
job = '1a1b41e9232-fc05-865b'
assert terminal['job_id'] == launch['job']['id'] == job
assert launch['job']['host'] == intent['host'] == 'mac'
assert launch['job']['idempotency_key'] == intent['idempotency_key'] == 'heptabao-mac-fixed-slot-coordinator-recovery-20261107-r2'
assert launch['job']['args'] == intent['args'] == ['-I', '-S', '-B', '-']
assert launch['job']['launch_state'] == 'launched' and launch['reused'] is False
assert launch['job']['request_digest'] == '685cc6f3b6c5a71469a1cab981b24b34a702efbb6a6d90486151c129b3960c68'
assert type(launch['job']['request_fingerprint']) is int  # parse original JSON exactly, never a float round-trip
assert intent['stdinBytes'] == 250110 and intent['stdinSha256'] == '26607ac1cff11a8478ebfc09c0cb7a699c1897c188070c0278ef2dd02a8100f0'
assert intent['timeout_seconds'] == 630
assert terminal['state'] == 'succeeded' and type(terminal['exit_code']) is int and terminal['exit_code'] == 0
assert terminal['output_complete'] is True and terminal['output_durable'] is True
assert terminal['terminal_publication_confirmed'] is True
assert terminal['timed_out'] is False and terminal['cancelled'] is False
assert terminal['log_bytes'] == {'stdout': {'seen': 118589, 'stored': 118589}, 'stderr': {'seen': 0, 'stored': 0}}
assert terminal['log_synced'] == {'stdout': True, 'stderr': True}
assert terminal['log_truncated'] == {'stdout': False, 'stderr': False}
joined, offset = bytearray(), 0
for ordinal in range(1, 9):
    page = read('read-page-%03d.original.json' % ordinal)
    out, err = page['stdout'], page['stderr']
    part = bytes.fromhex(out['bytes_hex'])
    assert page['job_id'] == job and out['offset'] == offset and out['size'] == len(raw)
    assert part == out['text'].encode() and out['next_offset'] == offset + len(part)
    assert out['eof'] is (ordinal == 8)
    assert err == {'bytes_hex': '', 'eof': True, 'next_offset': 0, 'offset': 0, 'size': 0, 'text': ''}
    joined.extend(part); offset = out['next_offset']
assert bytes(joined) == raw and offset == len(raw)
assert report['ok'] is True and report['schema'] == 'heptabao.fixed-slot-normal-recovery-qualification.r2'
assert report['originalAttemptStillFailed'] is True and report['originalExecutionKeyReplayed'] is False
assert report['originalAdmission']['originalJob'] == '1a1b3e976fc-fc05-8575'
assert report['originalClosedEvidenceAndPublishedDirectoriesUnchanged'] is True
assert report['allProtectedSourcesAndPrivateInputsUnchanged'] is True
assert report['productCommit'] == '4bde9aee03fcd27c59e13607e529b1cee594b249'
assert report['coordinatorImplementationSha256'] == '248057b53a13708cc0650b73c83bc86729a7572e0d1bf24768ea94b8d3fd8265'
assert [p['phase'] for p in report['nodePhases']] == ['initial', 'cold']
assert [p['phase'] for p in report['apiPhases']] == ['initial', 'cold-new-process']
assert [len(p['checks']) for p in report['nodePhases']] == [10, 12]
assert [len(p['checks']) for p in report['apiPhases']] == [19, 11]
assert [p['wire']['requestCount'] for p in report['nodePhases']] == [173, 59]
assert [p['requestCount'] for p in report['apiPhases']] == [15, 8]
for phase in report['nodePhases']:
    assert phase['ok'] is True and phase['closureFailures'] == [] and phase['completedWithinOriginalPhase'] is True
    assert all(row['passed'] is True for row in phase['checks'])
    assert phase['sqlite'] == {'opened': 6, 'closed': 6, 'allOriginalHandlesClosedOnce': True}
    assert phase['explicitFiles']['opened'] == phase['explicitFiles']['closed']
    assert phase['explicitFiles']['allOriginalExplicitDescriptorsClosedOnce'] is True
    assert all(resource['closed'] is True for resource in phase['resources'])
    wire = phase['wire']
    assert len(wire['requests']) == wire['requestCount']
    assert all(wire[k] is True for k in ('allDispatchedResponsesComplete', 'allDispatchedTlsVerified',
        'allOriginalRequestsClosed', 'allOriginalSocketsClosed'))
    assert wire['deniedOtherNetwork'] == 0
    sockets = {row['ordinal']: row for row in wire['sockets']}
    assert len(sockets) == len(wire['sockets'])
    for row in sockets.values():
        assert all(row[k] is True for k in ('actualIpv4AndPort', 'authorized', 'closed', 'leafExact', 'secureConnectObserved'))
        assert row['protocol'] in ('TLSv1.2', 'TLSv1.3')
    for row in wire['requests']:
        assert all(row[k] is True for k in ('closed', 'ended', 'originalSocketBound', 'responseComplete', 'responseSeen'))
        assert row['socketOrdinal'] in sockets and type(row['status']) is int and 200 <= row['status'] < 600
for phase in report['apiPhases']:
    assert phase['unknownHttpOutcomeCount'] == 0 and len(phase['requests']) == phase['requestCount']
    assert all(row['passed'] is True for row in phase['checks'])
    for row in phase['requests']:
        assert row['outcomeUnknown'] is False
        assert all(row[k] is True for k in ('dispatched', 'tlsVerified', 'responseComplete',
            'responsePrivatelyDurable', 'responseReaderClosed', 'socketsClosed'))
        assert row['httpRequestCount'] == 1 and row['routeCategory'] != 'init'
assert report['nodePhases'][0]['localReceiptInterruptionInjected'] is True
assert report['nodePhases'][0]['originalOperationPendingForColdReconciliation'] is True
assert report['nodePhases'][1]['originalOperationPendingForColdReconciliation'] is False
assert report['nodePhases'][1]['wire']['requests'][0]['routeCategory'] == 'ack'
assert report['nodePhases'][1]['wire']['requests'][0]['method'] == 'GET'
assert report['networkResponseLossSimulated'] is False
assert len(report['serverProcesses']) == len(report['originalServerCleanupRecords']) == 2
assert [row['pid'] for row in report['originalServerCleanupRecords']] == [27819, 27942]
for row in report['serverProcesses']:
    c = row['cleanup']
    assert c['ok'] is True and c['outcomeUnknown'] is False and c['directChildReaped'] is True
    assert c['allGroupRowsEmptyAfterReap'] is True and c['remainingGroupRows'] == []
    assert c['signals'] == ['SIGTERM'] and c['exitCode'] == -15 and c['postReapSignalSent'] is False
    assert row['errors'] == [] and all(log['newCredentialMaterialLogged'] is False for log in row['logs'])
assert report['allOriginalServersClosed'] is True and report['finalServerRunning'] is False
assert report['explicitDescriptors'] == 195 and report['allExplicitDescriptorsClosedOnce'] is True
assert report['descriptorCloseErrors'] == [] and report['nodeBusinessOutcomeUnknown'] is False
assert len(report['commands']['commands']) == 3 and report['commands']['allOwnedCommandsStopped'] is True
assert report['commands']['unknownCommandCount'] == 0
for row in report['commands']['commands']:
    assert row['exitCode'] == 0 and row['outcomeUnknown'] is False and row['streamsClosed'] is True
    assert row['cleanup']['ok'] is True
assert report['volumeClosure']['allDescriptorsClosed'] is True and report['volumeClosure']['lastAnchorCheckPassed'] is True
assert report['volumeClosure']['closeErrors'] == []
assert report['deadlineAfterClosurePassed'] is True and report['cancellationObserved'] is False
for key in ('initializationRequests', 'nativeCryptoCommands', 'providerCalls', 'currentCredentialReads',
            'productionClientChanges', 'legacyChanges', 'j3160Requests'):
    assert type(report[key]) is int and report[key] == 0
assert report['launchAgentInstalled'] is False and report['productionCutoverQualified'] is False
assert report['syntheticCredentialsOnly'] is True
print(json.dumps({'schema': 'heptabao.fixed-slot-coordinator-recovery-evidence-verification.r2',
    'ok': True, 'originalJob': job, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
    'losslessPages': 8, 'nodeBusinessChecks': 22, 'outerChecks': 30,
    'nodeCompleteRequests': 232, 'outerCompleteRequests': 23, 'totalCompleteRequests': 255,
    'parentExplicitFds': 195, 'nodeExplicitFds': 257, 'nodeSqliteHandles': 12,
    'rustGenerationsClosed': 2, 'ownedCommandRowsClosed': 3, 'unknownOutcomes': 0,
    'originalR1StillFailed': True, 'sameInitializedStoreRecoveredWithoutInit': True,
    'nativeIntegerRawTextRetained': True, 'independentPostTerminalAbsenceRun': False,
    'syntheticOnly': True, 'providerValidityOrProductionCutoverQualified': False}, sort_keys=True))
