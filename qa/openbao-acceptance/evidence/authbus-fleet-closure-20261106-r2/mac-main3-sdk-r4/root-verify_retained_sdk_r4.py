#!/usr/bin/env python3
"""Verify retained original SDK r4 evidence; no remote/product execution."""
import hashlib
import json
import sys
from pathlib import Path

assert len(sys.argv) <= 2
ROOT = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parent / 'sdk-r4-retained'
BLOBS = {
    'execution.stdout.original.json': 'dc2264f196dbe142dd686b11bfde731339849219',
    'execution-terminal.original.json': '144bb383d12ff53ad9f76b2e9ee6b550bba254a0',
    'independent-absence.stdout.original.json': 'ef7f953584ad417b7cb5707437aca90fd18435bc',
    'independent-absence-authority.public.json': '1a4fca7d6fb1121600883a0b9885b52a893206b4',
    '103-final-result.public.json': 'f2fbf02654165ebcdbd4e4809219c0d182c29216',
    '098-complete-command-batch.public.json': 'f999d70adfe91d9d2cfceb309e90def380d3a97a',
    '099-complete-command-batch.public.json': '09419a612cdc0829e5407de9a58990f6a8263daf',
    '100-complete-command-batch.public.json': '94c68e614ff72b73c35dac7d6fad609cc1fe98cb',
    '101-complete-command-batch.public.json': '771228d572c8abc541fd2ed3a0ac4a757505de2a',
    '102-complete-command-batch.public.json': '56680dc5f2312a1c4842a4648ca8f7a801acca88',
}
raw, data, pins = {}, {}, {}
for name, blob in BLOBS.items():
    path = ROOT / name
    if not path.exists() and name[:3].isdecimal():
        path = ROOT / 'journal' / name
    content = path.read_bytes()
    assert hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == blob
    raw[name], data[name] = content, json.loads(content)
    pins[name] = {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'gitBlob': blob}

j = data['execution.stdout.original.json']
terminal = data['execution-terminal.original.json']
absence = data['independent-absence.stdout.original.json']
authority = data['independent-absence-authority.public.json']
for value, job, name in (
    (terminal, '1a1b2babcc1-fc05-7f81', 'execution.stdout.original.json'),
    (authority, '1a1b2c18152-fc05-7f9a', 'independent-absence.stdout.original.json'),
):
    assert value['job_id'] == job and value['state'] == 'succeeded' and value['exit_code'] == 0
    assert all(value[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
    assert all(value[k] is False for k in ('timed_out', 'cancelled', 'automatic_retry'))
    assert value['log_bytes']['stdout'] == {'seen': len(raw[name]), 'stored': len(raw[name])}
    assert value['log_bytes']['stderr'] == {'seen': 0, 'stored': 0}
    assert all(v is False for v in value['log_truncated'].values())

final_name = '103-final-result.public.json'
final = data[final_name]
assert final['event'] == 'final-result' and final['index'] == 103
assert final['value'] == {k: v for k, v in j.items() if k not in ('journalRows', 'journalClosed')}
assert absence['finalResultSha256'] == pins[final_name]['sha256']
assert all(j[k] is True for k in ('ok', 'actualPluginSdkQualified', 'closuresKnown', 'journalClosed'))
assert all(j[k] is False for k in ('providerCalled', 'providerRefreshAttempted', 'providerValid',
    'productionChanged', 'productionTrafficCutover', 'productionClientRollbackQualified',
    'wholeProductionDatabaseRollback', 'j3160Contacted', 'credentialValuesOrDigestsPublished'))
assert j['canonicalProduct']['commit'] == '4bde9aee03fcd27c59e13607e529b1cee594b249'

commands = []
for original in j['commands']['completeCommandBatchFiles']:
    name = Path(original['path']).name
    assert original['bytes'] == pins[name]['bytes'] and original['sha256'] == pins[name]['sha256']
    row = data[name]
    assert row['event'] == 'complete-command-batch' and row['value']['firstIndex'] == len(commands)
    commands.extend(row['value']['commands'])
assert len(commands) == j['commands']['completeCommandCount'] == 67
assert j['commands']['allOwnedCommandsStopped'] is True and j['commands']['unknownCommandCount'] == 0
for row in commands:
    assert row['completeBeforeDeadline'] is True and row['streamsClosed'] is True and row['outcomeUnknown'] is False
    cleanup = row['cleanup']
    assert all(cleanup[k] is True for k in ('ok', 'directChildReaped', 'ownedLiveGroupEmptyBeforeReap', 'allGroupRowsEmptyAfterReap'))
    assert cleanup['outcomeUnknown'] is False and cleanup['remainingGroupRows'] == []

assert len(j['phases']) == 2
outer_checks = sdk_checks = outer_http = sdk_http = sqlite_connections = 0
for index, phase in enumerate(j['phases']):
    assert phase['phase'] == ('initial', 'cold-new-process')[index]
    assert len(phase['checks']) == (32, 20)[index] and all(x['passed'] is True for x in phase['checks'])
    assert len({x['case'] for x in phase['checks']}) == len(phase['checks'])
    assert phase['unknownHttpOutcomeCount'] == 0 and phase['sdkChildOutcomeUnknown'] is False
    assert phase['allDispatchedResponsesComplete'] is True and phase['allReturnedSocketsClosed'] is True
    assert len(phase['requests']) == phase['requestCount'] == (20, 14)[index]
    for request in phase['requests']:
        assert request['httpRequestCount'] == 1 and request['outcomeUnknown'] is False
        assert all(request[k] is True for k in ('responseComplete', 'tlsVerified', 'socketsClosed', 'responseReaderClosed'))
    assert len(phase['sdkChildren']) == 1
    sdk = phase['sdkChildren'][0]
    assert sdk['ok'] is True and sdk['outcomeUnknown'] is False
    assert len(sdk['checks']) == (56, 109)[index] and all(x['passed'] is True for x in sdk['checks'])
    assert sdk['inverseCompleted'] is bool(index) and sdk['inverseMutationAttempted'] is bool(index)
    assert sdk['inverseRetried'] is False and sdk['candidateSaved'] is True
    assert sdk['sourceOwnerCredentialCount'] == 3 and sdk['sourceConsumerReferenceCount'] == 15
    assert sdk['expiredInputCount'] == 3 and sdk['providerValid'] is False
    assert sdk['workerReadDescriptorsOpened'] == sdk['workerReadDescriptorsClosed']
    assert sdk['forbiddenChildAttemptCount'] == 0 and sdk['serviceStopped'] is True and sdk['networkHooksRestored'] is True
    sql = sdk['sqlite']
    assert sql['allOriginalHandlesClosedOnce'] is True and sql['denials'] == 0
    assert sql['opened'] == sql['closed'] == sql['attempts'] == (422, 363)[index]
    connection = sdk['connections']
    assert all(connection[k] is True for k in ('allDispatchedResponsesComplete', 'allObservedSocketsClosed', 'ownedHttpsAgentClosed'))
    assert all(connection[k] == 0 for k in ('otherNetworkDenials', 'remainingRequestCount', 'remainingSocketCount', 'unknownOutcomeCount'))
    assert len(sdk['wire']) == (12, 9)[index]
    for request in sdk['wire']:
        assert request['requestCount'] == 1 and request['outcomeUnknown'] is False
        assert all(request[k] is True for k in ('responseComplete', 'tlsVerified', 'requestClosed', 'socketClosed',
            'tlsSocketAuthorized', 'tlsEndpointMatched', 'tlsPeerCertificateAvailable', 'tlsHostMatched', 'tlsLeafMatched'))
    outer_checks += len(phase['checks']); sdk_checks += len(sdk['checks'])
    outer_http += len(phase['requests']); sdk_http += len(sdk['wire']); sqlite_connections += sql['closed']

manager = j['manager']
assert all(manager[k] is True for k in ('ok', 'allKnownLineagesClosed', 'allRegistrationsClosed', 'allOwnedCommandsStopped', 'allManagerReadDescriptorsClosed'))
assert manager['outcomeUnknown'] is False and len(manager['registrations']) == 2
assert all(x['registrationClosed'] is True and x['lineagesClosed'] is True and x['remainingGroupRows'] == [] for x in manager['registrations'])
assert all(x['allReturnedDescriptorsClosed'] is True for x in j['sourceFences'])
assert absence['ok'] is True and absence['serviceMutationDispatched'] is False and len(absence['rounds']) == 2
for row in absence['rounds']:
    assert row['guiLabelAbsent'] is True and row['guiQueryExitCode'] == 113
    assert row['relatedPidGroupOrDirectChildRows'] == []
    assert len(row['nativePidAbsence']) == 5 and all(x['errno'] == 3 and x['returnedBytes'] == 0 for x in row['nativePidAbsence'])

print(json.dumps({'schema': 'heptabao.root-retained-sdk-r4-verification.r1', 'ok': True,
    'originalJob': terminal['job_id'], 'originalAbsenceJob': authority['job_id'],
    'outerChecks': outer_checks, 'sdkChecks': sdk_checks, 'outerHttp': outer_http, 'sdkHttp': sdk_http,
    'allCompleteHttpCount': outer_http + sdk_http, 'sqliteConnectionsClosedOnce': sqlite_connections,
    'originalHelperCommandsClosed': len(commands), 'independentAbsenceRounds': 2,
    'finalJournalAndStdoutExactlyAgree': True, 'allOriginalPublicBytePinsVerified': pins,
    'newRemoteOrProductExecution': False, 'providerValid': False, 'productionClientRollbackQualified': False,
    'fullReplacementQualified': False}, sort_keys=True))
