#!/usr/bin/env python3
"""Independently verify all original range receipts, byte strings and closure."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
JOBS = {'pocket': ('pocket4', '1a1b2fd4226-fc05-805e', 770594, 13992, 15903),
        'rog': ('rog', '1a1b2fd8256-fc05-805f', 770423, 13990, 15900)}
source = (HERE / 'inspect_linux_sdk_permissions_r1.py').read_bytes()
assert hashlib.sha256(source).hexdigest() == '904643f4bf3ab8eda134fcee3b4a6949bf5b64edf4f295d9136acd0d12c35a0f'
results = []
for prefix, (host, job, size, descriptors, candidates) in JOBS.items():
    root = HERE / (prefix + '-sdk-permissions-r1-retained')
    launch = json.loads((root / 'runtime-launch.original.json').read_bytes())
    terminal = json.loads((root / 'runtime-terminal.original.json').read_bytes())
    assert launch['job']['host'] == host and launch['job']['id'] == job and launch['reused'] is False
    assert terminal['job_id'] == job and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
    assert all(terminal[k] is True for k in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
    assert all(terminal[k] is False for k in ('automatic_retry', 'cancelled', 'timed_out'))
    assert terminal['log_bytes'] == {'stderr': {'seen': 0, 'stored': 0},
                                     'stdout': {'seen': size, 'stored': size}}
    offset = 0
    whole = bytearray()
    for number in range(48):
        page = json.loads((root / ('runtime-read-%02d.original.json' % number)).read_bytes())
        out, err = page['stdout'], page['stderr']
        assert page['job_id'] == job and out['offset'] == offset and out['size'] == size
        raw = bytes.fromhex(out['bytes_hex'])
        assert raw == out['text'].encode() and len(raw) == min(16384, size - offset)
        offset += len(raw)
        assert out['next_offset'] == offset and out['eof'] == (number == 47)
        assert err['size'] == err['offset'] == err['next_offset'] == 0
        assert err['text'] == err['bytes_hex'] == '' and err['eof'] is True
        whole.extend(raw)
    whole = bytes(whole)
    assert offset == size and whole == (root / 'stdout.original.json').read_bytes()
    q = json.loads(whole)
    assert q['ok'] and q['allBeforeAfterMetadataIdentitiesExact'] and q['allDescriptorsClosedOnce']
    assert q['entryCount'] == 33869 and q['directories'] == 1914 and q['regularFiles'] == 31938
    assert q['symlinks'] == 17 and q['externalSymlinkCount'] == 0
    assert len(q['descriptors']) == descriptors and all(r['closeAttempts'] == 1 and r['closed'] is True for r in q['descriptors'])
    assert q['candidateCount'] == candidates and q['candidateChanges'] == [] and q['publicCandidateListComplete'] is False
    assert not any(q[k] for k in ('permissionsChanged', 'sdkExecuted', 'credentialDatabaseOpened',
                                 'networkOpened', 'productionClientQualification',
                                 'actualExecutableDependencyClosureQualified',
                                 'permissionsChangeAuthorizedByThisReceipt'))
    assert all(q[k] == 0 for k in ('serviceActions', 'providerCalls', 'childProcesses'))
    results.append({'host': host, 'jobId': job, 'originalStdoutBytes': size,
                    'originalStdoutSha256': hashlib.sha256(whole).hexdigest(),
                    'originalStdoutGitBlob': hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + whole).hexdigest(),
                    'completeOriginalRangeReceiptsVerified': 48,
                    'allOriginalTextAndHexBytesEqual': True, 'allOriginalFdsClosedOnce': descriptors,
                    'observedSdkEntries': 33869, 'groupOrOtherWritableCodeAndDirectoryCandidates': candidates,
                    'additionalWritableNonCodeFiles': q['writableNonCodeCount'],
                    'actualExecutableDependencyClosureQualified': False, 'productionQualification': False})
receipt = {'schema': 'heptabao.root-retained-linux-sdk-permission-verification.r1', 'ok': True,
           'sourceSha256': hashlib.sha256(source).hexdigest(), 'hosts': results,
           'permissionChangesPerformed': False, 'credentialValuesOrHashesRead': False}
raw = json.dumps(receipt, indent=2, sort_keys=True) + '\n'
(HERE / 'linux-sdk-permissions-r1.root-verification.public.json').write_text(raw)
print(raw, end='')
