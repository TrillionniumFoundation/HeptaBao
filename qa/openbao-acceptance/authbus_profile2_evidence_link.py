#!/usr/bin/env python3
"""Link independent provider and consumer receipts without rewriting their outcomes.

This verifier performs no network request and publishes no credential or account
identity. It does not turn either failed top-level run into a successful run and
does not claim current provider connectivity or production readiness.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import stat
import time


def sha(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
        assert info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o077 and info.st_size < 2 * 1024 * 1024
        raw = os.read(fd, 2 * 1024 * 1024)
        after, current = os.fstat(fd), Path(path).lstat()
        identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        assert identity(info) == identity(after) == identity(current) and len(raw) == info.st_size
        return raw, json.loads(raw)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-run', type=Path, required=True)
    parser.add_argument('--lifecycle-run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    pr, provider_run = read(args.provider_run / 'result.public.json')
    lr, lifecycle_run = read(args.lifecycle_run / 'result.public.json')
    ur, usage = read(args.provider_run / 'selected-account-provider-read.public.json')
    sr, selection = read(args.provider_run / 'consumer-initial/runtime-selection.private.json')
    assert usage.get('ok') is True and usage.get('httpStatus') == 200 and usage.get('tlsVerified') is True
    assert usage.get('requestCount') == 1 and usage.get('actualDefaultSelectedAccountProviderValidated') is True
    assert usage.get('selectionSha256') == sha(sr) and provider_run['actualDefaultSelectedProviderRead'] == usage
    origin = 'actual_installed_sdk_default_model_resolver_after_actual_authbus_cycle'
    assert selection.get('source') == origin and selection['resolvedApiKey'] == selection['credential']['access']
    claims = json.loads(base64.urlsafe_b64decode(selection['resolvedApiKey'].split('.')[1] + '==='))
    assert claims['https://api.openai.com/auth']['chatgpt_account_id'] == selection['credential']['accountId']
    assert claims['exp'] > time.time()
    binding_keys = ('sourceCommit', 'sourceTree', 'binarySha256', 'sourceNativeSha256', 'selectedCredentialSha256')
    assert all(provider_run[k] == lifecycle_run[k] for k in binding_keys)
    installed_pins = lambda d: {p: value for p, value in d['sourcePins'].items() if p.startswith(('/Users/', '/opt/'))}
    assert installed_pins(provider_run) == installed_pins(lifecycle_run)
    phases = {p['phase']: p for p in lifecycle_run['phases']}
    required = ('initial', 'cold-new-process', 'initial.rollback', 'cold-new-process.rollback')
    assert all(phases[p]['ok'] is True and all(c['passed'] is True for c in phases[p]['checks']) for p in required)
    assert lifecycle_run.get('ownedServerStopped') is True
    assert lifecycle_run.get('actualServerColdRestartQualified') is True
    assert lifecycle_run.get('privateLogicalStoreRollbackQualified') is True
    assert lifecycle_run.get('actualInstalledPluginImportedCredential') is True
    assert lifecycle_run.get('actualInstalledDefaultResolverQualified') is True
    failures = [c['case'] for c in lifecycle_run['checks'] if c['passed'] is not True]
    assert failures == ['actual_default_selected_provider_read']
    selections = []
    for phase in ('initial', 'cold-new-process'):
        raw, other = read(args.lifecycle_run / ('consumer-' + phase) / 'runtime-selection.private.json')
        assert other.get('source') == origin
        assert all(other[k] == selection[k] for k in ('profileId', 'credential', 'resolvedApiKey', 'credentialSha256', 'model'))
        selections.append({'phase': phase, 'sha256': sha(raw), 'credentialAndResolvedAccessByteIdentical': True})
    assert all(d.get('productionChanged') is False and d.get('productionTrafficCutover') is False
               and d.get('j3160Contacted') is False and d.get('allAccountsQualified') is False
               for d in (provider_run, lifecycle_run))
    report = {'schema': 'heptabao.independent-profile2-evidence-link.v1',
        'evidenceBindingVerified': True, 'sameRunCompletePass': False,
        'providerConnectivityIntermittent': True, 'currentProviderConnectivityQualified': False,
        'productionGatewaySelectionQualified': False, 'productionRolloutQualified': False,
        'allAccountsQualified': False, 'j3160Contacted': False, 'networkRequestsPerformed': 0,
        'credentialValuesPublished': False, 'accountIdentitiesPublished': False,
        'productionChanged': False, **{k: lifecycle_run[k] for k in binding_keys},
        'sourceProfileCount': lifecycle_run['sourceProfileCount'], 'selectedProfileOrdinal': 2,
        'providerRun': {'path': str(args.provider_run / 'result.public.json'), 'sha256': sha(pr),
            'originalOk': provider_run['ok'], 'originalError': provider_run.get('error'),
            'providerProofPath': str(args.provider_run / 'selected-account-provider-read.public.json'),
            'providerProofSha256': sha(ur), 'providerHttpStatus': usage['httpStatus'], 'tlsVerified': usage['tlsVerified'],
            'actualDefaultSelectionSha256': sha(sr)},
        'lifecycleRun': {'path': str(args.lifecycle_run / 'result.public.json'), 'sha256': sha(lr),
            'originalOk': lifecycle_run['ok'], 'originalError': lifecycle_run.get('error'),
            'checksPassed': sum(c['passed'] is True for c in lifecycle_run['checks']),
            'checksTotal': len(lifecycle_run['checks']), 'failedCases': failures,
            'freshProviderRead': lifecycle_run['actualDefaultSelectedProviderRead'],
            'phases': [{'phase': p, 'ok': phases[p]['ok'], 'checksPassed': len(phases[p]['checks'])} for p in required]},
        'linkedActualSelections': selections, 'installedSourcePins': installed_pins(lifecycle_run),
        'qualifications': {'actualInstalledAuthBusImport': True, 'actualDefaultModelSelection': True,
            'actualProviderAcceptedSameCredentialInSeparateRun': True, 'actualFormalV6SigkillRecovery': True,
            'actualInstalledSdkLogicalRollbackInBothProcesses': True, 'productionRollbackProven': False},
        'limits': ['Independent run outcomes remain unchanged; no single complete run is asserted.',
            'The provider accepted the same selected credential once; two other observed connection attempts timed out.',
            'Only original profile-2 was validated. Other stored accounts remain unqualified.',
            'Rollback covers isolated logical SDK stores, not a restarted production gateway.',
            'Legacy relay still requires its old fixed identity and the existing DE egress policy.'],
        'createdUnixMs': int(time.time() * 1000)}
    raw = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    for value in (selection['resolvedApiKey'], selection['credential']['refresh'], selection['profileId'], selection['credential']['accountId']):
        assert value.encode() not in raw
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'evidenceBindingVerified': True, 'sameRunCompletePass': False,
                      'result': str(args.output), 'sha256': sha(raw)}))


if __name__ == '__main__':
    main()
