#!/usr/bin/env python3
"""Recompute the exact ROG r2 receipt boundaries without contacting any host."""
from pathlib import Path
import argparse, hashlib, json

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p): return json.loads(Path(p).read_text())
def checks(v, count):
    assert v['ok'] is True and len(v['checks']) == count
    assert all(c['passed'] is True for c in v['checks'])
    return {c['case']: c for c in v['checks']}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--r1', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    r1 = args.r1 or root.with_name('authbus-rog-current-profile1-61ff-r1')
    raw = root / 'evidence/raw'
    manifest = read(raw / 'export-manifest.public.json')
    assert len(manifest['files']) == 10
    for name, p in manifest['files'].items():
        path = raw / name
        assert path.is_file() and path.stat().st_size == p['bytes'] and sha(path) == p['sha256'], name
    archive = root / 'evidence/complete-public-evidence-r2.tar.gz'
    assert archive.stat().st_size == 8704
    assert sha(archive) == '9ab2d2822e78cb442496bb50a60c6c3bcb9ca182e51e98ad0a907daa99373eef'
    assert manifest['exporterSha256'] == sha(root / 'export_evidence_r2.py') == 'ace397610ef6e561272877fc42c6e3a157c3436c49098cf7d791bce6034d1dd0'
    assert manifest['sourceCredentialsAndIdentitiesAbsent'] is True
    assert manifest['originalR1AndR2FilesUnchanged'] is True

    stage = read(raw / 'control/stage.public.json')
    intent = read(raw / 'run-r2/intent.public.json')
    outer = read(raw / 'run-r2/execution.result.public.json')
    live = read(raw / 'run-r2/live/result.public.json')
    freeze = read(root / 'source-freeze.public.json')
    assert stage['ok'] and stage['payloadSha256'] == freeze['payloadSha256'] == sha(root / 'stage-input.json')
    assert stage['pins'] == intent['pinsBefore'] and len(stage['pins']) == 34
    for file, value in freeze['embeddedPins'].items():
        remote = freeze['root'] + '/control/' + file
        assert stage['pins'][remote] == value
        if file != 'prior-provider-proof.public.json': assert sha(root / file) == value
    for file, value in freeze['expectedPins'].items(): assert stage['pins'][file] == value
    assert (root / 'driver.py').read_bytes() == (r1 / 'driver.py').read_bytes()
    before_consumer = (r1 / 'consumer.mjs').read_text()
    after_consumer = (root / 'consumer.mjs').read_text()
    old = 'const missing = await storeApi.m({ agentDir, updater: store => {'
    new = 'const missing = await storeApi.m({ agentDir, saveOptions: { preserveStateProfileIds: [plan.expectedProfileId] }, updater: store => {'
    assert before_consumer.count(old) == 1 and before_consumer.replace(old, new) == after_consumer
    assert "forceRefresh: false" in after_consumer
    assert "digest(store) !== candidate.storeSha256" in after_consumer
    assert intent['budgets'] == {'httpSeconds': 10, 'consumerSeconds': 70, 'rollbackSeconds': 35, 'outerSeconds': 440}
    for k in ['onlyFreshRunWritable', 'privateNetworkNamespace', 'privatePidNamespace']: assert intent[k] is True
    for k in ['providerNetworkEgress', 'productionChanged', 'automaticRetry']: assert intent[k] is False
    assert ['--ro-bind', '/', '/'] == intent['argv'][1:4]
    for v in ['--unshare-net', '--unshare-pid', '--die-with-parent']: assert v in intent['argv']

    c = checks(live, 48)
    assert live['sourceCommit'] == '33cafa4c6e29f0bde1553e041550d21b4c725d9c'
    assert live['sourceTree'] == 'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
    assert live['binarySha256'] == '7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
    assert c['cold_sealed']['status'] == 503 and c['cold_unseal']['status'] == 200
    assert c['actual_sigkill_waited']['passed'] is True
    assert c['production_complete_auth_rows_unchanged']['passed'] is True
    assert c['production_configuration_order_exclusions_unchanged']['passed'] is True
    assert live['source']['sourceDefaultModel'] == {'primary': 'codex/gpt-6.1-sol'}
    credential = 'bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1'
    assert live['source']['credentialSha256'] == credential and live['source']['profileOrdinal'] == 1
    assert live['source']['sourceProfileCount'] == 3
    assert live['priorProviderLink']['credentialSha256'] == credential
    assert live['priorProviderLink']['currentCapturedAndSdkSelectedCredentialExact'] is True
    assert live['priorProviderLink']['freshProviderRequest'] is False
    assert live['priorProviderLink']['priorProofSha256'] == '3050622c35bacb53ac47f532d4d5230c7c5c68bd2db243376c3c27385744a878'
    assert len(live['phases']) == 4
    for i, phase in enumerate(['initial', 'cold-new-process']):
        p = live['phases'][i]
        q = read(raw / ('run-r2/live/consumer-' + phase + '/result.public.json'))
        assert p == q and p['phase'] == phase
        checks(p, 55)
        assert p['returnCode'] == 0 and p['timedOut'] is False
        assert p['actualExplicitProfileSelectionQualified'] is True
        assert p['defaultGatewaySelectionQualified'] is False
        assert p['productionOrderOverrideQualified'] is False
        assert p['plugin']['importedProfiles'] == 1 and p['plugin']['changedOrders'] == 0
        assert p['plugin']['effectiveMissing'] == p['plugin']['effectiveMismatched'] == 0
        assert p['plugin']['pendingRuntimeRefreshes'] == 0
        assert len(p['wire']) == 6 and all(w['status'] == 200 and w['tlsVerified'] is True for w in p['wire'])
        assert p['wire'][0]['method'] == 'POST' and p['wire'][0]['path'] == '/v1/auth/approle/login'
        assert p['wire'][2]['path'] == '/v1/openclaw-auth/data/profiles/sha256-' + credential
        for action, status in [('unassigned_denied',403), ('renew',200), ('revoke',204), ('revoked_denied',403)]:
            assert c[phase + '.' + action]['status'] == status
        rb = live['phases'][i + 2]
        assert rb == read(raw / ('run-r2/live/consumer-' + phase + '/rollback-result.public.json'))
        checks(rb, 39)
        assert rb['wire'] == [] and rb['returnCode'] == 0 and rb['timedOut'] is False
        assert rb['retried'] is False and rb['originalOrderPreserved'] is True
    assert live['phases'][0]['sourceOrderSha256'] == live['phases'][1]['sourceOrderSha256'] == 'f640d46aaa1019caef315e11b68b3cafd04306ec8b59164ae2098d469c655290'
    assert live['phases'][0]['sourceUsageSha256'] == live['phases'][1]['sourceUsageSha256'] == '51916e8ddafee4245248a68a91d36929740cd921bc630fb9263a030bf0b59a64'
    assert live['rollbackOutcomes'] == outer['rollbackOutcomes'] == {'initial':'success','cold-new-process':'success'}
    assert outer['coreChecks'] == outer['corePassed'] == 48 and outer['returnCode'] == 0 and outer['ok'] is True
    assert outer['coreResultSha256'] == sha(raw / 'run-r2/live/result.public.json')
    assert outer['intentSha256'] == sha(raw / 'run-r2/intent.public.json')
    assert outer['productionUnitBefore'] == outer['productionUnitAfter'] == intent['productionUnitBefore']
    for k in ['frozenInputsUnchanged','protectedInputsUnchanged','productionUnitUnchanged','ownedNamespaceProcessExited','ownedServerStopped','pidNamespaceTeardownEnforced']: assert outer[k] is True
    for k in ['productionChanged','productionTrafficCutover','providerCalled','fullReplacementQualified','productionGatewaySelectionQualified']: assert outer[k] is False and live[k] is False
    for k in ['timedOut','outcomeUnknown','automaticRetry','providerAvailabilityQualified']: assert outer[k] is False

    late = read(raw / 'evidence-export-r2/source-second-read.public.json')
    assert late['wholeRowsExact'] is False and late['sameCredentialGeneration'] is True
    assert late['profile1CredentialSha256'] == credential
    assert late['wholeRowsBeforeSha256'] == live['source']['wholeAuthRowsSha256']
    assert late['storeRowsBeforeSha256'] == late['storeRowsAfterSha256']
    assert late['fieldComparisons']['store']['logicalExact'] is True
    assert late['fieldComparisons']['state']['changedTopLevelKeys'] == ['usageStats']
    assert len(late['usageFieldChanges']) == 1
    assert late['usageFieldChanges'][0]['sourceProfileOrdinal'] == 3
    assert late['usageFieldChanges'][0]['changedKeys'] == ['lastUsed']
    for k in ['notUsedAsRollbackTarget','liveSynchronousSourceInvariantUnchanged','lateDriftCausalityNotAttributed','sourceKernelReadOnly']: assert late[k] is True
    audit = read(raw / 'evidence-export-r2/rollback-independent-sdk-read.public.json')
    assert audit['ok'] and len(audit['phases']) == 2
    for p in audit['phases']:
        assert p['wholeLogicalExact'] and p['sourceCloneUnchanged'] and p['selectedResolvedAccessExact']
        assert p['selectedCredentialSha256'] == credential
        assert p['wholeLogicalSdkBeforeSha256'] == p['wholeLogicalSdkAfterSha256'] == 'cb2a7d70f1a05d5d54b7aa8840597a11302e409ef7a408fa5bf40337c42e466c'
        assert set(p['fields']) == {'profiles','order','usageStats','lastGood'}
        for f in p['fields'].values(): assert f['exact'] and f['beforeSha256'] == f['afterSha256']
        assert p['networkOrChildAttempts'] == p['sdkRead']['networkOrChildOperationsAttempted'] == 0
        assert p['sdkRead']['ok'] and p['sdkRead']['providerCalled'] is False
    failure = read(r1 / 'evidence/failure-r1/result.public.json')
    assert failure['ok'] is False and len(failure['checks']) == 24
    assert sum(c['passed'] for c in failure['checks']) == 23
    assert failure['rollbackOutcomes'] == {'initial':'no_complete_candidate_unknown'}
    diagnostic = read(r1 / 'evidence/failure-r1/cohort-diagnostic.public.json')
    assert diagnostic['rawSelectedAbsent'] is True and diagnostic['rawStateOrderExactBaseline'] is True and diagnostic['rawStateUsageExactBaseline'] is False
    sdk = read(r1 / 'evidence/failure-r1/usage-source-complete.public.json')
    assert sdk['sdkStoreSha256'] == '25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf'
    assert sha(r1 / 'evidence/failure-r1/usage-source-complete.public.json') == 'a4451c6a79f253a48afe27b51ad564f3acfe1a617bd6c7a699148eb55819fd2f'
    source_text = json.dumps(sdk['sourceSpans'])
    assert 'preserveStateProfileIds' in source_text and 'params.saveOptions' in source_text

    terminals = read(root / 'evidence/terminal-statuses.public.json')['jobs']
    expected = {'1a1a6f78de9-fc05-29ab':0,'1a1a6fab472-fc05-29b8':0,'1a1a6fcdf0f-fc05-29c4':0,'1a1a703da50-fc05-29e1':0,'1a1a705db11-fc05-29ea':1,'1a1a708a1a1-fc05-29f6':1,'1a1a70a0b3c-fc05-29fa':0,'1a1a70f2a36-fc05-2a06':0,'1a1a718f122-fc05-2a1c':0,'1a1a719db42-fc05-2a20':0,'1a1a71ff3e7-fc05-2a3d':1,'1a1a723c1a0-fc05-2a54':0}
    assert terminals.keys() == expected.keys()
    for job, code in expected.items():
        t = terminals[job]
        assert t['job_id'] == job and t['exit_code'] == code and t['state'] == ('failed' if code else 'succeeded')
        for k in ['output_complete','output_durable','terminal_publication_confirmed']: assert t[k] is True
        for k in ['timed_out','automatic_retry','cancelled']: assert t[k] is False
    report = {
      'schema':'heptabao.rog-current-profile1-local-evidence-review.v1','ok':True,
      'reviewerSha256':sha(Path(__file__)),'archiveSha256':sha(archive),'rawFiles':manifest['files'],
      'sourcePins':freeze['embeddedPins'],'terminalStatusesSha256':sha(root / 'evidence/terminal-statuses.public.json'),
      'authoritativeJobs':{j:{'state':t['state'],'exitCode':t['exit_code']} for j,t in terminals.items()},
      'sourceCommit':live['sourceCommit'],'sourceTree':live['sourceTree'],'normalBinarySha256':live['binarySha256'],
      'counts':{'parent':48,'initialSdk':55,'coldSdk':55,'initialRollback':39,'coldRollback':39,'independentPostRollbackSdkReads':2},
      'r1FailurePreserved':True,'sdkSupportedPreserveStateOptionUsed':True,'allOriginalGuardsAndBudgetsRetained':True,
      'actualCurrentCredentialSha256':credential,'actualOriginalInstalledSdkExplicitProfileSelected':True,
      'actualTlsAppRoleKvPolicyRenewRevokeBothPhases':True,'actualServerSigkillAndColdSealedUnseal':True,
      'fullLogicalSdkCasRollbackBothPhases':True,'independentPostRollbackSdkWholeLogicalExact':True,
      'productionUnitAnd34FrozenPinsUnchangedDuringRun':True,'originalOrderUsageDefaultsExclusionsPreserved':True,
      'synchronousSourceAllAuthRowsExact':True,'lateSourceAllAuthRowsExact':False,
      'lateDrift':{'storeLogicalAndRowsExact':True,'credentialGenerationExact':True,'stateChangedKeys':['usageStats'],
        'sourceOrdinal':3,'usageChangedKeys':['lastUsed'],'stateTimestampChanged':True,'causeAttributed':False,'usedAsRollbackTarget':False},
      'ownedServerStopped':True,'namespaceProcessExited':True,'pidNamespaceTeardownEnforced':True,
      'providerProofScope':'Historical exact-generation GET only; no fresh provider request in r2.',
      'scope':{'singleRogMainProfileOrdinal':1,'sourceProfileCount':3,'defaultModel':'codex/gpt-6.1-sol',
        'privateStoreRecovery':True,'productionServiceRestart':False,'productionGatewayDefaultSelection':False,
        'allAgentsOrAccounts':False,'freshProviderValidity':False,'productionTrafficCutover':False,'fullReplacementQualified':False,
        'oauthRefresh':False,'modelPost':False,'j3160Contacted':False,'productionSourceWrites':False}}
    body = json.dumps(report,sort_keys=True,indent=2) + '\n'
    if args.output:
        if args.output.exists(): assert args.output.read_text() == body
        else: args.output.write_text(body)
    print(body, end='')

if __name__ == '__main__': main()
