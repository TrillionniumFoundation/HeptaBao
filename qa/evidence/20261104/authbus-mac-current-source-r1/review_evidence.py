#!/usr/bin/env python3
"""Review complete recovered public bytes; no remote access or credential reads."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent
E=ROOT/'evidence'
R=E/'raw'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(n):return json.loads((R/n).read_bytes())
def checks(j,count):
    assert j['ok'] is True and len(j['checks'])==count and all(c['passed'] is True for c in j['checks'])
    return {c['case']:c for c in j['checks']}
manifest=read('export-manifest.public.json')
for name,pin in manifest['files'].items():
    p=R/name
    assert p.stat().st_size==pin['bytes'] and sha(p)==pin['sha256']
assert manifest['sourceCredentialAndIdentityBytesAbsent'] is True
assert manifest['ownedServersRemainingAtExport']==[]
terminal=json.loads((E/'terminal-status.public.json').read_bytes())
assert terminal['job_id']=='1a1a6eccc77-fc05-2986' and terminal['state']=='succeeded' and terminal['exit_code']==0
assert terminal['timed_out'] is False and all(terminal[x] is True for x in ('output_complete','output_durable','terminal_publication_confirmed'))
outer=read('result.public.json');checks(outer,14)
stage=read('stage.public.json');assert stage['ok'] and len(stage['pins'])==52
assert outer['sourcePins']==stage['pins'] and outer['frozenInputsUnchangedAtExit'] is True
assert outer['sourceBefore']==outer['sourceAfter']=={'commit':'33cafa4c6e29f0bde1553e041550d21b4c725d9c','tree':'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336','trackedClean':True}
assert outer['relayPidsBefore']==outer['relayPidsAfter']
assert outer['allOwnedServersStopped'] is True and outer['ownedServersRemaining']==[]
for phase in outer['phases']:assert phase['returnCode']==0 and phase['timedOut'] is False
rows=read('current-auth-rows-r1/result.public.json');rowchecks=checks(rows,50)
assert rows['capture']['agents']==5 and rows['capture']['profileRows']==12
assert rows['capture']['expiredOAuthProfiles']==12 and rows['capture']['futureDatedOAuthProfiles']==0
assert rows['capture']['literalCredentialFields']==24 and rows['capture']['oldBackupUsed'] is False
assert rows['providerCredentialValidityQualified'] is False and rows['sourceAuthStateStillExact'] is True
rowphases={p['case']:p for p in rows['phases']}
for name in ('initial-read','cold-read'):checks(rowphases[name],15)
assert rowphases['initial-read']['documentsSha256']==rowphases['cold-read']['documentsSha256']==rows['capture']['documentsSha256']
for name in ('baseline-sdk','migrated-sdk','rollback-sdk'):
    assert rowphases[name]['ok'] and rowphases[name]['networkOrChildOperationsAttempted']==0
assert rowphases['baseline-sdk']['stores']==rowphases['migrated-sdk']['stores']==rowphases['rollback-sdk']['stores']
for name in ('actual_server_sigkill_waited','current_sdk_reads_migrated_credentials_exactly','current_sdk_reads_auth_only_rollback_exactly','source_credential_store_still_current'):
    assert rowchecks[name]['passed']
assert rowchecks['cold_sealed']['status']==503
custody=read('current-auth-rows-r1/custody.public.json')
assert custody['ok'] and custody['driverReceiptSha256']==sha(R/'current-auth-rows-r1/result.public.json')
assert custody['encryptedDataFiles']==52 and custody['encryptedDataBytes']==544220
assert custody['sensitivePrivateFiles']==36 and custody['stagingServerRemainingPids']==[]
for name in ('sensitiveFilesOwnerPrivateSingleLink','encryptedDataNoSourceCredentialPlaintext','diagnosticsNoSourceCredentialPlaintext'):assert custody[name] is True
selector=read('native-profile2-selector-r1/result.public.json');selectionchecks=checks(selector,54)
for phase,count in zip(selector['phases'],(51,51,40,40)):checks(phase,count)
assert selector['sourceCommit']=='33cafa4c6e29f0bde1553e041550d21b4c725d9c'
assert selector['binarySha256']=='d8a9e827a8c0dc0403df24783ea15849bbad88ca88c52985d1cdca0e4d75bd20'
assert selector['sourceNativeSha256']=='d13068db6b55edc3e1ca798b3726e2c5fc6de659b160a4b10dfdd333d5b5682c'
assert selector['selectedCredentialSha256']=='48e095587f180413f65274d6d25d88d4ee6f9f99d981575f54bc4fb3399c286e'
assert selector['providerReadPerformedThisRun'] is False and selector['singleCurrentAccountValidated'] is False
assert selector['priorProviderCredentialBindingQualified'] is True
assert selector['providerValidationLink']['credentialAndResolvedAccessByteIdentical'] is True
assert selector['providerValidationLink']['proofSha256']=='2a7df051464c3036b9d5d50ab17647c93ea75b6d7bcfd320415166c52fbf4867'
assert selector['actualInstalledDefaultResolverQualified'] and selector['actualServerColdRestartQualified'] and selector['privateLogicalStoreRollbackQualified']
for name,code in [('consumer.denied_unassigned_profile',403),('consumer.renew_self',200),('consumer.revoke_self',204),('consumer.revoked_token_rejected',403),('cold_sealed',503)]:assert selectionchecks[name]['status']==code
assert selector['ownedServerStopped'] is True
assert selector['actualBridgeProviderReady'] is False and selector['actualBridgeSelectorMatched'] is False
assert selector['guardBefore']['allowed'] is False and selector['guardAfter']['allowed'] is False
assert selector['guardBefore']['reason']==selector['guardAfter']['reason']=='geoip_disagreement'
for j in (outer,rows,selector):
    assert j['productionChanged'] is False and j['productionTrafficCutover'] is False and j['j3160Contacted'] is False
report={'schema':'heptabao.normal33-current-auth-source-agent-review.v1','ok':True,
 'liveJob':terminal['job_id'],'fullRawFilesValidated':len(manifest['files']),
 'rawFiles':manifest['files'],'archiveSha256':sha(E/'complete-public-evidence-r1.tar.gz'),
 'sourcePinsCount':52,'sourceCommit':selector['sourceCommit'],'sourceTree':selector['sourceTree'],'binarySha256':selector['binarySha256'],
 'assertions':{'outer':14,'currentAuthRowDriver':50,'initialAppRoleReadAclRevoke':15,'coldAppRoleReadAclRevoke':15,
    'actualSelectorDriver':54,'actualSdkInitial':51,'actualSdkCold':51,'actualSdkInitialRollback':40,'actualSdkColdRollback':40},
 'currentSourceRows':rows['capture'],
 'currentRowsQualification':'Fresh five-agent auth-row lossless migration and auth-only recovery; all twelve captured OAuth profile records are expired, and records are not a count of unique accounts.',
 'sdkRecovery':'Three offline installed-SDK reads match whole logical stores. Independent cold server process plus initial/cold original installed-plugin and SDK default selection. Two full logical-store SDK CAS rollbacks restore private baselines.',
 'processBoundary':'Actual server process SIGKILL/wait/cold unseal; no operating-system service-manager or production-service restart is claimed.',
 'providerProof':selector['providerValidationLink'],'nativeCredentialSha256':selector['selectedCredentialSha256'],
 'providerReadThisRun':False,'oauthRefreshThisRun':False,'newLoginThisRun':False,
 'productionGatewaySelectionQualified':False,'productionTrafficRollbackQualified':False,'completeOpenClawDatabaseRecoveryQualified':False,
 'allAccountsQualified':False,'fullReplacementQualified':False,
 'bridgeGate':{'actualBridgeReady':False,'exactSelectorOptionsRefused':True,'productionGuardReason':'geoip_disagreement','policyChanged':False},
 'sourceAndProductionFencesUnchanged':True,'allOwnedServersStopped':True,'independentExportRemaining':[],
 'rawReceiptReadTimeoutPreserved':True,'liveJobReplayed':False,
 'rogCurrentProfile1Scope':'Separate current SQLite read matched prior verified credential generation; no new normal33 ROG storage/SDK qualification is inferred from this Mac run.'}
out=E/'agent-review.public.json';out.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'ok':True,'reviewSha256':sha(out),'reviewBytes':out.stat().st_size,'rawFiles':len(manifest['files']),'assertions':report['assertions']}))
