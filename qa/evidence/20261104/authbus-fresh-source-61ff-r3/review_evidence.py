#!/usr/bin/env python3
"""Recompute the two typed fresh-source observations without accessing any credential."""
import datetime,hashlib,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parent
E=ROOT/'evidence'
checks=[]
pins={}
def read(relative):
    p=ROOT/relative;b=p.read_bytes();pins[relative]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()};return b
def load(relative):return json.loads(read(relative))
def check(name,condition):
    checks.append({'name':name,'ok':bool(condition)})
    if not condition:raise AssertionError(name)
def sha(b):return hashlib.sha256(b).hexdigest()
def terminal(label,t,job,exit_code):
    check(label+'.identity',t['job_id']==job)
    check(label+'.exit',t['exit_code']==exit_code and t['state']==('succeeded' if exit_code==0 else 'failed'))
    check(label+'.durable',all(t[k] is True for k in ['output_complete','output_durable','terminal_publication_confirmed']))
    check(label+'.bounded',all(t[k] is False for k in ['automatic_retry','cancelled','timed_out']))
    check(label+'.logs',all(t['log_truncated'][k] is False and t['log_synced'][k] is True and t['log_errors'][k] is None for k in ['stdout','stderr']))
controller=load('evidence/controller-receipts.public.json')
terminal('stage',controller['stage']['terminal'],'1a1a74fae2d-fc05-2af2',0)
terminal('managed1',controller['managed']['terminal'],'1a1a750676e-fc05-2af5',1)
terminal('native4',controller['native']['terminal'],'1a1a7514ff4-fc05-2afc',0)
terminal('classification',load('evidence/readonly-receipt-export-terminal.public.json'),'1a1a7582374-fc05-2b10',0)
stage_stdout=[json.loads(s) for s in controller['stage']['read']['stdout']['text'].splitlines()]
check('stage15pins',stage_stdout[0]['pins']==15 and stage_stdout[0]['providerCalled'] is False)
check('offlinePreflight',stage_stdout[1]['prerequestImportAndHeadersValidated'] is True and stage_stdout[1]['providerCalled'] is False)
stage_input=load('stage-input.json')
for name,h in stage_input['filePins'].items():
    b=read(name);check('source.'+name,sha(b)==h and stage_input['files'][name].encode()==b)
export=load('evidence/readonly-receipt-export.public.json')
for f in controller['managed']['receipts']['files']:
    name='evidence/managed1-r1/'+pathlib.Path(f['path']).name
    b=read(name);check('managedRaw.'+pathlib.Path(name).name,len(b)==f['size'] and sha(b)==f['sha256'] and b==f['text'].encode())
for f in export['nativeFiles']:
    b=read('evidence/'+f['relative']);check('nativeRaw.'+pathlib.Path(f['relative']).name,len(b)==f['bytes'] and sha(b)==f['sha256'] and b==f['text'].encode())
cores={}
for case,status,kind,credential in [
 ('managed1-r1',401,'managed-profile1-after-authbus-recovery','bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1'),
 ('native4-r1',200,'unmanaged-native-user4','63a40b812af24584847961eeaff54e780eacc66625970ee40ea2d9b1e0a70398')]:
    prefix='evidence/'+case+'/'
    core=load(prefix+'result.public.json');outer=load(prefix+'outer-result.public.json');ledger=load(prefix+'request-started.public.json')
    cores[case]=core
    check(case+'.status',core['httpStatus']==status and outer['httpStatus']==status)
    check(case+'.once',core['requestCount']==outer['requestCount']==1 and outer['requestLedgerExists'] is True and ledger['retryAllowed'] is False)
    check(case+'.rawBinding',outer['resultSha256']==pins[prefix+'result.public.json']['sha256'] and core['requestLedgerSha256']==pins[prefix+'request-started.public.json']['sha256'])
    check(case+'.endpoint',ledger['method']=='GET' and ledger['endpoint']=='https://chatgpt.com/backend-api/wham/usage')
    check(case+'.helperPins',ledger['helperSha256']==stage_input['filePins']['fresh_usage_read.mjs'] and ledger['sdkUsageModuleSha256']=='cab428b63c6e8912f444089e120c95aea4a1d5edf4258c7fd1b20346558d12e6')
    check(case+'.typedSource',core['sourceKind']==outer['sourceKind']==kind and core['sourceKindPreserved'] is True)
    check(case+'.generation',core['sourceBindingBefore']==core['sourceBindingAfter']==ledger['sourceBinding'] and core['sourceBindingBefore']['credentialSha256']==credential)
    check(case+'.sourceTiming',core['currentSourceBoundImmediatelyBeforeDispatch'] is True and core['currentSourceGenerationUnchangedAfterResponse'] is True)
    check(case+'.responseCustody',core['responseDurableBeforeSdkParse'] is True and len(core['responseSha256'])==64 and core['responseBytes']>0)
    check(case+'.TLS',core['tlsConnected'] is True and core['tlsVerified'] is True and core['requestWritten'] is True)
    check(case+'.unambiguous',outer['providerOutcomeUnknown'] is False and outer['timedOut'] is False)
    check(case+'.noUnexpectedOperation',core['unexpectedOperations']==0)
    for key in ['providerMutationAttempted','refreshAttempted','modelCalled','productionChanged','productionCutover','j3160Contacted','credentialValuesPublished','accountIdentitiesPublished','allAccountsQualified','nativeSourceAdoptedByAuthBus','productionGatewaySelectionQualified','automaticRetry']:
        check(case+'.'+key,core[key] is False)
    check(case+'.unit',outer['productionUnitBefore']==outer['productionUnitAfter'] and outer['productionUnitUnchanged'] is True and outer['productionUnitBefore']['MainPID']=='2436' and outer['productionUnitBefore']['ActiveState']=='active')
    check(case+'.cleanup',outer['ownedNamespaceProcessExited'] is True and outer['pidNamespaceTeardownEnforced'] is True)
    check(case+'.pinsUnchanged',outer['sourcePinsUnchanged'] is True)
    check(case+'.noProductionMutation',all(outer[k] is False for k in ['productionChanged','productionTrafficCutover','modelCalled','refreshDispatched','automaticRetry']))
    check(case+'.tmpFallback',core['actualSdkPrivateTmpFallback'] is True)
managed,native=cores['managed1-r1'],cores['native4-r1']
check('managedProviderRed',managed['ok'] is False and managed['sdkErrorPresent'] is True and managed['sdkParsed'] is False and managed['error']=='current_source_provider_read_failed')
check('nativeProviderGreen',native['ok'] is True and native['freshReadOnlyProviderValidityQualified'] is True and native['sdkParsed'] is True and native['usageWindowStructureValid'] is True and native['usageWindowCount']==1 and native['modelAvailabilityQualified'] is False)
check('separateIdentity',managed['sourceBindingBefore']['accountIdSha256']!=native['sourceBindingBefore']['accountIdSha256'])
check('sameUnmanagedNativeProtected',managed['sourceBindingBefore']['nativeSourceGeneration']==native['sourceBindingBefore']['nativeSourceGeneration']=='6f5bcf6e72e50f6ff757823239de74050f4a2841b0b4040829bb550a75572133')
classification=load('evidence/managed1-401-classification.public.json')
check('classificationExact',classification==export['managed401Classification'] and classification['responseSha256']==managed['responseSha256'] and classification['responseBytes']==managed['responseBytes']==334)
fields={x['path']:x['safeValue'] for x in classification['safeErrorFields']}
check('providerTokenExpired',fields=={'error.code':'token_expired','error.type':'invalid_request_error','detail.code':'token_expired'} and classification['messageTermPredicates']['tokenExpired'] is True)
check('classificationReadOnly',classification['sourceReadOnly'] is True and classification['providerCalled'] is False and classification['rawBodyPublished'] is False and classification['refreshAttempted'] is False)
old=ROOT.parent/'authbus-fresh-source-61ff-r2/evidence'
oldcore=json.loads((old/'result.public.json').read_bytes());oldouter=json.loads((old/'outer-result.public.json').read_bytes())
check('preservedPreDispatchRed',oldcore['ok'] is False and oldcore['requestCount']==0 and oldcore['providerCalled'] is False and oldouter['requestLedgerExists'] is False and oldouter['ownedNamespaceProcessExited'] is True)
read('read_receipts_and_classify.py')
sdk=ROOT.parent/'authbus-route-audit-61ff-r1/source/provider-usage-BxQS-VWA.js'
sdkbytes=sdk.read_bytes()
check('sdkTimeoutSourcePin',sha(sdkbytes)=='cab428b63c6e8912f444089e120c95aea4a1d5edf4258c7fd1b20346558d12e6')
check('sdkAbsoluteRequestAbort',all(s in sdkbytes.decode() for s in ['const controller = new AbortController();','setTimeout(controller.abort.bind(controller), safeTimeoutMs)','signal: controller.signal','clearTimeout(timer)']))
report={'schema':'heptabao.typed-fresh-source-evidence-review.v1','evidenceConsistent':True,'checksPassed':len(checks),'checksTotal':len(checks),'checks':checks,'inputPins':pins,
 'observations':{'managed1':{'currentProviderQualified':False,'httpStatus':401,'providerErrorCode':'token_expired','credentialSha256':managed['sourceBindingBefore']['credentialSha256'],'requestCount':1},'native4':{'currentReadOnlyProviderQualified':True,'httpStatus':200,'credentialSha256':native['sourceBindingBefore']['credentialSha256'],'requestCount':1,'remainsUnmanaged':True}},
 'boundaries':{'productionCutover':False,'allManagedAccountsQualified':False,'managed2NotYetObservedInThisRun':True,'modelAvailabilityQualified':False,'nativeFactoryRetireReopenQualified':False,'activeRefreshAttempted':False,'newLoginAttempted':False,'rawProviderBodiesRemainHostPrivate':True,'storageRecovery236IsIndependent':True,'historicalManaged1HTTP200IsNotCurrentQualification':True,'jwtFutureExpiryDoesNotOverrideProvider401':True,'sdkRequestAbortMs':18000,'socketInactivityTimeoutMs':15000,'outerChildDeadlineSeconds':35},
 'jobIds':{'stage':'1a1a74fae2d-fc05-2af2','managed1':'1a1a750676e-fc05-2af5','native4':'1a1a7514ff4-fc05-2afc','classification':'1a1a7582374-fc05-2b10'}}
data=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();dest=E/'agent-review.public.json';dest.write_bytes(data)
print(json.dumps({'evidenceConsistent':True,'checksPassed':len(checks),'currentManaged1Qualified':False,'currentNative4ReadOnlyQualified':True,'path':str(dest),'sha256':sha(data)},sort_keys=True))
