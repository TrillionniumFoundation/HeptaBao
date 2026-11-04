#!/usr/bin/env python3
"""Prepare current, same-account Mac sources; never contact a provider/server.

Order is finalized separately by the actual installed SDK on a private copy.
Source validity and account quota are deliberately separate evidence fields.
"""
from __future__ import annotations
import argparse, base64, copy, importlib.util, json, os, time
from pathlib import Path
from authbus_profile2_selector_live import need, encoded, sha, digest, file_sha, read_private, put

BASE=Path('/Volumes/T5/hepta-vnext-recovery-20261013')
CORE=BASE/'authbus-profile2-selector-c138-20261104-r1/final360-core-r2'
GATEWAY=CORE.parent/'final360-gateway-r8'
P1=BASE/'authbus-profile1-source-36076-20261104-r1'
P3=BASE/'authbus-profile3-native-refresh-36076-20261104-r1'
SOURCE=BASE/'continuation-20261104-blocker-closure-r1/source'
LIVE=Path('/Users/qianqi/.openclaw')
NATIVE=Path('/Users/qianqi/.codex/auth.json')
CONFIG='ca2dd7d7879fa901dfb24e00837b56a4e0fd230600d7ed1e3086eda194187d4d'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work-dir',type=Path,required=True);args=p.parse_args()
    os.umask(0o077);root=args.work_dir;root.mkdir(mode=0o700)
    r={'schema':'heptabao.multi-current-source-prepare.v1','ok':False,'checks':[],
       'productionChanged':False,'providerCalled':False,'refreshCalled':False,'modelCalled':False,
       'credentialValuesPublished':False,'accountIdentitiesPublished':False,
       'businessAvailabilityQualified':False,'allAccountsQualified':False,
       'orderFinalizedByActualSdk':False,'sourceCommit':'36076db5f5afe00db75eba9b607dee7802dae554'}
    def check(k,v):r['checks'].append({'case':k,'passed':bool(v)});need(v,k)
    try:
        spec=importlib.util.spec_from_file_location('multi_current_stage',SOURCE/'qa/openbao-acceptance/authbus_current_credential_stage.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        before=helper.capture(LIVE,CONFIG);main_doc=next(d for d in before if d['agent']=='main')
        cfg=json.loads(read_private(LIVE/'openclaw.json'));store=json.loads(main_doc['rows']['store'][0][1]);ids=list(store['profiles'])
        check('existing_three_account_scope',len(ids)==3)
        p1raw=read_private(P1/'source-private/selected-credential.private.json');p1=json.loads(p1raw)
        proof=json.loads(read_private(P1/'source-private/provider-proof.public.json'))
        capture=json.loads(read_private(P1/'source-private/source-capture.public.json'))
        binding=json.loads(read_private(P1/'source-binding.public.json'))
        check('rog_frozen_provider_verified_packet',sha(p1raw)=='5dfd90b40f4698d6cd989017205dcc58f8f3270236c8741589d269b7a58267f2'
              and file_sha(P1/'source-private/provider-proof.public.json')=='3050622c35bacb53ac47f532d4d5230c7c5c68bd2db243376c3c27385744a878'
              and capture.get('ok') is True and binding.get('ok') is True)
        core=json.loads(read_private(CORE/'result.public.json'));sel=json.loads(read_private(CORE/'consumer-initial/runtime-selection.private.json'))
        check('native_same_current_verified_generation',core.get('ok') is True and file_sha(NATIVE)==core['sourceNativeSha256']
              and digest(sel['credential'])==core['selectedCredentialSha256']=='48e095587f180413f65274d6d25d88d4ee6f9f99d981575f54bc4fb3399c286e')
        source_credentials=[p1['credential'],sel['credential']];source_info=[];entries=[];documents={};target_credentials={}
        for ordinal,credential in enumerate(source_credentials,1):
            matches=[key for key,c in store['profiles'].items() if c.get('accountId')==credential.get('accountId') and c.get('provider')==credential.get('provider') and c.get('type')==credential.get('type')]
            check('profile'+str(ordinal)+'.unique_original_identity',len(matches)==1 and ids.index(matches[0])==ordinal-1)
            pid=matches[0];old=store['profiles'][pid];claims=json.loads(base64.urlsafe_b64decode(credential['access'].split('.')[1]+'==='))
            check('profile'+str(ordinal)+'.identity_and_claim',all(old.get(k)==credential.get(k) for k in ['accountId','provider','type','email'])
                  and claims['https://api.openai.com/auth']['chatgpt_account_id']==old['accountId'])
            check('profile'+str(ordinal)+'.access_future',claims['exp']>time.time()+600 and credential['expires']>time.time()*1000+600000)
            d=digest(credential);identity=digest({k:credential.get(k) for k in ['provider','type','email','accountId','projectId']});key='sha256-'+d
            payload={'schemaVersion':1,'profileId':pid,'credential':credential,'digest':d,'identity':identity}
            documents['profiles/'+key]=payload;target_credentials[pid]=credential
            entries.append({'profileId':pid,'digest':d,'identity':identity,'key':key,'provider':credential['provider'],
                            'type':credential['type'],'expires':credential['expires'],'quarantined':False,'status':'active'})
            source_info.append({'destinationOrdinal':ordinal,'credentialSha256':d,'accountIdSha256':sha(credential['accountId'].encode()),
                                'source':'rog-current-verified-account1' if ordinal==1 else 'mac-current-native-account2'})
        bad=json.loads(read_private(P3/'terminal-classification.public.json'))
        check('profile3_known_terminal_invalid_refresh',bad.get('providerHttpStatus')==401 and bad.get('providerErrorCode')=='invalid_refresh_token'
              and bad.get('completeResponse') is True and bad.get('outcomeUnknown') is False)
        gateway=json.loads(read_private(GATEWAY/'result.public.json'));classification=json.loads(read_private(GATEWAY/'business-provider-classification-r2.public.json'))
        check('profile2_actual_usage_limit_preserved',gateway.get('actualDefaultModelBusinessRequestQualified') is False
              and classification.get('installedProviderErrorType')=='usage_limit_reached')
        usage1=json.loads(read_private(P1/'source-private/current-usage-state.public.json'))
        check('profile1_quota_same_generation',usage1['credentialSha256']==digest(source_credentials[0]) and len(usage1['stateProjections'])==1)
        check('profile1_actual_subscription_limit',usage1['stateProjections'][0].get('blockedReason')=='subscription_limit'
              and usage1['stateProjections'][0].get('blockedSource')=='wham')
        import sqlite3
        db=sqlite3.connect((GATEWAY/'candidate-state-retained/agents/main/agent/openclaw-agent.sqlite').as_uri()+'?mode=ro',uri=True)
        try:state_rows=db.execute('SELECT state_json FROM auth_profile_state WHERE state_key=?',('primary',)).fetchall()
        finally:db.close()
        check('profile2_actual_runtime_state',len(state_rows)==1)
        observed2=json.loads(state_rows[0][0]).get('usageStats',{}).get(ids[1],{})
        observed_usage={ids[0]:usage1['stateProjections'][0],ids[1]:observed2}
        documents['manifest']={'schemaVersion':1,'generation':1,'profiles':entries}
        documents['scheduler-assignments']={'schemaVersion':1,'generation':1,'assignments':[]}
        put(root/'captured-auth-rows.private.json',before);put(root/'original-config.private.json',cfg)
        put(root/'seed-documents-without-order.private.json',documents)
        put(root/'source-bundle.private.json',{'schema':'heptabao.multi-current-source-private-bundle.v1','credentials':target_credentials,
          'targetProfileIds':ids[:2],'excludedProfileIds':[ids[2]],'observedUsageByProfile':observed_usage,
          'sourceInfo':source_info,'profile3InvalidRefreshReceiptSha256':file_sha(P3/'terminal-classification.public.json'),
          'originalConfiguredOrder':cfg.get('auth',{}).get('order',{}).get('openai'),'originalStoredOrder':store.get('order',{}).get('openai')})
        r.update(sources=source_info,profile3ExcludedForConfirmedInvalidRefresh=True,
                 profile1QuotaState=usage1['stateProjections'][0],profile2QuotaClassification='usage_limit_reached',
                 profile2ObservedRuntimeState=observed2,productionConfigSha256=CONFIG,
                 configuredOrderReferencesMissingProfiles=all(x not in ids for x in cfg.get('auth',{}).get('order',{}).get('openai',[])),
                 originalConfiguredOrderSha256=digest(cfg.get('auth',{}).get('order',{}).get('openai')),
                 originalStoredOrderSha256=digest(store.get('order',{}).get('openai')),
                 sourceBundleSha256=file_sha(root/'source-bundle.private.json'),
                 capturedRowsSha256=file_sha(root/'captured-auth-rows.private.json'))
        after=helper.capture(LIVE,CONFIG);check('original_all_auth_rows_unchanged',all(a['rows']==b['rows'] for a,b in zip(before,after)))
        check('native_source_unchanged',file_sha(NATIVE)==core['sourceNativeSha256'])
        r['ok']=True
    except Exception as e:r['error']=str(e) if type(e).__name__=='Refused' else type(e).__name__
    put(root/'prepare.public.json',r);print(json.dumps({'ok':r['ok'],'error':r.get('error'),'receipt':str(root/'prepare.public.json'),'sha256':file_sha(root/'prepare.public.json')}));return 0 if r['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
