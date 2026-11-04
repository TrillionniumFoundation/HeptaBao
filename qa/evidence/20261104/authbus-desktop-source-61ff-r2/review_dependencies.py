#!/usr/bin/env python3
"""Recompute read-only Desktop inventory boundaries and cross-source distinctions."""
import pathlib,json,hashlib,base64,zlib,datetime
R=pathlib.Path(__file__).resolve().parent;E=R/'evidence';checks=[];pins={}
def read(p):
 b=(R/p).read_bytes();pins[p]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()};return b
def load(p):return json.loads(read(p))
def ck(n,v):
 checks.append({'name':n,'ok':bool(v)});assert v,n
def terminal(path,job):
 t=load(path);ck(path+'.job',t['job_id']==job and t['exit_code']==0 and t['state']=='succeeded')
 ck(path+'.durable',t['output_complete'] and t['output_durable'] and t['terminal_publication_confirmed'] and not t['timed_out'] and not t['automatic_retry'])
for data,env in [('dependencies.public.json','stdout-envelope.public.json'),('ownership-supplement.public.json','ownership-supplement-envelope.public.json')]:
 p=load('evidence/'+env);raw=read('evidence/'+data);z=base64.b64decode(p['dataBase64']);ck(data+'.nativeRawBinding',zlib.decompress(z)==raw and len(raw)==p['bytes'] and hashlib.sha256(raw).hexdigest()==p['sha256'] and hashlib.sha256(z).hexdigest()==p['zlibSha256'])
d=load('evidence/dependencies.public.json');s=load('evidence/ownership-supplement.public.json');sdk=load('evidence/sdk-pins.public.json')
terminal('evidence/terminal.public.json','1a1a7608001-fc05-2b34')
terminal('evidence/ownership-supplement-terminal.public.json','1a1a7667ca6-fc05-2b4f')
terminal('evidence/sdk-pins-terminal.public.json','1a1a76bcaaa-fc05-2b64')
ck('scope',d['ok'] is True and d['productionChanged'] is False and d['providerCalled'] is False and d['refreshAttempted'] is False and d['serviceActions']==[] and d['credentialValuesPublished'] is False)
ck('exactConfig',d['configurationSha256']=='7dc5e5412ddc6da4977d44743261376e24c0d644dabd3b082c8c57f3647ed1d3' and d['allStaticFilesUnchanged'])
agents=d['agentSources'];profiles=[p for a in agents for p in a.get('profiles',[])]
ck('eightConfiguredSixExisting',len(d['agents'])==len(agents)==8 and sum(a['present'] for a in agents)==6)
ck('tenRowsFourDistinct',len(profiles)==10 and len({p['credentialSha256']for p in profiles})==4)
observed=datetime.datetime.fromisoformat(d['observedAt']).timestamp()
ck('threeJwtExpiredRows',sum(p.get('jwt',{}).get('expiresUnixSeconds',1e30)<=observed for p in profiles)==3)
bc=d['authbus'];ck('existingDesktopLocalProvider',bc['enabled'] is True and bc['address']['scheme']=='https' and bc['address']['hostname']=='127.0.0.1' and bc['address']['port']==18200 and bc['configuration']['hostId']=='desktop')
ck('followerScope',bc['configuration']['leader'] is False and bc['configuration']['publishNew'] is True and bc['configuration']['orderExcludeAgentIds'] is None)
ck('roleSidContentsNotRead',all(f['contentsRead'] is False for f in d['authbusCredentialFiles']if f['kind'] in ['roleIdFile','secretIdFile']))
ck('systemProviderActive',d['managerBefore'][0]['exitCode']==0 and d['managerBefore'][0]['properties']['MainPID']=='2013' and d['managerBefore'][0]['properties']['ActiveState']=='active')
ck('renewalTimerActive',d['managerBefore'][2]['exitCode']==0 and d['managerBefore'][2]['properties']['ActiveState']=='active')
ck('userManagerProbeDenied',all(v['exitCode']==1 for v in d['managerBefore']if v['userScope']))
ck('configurationPermissionBoundary',all(v['read'] is False and v['errorClass']=='PermissionError'for v in d['providerConfigurationFiles']))
ck('providerBinary270Path',any('/opt/hepta-openbao/2.7.0/bao'in u['executablePaths']for u in d['unitFiles']))
status=next(x['status']for x in d['authbusLocalState']if x['name']=='status.json')
ck('localStatusPendingTwo',status['ok'] is True and status['manifestGeneration']==1 and status['manifestProfiles']==3 and status['pendingRuntimeRefreshes']==2 and status['agentStores']==6)
applied=next(x['profiles']for x in d['authbusLocalState']if x['name']=='applied-profiles.json');main=next(a for a in agents if a['agentId']=='main')
byid={p['profileIdSha256']:p for p in main['profiles']}
ck('twoLocalAppliedDigestDivergences',sum(x['credentialDigest']!=byid[x['profileIdSha256']]['credentialSha256']for x in applied)==2)
native=d['nativeUserAuth'];ck('nativeDistinctFromAllSdkRows',native['matchingSdkProfiles']==[] and native['accessPresent'] and native['refreshPresent'])
managed1=json.loads((R.parent/'authbus-fresh-source-61ff-r3/evidence/managed1-r1/result.public.json').read_bytes())
ck('sameIdentityAsRogManaged1DifferentGeneration',native['accountIdSha256']==managed1['sourceBindingBefore']['accountIdSha256'] and native['jwt']['expiresUnixSeconds']!=managed1['sourceBindingBefore']['jwtExpiresUnixSeconds'])
guards=s['heldGuards'];ck('threeHeldConditionsPreserved',len(guards)==3 and all(g['conditions'][0]['name']=='ConditionPathExists' and g['conditions'][0]['negated'] for g in guards))
ck('gatewayMarkerAbsentAuxiliaryMarkersPresent',[g['conditions'][0]['pathExists']for g in guards]==[False,True,True])
state=next(v for v in s['authState']if v['agentId']=='main')
ids=[p['profileIdSha256']for p in main['profiles']]
ck('actualStateMainOrder4213',state['order']['openai']==[ids[3],ids[1],ids[0],ids[2]])
ck('stateDistinctFromRawSecretsStore',main['orderSha256']==hashlib.sha256(b'null').hexdigest() and state['hasOrder'] is True)
for f in s['fixedPublicSources']:
 b=read('source/'+f['name']);ck('fixedSource.'+f['name'],b==f['text'].encode() and len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256'])
for name in ['agent-runtime.js','store-DH33UrUj.js','profiles-DyU-YCq2.js']:
 p=R.parent/'authbus-route-audit-61ff-r1/source'/name
 h=hashlib.sha256(p.read_bytes()).hexdigest();ck('desktopSdkMatchesReviewedRog.'+name,any(x['path'].endswith('/'+name) and x['sha256']==h for x in sdk['files']))
read('read_dependencies.py');read('read_ownership_supplement.py')
report={'schema':'heptabao.desktop-existing-dependencies-evidence-review.v1','evidenceConsistent':True,'checksPassed':len(checks),'checksTotal':len(checks),'checks':checks,'inputPins':pins,
 'qualifiedScope':'Read-only existing Desktop client/provider/source dependency projection; no provider request, migration, restart, renewal or cutover.',
 'findings':{'configuredAgents':8,'existingAgentDatabases':6,'oauthRows':10,'distinctCredentialGenerations':4,'jwtExpiredRowsAtObservation':3,'existingProviderUnitBinaryPathVersion':'2.7.0','existingProviderEndpoint':'https://127.0.0.1:18200','localManifestGeneration':1,'localPendingRuntimeRefreshes':2,'nativeCurrentGenerationDistinctFromEveryStoredSdkRow':True,'sharedAccountIdentityWithRogManaged1':True,'causalRefreshWriterIdentified':False,'currentProviderValidityQualified':False},
 'limitations':{'crossAgentAtomicSnapshot':False,'rootOnlyProviderConfigRead':False,'canonicalServerManifestRead':False,'userManagerEffectiveStateQualifiedByThisProbe':False,'defaultGatewaySelectionQualified':False,'liveRefreshOwnershipQualified':False,'allClientsMigrated':False,'rawStoreOrderIsNotSdkMaterializedOrder':True,'nativeWriterOverlapObservedLive':False,'factoryRecyclerBypassIsStaticReachabilityFindingOnly':True,'namespaceOwnerIdsMustNotBeReadAsHostUidForUnmappedRoot':True}}
b=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();(E/'agent-review.public.json').write_bytes(b)
print(json.dumps({'checks':len(checks),'path':str(E/'agent-review.public.json'),'sha256':hashlib.sha256(b).hexdigest()},sort_keys=True))
