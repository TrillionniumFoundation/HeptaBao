#!/usr/bin/env python3
"""Owned actual plugin/SDK phases around the normal native server.

The original API wire owner and launchd lifetimes are reused. All protocol
credentials stay in Mac-local private files. No production writer or provider
request is admitted. The exact inverse covers only the five fixture auth stores,
their two auth tables and six AuthBus caches, never an entire production DB.
"""
from __future__ import annotations
import hashlib,json,os,re,stat,time
from pathlib import Path
from main3_source_fence import need,ident,LIVE
import main3_api_cycle as wire
from main3_source_authority import SDK_SOURCE_PINS
from main3_sdk_public_pins import ASSET_PINS,SDK_EXTRA_PINS,NODE_SHA,MOUNT_SHA

ROOT=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-sdk-20261106-r2')
STATE=ROOT/'state';SDK=Path('/opt/homebrew/lib/node_modules/openclaw')
NODE='/opt/homebrew/Cellar/node/25.9.0_1/bin/node'
AGENTS=('main','trnm','hepta-ui','hepta','hepta-backend')
ROLE='main3-installed-sdk'
PLUGINS=('index.js','package.json','order-policy.js','runtime-refresh-policy.js',
 'codex-client-recycler.js','provider-error-classifier.js','bad-refresh-quarantine.js','lease-assignments.js')
WORKERS=('main3_sdk_cycle_r2.mjs','main3_sdk_wire_r2.mjs','main3_auth_rows_cas_r1.mjs','main3_authbus_cache_cas_r1.mjs')

def encoded(value):return (json.dumps(value,ensure_ascii=False,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def exact_private_read(api,path,maximum=1048576):
    api.remaining(1);raw=api.guard.read(path,maximum,private=True);api.remaining(1);return raw
def private_new(api,path,value,*,raw=False):
    path=Path(path);data=value if raw else encoded(value)
    need(path.is_absolute() and path.is_relative_to(ROOT) and '..' not in path.parts
         and isinstance(data,bytes) and len(data)<=4*1048576,'sdk_fixed_bounded_private_output')
    api.remaining(1);api.guard.write_new(path,data);api.remaining(1)
    # The helper's returned content digest is deliberately discarded.

def sandbox_profile(port=None,*,seed=False):
    need(seed or type(port) is int and 1024<=port<=65535,'sdk_one_owned_listener')
    need(Path.cwd()==LIVE.parent,'sdk_original_account_home_cwd')
    lines=['(version 1)','(deny default)','(allow process*)','(allow signal (target children))',
      '(allow sysctl-read)','(allow mach-lookup)','(allow file-read-metadata)']
    for item in ('/System','/usr','/bin','/sbin','/Library','/private/etc','/opt/homebrew','/dev/fd'):
        lines.append('(allow file-read* (subpath '+json.dumps(item)+'))')
    for item in (ROOT/'qa',ROOT/'plugin',ROOT/'input',ROOT/'private'):
        lines.append('(allow file-read* (subpath '+json.dumps(str(item))+'))')
    # Actual four-factor Mac probe admitted only these directory literals.
    # No ancestor subpath, protected file, additional write or network grant.
    directories={LIVE.parent,*LIVE.parent.parents,
      *(ROOT/'qa/main3_sdk_seed_r1.mjs').parents,
      *(ROOT/'input/seed-plan.private.json').parents}
    for item in sorted(directories,key=str):
        lines.append('(allow file-read* (literal '+json.dumps(str(item))+'))')
    for item in (ROOT/'private',):
        lines.append('(allow file-write* (subpath '+json.dumps(str(item))+'))')
    if not seed:
        lines += ['(allow file-read* (subpath '+json.dumps(str(STATE))+'))',
                  '(allow file-write* (subpath '+json.dumps(str(STATE))+'))']
        for phase in ('initial','cold-new-process'):
            lines += ['(allow file-read* (subpath '+json.dumps(str(ROOT/phase))+'))',
                      '(allow file-write* (subpath '+json.dumps(str(ROOT/phase))+'))']
        for item in (ROOT/'server/tls/server.crt',ROOT/'server/private/sdk-role-id',ROOT/'server/private/sdk-secret-id'):
            lines.append('(allow file-read* (literal '+json.dumps(str(item))+'))')
        lines.append('(allow network-outbound (remote ip '+json.dumps('127.0.0.1:'+str(port))+'))')
    for item in ('/dev/null','/dev/urandom','/dev/random'):
        lines.append('(allow file-read* (literal '+json.dumps(item)+'))')
    lines.append('(allow file-write* (literal "/dev/null"))')
    return ('\n'.join(lines)+'\n').encode()

def validate_worker_result(value,phase):
    need(isinstance(value,dict) and value.get('schema')=='heptabao.mac-main3-sdk-private-cycle.r2'
      and value.get('ok') is True and value.get('phase')==phase
      and value.get('mode')==('initial' if phase=='initial' else 'cold-inverse')
      and value.get('sourceOwnerCredentialCount')==3 and value.get('sourceConsumerReferenceCount')==15,
      'sdk_actual_complete_worker_scope')
    for key in ('productionChanged','productionTrafficCutover','productionClientRollbackQualified',
      'actualGatewayRestarted','providerCalled','providerRefreshAttempted','providerValid','j3160Contacted',
      'credentialValuesOrDigestsPublished','profileIdsPublished','actualCentralOrderPolicyCopied',
      'originalProductionNoncredentialStateCopied','sdkTransitiveDependencyClosureClaimed','outcomeUnknown'):
        need(value.get(key) is False,'sdk_worker_no_provider_or_production_effect')
    need(value.get('serviceStopAttempted') is True and value.get('serviceStopped') is True
      and value.get('networkHooksRestored') is True and value.get('candidateSaved') is True
      and value.get('privateTokenCustodyRecorded') is True and value.get('forbiddenChildAttemptCount')==0
      and value.get('unexpectedDiagnosticBytes')==0 and value.get('inverseRetried') is False,
      'sdk_worker_closed_plugin_and_known_state')
    checks=value.get('checks');need(isinstance(checks,list) and checks and all(row.get('passed') is True for row in checks),
      'sdk_worker_complete_named_checks')
    rows=value.get('wire');need(isinstance(rows,list) and 1<=len(rows)<=192
      and all(row.get('requestCount')==1 and row.get('responseComplete') is True and row.get('tlsVerified') is True
        and row.get('outcomeUnknown') is False and row.get('socketClosed') is True for row in rows),
      'sdk_worker_all_original_wire_outcomes_known')
    connections=value.get('connections',{})
    need(connections.get('ownedHttpsAgentClosed') is True and connections.get('remainingRequestCount')==0
      and connections.get('remainingSocketCount')==0 and connections.get('otherNetworkDenials')==0
      and connections.get('allDispatchedResponsesComplete') is True and connections.get('unknownOutcomeCount')==0
      and connections.get('allObservedSocketsClosed') is True,'sdk_worker_all_owned_connections_closed')
    sql=value.get('sqlite',{});need(sql.get('allOriginalHandlesClosedOnce') is True and sql.get('denials')==0
      and type(sql.get('opened')) is int and sql['opened']>0 and sql['opened']==sql.get('closed'),
      'sdk_worker_every_original_database_closed')
    cache=value.get('sdkCacheClose',{})
    need(cache.get('originalCallbackRegistrations')==1 and cache.get('originalCallbackInvocations')==1
      and cache.get('observerRestored') is True and cache.get('originalListenerRemoved') is True
      and cache.get('globalExitEventEmitted') is False and cache.get('arbitraryRawHandlesClosed') is False
      and value.get('originalStateCacheCloseInvocations')==1,'sdk_worker_actual_source_bound_cache_close')
    probes=value.get('kernelSandbox',{})
    need(all(probes.get(k) is True for k in ('syntheticReadDenied','syntheticWriteDenied',
      'otherLoopbackConnectDenied','originalProbeSocketClosed')) and probes.get('productionPathProbed') is False,
      'sdk_worker_actual_kernel_refusals')
    need(value.get('workerReadDescriptorsOpened')==value.get('workerReadDescriptorsClosed'),
      'sdk_worker_private_read_descriptors_closed')
    need(value.get('inverseMutationAttempted') is (phase!='initial') and value.get('inverseCompleted') is (phase!='initial'),
      'sdk_exact_phase_inverse_result')

class Api(wire.Api):
    def __init__(self,plan,phase,phase_until,journal,guard,commands):
        super().__init__(plan,phase,phase_until,journal,guard)
        self.commands=commands;self.sdk_results=[];self.sdk_unknown=False;self.seed_result=None
    def run_owned_node(self,label,argv,maximum,deadline):
        self.remaining(1);self.guard.check()
        self.journal.append('sdk-child-intent',{'case':label,'argv':argv,'originalPhaseSeconds':120,
          'allocatedSeconds':max(0,deadline-time.monotonic()),'automaticRetry':False})
        row,out,err=self.commands.run(label,argv,until=deadline,maximum=maximum)
        # These original command rows retain lifecycle/byte counts, but never a
        # digest of an unexpected possibly private diagnostic stream.
        row.pop('stdoutSha256',None);row.pop('stderrSha256',None)
        row['privateStreamDigestsWithheld']=True
        self.journal.append('sdk-child-result',{'case':label,'command':row})
        if row['outcomeUnknown']:self.sdk_unknown=True
        # Bounded diagnostic retention is under the original outer custody
        # deadline, including when the business phase has already failed.
        # No provider, HTTP or SDK business step follows an expired phase.
        self.guard.write_new(ROOT/self.phase/(label+'.stderr.private'),err)
        self.guard.write_new(ROOT/self.phase/(label+'.stdout.private.json'),out)
        need(row['exitCode']==0 and row['completeBeforeDeadline'] is True and not row['outcomeUnknown']
          and row['streamsClosed'] is True and not err,'sdk_original_owned_child_known_zero')
        value=json.loads(out)
        return value
    def public(self):
        result=super().public();result.update(sdkChildren=self.sdk_results,seedPreparation=self.seed_result,
          actualPluginSdkPhaseExecuted=bool(self.sdk_results),sdkChildOutcomeUnknown=self.sdk_unknown,
          wholeProductionDatabaseRollback=False,productionClientRollbackQualified=False)
        if self.sdk_unknown:result['allDispatchedResponsesComplete']=False
        return result

def fixed_public_sources(api,fence):
    fence.observe('preflight')
    pins={}
    for relative,pin in ASSET_PINS.items():
        data=api.guard.read(ROOT/relative,2*1048576,private=True)
        need(len(data)==pin['bytes'] and sha(data)==pin['sha256'],'sdk_exact_owned_public_asset')
        if relative.startswith('plugin/'):
            current,_=fence.read(LIVE/'extensions/openclaw-authbus'/Path(relative).name,2*1048576)
            need(sha(current)==pin['sha256'],'sdk_complete_current_installed_plugin_source')
        if relative.startswith('plugin/') or relative in {'qa/'+name for name in WORKERS}:
            pins[str(ROOT/relative)]=pin['sha256']
    for relative,pin in {**SDK_SOURCE_PINS,**SDK_EXTRA_PINS}.items():
        current,_=fence.read(SDK/relative,2*1048576)
        need(sha(current)==pin,'sdk_current_public_dependency_source')
        pins[str(SDK/relative)]=pin
    for filename,pin in ((NODE,NODE_SHA),('/sbin/mount',MOUNT_SHA),
      ('/usr/bin/sandbox-exec','abc5bb136d6b5cce8fa85d789f78e3326c51ca60cae637b2064adfb67a1dcd9a')):
        current,_=fence.read(Path(filename),2*1048576)
        need(sha(current)==pin,'sdk_current_fixed_public_runtime')
    return pins

def prepare_current_private_inputs(api,fence):
    fixed_public_sources(api,fence)
    raw,_=fence.read(LIVE/'openclaw.json',1048576,private=True,expected=fence.doc['configurationIdentity'])
    need(sha(raw)==fence.doc['configurationSha256'],'sdk_same_whole_current_configuration')
    config=json.loads(raw);entry=config.get('plugins',{}).get('entries',{}).get('openclaw-authbus',{})
    original=entry.get('config')
    need(entry.get('enabled') is True and isinstance(original,dict) and original.get('hostId')=='mac'
      and original.get('leader') is False and original.get('publishNew') is True and original.get('manageOrder') is True,
      'sdk_exact_observed_current_plugin_flags')
    private_new(api,ROOT/'input/selected-main3.private.json',fence.doc)
    private_new(api,ROOT/'protected-read',b'owned synthetic protected read probe\n',raw=True)
    private_new(api,ROOT/'protected-write',b'owned synthetic protected write probe\n',raw=True)
    private_new(api,ROOT/'input/seed-plan.private.json',{'schema':'heptabao.mac-main3-seed-plan.private.r1',
      'parentPid':os.getpid(),'remainingMs':max(1,int(api.remaining(10)*1000))})
    private_new(api,ROOT/'initial/seed.sb',sandbox_profile(seed=True),raw=True)
    value=api.run_owned_node('sdk-private-seed',['/usr/bin/sandbox-exec','-f',str(ROOT/'initial/seed.sb'),
      NODE,'--no-warnings',str(ROOT/'qa/main3_sdk_seed_r1.mjs'),str(ROOT/'input/seed-plan.private.json')],
      16384,min(api.until,time.monotonic()+10))
    need(value.get('schema')=='heptabao.mac-main3-authbus-seed.public.r1' and value.get('ok') is True
      and value.get('selectedOwnerCount')==3 and value.get('actualPluginPureFunctionsExecuted') is True
      and value.get('kernelReadWriteNetworkRefusalsObserved') is True and value.get('allOwnedDescriptorsClosed') is True
      and value.get('providerCalled') is False and value.get('productionWrites')==0,
      'sdk_known_private_seed_result')
    api.seed_result=value
    seed=json.loads(exact_private_read(api,ROOT/'private/seed.private.json'))
    need(seed.get('schema')=='heptabao.mac-main3-authbus-seed.private.r1' and len(seed.get('payloads',[]))==3
      and len(seed.get('managedProfiles',[]))==3,'sdk_private_seed_scope')
    need(seed.get('schedulerAssignments')=={'schemaVersion':1,'generation':1,'scopes':[],
      'assignments':[],'refreshLeases':[]},'sdk_explicit_synthetic_empty_scheduler_assignments')
    for i,(managed,payload,entry) in enumerate(zip(seed['managedProfiles'],seed['payloads'],fence.doc['ownerEntries'],strict=True),1):
        need(managed=={'profileId':entry['profileId'],'key':'selected-main-'+str(i),'credential':entry['credential']}
          and payload['key']==managed['key'] and payload['data']['credential']==entry['credential']
          and payload['data']['profileId']==entry['profileId'],'sdk_private_seed_actual_objects_exact')
    return original,seed

def run_worker(api,fence,state):
    phase=api.phase;configuration=dict(state['originalPluginConfig'])
    configuration.update(address='https://127.0.0.1:'+str(api.plan['port']),
      caFile=str(ROOT/'server/tls/server.crt'),roleIdFile=str(ROOT/'server/private/sdk-role-id'),
      secretIdFile=str(ROOT/'server/private/sdk-secret-id'))
    if phase=='initial':
        private_new(api,STATE/'openclaw.json',{'agents':{'list':[{'id':name,'agentDir':str(STATE/'agents'/name/'agent')} for name in AGENTS]},
          'plugins':{'entries':{'openclaw-authbus':{'enabled':True,'config':configuration}}}})
    private_new(api,ROOT/phase/'worker.sb',sandbox_profile(api.plan['port']),raw=True)
    plan={'schema':'heptabao.mac-main3-sdk-worker.private.r1','phase':phase,
      'mode':'initial' if phase=='initial' else 'cold-inverse','workRoot':str(ROOT),'stateRoot':str(STATE),
      'phaseRoot':str(ROOT/phase),'sdkRoot':str(SDK),'pluginEntry':str(ROOT/'plugin/index.js'),
      'pluginConfig':configuration,'originalPluginConfig':state['originalPluginConfig'],
      'inputCapsulePath':str(ROOT/'input/selected-main3.private.json'),
      'managedProfiles':state['seed']['managedProfiles'],
      'baselineOutput':str(ROOT/'private/baseline.private.json'),
      'initialCandidateOutput':str(ROOT/'private/initial-candidate.private.json'),
      'latestCandidateOutput':str(ROOT/'private/cold-candidate.private.json'),
      'rollbackOnce':str(ROOT/'private/rollback-once.private.json'),
      'custodyOutput':str(ROOT/phase/'custody.private.json'),
      'serverCertificateSha256':api.plan['certificateLeafSha256'],'sourcePins':fixed_public_sources(api,fence),
      'mountToolSha256':MOUNT_SHA,'phaseOwnerPid':os.getpid(),
      'phaseRemainingMs':max(1,int(api.remaining(120)*1000))}
    private_new(api,ROOT/phase/'worker-plan.private.json',plan)
    api.sdk_unknown=True
    value=api.run_owned_node('sdk-'+phase,['/usr/bin/sandbox-exec','-f',str(ROOT/phase/'worker.sb'),
      NODE,'--no-warnings',str(ROOT/'qa/main3_sdk_cycle_r2.mjs'),str(ROOT/phase/'worker-plan.private.json')],
      262144,api.until)
    # The frozen worker also scans all private credential strings before output.
    public=json.dumps(value,ensure_ascii=False)
    secrets=[state['rootToken'],state['unsealKey'],state['roleId'],state['secretId'],fence.doc['configurationSha256']]
    for payload in state['seed']['payloads']:secrets.extend((payload['data']['digest'],payload['data']['identity']))
    for entry in fence.doc['ownerEntries']:
        secrets.extend([entry['profileId'],*[v for v in entry['credential'].values() if isinstance(v,str) and len(v)>=8]])
    need(not any(value in public for value in secrets if isinstance(value,str) and len(value)>=8),'sdk_public_worker_projection_contains_no_private_values')
    validate_worker_result(value,phase);api.sdk_unknown=False
    fixed_public_sources(api,fence);api.sdk_results.append(value)
    custody=json.loads(exact_private_read(api,ROOT/phase/'custody.private.json',65536))
    need(custody.get('schema')=='heptabao.mac-main3-sdk-tokens.private.r1' and custody.get('phase')==phase
      and isinstance(custody.get('tokens'),list) and len(custody['tokens'])==1
      and isinstance(custody['tokens'][0],str) and 8<=len(custody['tokens'][0])<=16384,
      'sdk_exact_private_actual_plugin_token')
    return custody['tokens'][0]

def seed_write(api,fence,case,key,value,slot=0):
    fence.observe('before-canonical-write')
    result=api.call(case,'POST','/v1/openclaw-auth/data/'+key,{'data':value,'options':{'cas':0}},category='kv-write',slot=slot)
    api.check(case+'.version_one',result.get('data',{}).get('version')==1)

def initial(api,fence):
    fence.observe('before-phase')
    original,seed=prepare_current_private_inputs(api,fence)
    health=api.call('initial.uninitialized_tls_health','GET','/v1/sys/health',token='',expected=501,category='health',readiness=True)
    api.check('initial.uninitialized_sealed',health.get('initialized') is False and health.get('sealed') is True)
    recovery=api.call('initial.initialize_once','POST','/v1/sys/init',{'secret_shares':1,'secret_threshold':1},token='',category='init')
    api.root_token=recovery.get('root_token');key=recovery.get('keys_base64',[None])[0]
    api.check('initial.private_recovery_material',isinstance(api.root_token,str) and bool(api.root_token) and isinstance(key,str) and bool(key))
    state={'rootToken':api.root_token,'unsealKey':key,'originalPluginConfig':original,'seed':seed,'tokens':[]}
    private_new(api,ROOT/'server/private/sdk-recovery.private.json',{'rootToken':api.root_token,'unsealKey':key})
    unsealed=api.call('initial.unseal_once','POST','/v1/sys/unseal',{'key':key},token='',category='unseal')
    api.check('initial.unsealed',unsealed.get('sealed') is False)
    api.call('initial.kv_mount','POST','/v1/sys/mounts/openclaw-auth',{'type':'kv','options':{'version':'2'}},expected=204,category='mount')
    api.call('initial.native_activation','POST','/v1/sys/storage/native-v6/activate',{},expected=204,category='activate')
    cap=api.call('initial.native_capacity','GET','/v1/sys/internal/capacity',category='capacity')
    api.check('initial.normal_native_format_two',cap.get('data',{}).get('native_kv2_reader_format')==2
      and cap['data'].get('state_storage_format')=='heptabao-state-records-v6')
    api.call('initial.approle_mount','POST','/v1/sys/auth/approle',{'type':'approle'},expected=204,category='mount')
    for i,payload in enumerate(seed['payloads'],1):seed_write(api,fence,'initial.seed_profile_'+str(i),'profiles/'+payload['key'],payload['data'],i)
    seed_write(api,fence,'initial.seed_manifest','manifest',seed['manifest'])
    seed_write(api,fence,'initial.seed_fixture_order_policy','order-policy',seed['orderPolicy'])
    seed_write(api,fence,'initial.seed_fixture_scheduler_assignments','scheduler-assignments',seed['schedulerAssignments'])
    reads=['manifest','order-policy','scheduler-assignments',*['profiles/selected-main-'+str(i) for i in (1,2,3)]]
    policy='\n'.join('path "openclaw-auth/data/'+name+'" { capabilities = ["read"] }' for name in reads)+'\n'
    policy+='path "openclaw-auth/data/inbox/mac/*" { capabilities = ["create", "update"] }\n'
    for route,capability in [('lookup-self','read'),('renew-self','update'),('revoke-self','update')]:
        policy+='path "auth/token/'+route+'" { capabilities = ["'+capability+'"] }\n'
    api.call('initial.scoped_policy','PUT','/v1/sys/policies/acl/'+ROLE,{'policy':policy},expected=204,category='policy')
    api.call('initial.scoped_role','POST','/v1/auth/approle/role/'+ROLE,
      {'token_policies':[ROLE],'token_ttl':'1200s','token_max_ttl':'1800s','secret_id_num_uses':0,'secret_id_ttl':'3600s'},expected=204,category='role')
    rid=api.call('initial.role_id','GET','/v1/auth/approle/role/'+ROLE+'/role-id',category='role-id')['data']['role_id']
    sid=api.call('initial.secret_id','POST','/v1/auth/approle/role/'+ROLE+'/secret-id',{},category='secret-id')['data']['secret_id']
    need(isinstance(rid,str) and isinstance(sid,str) and len(rid)>=8 and len(sid)>=8,'sdk_received_private_approle_material')
    state.update(roleId=rid,secretId=sid)
    private_new(api,ROOT/'server/private/sdk-role-id',(rid+'\n').encode(),raw=True)
    private_new(api,ROOT/'server/private/sdk-secret-id',(sid+'\n').encode(),raw=True)
    token=run_worker(api,fence,state);state['tokens'].append(token)
    lookup=api.call('initial.actual_plugin_token_lookup','GET','/v1/auth/token/lookup-self',token=token,category='lookup')
    api.check('initial.actual_plugin_scoped_policy',ROLE in lookup.get('data',{}).get('policies',[]))
    renewal=api.call('initial.actual_plugin_token_renew_once','POST','/v1/auth/token/renew-self',{'increment':'1200s'},token=token,category='renew')
    api.check('initial.actual_plugin_token_renewed',renewal.get('auth',{}).get('client_token')==token and renewal['auth'].get('renewable') is True)
    api.call('initial.actual_plugin_admin_denied','GET','/v1/sys/mounts',token=token,expected=403,category='admin-denied')
    private_new(api,ROOT/'server/private/sdk-initial-state.private.json',state)
    fence.observe('after-phase');return state

def cold(api,fence,state):
    fence.observe('before-phase');api.root_token=state['rootToken']
    health=api.call('cold.sealed_tls_health','GET','/v1/sys/health',token='',expected=503,category='health',readiness=True)
    api.check('cold.actual_server_restart_sealed',health.get('initialized') is True and health.get('sealed') is True)
    unsealed=api.call('cold.unseal_existing','POST','/v1/sys/unseal',{'key':state['unsealKey']},token='',category='unseal')
    api.check('cold.unsealed',unsealed.get('sealed') is False)
    old=state['tokens'][0]
    api.call('cold.old_actual_plugin_token_persisted','GET','/v1/auth/token/lookup-self',token=old,category='lookup')
    for i,payload in enumerate(state['seed']['payloads'],1):
        value=api.call('cold.persisted_profile_'+str(i),'GET','/v1/openclaw-auth/data/profiles/'+payload['key'],token=old,category='kv-read',slot=i)
        api.check('cold.private_profile_exact_'+str(i),value.get('data',{}).get('data')==payload['data']
          and value['data'].get('metadata',{}).get('version')==1)
    new=run_worker(api,fence,state);api.check('cold.new_process_new_plugin_token',new!=old)
    for i,token in enumerate((old,new),1):
        api.call('cold.revoke_actual_plugin_token_'+str(i),'POST','/v1/auth/token/revoke',{'token':token},expected=204,category='revoke')
        api.call('cold.revoked_plugin_lookup_denied_'+str(i),'GET','/v1/auth/token/lookup-self',token=token,expected=403,category='lookup')
        api.call('cold.revoked_plugin_kv_denied_'+str(i),'GET','/v1/openclaw-auth/data/manifest',token=token,expected=403,category='kv-read')
    api.call('cold.destroy_sdk_secret_once','POST','/v1/auth/approle/role/'+ROLE+'/secret-id/destroy',
      {'secret_id':state['secretId']},expected=204,category='secret-destroy')
    api.call('cold.destroyed_sdk_secret_login_denied','POST','/v1/auth/approle/login',
      {'role_id':state['roleId'],'secret_id':state['secretId']},token='',expected=400,category='login')
    fence.observe('after-phase')
