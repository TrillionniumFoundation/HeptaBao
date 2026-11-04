#!/usr/bin/env python3
"""Actual isolated installed gateway: AuthBus import, one default-model request,
cold restart, complete private state rollback and restarted baseline readiness.

The live gateway, its state, other accounts, relay and production routing are not
changed. A completed core receipt and exact current native generation are needed.
"""
from __future__ import annotations
import argparse, base64, copy, importlib.util, json, os, secrets, shutil, signal, socket
import subprocess, sys, time, traceback
from pathlib import Path
from authbus_profile2_selector_live import Refused, need, encoded, sha, file_sha, digest, read_private, put, service_pids

HEAD='36076db5f5afe00db75eba9b607dee7802dae554'
TREE='ae71c4b243afd4099db66e7d9882b3f28c777a95'
PROBE='Reply exactly HEPTABAO_OK.'
NODE='/opt/homebrew/bin/node'

def http(port, method, route, data=None, token=None, timeout=3):
    import http.client
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=timeout)
    try:
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        conn.request(method,route,encoded(data) if data is not None else None,headers)
        response=conn.getresponse();raw=response.read(65537)
        need(len(raw)<=65536,'gateway_response_bound')
        try:body=json.loads(raw)
        except Exception:body={}
        return response.status,body,raw
    finally:conn.close()

def manifest(root):
    out={}
    for p in sorted(root.rglob('*')):
        need(not p.is_symlink(),'state_symlink_refused')
        s=p.stat();name=str(p.relative_to(root))
        out[name]={'mode':s.st_mode&0o777,'kind':'directory' if p.is_dir() else 'file'}
        if p.is_file():out[name].update(sha256=file_sha(p),bytes=s.st_size)
    return out

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ['work-dir','core-root','source','binary','build-result','sdk','live-state','native-source']:
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--config-sha256',required=True);args=ap.parse_args()
    os.umask(0o077);root=args.work_dir;root.mkdir(mode=0o700)
    for n in ['tmp','state','workspace','home','plugin']:(root/n).mkdir(mode=0o700)
    state=root/'state';cfg_path=state/'openclaw.json'
    ledger_dir=args.core_root.parent/'final360-gateway-single-request-ledger';ledger_dir.mkdir(mode=0o700,exist_ok=True)
    provider_ledger=ledger_dir/'provider-dispatch.private.json'
    need(not provider_ledger.exists(),'prior_provider_dispatch_no_replay')
    r={'schema':'heptabao.actual-isolated-profile2-gateway.v1','ok':False,'checks':[],
       'sourceCommit':HEAD,'sourceTree':TREE,'productionChanged':False,'productionTrafficCutover':False,
       'productionGatewayRollbackQualified':False,'allAccountsQualified':False,'oldRelayMigrationQualified':False,
       'providerRouteClassification':'Existing profile-2 native OpenAI ChatGPT Responses path; HTTPS to configured chatgpt.com endpoint; no legacy relay/proxy',
       'legacyRelayContacted':False,'legacyDEGuardChangedOrBypassed':False,
       'providerRefreshAttempted':False,'j3160Contacted':False,'credentialValuesPublished':False,
       'accountIdentitiesPublished':False,'businessRequestBudget':1,'startedUnixMs':int(time.time()*1000),
       'phases':[],'businessRequest':{'attempted':False}}
    server=None;gateway=None;log_handles=[];sensitive=[];before=None;helper=None
    def check(code,value,**detail):
        r['checks'].append({'case':code,'passed':bool(value),**detail});need(value,code)
    try:
        receipt=json.loads(args.build_result.read_bytes());core_bytes=read_private(args.core_root/'result.public.json');core=json.loads(core_bytes)
        check('final_core_result',core.get('ok') is True and core.get('sourceCommit')==HEAD and core.get('sourceTree')==TREE
              and core.get('actualInstalledPluginImportedCredential') and core.get('privateLogicalStoreRollbackQualified'))
        check('normal_final_binary',receipt.get('source_commit')==HEAD and receipt.get('source_tree')==TREE
              and receipt.get('normal_default_candidate') is True and receipt.get('source_freeze_verified') is True
              and receipt.get('build_exit_code')==0 and receipt['artifacts']['heptabao-server']['sha256']==core['binarySha256']==file_sha(args.binary))
        check('final_source_clean',subprocess.check_output(['git','-C',str(args.source),'rev-parse','HEAD'],text=True).strip()==HEAD
              and subprocess.check_output(['git','-C',str(args.source),'rev-parse','HEAD^{tree}'],text=True).strip()==TREE
              and subprocess.run(['git','-C',str(args.source),'diff','--quiet']).returncode==0
              and subprocess.run(['git','-C',str(args.source),'diff','--cached','--quiet']).returncode==0)
        check('current_native_generation',file_sha(args.native_source)==core['sourceNativeSha256'])
        selection_bytes=read_private(args.core_root/'consumer-initial/runtime-selection.private.json');selection=json.loads(selection_bytes)
        check('actual_default_selection_binding',selection.get('source')=='actual_installed_sdk_default_model_resolver_after_actual_authbus_cycle'
              and digest(selection['credential'])==selection['credentialSha256']==core['selectedCredentialSha256']
              and selection['credential']['access']==selection['resolvedApiKey'] and selection['credential']['expires']>time.time()*1000+600000)
        native=json.loads(read_private(args.native_source));native_tokens=native['tokens']
        selected_jwt=json.loads(base64.urlsafe_b64decode(selection['resolvedApiKey'].split('.')[1]+'==='))
        check('current_native_selected_wire_jwt_same_account',native.get('auth_mode')=='chatgpt'
              and native_tokens['access_token']==selection['resolvedApiKey']
              and native_tokens['account_id']==selection['credential']['accountId']
              and selected_jwt['https://api.openai.com/auth']['chatgpt_account_id']==selection['credential']['accountId'])
        transport=args.sdk/'dist/openai-transport-stream-B0WkSqXp.js'
        check('installed_native_transport_contract',file_sha(transport)=='82712e39d2863f055210df3a33f4a725872bcbf3dfef1b7ba181dba882f60edc')
        put(root/'provider-identity-contract.public.json',{'schema':'heptabao.actual-native-gateway-identity-contract.v1',
            'sourceNativeSha256':core['sourceNativeSha256'],'selectedCredentialSha256':selection['credentialSha256'],
            'nativeAccountMatchesSelected':True,'selectedAccessMatchesNative':True,'wireJwtAccountMatchesNative':True,
            'accountIdSha256':sha(selection['credential']['accountId'].encode()),'providerTransportSource':str(transport),
            'providerTransportSha256':file_sha(transport),'headerContract':'Installed createOpenAIResponsesClient passes the actual selected apiKey unchanged; buildOpenAIClientHeaders merges configured and caller headers without synthesizing ChatGPT-Account-Id. The guard verifies the bearer JWT account and verifies the optional header if present.',
            'credentialOrHeaderSubstitution':False,'oldBundledResponsesHeaderRuleUsed':False})
        put(root/'selection.private.json',selection_bytes)
        credential=selection['credential'];pid=selection['profileId'];sensitive=[pid]+[v for k,v in credential.items() if isinstance(v,str) and len(v)>7 and k not in ('type','provider','chatgptPlanType')]
        qa=args.source/'qa/openbao-acceptance';sys.path.insert(0,str(qa))
        spec=importlib.util.spec_from_file_location('profile2_gateway_stage_helper',qa/'authbus_current_credential_stage.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        before=helper.capture(args.live_state,args.config_sha256);pids_before=service_pids()
        original_cfg=json.loads(read_private(args.live_state/'openclaw.json'))
        default=original_cfg['agents']['defaults']['model'];default=default['primary'] if isinstance(default,dict) else default
        check('same_actual_default_model',default==core['actualDefaultModel']==selection['model']['provider']+'/'+selection['model']['id'])
        provider=copy.deepcopy(original_cfg['models']['providers']['openai'])
        check('native_provider_route',provider['api']=='openai-chatgpt-responses' and provider['baseUrl']=='https://chatgpt.com/backend-api/codex')
        plugin=root/'plugin';source_pins={}
        for p in (args.core_root/'installed-plugin-copy').iterdir():
            if p.is_file():put(plugin/p.name,p.read_bytes());source_pins[str(p)]=file_sha(p);source_pins[str(plugin/p.name)]=file_sha(p)
        live_plugin=args.live_state/'extensions/openclaw-authbus'
        put(plugin/'openclaw.plugin.json',(live_plugin/'openclaw.plugin.json').read_bytes())
        source_pins[str(live_plugin/'openclaw.plugin.json')]=file_sha(live_plugin/'openclaw.plugin.json')
        source_pins[str(plugin/'openclaw.plugin.json')]=file_sha(plugin/'openclaw.plugin.json')
        (plugin/'node_modules').mkdir(mode=0o700);(plugin/'node_modules/openclaw').symlink_to(args.sdk)
        for name in ['openclaw.mjs','package.json','dist/plugin-sdk/agent-runtime.js','dist/store-DH33UrUj.js',
                     'dist/model-auth-CJEm9SNp.js','dist/order-CeBlX0NH.js','dist/openai-chatgpt-provider-BfBZlMyL.js',
                     'dist/undici-runtime-BL8ZN-Ey.js','dist/runtime-fetch-k5Zth7kk.js','node_modules/undici/index.js',
                     'dist/openai-transport-stream-B0WkSqXp.js','dist/stream-BcRkg2P0.js',
                     'node_modules/@openclaw/ai/dist/openai-chatgpt-responses-DVC4Bk_A.mjs']:
            source_pins[str(args.sdk/name)]=file_sha(args.sdk/name)
        for name in ['authbus_profile2_gateway_live.py','authbus_gateway_guard.mjs','authbus_gateway_store.mjs']:
            p=Path(__file__).with_name(name);source_pins[str(p)]=file_sha(p)
        r.update(binarySha256=file_sha(args.binary),coreReceiptSha256=sha(core_bytes),coreRoot=str(args.core_root),
                 selectedCredentialSha256=selection['credentialSha256'],actualDefaultModel=default,sourcePins=source_pins)
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        server=smoke.Instance(args.binary,root/'server');sc=json.loads((server.root/'server.json').read_bytes())
        sc['storage']={'native_v6_file':{'path':sc['data_dir']}};(server.root/'server.json').write_bytes(encoded(sc));server.start()
        def call(code,method,route,body=None,token=None,expected=200):
            status,data=server.call(method,route,body,token=token);check(code,status==expected,status=status);return data
        init=call('initialize','POST','sys/init',{'secret_shares':1,'secret_threshold':1},token='');server.token=init['root_token'];unseal=init['keys_base64'][0]
        sensitive.extend([server.token,unseal]);put(root/'recovery.private.json',{'rootToken':server.token,'unsealKey':unseal})
        call('unseal','POST','sys/unseal',{'key':unseal},token='')
        call('kv_mount','POST','sys/mounts/openclaw-auth',{'type':'kv','options':{'version':'2'}},expected=204)
        call('approle_mount','POST','sys/auth/approle',{'type':'approle'},expected=204)
        call('formal_activation','POST','sys/storage/native-v6/activate',{},expected=204)
        check('formal_format2',call('formal_capacity','GET','sys/internal/capacity')['data']['native_kv2_reader_format']==2)
        key='sha256-'+selection['credentialSha256'];identity=digest({k:credential.get(k) for k in ['provider','type','email','accountId','projectId']})
        payload={'schemaVersion':1,'profileId':pid,'credential':credential,'digest':selection['credentialSha256'],'identity':identity}
        entry={k:v for k,v in payload.items() if k not in ['credential','schemaVersion']};entry.update(key=key,provider=credential['provider'],type=credential['type'],expires=credential['expires'],quarantined=False,status='active')
        order={'schemaVersion':1,'generation':1,'providers':{'openai':{'candidates':[{'profileId':pid,'digest':selection['credentialSha256'],'enrolledAt':int(time.time()*1000)}],'activeProfile':pid,'enforceManagedOrder':True}}}
        documents={'profiles/'+key:payload,'order-policy':order,'scheduler-assignments':{'schemaVersion':1,'generation':1,'assignments':[]},'manifest':{'schemaVersion':1,'generation':1,'profiles':[entry]}}
        for name,value in documents.items():call('seed.'+name.split('/')[0],'POST','openclaw-auth/data/'+name,{'data':value,'options':{'cas':0}})
        policy='\n'.join('path "openclaw-auth/data/'+name+'" { capabilities=["read"] }' for name in documents)+'\npath "openclaw-auth/data/inbox/gateway-profile2-canary/*" { capabilities=["create","update"] }'
        call('policy','PUT','sys/policies/acl/gateway-profile2-canary',{'policy':policy},expected=204)
        role_path='auth/approle/role/gateway-profile2-canary'
        call('role','POST',role_path,{'token_policies':['gateway-profile2-canary'],'token_ttl':'600s','token_max_ttl':'1200s','secret_id_ttl':'1800s','secret_id_num_uses':0},expected=204)
        role=call('role_id','GET',role_path+'/role-id')['data']['role_id'];secret=call('secret_id','POST',role_path+'/secret-id',{})['data']['secret_id'];sensitive.extend([role,secret])
        (root/'credentials').mkdir(mode=0o700)
        for name,data in [('role_id',role.encode()),('secret_id',secret.encode()),('ca.crt',(server.root/'ca.crt').read_bytes())]:put(root/'credentials'/name,data)
        plugin_cfg={'address':server.address,'caFile':str(root/'credentials/ca.crt'),'roleIdFile':str(root/'credentials/role_id'),'secretIdFile':str(root/'credentials/secret_id'),
                    'hostId':'gateway-profile2-canary','leader':False,'publishNew':False,'manageOrder':True,'schedulerMode':'shadow','pollIntervalMs':300000,'maxRefreshesPerCycle':1}
        sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close();token=secrets.token_hex(32);sensitive.append(token)
        params={'transport':'sse','maxTokens':32,'timeoutMs':45000,'reasoningEffort':'none','textVerbosity':'low'}
        baseline_cfg={'agents':{'defaults':{'model':{'primary':default,'fallbacks':[]},'models':{default:{'params':params}},'workspace':str(root/'workspace'),
                     'skipBootstrap':True,'contextInjection':'never','startupContext':{'enabled':False},'memorySearch':{'enabled':False},'skills':[],
                     'heartbeat':{'every':'0s','target':'none'},'timeoutSeconds':60,'maxConcurrent':1,'thinkingDefault':'off'},
                     'list':[{'id':'main','default':True,'agentDir':str(state/'agents/main/agent'),'workspace':str(root/'workspace'),
                              'runRetries':{'base':1,'perProfile':0,'min':1,'max':1},'tools':{'deny':['*']}}]},
                     'models':{'providers':{'openai':provider}},'tools':{'deny':['*']},'channels':{},'cron':{'enabled':False,'triggers':{'enabled':False}},
                     'hooks':{'enabled':False,'internal':{'enabled':False}},'browser':{'enabled':False},'web':{'enabled':False},
                     'discovery':{'mdns':{'mode':'off'},'wideArea':{'enabled':False}},'skills':{'allowBundled':[],'load':{'watch':False},'limits':{'maxSkillsInPrompt':0},'workshop':{'autonomous':{'enabled':False}}},
                     'plugins':{'enabled':True,'allow':['openai','openclaw-authbus'],'bundledDiscovery':'allowlist','load':{'paths':[str(plugin)]},'slots':{'memory':'none'},'entries':{'openai':{'enabled':True},'openclaw-authbus':{'enabled':False,'config':plugin_cfg}}},
                     'logging':{'level':'info','file':str(root/'gateway.log.private')},
                     'gateway':{'mode':'local','port':port,'bind':'loopback','auth':{'mode':'token','token':token,'allowTailscale':False},'tailscale':{'mode':'off'},'reload':{'mode':'off'},
                                'controlUi':{'enabled':False},'channelHealthCheckMinutes':0,'nodes':{'browser':{'mode':'off'}},
                                'http':{'endpoints':{'chatCompletions':{'enabled':True,'maxBodyBytes':4096,'maxImageParts':0,'maxTotalImageBytes':1}}}}}
        put(cfg_path,baseline_cfg)
        env={'PATH':'/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':os.environ['HOME'],'TMPDIR':str(root/'tmp'),
             'OPENCLAW_STATE_DIR':str(state),'OPENCLAW_CONFIG_PATH':str(cfg_path),'OPENCLAW_OAUTH_DIR':str(state/'oauth'),'OPENCLAW_HOME':str(root/'home'),
             'OPENCLAW_SKIP_CHANNELS':'1','OPENCLAW_SKIP_CRON':'1','OPENCLAW_SKIP_STARTUP_MODEL_PREWARM':'1',
             'NODE_DISABLE_COMPILE_CACHE':'1','OPENCLAW_NO_RESPAWN':'1','NO_COLOR':'1'}
        ips=sorted({x[4][0] for x in socket.getaddrinfo('chatgpt.com',443,socket.AF_UNSPEC,socket.SOCK_STREAM)})
        check('provider_dns_has_addresses',bool(ips));r['providerAddressCount']=len(ips)
        rules=['(version 1)','(deny default)','(allow process*)','(allow sysctl-read)','(allow mach-lookup)','(allow file-read*)',
               '(allow file-write* (subpath '+json.dumps(str(root))+'))',
               '(allow file-write* (subpath '+json.dumps(str(ledger_dir))+'))','(allow file-write* (literal "/dev/null"))',
               '(allow network-bind (local ip "localhost:*"))','(allow network-inbound (local ip "localhost:*"))',
               '(allow network-outbound (remote ip '+json.dumps('localhost:'+server.address.rsplit(':',1)[1])+'))']
        # macOS sandbox address filters only accept '*' or 'localhost'. The
        # pinned envelope additionally rejects every TLS endpoint except this
        # private Bao listener and the configured provider during its one call.
        rules += ['(allow network-outbound (remote ip "*:443"))',
                  '(allow network-outbound (remote unix-socket (literal "/private/var/run/mDNSResponder")))']
        put(root/'gateway.sb',('\n'.join(rules)+'\n').encode())
        put(root/'intent.public.json',{'schema':'heptabao.actual-isolated-gateway-intent.v1','sourceCommit':HEAD,'binarySha256':r['binarySha256'],
            'coreReceiptSha256':sha(core_bytes),'actualDefaultModel':default,'probeText':PROBE,'providerDispatchBudget':1,'refreshDispatchBudget':0,
            'noAutomaticRequestReplay':True,'channelsEnabled':False,'cronEnabled':False,'toolsEnabled':False,'autonomousSkillsEnabled':False,
            'selectedProfileCount':1,'otherAccountsCopied':False,'rollbackScope':'Entire private gateway state tree from a stopped baseline plus exact SDK logical store; production gateway excluded.',
            'productionChanged':False,'providerEndpoint':'https://chatgpt.com/backend-api/codex/responses'})
        def store_phase(name,mode):
            plan={'sdkRoot':str(args.sdk),'stateRoot':str(state),'selectionPath':str(root/'selection.private.json'),'mode':mode}
            pp=root/(name+'-store-plan.private.json');put(pp,plan)
            proc=subprocess.run([NODE,str(Path(__file__).with_name('authbus_gateway_store.mjs')),str(pp)],env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
            put(root/(name+'-store.stdout.private'),proc.stdout);put(root/(name+'-store.stderr.private'),proc.stderr)
            value=json.loads(proc.stdout);put(root/(name+'-store.public.json'),value);check(name+'.sdk_store',proc.returncode==0 and value.get('ok') is True)
            return value
        baseline_store=store_phase('baseline-initialize','initialize')
        plan_base={'workRoot':str(root),'stateRoot':str(state),'sdkRoot':str(args.sdk),'selectionPath':str(root/'selection.private.json'),
                   'providerLedgerPath':str(provider_ledger),'baoAddress':server.address,'baoCertificateSha256':cert_sha256(server.root/'tls.crt'),'sourcePins':source_pins,
                   'accountBindingContract':'pinned-installed-openai-transport-bearer-jwt-v1',
                   'defaultModel':default,'providerEndpoint':'https://chatgpt.com/backend-api/codex/responses','probeText':PROBE,'providerAddresses':ips,'gatewayPort':port}
        def start_gateway(name,selected=False):
            nonlocal gateway
            pp=root/(name+'-plan.private.json');put(pp,{**plan_base,'phase':name})
            out=(root/(name+'.stdout.private')).open('xb');err=(root/(name+'.stderr.private')).open('xb');log_handles.extend([out,err])
            child_env={**env,'HEPTABAO_GATEWAY_PLAN':str(pp)}
            argv=['/usr/bin/sandbox-exec','-f',str(root/'gateway.sb'),NODE,'--import',str(Path(__file__).with_name('authbus_gateway_guard.mjs')),
                  str(args.sdk/'openclaw.mjs'),'gateway','run','--port',str(port),'--bind','loopback','--auth','token','--tailscale','off','--ws-log','compact']
            gateway=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=child_env,start_new_session=True)
            deadline=time.monotonic()+90;ready=False
            while time.monotonic()<deadline:
                need(gateway.poll() is None,'gateway_'+name+'_exited')
                try:
                    status,_,_=http(port,'GET','/readyz',token=token)
                    plugin_ok=not selected
                    if selected:
                        p=state/'authbus/status.json'
                        if p.exists():plugin_ok=json.loads(p.read_bytes()).get('ok') is True
                    if status==200 and plugin_ok:ready=True;break
                except (OSError,ValueError):pass
                time.sleep(0.25)
            check(name+'.ready',ready)
            r['phases'].append({'phase':name,'gatewayPid':gateway.pid,'ready':True,'appRoleImportRequired':selected})
            return store_phase(name,'observe-selected' if selected else 'observe')
        def stop_gateway(name):
            nonlocal gateway
            if gateway is None:return
            process=gateway;os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10);gateway=None
            check(name+'.actual_sigkill_wait',process.returncode==-9)
        start_gateway('baseline');stop_gateway('baseline')
        baseline_store=store_phase('baseline-stopped','observe')
        baseline_manifest=manifest(state);put(root/'baseline-manifest.public.json',baseline_manifest)
        shutil.copytree(state,root/'baseline-state',copy_function=shutil.copy2)
        check('cold_baseline_backup_exact',manifest(root/'baseline-state')==baseline_manifest)
        candidate_cfg=copy.deepcopy(baseline_cfg);candidate_cfg['plugins']['entries']['openclaw-authbus']['enabled']=True
        cfg_path.write_bytes(encoded(candidate_cfg))
        start_gateway('candidate-initial',True)
        put(root/'provider-armed.private',b'one authorized nonsensitive default-model request\n')
        r['businessRequest']={'attempted':True,'modelTarget':'openclaw/default','modelOverrideProvided':False,'profileOverrideProvided':False,'retry':False,'prompt':PROBE}
        try:
            status,body,raw=http(port,'POST','/v1/chat/completions',{'model':'openclaw/default','messages':[{'role':'user','content':PROBE}],
                    'stream':False,'max_completion_tokens':32,'tools':[],'tool_choice':'none'},token=token,timeout=70)
            put(root/'business-response.private.json',raw)
            reply=body.get('choices',[{}])[0].get('message',{}).get('content') if body.get('choices') else None
            r['businessRequest'].update(httpStatus=status,responseSha256=sha(raw),responseBytes=len(raw),boundedReply=isinstance(reply,str) and len(reply)<=128,
                                        expectedReply=isinstance(reply,str) and reply.strip()=='HEPTABAO_OK',replySha256=sha(reply.encode()) if isinstance(reply,str) else None)
        except Exception as error:r['businessRequest'].update(errorClass=type(error).__name__,outcomeUnknown=True)
        stop_gateway('candidate-initial');old=server.process;server.stop();check('server.actual_sigkill_wait',old.returncode==-9)
        server.start();call('server.cold_sealed','GET','sys/health',expected=503);call('server.cold_unseal','POST','sys/unseal',{'key':unseal},token='')
        start_gateway('candidate-cold',True);stop_gateway('candidate-cold')
        state.rename(root/'candidate-state-retained');shutil.copytree(root/'baseline-state',state,copy_function=shutil.copy2)
        check('rollback_all_private_state_files_exact_before_restart',manifest(state)==baseline_manifest)
        check('rollback_config_bytes_exact',cfg_path.read_bytes()==encoded(baseline_cfg))
        rolled=store_phase('rollback-before-restart','observe');check('rollback_sdk_logical_store_exact',rolled['storeSha256']==baseline_store['storeSha256'])
        restarted=start_gateway('rollback-restarted');check('rollback_restarted_sdk_logical_store_exact',restarted['storeSha256']==baseline_store['storeSha256'])
        stop_gateway('rollback-restarted')
        network=[json.loads(p.read_bytes()) for p in sorted(root.glob('network-*.public.json'))]
        requests=[v for d in network for v in d.get('providerRequests',[])];r['networkReports']=[{'path':p.name,'sha256':file_sha(p)} for p in sorted(root.glob('network-*.public.json'))]
        r['providerRequests']=requests;r['blockedOperations']=[v for d in network for v in d.get('blocked',[])]
        r['isolatedGatewayReadyQualified']=True;r['actualGatewayAppRoleCredentialImportQualified']=True
        r['isolatedGatewayColdRestartQualified']=True;r['isolatedGatewayFullStateRollbackQualified']=True
        after=helper.capture(args.live_state,args.config_sha256);check('live_original_five_auth_rows_unchanged',all(a['rows']==b['rows'] for a,b in zip(before,after)))
        check('live_native_source_unchanged',file_sha(args.native_source)==core['sourceNativeSha256'])
        check('live_relay_pids_unchanged',service_pids()==pids_before)
        check('installed_sources_unchanged',all(file_sha(p)==pin for p,pin in source_pins.items()))
        check('normal_binary_unchanged',file_sha(args.binary)==r['binarySha256'])
        check('report_contains_no_credential_values',all(v.encode() not in encoded(r) for v in sensitive))
        check('one_actual_provider_post',len(requests)==1)
        check('actual_owned_default_credential_on_wire',all(v.get('actualDefaultModelMatched') and v.get('actualSelectedCredentialMatched') and v.get('actualAccountMatched') and v.get('toolsCount')==0 for v in requests))
        check('no_second_dispatch_on_cold_or_rollback',all(not d.get('providerRequests') for d in network if d.get('phase')!='candidate-initial'))
        good=r['businessRequest'].get('httpStatus')==200 and r['businessRequest'].get('expectedReply') is True
        good=good and requests[0].get('status')==200 and requests[0].get('complete') is True
        r['actualDefaultModelBusinessRequestQualified']=good
        check('actual_default_model_business_request',good)
        r['ok']=True
    except Exception as error:
        r['error']=str(error) if isinstance(error,Refused) else type(error).__name__
        r['errorClass']=type(error).__name__;r['errorFrames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        if gateway is not None:
            try:os.killpg(gateway.pid,signal.SIGKILL);gateway.wait(timeout=10)
            except Exception:pass
            r['ownedGatewayStopped']=gateway.poll() is not None
        else:r['ownedGatewayStopped']=True
        if server is not None and server.process is not None:
            old=server.process;server.stop();r['ownedServerStopped']=old.returncode is not None
        for f in log_handles:f.close()
        r['finishedUnixMs']=int(time.time()*1000);put(root/'result.public.json',r)
    print(json.dumps({'ok':r['ok'],'error':r.get('error'),'checks':len(r['checks']),'result':str(root/'result.public.json'),'sha256':file_sha(root/'result.public.json')}));return 0 if r['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
