#!/usr/bin/env python3
"""Pocket4 actual current agent-native contract, separate from original generic QA.
Current full source and missing-current-profile recovery scenarios, formal HeptaBao,
real installed AuthBus/SDK/native factory, strict two-agent rollback. No provider
egress or production writes. Caller must supply private PID/network namespaces and
read-only production/source mounts. Original 10/70/35 second budgets are retained.
"""
from __future__ import annotations
import argparse,base64,copy,hashlib,importlib.util,json,os,signal,socket,sqlite3,stat,subprocess,sys,time,traceback
from pathlib import Path
COMMIT='33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE='cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
BINARY_SHA='7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
BUILD_SHA='7fa76585e94fe2e60bbc3ce754f37e4d9d433e4cf576fcc2e39a1e95771f3f42'
NATIVE_SHA='2fa263744917e1d71658daa4f34e09ea448fe77ec0b2c0f8ec22c01e2cd84e8e'
CONFIG_SHA='3611380b8c77282e785e00e20d9eba8bc8cf0164b3b3f00e2ea5d1f52a441c98'
ACCOUNT_SHA='8fc636f1db234f6f224599719619793d5f0b885213d84d126202b5de472f7875'
CREDENTIAL_SHA='a440653bdbed7e00251c1e2e1cb969bb4d04d94bf502304ee6a5b04eacf09cb1'
ACCESS_SHA='25599c616259f271ba3150af06dfdbf8967467455f45278d114c70248eaf76d4'
PROFILE_ID_SHA='36b8ea03a6884be553e4124e76df9fb87a40cf13acb795ee8582e3ad0ab2c319'
AGENTS=('main','tg8687951891')
TABLES={'store':('auth_profile_store','store_key','store_json'),'state':('auth_profile_state','state_key','state_json')}
PLUGIN_FILES=('index.js','bad-refresh-quarantine.js','codex-client-recycler.js','lease-assignments.js',
 'order-policy.js','provider-error-classifier.js','runtime-refresh-policy.js','package.json')
class Refused(Exception):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def sha(value):
    return hashlib.sha256(value).hexdigest()

def digest(value):
    return sha(encoded(value))

def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def ident(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_uid, s.st_gid, s.st_mode,
            s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)

def read_private(path, maximum=2 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o077
             and before.st_size <= maximum, 'private_input_custody')
        raw = os.read(fd, maximum + 1)
        need(ident(before) == ident(os.fstat(fd)) == ident(path.lstat())
             and len(raw) == before.st_size, 'private_input_changed')
        return raw
    finally:
        os.close(fd)

def put(path, value):
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def capture_sources(live):
    need(file_sha(live/'openclaw.json')==CONFIG_SHA,'source_configuration_changed')
    cfg=json.loads((live/'openclaw.json').read_bytes())
    need(tuple(a.get('id')for a in cfg['agents']['list'])==AGENTS,'configured_agent_scope_changed')
    documents=[]
    for agent in cfg['agents']['list']:
        aid=agent['id'];directory=live/'agents'/aid/'agent'
        need(Path(agent.get('agentDir',directory))==directory,'source_agent_directory_changed')
        database=directory/'openclaw-agent.sqlite'
        for parent in (live,live/'agents',directory.parent,directory):
            s=parent.lstat()
            need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and not parent.is_symlink()
                 and not stat.S_IMODE(s.st_mode)&0o022,'source_parent_custody')
        fd=os.open(database,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode)and before.st_uid==os.geteuid()
                 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,'source_database_custody')
            sidecars={}
            for suffix in ('-wal','-shm'):
                p=Path(str(database)+suffix)
                if p.exists():
                    s=p.lstat()
                    need(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()
                         and not stat.S_IMODE(s.st_mode)&0o077 and s.st_nlink==1,'source_sidecar_custody')
                    sidecars[suffix]=list(ident(s))
            need(bool(os.statvfs(database).f_flag&os.ST_RDONLY),'source_database_not_kernel_readonly')
            db=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=3)
            try:
                db.execute('PRAGMA query_only=ON');db.execute('PRAGMA temp_store=MEMORY');db.execute('BEGIN')
                document={'schema':'heptabao.current-auth-complete-tables.v1','host':'pocket4','agent':aid,'rows':{}}
                for kind,(table,key,column)in TABLES.items():
                    rows=db.execute('SELECT '+key+','+column+',updated_at FROM '+table+' ORDER BY '+key).fetchall()
                    need(len(rows)<=32 and all(isinstance(r[1],str)and len(r[1].encode())<=1024*1024 for r in rows),
                         'auth_table_bounded_scope')
                    document['rows'][kind]=[list(r)for r in rows]
                db.rollback()
            finally:db.close()
            current=database.lstat()
            need(tuple(ident(before)[i]for i in (0,1,3,4,5,6))
                 ==tuple(ident(os.fstat(fd))[i]for i in (0,1,3,4,5,6))
                 ==tuple(ident(current)[i]for i in (0,1,3,4,5,6)),'source_database_identity_changed')
            document['sourceMetadata']=list(ident(before))
            document['sourceSidecars']=sidecars
            document['readContract']={'mode':'ro + query_only + BEGIN','sourceMountReadOnly':True,
              'walHonored':True,'completeAuthTablesOnly':True}
            documents.append(document)
        finally:os.close(fd)
    return documents,cfg

def primary(document,kind,default):
    rows=[r for r in document['rows'][kind]if r[0]=='primary']
    need(len(rows)<=1,'duplicate_primary_row')
    return json.loads(rows[0][1])if rows else copy.deepcopy(default)

def restore_registry(state,registry,registry_schema):
    target=state/'state';target.mkdir(mode=0o700)
    db=sqlite3.connect(target/'openclaw.sqlite')
    try:
        db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
        db.execute(registry_schema)
        db.execute('INSERT INTO installed_plugin_index ('+','.join(registry['columns'])+') VALUES ('+
                   ','.join('?'for _ in registry['columns'])+')',registry['row'])
        db.commit()
    finally:db.close()
    (target/'openclaw.sqlite').chmod(0o600)

def bounded_node(node,consumer,plan,env,seconds):
    process=subprocess.Popen([node,str(consumer),str(plan)],env=env,stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    try:
        out,err=process.communicate(timeout=seconds)
        return process.returncode,out,err,False
    except subprocess.TimeoutExpired:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=process.communicate(timeout=5)
        return process.returncode,out,err,True

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('project-root','work-dir','binary','build-result','native-receipt','prepare','consumer'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--scenario',choices=('full-current-baseline','missing-current-ordinal5-recovery'),required=True)
    parser.add_argument('--node',default='/usr/bin/node');parser.add_argument('--parent-netns-inode',type=int,required=True)
    args=parser.parse_args();os.umask(0o077);root=args.work_dir;root.mkdir(mode=0o700);(root/'tmp').mkdir(mode=0o700)
    live=Path('/home/alex/.openclaw');sdk=Path('/home/alex/.npm-global/lib/node_modules/openclaw')
    live_plugin=live/'extensions/openclaw-authbus'
    report={'schema':'heptabao.pocket-current-native-core.v1','ok':False,'host':'pocket4',
      'sourceCommit':COMMIT,'sourceTree':TREE,'fixtureScenario':args.scenario,'checks':[],'phases':[],
      'startedUnixMs':int(time.time()*1000),'productionChanged':False,'productionTrafficCutover':False,
      'allAccountsQualified':False,'providerNetworkEgress':False,'nativeBackendAttemptCount':None,
      'modelRequestDispatched':False,'j3160Contacted':False,'credentialValuesPublished':False,
      'httpBudgetSeconds':10,'consumerBudgetSeconds':70,'rollbackBudgetSeconds':35,
      'originalGenericConsumerAndReceiptsUnchanged':True,'providerAvailabilityQualified':False,
      'scope':'Actual current main/tg native agent transport. Local login RPC and cold recovery under no provider egress; no model quota or production restart qualification.'}
    server=None;captured=None;prepare=None;plans={};source_pins={};diagnostics=[];secrets_seen=[]
    def check(code,value,**detail):
        report['checks'].append({'case':code,'passed':bool(value),**detail});need(value,code)
    def rollback_phase(name,entry):
        if entry['rollbackAttempted']:
            return
        entry['rollbackAttempted']=True
        work,plan,env=entry['work'],entry['plan'],entry['env']
        checkpoint=Path(plan['candidateOutput'])
        baseline=Path(plan['baselineOutput'])
        if not checkpoint.exists() or not baseline.exists():
            entry['rollbackOutcome']='no_candidate_checkpoint_unknown'
            report['phases'].append({'phase':name+'.rollback','ok':False,'attempted':False,
              'guardConsumed':True,'unknown':True,'reason':'No complete owned candidate custody checkpoint; no assumed state or retry'})
            return
        rollback={**plan,'mode':'rollback','custodyOutput':str(work/'rollback-auth.private.json')}
        path=work/'rollback-plan.private.json'
        try:
            put(path,rollback)
            rc,out,err,timed=bounded_node(args.node,args.consumer,path,env,35)
            put(work/'rollback.stdout.private',out);put(work/'rollback.stderr.private',err);diagnostics.extend((out,err))
            value=json.loads(out)if out else {'ok':False,'error':'rollback_no_public_result'}
            value.update(phase=name+'.rollback',attempted=True,guardConsumed=True,timeout=timed,returncode=rc,retried=False)
            put(work/'rollback-result.public.json',value);report['phases'].append(value)
            entry['rollbackOutcome']='success'if rc==0 and value.get('ok')is True and not timed else 'failed_or_unknown'
        except Exception as error:
            entry['rollbackOutcome']='failed_or_unknown'
            report['phases'].append({'phase':name+'.rollback','ok':False,'attempted':True,'guardConsumed':True,
              'unknown':True,'errorClass':type(error).__name__,'retried':False})
    try:
        own_net=os.stat('/proc/self/ns/net').st_ino
        check('kernel_private_network',own_net!=args.parent_netns_inode and [n for _,n in socket.if_nameindex()]==['lo'])
        check('kernel_production_and_inputs_readonly',all(os.statvfs(p).f_flag&os.ST_RDONLY
              for p in (live,sdk,args.project_root/'source',args.consumer.parent,args.binary.parent,args.prepare.parent))
              and not os.statvfs(root).f_flag&os.ST_RDONLY)
        report['networkIsolation']={'distinctNamespace':True,'onlyLoopback':True}
        build_raw=read_private(args.build_result);native_raw=read_private(args.native_receipt)
        check('normal_receipts_exact',sha(build_raw)==BUILD_SHA and sha(native_raw)==NATIVE_SHA)
        build,native=json.loads(build_raw),json.loads(native_raw)
        check('normal_source_and_binary_identity',build.get('source_commit')==COMMIT and build.get('source_tree')==TREE
          and build.get('build_exit_code')==0 and build.get('normal_default_candidate')is True
          and build.get('source_freeze_verified')is True and native.get('source_commit')==COMMIT
          and native.get('source_tree')==TREE and native.get('binary_sha256')==BINARY_SHA and file_sha(args.binary)==BINARY_SHA)
        report.update(binarySha256=BINARY_SHA,buildReceiptSha256=BUILD_SHA,nativeBuildReceiptSha256=NATIVE_SHA)
        prepare=json.loads(read_private(args.prepare))
        check('reviewed_current_native_prepare',prepare.get('ok')is True and prepare.get('nativeVersion')=='0.144.3'
          and prepare.get('sourceConfigSha256')==CONFIG_SHA and tuple(prepare.get('agents',[]))==AGENTS)
        source_pins=prepare['sourcePins']
        check('all_prepared_source_pins_exact',all(file_sha(p)==h for p,h in source_pins.items()))
        check('consumer_review_pin',file_sha(args.consumer)==prepare['consumerSha256'])
        check('native_binary_pin',file_sha(prepare['nativeBinary']['path'])==prepare['nativeBinary']['sha256'])
        manifest_path=args.project_root/'original-core-helper-pins.public.json'
        helpers=json.loads(read_private(manifest_path))
        check('original_qa_helper_pins_exact',all(file_sha(args.project_root/r['relative'])==r['sha256']for r in helpers['files']))
        captured,original_cfg=capture_sources(live)
        for document in captured:put(root/(document['agent']+'-source-auth.private.json'),document)
        main_source=next(d for d in captured if d['agent']=='main')
        tg_source=next(d for d in captured if d['agent']=='tg8687951891')
        original_store=primary(main_source,'store',{});original_state=primary(main_source,'state',{})
        profiles=original_store['profiles'];ids=list(profiles)
        check('exact_current_five_identities',len(ids)==5 and len(original_state.get('order',{}).get('openai',[]))==1)
        selected_id=original_state['order']['openai'][0];credential=profiles[selected_id]
        check('exact_current_ordinal5_generation',ids.index(selected_id)==4 and sha(selected_id.encode())==PROFILE_ID_SHA
          and digest(credential)==CREDENTIAL_SHA and sha(credential['accountId'].encode())==ACCOUNT_SHA
          and sha(credential['access'].encode())==ACCESS_SHA and credential.get('provider')=='openai' and credential.get('type')=='oauth')
        claims=json.loads(base64.urlsafe_b64decode(credential['access'].split('.')[1]+'==='))
        check('current_identity_jwt_bound_without_provider_claim',
          claims['https://api.openai.com/auth']['chatgpt_account_id']==credential['accountId']
          and claims['exp']>time.time()+900 and bool(credential.get('refresh')))
        tg_local=primary(tg_source,'store',{})
        check('current_tg_profile_free_raw_source_exact',isinstance(tg_local.get('profiles'),dict)
          and not tg_local['profiles'] and digest(tg_source['rows'])=='76f1ceb53832209d67692c17ba4967df8fa0114f2365989fa5a8c963b095c4e6')
        report['tgSourceRawShape']={'storeRows':len(tg_source['rows']['store']),'stateRows':len(tg_source['rows']['state']),
          'localProfiles':0,'completeRowsSha256':digest(tg_source['rows']),'originalRowsAndTimestampsPreserved':True}
        check('current_usage_not_cleared',original_state.get('usageStats',{})=={})
        for pid,c in profiles.items():
            secrets_seen.append(pid)
            secrets_seen.extend(v for k,v in c.items()if isinstance(v,str)and len(v)>=8
                                and k not in ('provider','type','chatgptPlanType'))
        report['currentSource']={'localProfileOrdinal':5,'profileIdSha256':PROFILE_ID_SHA,
          'accountSha256':ACCOUNT_SHA,'credentialSha256':CREDENTIAL_SHA,'accessSha256':ACCESS_SHA,
          'mainSourceProfileCount':5,'tgSourceProfileCount':0,'tgEffectiveInheritanceProvedBySelectorReceipt':
          '79e232c4282796ffb07c174fbc32c5e4a4cb5f87167ec42851fd042cc8a8f3ea',
          'sourceAuthTableSha256':{d['agent']:digest(d['rows'])for d in captured},
          'priorProviderProofReused':False,'freshProviderProofObtained':False}
        qa=args.project_root/'source/qa/openbao-acceptance';sys.path.insert(0,str(qa))
        spec=importlib.util.spec_from_file_location('current_native_materialize',qa/'authbus_current_credential_stage.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        plugin=root/'installed-plugin-copy';plugin.mkdir(mode=0o700)
        for name in PLUGIN_FILES:
            raw=(live_plugin/name).read_bytes();put(plugin/name,raw)
            need(sha(raw)==source_pins[str(live_plugin/name)],'installed_plugin_changed')
        (plugin/'node_modules').mkdir(mode=0o700);(plugin/'node_modules/openclaw').symlink_to(sdk)
        registry=json.loads(read_private(prepare['registryCapturePath']))
        check('registry_capture_exact',file_sha(prepare['registryCapturePath'])==prepare['registryCaptureSha256'])
        server=smoke.Instance(args.binary,root/'server')
        server_cfg=json.loads((server.root/'server.json').read_bytes())
        server_cfg['storage']={'native_v6_file':{'path':server_cfg['data_dir']}}
        (server.root/'server.json').write_bytes(encoded(server_cfg));server.start()
        def call(name,method,route,body=None,token=None,expected=200):
            status,value=server.call(method,route,body,token=token);check(name,status==expected,status=status);return value
        init=call('initialize','POST','sys/init',{'secret_shares':1,'secret_threshold':1},token='')
        server.token,unseal=init['root_token'],init['keys_base64'][0]
        secrets_seen.extend((server.token,unseal));put(root/'recovery.private.json',{'rootToken':server.token,'unsealKey':unseal})
        call('unseal','POST','sys/unseal',{'key':unseal},token='')
        call('kv2_mount','POST','sys/mounts/openclaw-auth',{'type':'kv','options':{'version':'2'}},expected=204)
        call('approle_mount','POST','sys/auth/approle',{'type':'approle'},expected=204)
        call('formal_activation','POST','sys/storage/native-v6/activate',{},expected=204)
        check('formal_format2',call('capacity','GET','sys/internal/capacity')['data']['native_kv2_reader_format']==2)
        identity=digest({k:credential.get(k)for k in ('provider','type','email','accountId','projectId')})
        profile_key='sha256-'+CREDENTIAL_SHA
        payload={'schemaVersion':1,'profileId':selected_id,'credential':credential,'digest':CREDENTIAL_SHA,'identity':identity}
        entry={k:v for k,v in payload.items()if k not in ('credential','schemaVersion')}
        entry.update(key=profile_key,provider='openai',type='oauth',expires=credential['expires'],quarantined=False,status='active')
        for name,value in [('profiles/'+profile_key,payload),
             ('order-policy',{'schemaVersion':1,'generation':1,'providers':{}}),
             ('scheduler-assignments',{'schemaVersion':1,'generation':1,'assignments':[]}),
             ('manifest',{'schemaVersion':1,'generation':1,'profiles':[entry]})]:
            call('publish.'+name.split('/')[0],'POST','openclaw-auth/data/'+name,{'data':value,'options':{'cas':0}})
        host_id='pocket4-current-native-canary'
        policy='\n'.join('path "openclaw-auth/data/'+name+'" { capabilities=["read"] }'
          for name in ('manifest','order-policy','scheduler-assignments','profiles/'+profile_key))
        policy+='\npath "openclaw-auth/data/inbox/'+host_id+'/*" { capabilities=["create","update"] }\n'
        policy+='\n'.join('path "auth/token/'+name+'" { capabilities=["'+verb+'"] }'
          for name,verb in [('lookup-self','read'),('renew-self','update'),('revoke-self','update')])
        role_name='pocket4-current-native'
        call('consumer.policy','PUT','sys/policies/acl/'+role_name,{'policy':policy},expected=204)
        route='auth/approle/role/'+role_name
        call('consumer.role','POST',route,{'token_policies':[role_name],'token_ttl':'180s','token_max_ttl':'600s',
          'secret_id_ttl':'1200s','secret_id_num_uses':0},expected=204)
        role=call('consumer.role_id','GET',route+'/role-id')['data']['role_id']
        secret=call('consumer.secret_id','POST',route+'/secret-id',{})['data']['secret_id'];secrets_seen.extend((role,secret))
        credentials=root/'credentials-consumer';credentials.mkdir(mode=0o700)
        put(credentials/'role_id',role.encode());put(credentials/'secret_id',secret.encode())
        put(credentials/'ca.crt',(server.root/'ca.crt').read_bytes())
        plugin_config={'address':server.address,'caFile':str(credentials/'ca.crt'),'roleIdFile':str(credentials/'role_id'),
          'secretIdFile':str(credentials/'secret_id'),'hostId':host_id,'leader':False,'publishNew':False,'manageOrder':True,
          'schedulerMode':'shadow','pollIntervalMs':300000,'maxRefreshesPerCycle':1}
        managed={'schemaVersion':1,'generation':2,'providers':{'openai':{'candidates':[{
          'profileId':selected_id,'digest':CREDENTIAL_SHA,'enrolledAt':int(time.time()*1000)}],
          'activeProfile':selected_id,'enforceManagedOrder':True}}}
        call('publish.current_order','POST','openclaw-auth/data/order-policy',{'data':managed,'options':{'cas':1}})
        def consumer_phase(name):
            work=root/('consumer-'+name);work.mkdir(mode=0o700);state=work/'state'
            documents=copy.deepcopy(captured)
            if args.scenario=='missing-current-ordinal5-recovery':
                row=next(r for d in documents if d['agent']=='main'for r in d['rows']['store']if r[0]=='primary')
                fixture_store=json.loads(row[1]);removed=fixture_store['profiles'].pop(selected_id)
                need(digest(removed)==CREDENTIAL_SHA,'missing_fixture_removed_only_current_credential')
                row[1]=encoded(fixture_store).decode()
            helper.materialize(state,documents)
            cfg=copy.deepcopy(original_cfg)
            workspace=work/'workspace';workspace.mkdir(mode=0o700)
            for agent in cfg['agents']['list']:
                agent['agentDir']=str(state/'agents'/agent['id']/'agent')
                if 'workspace'in agent:agent['workspace']=str(workspace/agent['id'])
            if 'workspace'in cfg.get('agents',{}).get('defaults',{}):cfg['agents']['defaults']['workspace']=str(workspace)
            cfg['plugins']['entries']['openclaw-authbus']['config']=copy.deepcopy(plugin_config)
            (state/'openclaw.json').write_bytes(encoded(cfg));(state/'home').mkdir(mode=0o700)
            restore_registry(state,registry,prepare['registrySchema'])
            consumer_pins={**source_pins,str(args.consumer):file_sha(args.consumer),
              str(Path(__file__)):file_sha(__file__),str(state/'openclaw.json'):file_sha(state/'openclaw.json')}
            for p in plugin.iterdir():
                if p.is_file():consumer_pins[str(p)]=file_sha(p)
            plan={'mode':'initial','fixtureScenario':args.scenario,'workRoot':str(root),'stateRoot':str(state),
              'sdkRoot':str(sdk),'pluginEntry':str(plugin/'index.js'),'pluginConfig':plugin_config,
              'expectedProfileId':selected_id,'expectedAccountId':credential['accountId'],
              'expectedCredentialSha256':CREDENTIAL_SHA,'expectedFullProfilesSha256':digest(profiles),
              'expectedProfileKey':profile_key,'serverCertificateSha256':cert_sha256(server.root/'tls.crt'),
              'model':{'id':'gpt-5.6-sol','provider':'openai','api':'openai-chatgpt-responses'},
              'sourcePins':consumer_pins,'selectionOutput':str(work/'runtime-selection.private.json'),
              'baselineOutput':str(work/'baseline-stores.private.json'),'candidateOutput':str(work/'candidate-stores.private.json'),
              'custodyOutput':str(work/'auth.private.json'),'nativePluginRoot':prepare['nativePluginRoot'],
              'nativeManagedCommand':prepare['nativeManagedCommand'],'nativeVersion':prepare['nativeVersion'],
              'sourceUserHome':'/home/alex','nativeWorkspace':str(workspace),
              'enabledHarnessOwnersPlusOpenai':prepare['enabledHarnessOwnersPlusOpenai']}
            path=work/'plan.private.json';put(path,plan)
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','TMPDIR':str(root/'tmp'),'HOME':'/home/alex',
              'OPENCLAW_STATE_DIR':str(state),'OPENCLAW_CONFIG_PATH':str(state/'openclaw.json'),
              'OPENCLAW_OAUTH_DIR':str(state/'oauth'),'OPENCLAW_HOME':str(state/'home')}
            plans[name]={'work':work,'plan':plan,'env':env,'rollbackAttempted':False,'rollbackOutcome':None}
            rc,out,err,timed=bounded_node(args.node,args.consumer,path,env,70)
            put(work/'stdout.private',out);put(work/'stderr.private',err);diagnostics.extend((out,err))
            value=json.loads(out)if out else {'ok':False,'error':'consumer_no_public_result'}
            value.update(phase=name,returncode=rc,timeout=timed);put(work/'result.public.json',value)
            report['phases'].append(value)
            check('consumer.'+name,rc==0 and value.get('ok')is True and not timed
                  and value.get('actualNativeFactoryQualified')is True and value.get('ownedNativeProcessesStopped')is True)
            return work
        first=consumer_phase('initial')
        tokens=json.loads(read_private(first/'auth.private.json'))['tokens'];check('real_approle_token_captured',len(tokens)==1)
        token=tokens[0];secrets_seen.append(token)
        call('policy_denies_unassigned','GET','openclaw-auth/data/profiles/unassigned',token=token,expected=403)
        call('real_token_renew','POST','auth/token/renew-self',{},token=token)
        call('real_token_revoke','POST','auth/token/revoke-self',{},token=token,expected=204)
        call('revoked_token_rejected','GET','openclaw-auth/data/manifest',token=token,expected=403)
        selected=json.loads(read_private(first/'runtime-selection.private.json'))
        check('current_generation_consumed_after_real_import',
          selected['credential']==credential and selected['credentialSha256']==CREDENTIAL_SHA
          and selected['source']=='actual_installed_authbus_then_actual_default_native_agent_factories')
        process=server.process;server.stop();check('actual_sigkill_and_wait',process.returncode==-9)
        server.start();call('cold_starts_sealed','GET','sys/health',expected=503)
        call('cold_unseal','POST','sys/unseal',{'key':unseal},token='')
        consumer_phase('cold-new-process')
        for name,entry in plans.items():rollback_phase(name,entry)
        check('all_rollback_guards_succeeded_once',all(e['rollbackAttempted']and e['rollbackOutcome']=='success'for e in plans.values()))
        after,_=capture_sources(live)
        check('both_production_auth_tables_unchanged',all(a['agent']==b['agent']and a['rows']==b['rows']for a,b in zip(captured,after)))
        check('all_source_pins_unchanged',all(file_sha(p)==h for p,h in source_pins.items()))
        check('normal_binary_unchanged',file_sha(args.binary)==BINARY_SHA)
        check('native_binary_unchanged',file_sha(prepare['nativeBinary']['path'])==prepare['nativeBinary']['sha256'])
        disk=[p for p in (server.root/'data').rglob('*')if p.is_file()]
        check('formal_server_disk_no_provider_plaintext',bool(disk)and all(
          all(credential[k].encode()not in p.read_bytes()for k in ('access','refresh'))for p in disk))
        diagnostics.extend(((server.root/'server.log').read_bytes(),encoded(report)))
        check('public_diagnostics_no_credential_values',all(all(s.encode()not in item for s in secrets_seen)for item in diagnostics))
        report.update(actualCurrentNativeConsumersQualified=True,actualServerColdRestartQualified=True,
          twoAgentSdkAndRawCasRollbackQualified=True,currentAllIdentitiesOrderUsagePreserved=True,
          missingCurrentCredentialRestored=args.scenario=='missing-current-ordinal5-recovery',ok=True)
    except Exception as error:
        report['error']=str(error)if isinstance(error,Refused)else type(error).__name__
        report['errorClass']=type(error).__name__
        report['errorFrames']=[{'file':Path(f.filename).name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        # Consume each rollback guard at most once; a failed/unknown CAS is never retried.
        for name,entry in plans.items():
            if not entry['rollbackAttempted']:rollback_phase(name,entry)
        report['rollbackGuards']={name:{'attemptedOnce':e['rollbackAttempted'],'outcome':e['rollbackOutcome'],
          'retried':False}for name,e in plans.items()}
        if any(e['rollbackOutcome']!='success'for e in plans.values()):report['ok']=False
        if captured is not None:
            try:
                after,_=capture_sources(live)
                report['sourceAfterFence']={'bothAuthTablesExact':all(a['rows']==b['rows']for a,b in zip(captured,after)),
                  'configExact':file_sha(live/'openclaw.json')==CONFIG_SHA,
                  'metadataObservedUnchanged':all(a['sourceMetadata']==b['sourceMetadata']and a['sourceSidecars']==b['sourceSidecars']for a,b in zip(captured,after)),
                  'kernelSourcesReadOnly':True}
                if not report['sourceAfterFence']['bothAuthTablesExact']or not report['sourceAfterFence']['configExact']:report['ok']=False
            except Exception as error:report['sourceAfterFence']={'ok':False,'errorClass':type(error).__name__};report['ok']=False
        if server is not None and server.process is not None:
            process=server.process
            try:server.stop();report['ownedServerStopped']=process.returncode is not None
            except Exception as error:report['ownedServerStopped']=False;report['cleanupErrorClass']=type(error).__name__;report['ok']=False
        native_phases=[p for p in report['phases']if p.get('phase')in ('initial','cold-new-process')]
        report['ownedNativeProcessesStopped']=(not plans)or (len(native_phases)==len(plans)and all(p.get('ownedNativeProcessesStopped')is True for p in native_phases))
        if not report.get('ownedServerStopped')or not report['ownedNativeProcessesStopped']:report['ok']=False
        report['finishedUnixMs']=int(time.time()*1000)
        if any(s in encoded(report).decode()for s in secrets_seen):
            report={'schema':'heptabao.pocket-current-native-core.v1','ok':False,'error':'public_projection_contains_sensitive_value'}
        put(root/'result.public.json',report)
    print(json.dumps({'ok':report['ok'],'error':report.get('error'),'checks':len(report.get('checks',[])),
                      'path':str(root/'result.public.json'),'sha256':file_sha(root/'result.public.json')}))
    return 0 if report['ok']else 1
if __name__=='__main__':raise SystemExit(main())
