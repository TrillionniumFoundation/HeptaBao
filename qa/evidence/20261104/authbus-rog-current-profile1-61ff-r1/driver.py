#!/usr/bin/env python3
"""ROG current profile 1: normal KV, original SDK explicit selection and rollback.
The launcher must provide a private network/PID namespace and read-only live roots.
No default-provider/order/exclusion override, provider call or refresh is permitted.
"""
from __future__ import annotations
import argparse,base64,copy,hashlib,importlib.util,json,os,signal,socket,sqlite3,stat,subprocess,sys,time,traceback
from pathlib import Path
COMMIT='33cafa4c6e29f0bde1553e041550d21b4c725d9c'
TREE='cdc2376e7b39c1d8bbbeb10a813d58bfe923f336'
BINSHA='7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba'
CONFIGSHA='a042bc7fba4ac1295e323e0112598972a2872a040c5464af9614e4c2e600bd15'
CREDENTIALSHA='bca88c7adde84057871fd63f202e6aba80d453a04f75151df1d29f269dfaa5f1'
PROOFSHA='3050622c35bacb53ac47f532d4d5230c7c5c68bd2db243376c3c27385744a878'
LIVE=Path('/home/qian-qi/.openclaw')
SDK=Path('/home/qian-qi/.npm-global/lib/node_modules/openclaw')
SOURCE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/ha-root-pull-response-final-source-r1')
BUILD=SOURCE.parent/'ha-root-pull-response-normal-build-rog-r1'
BINARY=BUILD/'artifacts/heptabao-server'
PLUGIN=('index.js','bad-refresh-quarantine.js','codex-client-recycler.js','lease-assignments.js','order-policy.js','provider-error-classifier.js','runtime-refresh-policy.js','package.json')
TABLES={'store':('auth_profile_store','store_key','store_json'),'state':('auth_profile_state','state_key','state_json')}
class Refused(Exception):pass
def need(ok,code):
    if not ok:raise Refused(code)
def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(v):return hashlib.sha256(enc(v)).hexdigest()
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def put(p,v):
    b=v if isinstance(v,bytes) else enc(v)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def private(p):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and not stat.S_IMODE(s.st_mode)&0o077 and s.st_size<=2097152,'private_input_custody')
        b=os.read(fd,2097153);t=os.fstat(fd);u=Path(p).lstat()
        ident=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_uid,x.st_mode,x.st_mtime_ns,x.st_ctime_ns)
        need(ident(s)==ident(t)==ident(u) and len(b)==s.st_size,'private_input_changed');return b
    finally:os.close(fd)
def capture():
    need(sha(LIVE/'openclaw.json')==CONFIGSHA,'production_configuration_changed')
    cfg=json.loads(private(LIVE/'openclaw.json'))
    mains=[a for a in cfg['agents']['list'] if a.get('id')=='main']
    directory=LIVE/'agents/main/agent'
    need(len(mains)==1 and Path(mains[0].get('agentDir',directory))==directory,'actual_main_directory_changed')
    for parent in (LIVE,LIVE/'agents',directory.parent,directory):
        s=parent.lstat();need(stat.S_ISDIR(s.st_mode) and not parent.is_symlink() and s.st_uid==os.geteuid() and not stat.S_IMODE(s.st_mode)&0o022,'source_parent_custody')
    path=directory/'openclaw-agent.sqlite';fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    ident=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,'source_database_custody')
        sides={}
        for suffix in ('-wal','-shm'):
            p=Path(str(path)+suffix)
            if p.exists():
                s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and not stat.S_IMODE(s.st_mode)&0o077,'source_sidecar_custody');sides[suffix]=ident(s)
        need('-wal' not in sides or '-shm' in sides,'readonly_wal_requires_shm')
        need(os.statvfs(path).f_flag&os.ST_RDONLY,'source_database_kernel_readonly')
        db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=3)
        try:
            db.execute('PRAGMA query_only=ON');db.execute('PRAGMA temp_store=MEMORY');db.execute('BEGIN')
            doc={'schema':'heptabao.current-rog-main-auth-tables.v1','host':'rog','agent':'main','rows':{},'sourceIdentity':list(ident(before))}
            for k,(table,key,column) in TABLES.items():
                rows=db.execute('SELECT '+key+','+column+',updated_at FROM '+table+' ORDER BY '+key).fetchall()
                need(len(rows)<=32 and all(isinstance(r[1],str) and len(r[1].encode())<=1048576 for r in rows),'auth_rows_bounded')
                doc['rows'][k]=[list(r) for r in rows]
            db.rollback()
        finally:db.close()
        need(ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'source_database_identity_changed')
        for suffix in ('-wal','-shm'):
            p=Path(str(path)+suffix);need(p.exists()==(suffix in sides),'source_sidecar_presence_changed')
            if p.exists():need(ident(p.lstat())==sides[suffix],'source_sidecar_identity_changed')
        return doc,cfg
    finally:os.close(fd)
def primary(doc,kind):
    rows=[r for r in doc['rows'][kind] if r[0]=='primary'];need(len(rows)==1,'primary_auth_row_missing_or_ambiguous');return json.loads(rows[0][1])
def node(consumer,plan,env,seconds):
    p=subprocess.Popen(['/usr/bin/node',str(consumer),str(plan)],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    timed=False
    try:out,err=p.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        timed=True
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        out,err=p.communicate(timeout=5)
    return p.returncode,out,err,timed

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--work-dir',type=Path,required=True);parser.add_argument('--control',type=Path,required=True)
    parser.add_argument('--parent-netns',type=int,required=True);args=parser.parse_args();os.umask(0o077)
    root=args.work_dir;root.mkdir(mode=0o700);(root/'tmp').mkdir(mode=0o700)
    consumer=args.control/'consumer.mjs';proof_path=args.control/'prior-provider-proof.public.json'
    report={'schema':'heptabao.rog-normal33-current-profile1-sdk-recovery.v1','ok':False,'checks':[],'phases':[],
      'sourceCommit':COMMIT,'sourceTree':TREE,'binarySha256':BINSHA,'productionChanged':False,'productionTrafficCutover':False,
      'providerCalled':False,'providerNetworkEgress':False,'refreshDispatched':False,'newLoginAttempted':False,'modelCalled':False,
      'j3160Contacted':False,'accountIdentitiesPublished':False,'credentialValuesPublished':False,'productionGatewaySelectionQualified':False,
      'productionDefaultProfile1Qualified':False,'allAccountsQualified':False,'fullReplacementQualified':False}
    instance=None;plans={};confidential=[];logs=[];source=None
    def check(name,ok,**detail):
        report['checks'].append({'case':name,'passed':bool(ok),**detail});need(ok,name)
    def rollback(name,entry):
        if entry['rollbackAttempted']:return
        entry['rollbackAttempted']=True
        work,plan,env=entry['work'],entry['plan'],entry['env']
        if not Path(plan['selectionOutput']).exists() or not Path(plan['baselineOutput']).exists():
            entry['rollbackOutcome']='no_complete_candidate_unknown';return
        plan={**plan,'mode':'rollback','custodyOutput':str(work/'rollback-auth.private.json')}
        path=work/'rollback-plan.private.json';put(path,plan)
        rc,out,err,timed=node(consumer,path,env,35);put(work/'rollback.stdout.private',out);put(work/'rollback.stderr.private',err);logs.extend((out,err))
        value=json.loads(out) if out else {'ok':False,'error':'empty_rollback_result'}
        value.update(phase=name+'.rollback',returnCode=rc,timedOut=timed,retried=False)
        put(work/'rollback-result.public.json',value);report['phases'].append(value)
        entry['rollbackOutcome']='success' if rc==0 and value.get('ok') is True and not timed else 'failed_or_unknown'
    try:
        check('kernel_private_network',os.stat('/proc/self/ns/net').st_ino!=args.parent_netns and [n for _,n in socket.if_nameindex()]==['lo'])
        check('kernel_production_and_code_readonly',all(os.statvfs(p).f_flag&os.ST_RDONLY for p in (LIVE,SDK,SOURCE,BUILD,args.control)) and not os.statvfs(root).f_flag&os.ST_RDONLY)
        report['networkIsolation']={'privateNetworkNamespace':True,'onlyLoopback':True,'productionKernelReadOnly':True}
        stage=json.loads(private(args.control/'stage.public.json'));pins=stage['pins']
        check('all_frozen_inputs_exact',all(sha(p)==h for p,h in pins.items()))
        build=json.loads(private(BUILD/'result.public.json'))
        check('normal33_build_receipt_and_binary',sha(BUILD/'result.public.json')=='7fa76585e94fe2e60bbc3ce754f37e4d9d433e4cf576fcc2e39a1e95771f3f42'
              and build.get('source_commit')==COMMIT and build.get('source_tree')==TREE and build.get('normal_default_candidate') is True
              and build.get('source_freeze_verified') is True and build.get('build_exit_code')==0 and sha(BINARY)==BINSHA)
        git=lambda *a:subprocess.check_output(['/usr/bin/git','-C',str(SOURCE),*a],text=True,timeout=10).strip()
        check('normal33_helper_source_clean',git('rev-parse','HEAD')==COMMIT and git('rev-parse','HEAD^{tree}')==TREE and git('diff','--name-only')=='' and git('diff','--cached','--name-only')=='')
        proof=json.loads(private(proof_path))
        check('prior_source_provider_proof_pin',sha(proof_path)==PROOFSHA and proof.get('selected_source_sha256')==CREDENTIALSHA
              and proof.get('single_current_credential_provider_validated') is True and proof['provider_read']['httpStatus']==200
              and proof['provider_read']['tlsVerified'] is True and proof['provider_read']['requestCount']==1 and proof['refresh_dispatched'] is False)
        source,cfg=capture();put(root/'source-auth-tables.private.json',source)
        original=primary(source,'store');profiles=original['profiles'];selected_id=list(profiles)[0];credential=profiles[selected_id]
        check('exact_current_profile1_generation',len(profiles)==3 and digest(credential)==CREDENTIALSHA and credential.get('provider')=='openai' and credential.get('type')=='oauth')
        claims=json.loads(base64.urlsafe_b64decode(credential['access'].split('.')[1]+'==='))
        check('current_jwt_account_and_expiry',claims['https://api.openai.com/auth']['chatgpt_account_id']==credential['accountId'] and claims['exp']>time.time()+900 and credential['expires']>time.time()*1000+900000)
        for pid,c in profiles.items():
            confidential.append(pid);confidential.extend(v for k,v in c.items() if isinstance(v,str) and len(v)>=8 and k not in ('provider','type','chatgptPlanType'))
        prod_plugin=cfg['plugins']['entries']['openclaw-authbus']['config'];exclusions=copy.deepcopy(prod_plugin.get('orderExcludeAgentIds',[]))
        report['source']={'database':str(LIVE/'agents/main/agent/openclaw-agent.sqlite'),'profileOrdinal':1,'credentialSha256':CREDENTIALSHA,
          'wholeAuthRowsSha256':digest(source['rows']),'configurationSha256':CONFIGSHA,'authConfigurationSha256':digest(cfg.get('auth',{})),
          'orderExclusionsSha256':digest(exclusions),'authbusConfigurationSha256':digest(cfg['plugins']['entries']['openclaw-authbus']),
          'sourceDefaultModel':cfg['agents']['defaults']['model'],'sourceProfileCount':len(profiles)}
        qa=SOURCE/'qa/openbao-acceptance';sys.path.insert(0,str(qa))
        spec=importlib.util.spec_from_file_location('current_main_materialize',qa/'authbus_current_credential_stage.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        from native_v6_authbus_client_live import smoke
        from cert_auth_live import cert_sha256
        plugin=root/'installed-plugin-copy';plugin.mkdir(mode=0o700)
        sourcepins={str(consumer):sha(consumer)}
        for name in PLUGIN:
            p=LIVE/'extensions/openclaw-authbus'/name;b=p.read_bytes();put(plugin/name,b)
            sourcepins[str(p)]=sourcepins[str(plugin/name)]=hashlib.sha256(b).hexdigest()
        (plugin/'node_modules').mkdir(mode=0o700);(plugin/'node_modules/openclaw').symlink_to(SDK)
        for p,h in pins.items():
            if str(p).startswith(str(SDK)):sourcepins[p]=h
        report['consumerSourcePins']=sourcepins
        instance=smoke.Instance(BINARY,root/'server');servercfg=json.loads((instance.root/'server.json').read_bytes())
        servercfg['storage']={'native_v6_file':{'path':servercfg['data_dir']}};(instance.root/'server.json').write_bytes(enc(servercfg));instance.start()
        def call(name,method,route,body=None,token=None,expected=200):
            status,value=instance.call(method,route,body,token=token);check(name,status==expected,status=status);return value
        init=call('initialize','POST','sys/init',{'secret_shares':1,'secret_threshold':1},token='')
        instance.token,unseal=init['root_token'],init['keys_base64'][0];confidential.extend((instance.token,unseal));put(root/'recovery.private.json',{'rootToken':instance.token,'unsealKey':unseal})
        call('unseal','POST','sys/unseal',{'key':unseal},token='');call('kv2_mount','POST','sys/mounts/openclaw-auth',{'type':'kv','options':{'version':'2'}},expected=204)
        call('approle_mount','POST','sys/auth/approle',{'type':'approle'},expected=204);call('formal_activation','POST','sys/storage/native-v6/activate',{},expected=204)
        check('formal_format2',call('capacity','GET','sys/internal/capacity')['data']['native_kv2_reader_format']==2)
        identity=digest({k:credential.get(k) for k in ('provider','type','email','accountId','projectId')});key='sha256-'+CREDENTIALSHA
        payload={'schemaVersion':1,'profileId':selected_id,'credential':credential,'digest':CREDENTIALSHA,'identity':identity}
        entry={k:v for k,v in payload.items() if k not in ('credential','schemaVersion')};entry.update(key=key,provider='openai',type='oauth',expires=credential['expires'],quarantined=False,status='active')
        documents={'profiles/'+key:payload,'order-policy':{'schemaVersion':1,'generation':1,'providers':{}},
          'scheduler-assignments':{'schemaVersion':1,'generation':1,'assignments':[]},'manifest':{'schemaVersion':1,'generation':1,'profiles':[entry]}}
        for name,data in documents.items():call('publish.'+name.split('/')[0],'POST','openclaw-auth/data/'+name,{'data':data,'options':{'cas':0}})
        policy='\n'.join('path "openclaw-auth/data/'+name+'" { capabilities=["read"] }' for name in documents)
        policy+='\npath "openclaw-auth/data/inbox/rog-current-profile1/*" { capabilities=["create","update"] }\n'
        policy+='\n'.join('path "auth/token/'+n+'" { capabilities=["'+v+'"] }' for n,v in [('lookup-self','read'),('renew-self','update'),('revoke-self','update')])
        role_name='rog-current-profile1-consumer';route='auth/approle/role/'+role_name
        call('consumer.policy','PUT','sys/policies/acl/'+role_name,{'policy':policy},expected=204)
        call('consumer.role','POST',route,{'token_policies':[role_name],'token_ttl':'180s','token_max_ttl':'600s','secret_id_ttl':'1200s','secret_id_num_uses':0},expected=204)
        role=call('consumer.role_id','GET',route+'/role-id')['data']['role_id'];secret=call('consumer.secret_id','POST',route+'/secret-id',{})['data']['secret_id'];confidential.extend((role,secret))
        credentials=root/'credentials';credentials.mkdir(mode=0o700);put(credentials/'role_id',role.encode());put(credentials/'secret_id',secret.encode());put(credentials/'ca.crt',(instance.root/'ca.crt').read_bytes())
        pluginconfig={'address':instance.address,'caFile':str(credentials/'ca.crt'),'roleIdFile':str(credentials/'role_id'),'secretIdFile':str(credentials/'secret_id'),
          'hostId':'rog-current-profile1','leader':False,'publishNew':False,'manageOrder':True,'orderExcludeAgentIds':exclusions,
          'schedulerMode':'shadow','pollIntervalMs':300000,'maxRefreshesPerCycle':1}
        def consume(name):
            work=root/('consumer-'+name);work.mkdir(mode=0o700);state=work/'state';helper.materialize(state,[copy.deepcopy(source)])
            privatecfg={'agents':{'defaults':copy.deepcopy(cfg['agents']['defaults']),'list':[{'id':'main','agentDir':str(state/'agents/main/agent')}]},
              'auth':copy.deepcopy(cfg.get('auth',{})),'models':copy.deepcopy(cfg.get('models',{}))}
            (state/'openclaw.json').write_bytes(enc(privatecfg));(state/'home').mkdir(mode=0o700)
            plan={'mode':'initial','workRoot':str(root),'stateRoot':str(state),'sdkRoot':str(SDK),'pluginEntry':str(plugin/'index.js'),'pluginConfig':pluginconfig,
              'expectedProfileId':selected_id,'expectedAccountId':credential['accountId'],'expectedCredentialSha256':CREDENTIALSHA,'expectedProfileKey':key,
              'serverCertificateSha256':cert_sha256(instance.root/'tls.crt'),'model':cfg['agents']['defaults']['model'],
              'sourcePins':sourcepins,'sourceAuthConfigSha256':digest(privatecfg['auth']),'sourceModelsConfigSha256':digest(privatecfg['models']),
              'sourceDefaultModelSha256':digest(cfg['agents']['defaults']['model']),'sourceOrderExclusionsSha256':digest(exclusions),
              'selectionOutput':str(work/'runtime-selection.private.json'),'baselineOutput':str(work/'baseline-store.private.json'),'custodyOutput':str(work/'auth.private.json')}
            path=work/'plan.private.json';put(path,plan)
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(state/'home'),'TMPDIR':str(root/'tmp'),'OPENCLAW_STATE_DIR':str(state),
              'OPENCLAW_CONFIG_PATH':str(state/'openclaw.json'),'OPENCLAW_OAUTH_DIR':str(state/'oauth'),'OPENCLAW_HOME':str(state/'home')}
            plans[name]={'work':work,'plan':plan,'env':env,'rollbackAttempted':False}
            rc,out,err,timed=node(consumer,path,env,70);put(work/'stdout.private',out);put(work/'stderr.private',err);logs.extend((out,err))
            result=json.loads(out) if out else {'ok':False,'error':'empty_consumer_result'};result.update(phase=name,returnCode=rc,timedOut=timed)
            put(work/'result.public.json',result);report['phases'].append(result)
            check('consumer.'+name,rc==0 and result.get('ok') is True and not timed)
            selection=json.loads(private(work/'runtime-selection.private.json'))
            check('consumer.'+name+'.exact_provider_proof_binding',selection['source']=='actual_installed_sdk_explicit_profile_resolver_after_actual_authbus_recovery'
              and selection['credential']==credential and selection['resolvedApiKey']==credential['access'] and selection['credentialSha256']==CREDENTIALSHA)
            tokens=json.loads(private(work/'auth.private.json'))['tokens'];check('consumer.'+name+'.actual_approle',len(tokens)==1);confidential.extend(tokens)
            token=tokens[0];call(name+'.unassigned_denied','GET','openclaw-auth/data/profiles/unassigned',token=token,expected=403)
            call(name+'.renew','POST','auth/token/renew-self',{},token=token);call(name+'.revoke','POST','auth/token/revoke-self',{},token=token,expected=204)
            call(name+'.revoked_denied','GET','openclaw-auth/data/manifest',token=token,expected=403)
        consume('initial')
        originalprocess=instance.process;instance.stop();check('actual_sigkill_waited',originalprocess.returncode==-9)
        instance.start();call('cold_sealed','GET','sys/health',expected=503);call('cold_unseal','POST','sys/unseal',{'key':unseal},token='')
        consume('cold-new-process')
        for name,entry in plans.items():rollback(name,entry);check('rollback.'+name,entry.get('rollbackOutcome')=='success')
        fresh,freshcfg=capture()
        check('production_credential_store_unchanged',source['rows']['store']==fresh['rows']['store'])
        check('production_complete_auth_rows_unchanged',source['rows']==fresh['rows'])
        check('production_configuration_order_exclusions_unchanged',cfg==freshcfg and sha(LIVE/'openclaw.json')==CONFIGSHA)
        check('all_frozen_inputs_unchanged',all(sha(p)==h for p,h in pins.items()))
        disk=[p for p in (instance.root/'data').rglob('*') if p.is_file()]
        check('encrypted_storage_no_source_credentials',bool(disk) and all(all(s.encode() not in p.read_bytes() for s in confidential if len(s)>=8) for p in disk))
        diagnostics=logs+[(instance.root/'server.log').read_bytes(),enc(report)]
        check('public_diagnostics_no_credential_values',all(all(s.encode() not in b for s in confidential if len(s)>=8) for b in diagnostics))
        report['priorProviderLink']={'priorProofSha256':PROOFSHA,'credentialSha256':CREDENTIALSHA,'currentCapturedAndSdkSelectedCredentialExact':True,'freshProviderRequest':False,'scope':'Historical single GET success for exact current ROG source credential; current storage/explicit SDK selection and recovery only.'}
        report.update(ok=True,actualOriginalSdkExplicitProfileQualified=True,actualMissingProfileRecovered=True,originalOrderAndExclusionsPreserved=True,
          actualServerProcessColdRestartQualified=True,privateWholeLogicalStoreRollbackQualified=True,productionGatewaySelectionQualified=False)
    except Exception as error:
        report['error']=str(error) if isinstance(error,Refused) else type(error).__name__
        report['errorFrames']=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-5:]]
    finally:
        for name,entry in plans.items():
            if not entry['rollbackAttempted']:
                try:rollback(name,entry)
                except Exception as error:entry['rollbackOutcome']='cleanup_'+type(error).__name__;report['ok']=False
        report['rollbackOutcomes']={n:e.get('rollbackOutcome','not_attempted') for n,e in plans.items()}
        if any(v!='success' for v in report['rollbackOutcomes'].values()):report['ok']=False
        if instance is not None and instance.process is not None:
            old=instance.process;instance.stop();report['ownedServerStopped']=old.returncode is not None
        put(root/'result.public.json',report)
    print(json.dumps({'ok':report['ok'],'error':report.get('error'),'checks':len(report['checks']),'result':str(root/'result.public.json'),'ownedServerStopped':report.get('ownedServerStopped')}))
    return 0 if report['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
