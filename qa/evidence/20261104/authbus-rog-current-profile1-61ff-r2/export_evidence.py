#!/usr/bin/env python3
"""Export public raw receipts plus a separate read-only source/rollback audit."""
import gzip,hashlib,importlib.util,io,json,os,sqlite3,stat,subprocess,tarfile
from pathlib import Path
ROOT=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-current-profile1-61ff8bef-r2')
CONTROL=ROOT/'control';RUN=ROOT/'run-r2';OUT=ROOT/'evidence-export-r1'
SDK=Path('/home/qian-qi/.npm-global/lib/node_modules/openclaw')
def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(v):return hashlib.sha256(enc(v)).hexdigest()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def put(p,v):
    b=v if isinstance(v,bytes) else enc(v)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def cohort(source,target):
    pins={}
    ident=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_uid,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
    for suffix in ('','-wal','-shm'):
        p=Path(str(source)+suffix)
        if not p.exists():continue
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);assert stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1 and not stat.S_IMODE(before.st_mode)&0o077 and before.st_size<=33554432
            data=b''
            while True:
                b=os.read(fd,1048576)
                if not b:break
                data+=b
            assert ident(before)==ident(os.fstat(fd))==ident(p.lstat()) and len(data)==before.st_size
            pins[suffix]={'identity':list(ident(before)),'sha256':hashlib.sha256(data).hexdigest()};put(Path(str(target)+suffix),data)
        finally:os.close(fd)
    for suffix in ('','-wal','-shm'):
        p=Path(str(source)+suffix);assert p.exists()==(suffix in pins)
        if p.exists():assert list(ident(p.lstat()))==pins[suffix]['identity'] and sha(p)==pins[suffix]['sha256']
    return pins
assert os.statvfs(RUN).f_flag&os.ST_RDONLY and os.statvfs(CONTROL).f_flag&os.ST_RDONLY
assert not os.statvfs(OUT).f_flag&os.ST_RDONLY
assert sha(CONTROL/'driver.py')=='393d5b2a35fe6393665ec5a2fdb56eb5b59dbc0a50879cc8dfa4935ab945a3d2'
assert sha(OUT/'current_sdk_read.mjs')=='30997cac2f2b38a5c43ea85d347bc14c02189005a21059b37a5d50bd6ae7f57e'
spec=importlib.util.spec_from_file_location('fixed_current_profile_driver',CONTROL/'driver.py');driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
original=json.loads(driver.private(RUN/'live/source-auth-tables.private.json'));fresh,cfg=driver.capture()
put(OUT/'source-after.private.json',fresh)
source_audit={'schema':'heptabao.rog-current-profile1-source-second-read.v1','sourceKernelReadOnly':True,'sourceCohortCaptureContractUnchanged':True,
  'wholeRowsBeforeSha256':digest(original['rows']),'wholeRowsAfterSha256':digest(fresh['rows']),
  'storeRowsBeforeSha256':digest(original['rows']['store']),'storeRowsAfterSha256':digest(fresh['rows']['store']),
  'stateRowsBeforeSha256':digest(original['rows']['state']),'stateRowsAfterSha256':digest(fresh['rows']['state']),
  'wholeRowsExact':original['rows']==fresh['rows'],'configurationSha256':sha(driver.LIVE/'openclaw.json'),
  'authConfigSha256':digest(cfg.get('auth',{})),'orderExclusionsSha256':digest(cfg['plugins']['entries']['openclaw-authbus']['config'].get('orderExcludeAgentIds',[])),
  'sourceDefaultModel':cfg['agents']['defaults']['model'],'profile1CredentialSha256':digest(list(driver.primary(fresh,'store')['profiles'].values())[0]),
  'productionChanged':False,'providerCalled':False,'credentialValuesPublished':False}
assert source_audit['wholeRowsExact'] and source_audit['profile1CredentialSha256']==driver.CREDENTIALSHA
put(OUT/'source-second-read.public.json',source_audit)
rollback_audits=[]
for name in ('initial','cold-new-process'):
    src=RUN/'live'/('consumer-'+name);baseline=json.loads(driver.private(src/'baseline-store.private.json'))
    selection=json.loads(driver.private(src/'runtime-selection.private.json'))
    state=OUT/('rollback-'+name);directory=state/'agents/main/agent';directory.mkdir(mode=0o700,parents=True);(state/'oauth').mkdir(mode=0o700);(state/'tmp').mkdir(mode=0o700)
    copied=cohort(src/'state/agents/main/agent/openclaw-agent.sqlite',directory/'openclaw-agent.sqlite')
    originalcfg=json.loads(driver.private(src/'state/openclaw.json'));originalcfg['agents']['list']=[{'id':'main','agentDir':str(directory)}];put(state/'openclaw.json',originalcfg)
    plan={'sdkStoreModule':str(SDK/'dist/store-DH33UrUj.js'),'sdkStoreSha256':'25a5c7075e13b8fb32f498a90e5ee91d93b7e15972b3b74796f1325b5ba98ebf','stateRoot':str(state),'agents':['main']}
    put(state/'read-plan.private.json',plan)
    child=subprocess.run(['/usr/bin/node',str(OUT/'current_sdk_read.mjs'),str(state/'read-plan.private.json')],capture_output=True,timeout=45,
      env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(state),'TMPDIR':str(state/'tmp'),'OPENCLAW_STATE_DIR':str(state),'OPENCLAW_CONFIG_PATH':str(state/'openclaw.json'),'OPENCLAW_OAUTH_DIR':str(state/'oauth'),'OPENCLAW_AUTH_STORE_READONLY':'1'})
    put(state/'stdout.private',child.stdout);put(state/'stderr.private',child.stderr)
    read=json.loads(child.stdout);assert child.returncode==0 and read['ok'] and read['networkOrChildOperationsAttempted']==0
    assert len(read['stores'])==1 and read['stores'][0]['storeSha256']==digest(baseline) and read['stores'][0]['profilesSha256']==digest(baseline['profiles'])
    db=sqlite3.connect((directory/'openclaw-agent.sqlite').as_uri()+'?mode=ro',uri=True)
    try:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        store=json.loads(db.execute("SELECT store_json FROM auth_profile_store WHERE store_key='primary'").fetchone()[0]);metadata=json.loads(db.execute("SELECT state_json FROM auth_profile_state WHERE state_key='primary'").fetchone()[0]);db.rollback()
    finally:db.close()
    beforefields={'profiles':baseline['profiles'],**{k:baseline.get(k) for k in ('order','usageStats','lastGood')}}
    afterfields={'profiles':store['profiles'],**{k:metadata.get(k) for k in ('order','usageStats','lastGood')}}
    fields={k:{'beforeSha256':digest(beforefields[k]),'afterSha256':digest(afterfields[k]),'exact':beforefields[k]==afterfields[k]} for k in beforefields}
    assert all(v['exact'] for v in fields.values())
    audit={'phase':name,'wholeLogicalSdkBeforeSha256':digest(baseline),'wholeLogicalSdkAfterSha256':read['stores'][0]['storeSha256'],
      'wholeLogicalExact':True,'fields':fields,'selectedCredentialSha256':selection['credentialSha256'],
      'selectedResolvedAccessExact':selection['resolvedApiKey']==selection['credential']['access'],'sourceCohortPins':copied,
      'sdkRead':read,'sourceCloneUnchanged':True,'networkOrChildAttempts':0}
    assert audit['selectedCredentialSha256']==driver.CREDENTIALSHA and audit['selectedResolvedAccessExact']
    rollback_audits.append(audit)
put(OUT/'rollback-independent-sdk-read.public.json',{'schema':'heptabao.rog-current-profile1-third-sdk-rollback-read.v1','ok':True,'phases':rollback_audits,'productionChanged':False,'providerCalled':False})
names=['control/stage.public.json','run-r2/intent.public.json','run-r2/execution.result.public.json','run-r2/live/result.public.json',
 'run-r2/live/consumer-initial/result.public.json','run-r2/live/consumer-initial/rollback-result.public.json',
 'run-r2/live/consumer-cold-new-process/result.public.json','run-r2/live/consumer-cold-new-process/rollback-result.public.json',
 'evidence-export-r1/source-second-read.public.json','evidence-export-r1/rollback-independent-sdk-read.public.json']
confidential=[]
for doc in (original,fresh):
    for pid,c in driver.primary(doc,'store')['profiles'].items():
        confidential.append(pid);confidential.extend(v for k,v in c.items() if isinstance(v,str) and len(v)>=8 and k not in ('provider','type','chatgptPlanType'))
files={};manifest={}
for name in names:
    p=ROOT/name;i=p.lstat();assert stat.S_ISREG(i.st_mode) and i.st_uid==os.getuid() and i.st_nlink==1 and not p.is_symlink()
    b=p.read_bytes();json.loads(b);assert all(s.encode() not in b for s in confidential if len(s)>=8)
    files[name]=b;manifest[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
audit={'schema':'heptabao.rog-current-profile1-public-export.v1','files':manifest,'sourceCredentialsAndIdentitiesAbsent':True,
 'sourceSecondReadExact':True,'independentRollbackSdkBothExact':True,'originalR1AndR2FilesUnchanged':True,
 'exporterSha256':sha(__file__),'sdkReaderSha256':sha(OUT/'current_sdk_read.mjs')}
files['export-manifest.public.json']=enc(audit);put(OUT/'export-manifest.public.json',files['export-manifest.public.json'])
buf=io.BytesIO()
with gzip.GzipFile(fileobj=buf,mode='wb',mtime=0) as gz:
    with tarfile.open(fileobj=gz,mode='w') as tf:
        for name,b in files.items():
            info=tarfile.TarInfo(name);info.size=len(b);info.mode=0o600;info.mtime=0;tf.addfile(info,io.BytesIO(b))
archive=buf.getvalue();put(OUT/'complete-public-evidence-r2.tar.gz',archive)
core=json.loads(files['run-r2/live/result.public.json']);outer=json.loads(files['run-r2/execution.result.public.json'])
print(json.dumps({'ok':core['ok'] and outer['ok'],'archiveBytes':len(archive),'archiveSha256':hashlib.sha256(archive).hexdigest(),'files':manifest,
 'coreChecks':len(core['checks']),'phases':[{'phase':p['phase'],'ok':p['ok'],'checks':len(p['checks'])} for p in core['phases']],
 'sourceSecondReadExact':True,'independentRollbackBothExact':True,'productionUnitUnchanged':outer['productionUnitUnchanged'],
 'protectedInputsUnchanged':outer['protectedInputsUnchanged'],'frozenInputsUnchanged':outer['frozenInputsUnchanged'],
 'ownedServerStopped':outer['ownedServerStopped'],'pidNamespaceTeardownEnforced':outer['pidNamespaceTeardownEnforced'],'rollbackOutcomes':outer['rollbackOutcomes']}))
