import os,pathlib,json,hashlib,stat,zlib,base64
os.umask(0o077)
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-managed2-61ff8bef-r1');control=root/'control';work=root/'resolve-r1'
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and s.st_nlink==1 and s.st_mode&0o077==0 and s.st_size<=1048576;b=f.read()
 return b
def put(p,v):
 b=json.dumps(v,sort_keys=True,separators=(',',':')).encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
 return sha(b)
sb=read(control/'resolve-stage.public.json');assert sha(sb)=='740e79d7da02834481c08840eb8a7b59045e325f53db2b61dec9986e4cd8fa7b';stage=json.loads(sb)
for p,h in stage['pins'].items():assert sha(pathlib.Path(p).read_bytes())==h
ob=read(work/'outer-result.public.json');assert sha(ob)=='c58636c0e3fd31337c2fa8cc6cb65ebe89aa5ffae60052c92770ddcf78a84c08';outer=json.loads(ob)
assert outer['ok']and outer['returnCode']==0 and outer['sourcePinsUnchanged']and outer['productionUnitUnchanged']and outer['ownedNamespaceProcessExited']and outer['requestCount']==0 and not outer['providerOutcomeUnknown'] and not outer['timedOut']
cb=read(work/'result.public.json');assert sha(cb)==outer['resultSha256'];core=json.loads(cb)
assert core['ok']and core['actualCurrentSdkExplicitSelectionQualified']and core['unexpectedOperations']==0 and core['sourceBinding']['credentialSha256']=='131b8515d48433365dd84555e7659297d4d62de631f9a526a8a4293f03396175'
selected=read(work/'selection.private.json');assert sha(selected)==core['selectionSha256'];selection=json.loads(selected)
assert selection['source']=='actual_installed_sdk_explicit_profile_resolver_current_source_no_authbus_migration_claim' and selection['resolvedApiKey']==selection['credential']['access']
pins=dict(stage['pins'])
for p in [work/'result.public.json',work/'outer-result.public.json',work/'selection.private.json']:pins[str(p)]=sha(read(p))
plan={'caseId':'managed2-r1','sourceKind':'managed-profile2-current-sdk-explicit','work':str(root/'managed2-r1'),'helperSha256':'966efa4778aa7ca0fd23df84870f0b34015a03ff43ab62453e0401b4bd5f329c','selectionFileSha256':sha(selected),'resolverReceiptSha256':sha(cb),'resolverOuterSha256':sha(ob)}
p=control/'managed2-r1.plan.json';pins[str(p)]=put(p,plan)
usage={'schema':'heptabao.current-managed2-single-provider-get-stage.v1','ok':True,'pins':pins,'sourceKind':plan['sourceKind'],'providerCalled':False,'requestsAllowed':1,'noRefresh':True,'noModel':True,'automaticRetry':False,'productionChanged':False,'actualAuthbusMigrationClaimed':False}
h=put(control/'usage-stage.public.json',usage)
public=[]
for rel in ['control/resolve-stage.public.json','control/resolve-r1.plan.json','resolve-r1/result.public.json','resolve-r1/outer-result.public.json','resolve-r1/intent.public.json','control/managed2-r1.plan.json','control/usage-stage.public.json']:
 b=read(root/rel);public.append({'relative':rel,'bytes':len(b),'sha256':sha(b),'text':b.decode()})
raw=json.dumps({'schema':'heptabao.current-managed2-pre-provider-public-capsule.v1','ok':True,'providerCalled':False,'usageStageSha256':h,'selectionFileSha256':sha(selected),'files':public},sort_keys=True,separators=(',',':')).encode();z=zlib.compress(raw,9)
print(json.dumps({'bytes':len(raw),'sha256':sha(raw),'zlibSha256':sha(z),'dataBase64':base64.b64encode(z).decode()},separators=(',',':')))
