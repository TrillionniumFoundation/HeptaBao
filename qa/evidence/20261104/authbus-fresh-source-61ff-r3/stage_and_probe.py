import os,sys,pathlib,json,hashlib
os.umask(0o077)
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-source-61ff8bef-r3');assert not root.exists();raw=sys.stdin.buffer.read(131073);assert len(raw)<=131072;x=json.loads(raw)
assert set(x['files'])=={'fresh_usage_read.mjs','launcher.py'}
sha=lambda b:hashlib.sha256(b).hexdigest()
for n,b in x['files'].items():assert sha(b.encode())==x['filePins'][n]
assert x['filePins']=={'fresh_usage_read.mjs':'3cea30a81a539277a3a344e3e09e6c4742156947b4fb7d821fa3da88edbeffda','launcher.py':'4c2124978cffb3a47354e16a041def306cf7743d6f6a2ff5a90cc2dc2e88ae0f'}
expected={'/home/qian-qi/.npm-global/lib/node_modules/openclaw/dist/tmp-openclaw-dir-uPgNO8da.js':'c12ed50f959d17d9e4ca3e3cce60aa471ee160bdd705035a6d1ed63c47207b23','/home/qian-qi/.openclaw/openclaw.json':'a042bc7fba4ac1295e323e0112598972a2872a040c5464af9614e4c2e600bd15','/home/qian-qi/.codex/auth.json':'f4aee2935351eaa6d56ce99166a0123c3c9e3260ae8737e6d7ad8ce2c8c12b78','/home/qian-qi/.codex/config.toml':'57c13259d009c266c37d1c4578596c0a6236dae3862eccedb3eb74a99084c350','/home/qian-qi/.npm-global/lib/node_modules/openclaw/dist/provider-usage-BxQS-VWA.js':'cab428b63c6e8912f444089e120c95aea4a1d5edf4258c7fd1b20346558d12e6','/usr/bin/node':'fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48','/usr/bin/python3':'52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41','/usr/bin/bwrap':'523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6'}
for p,h in expected.items():assert sha(pathlib.Path(p).read_bytes())==h
r2=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-current-profile1-61ff8bef-r2');sel=r2/'run-r2/live/consumer-cold-new-process/runtime-selection.private.json';s=sel.lstat();assert s.st_uid==os.geteuid()and s.st_nlink==1 and (s.st_mode&0o777)==0o600 and not sel.is_symlink()
selectionsha=sha(sel.read_bytes());expected[str(sel)]=selectionsha
for name,h in [('run-r2/live/result.public.json','ec431072ef6e5ecd7f6f167d54c5aef857d071c97d4a5116eec0d2c9145d3fd7'),('run-r2/execution.result.public.json','c1a3c31b672ad333a609282e055d7773b803f24aa5a8048024cddc59ab6d7f96')]:
 p=r2/name;assert sha(p.read_bytes())==h;expected[str(p)]=h
root.mkdir(mode=0o700);control=root/'control';control.mkdir(mode=0o700)
def put(p,b):
 if not isinstance(b,bytes):b=json.dumps(b,sort_keys=True,separators=(',',':')).encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
 return sha(b)
for n,b in x['files'].items():expected[str(control/n)]=put(control/n,b.encode())
for case,kind in [('managed1-r1','managed-profile1-after-authbus-recovery'),('native4-r1','unmanaged-native-user4')]:
 p=control/(case+'.plan.json');v={'caseId':case,'sourceKind':kind,'work':str(root/case),'helperSha256':x['filePins']['fresh_usage_read.mjs'],'selectionFileSha256':selectionsha};expected[str(p)]=put(p,v)
report={'schema':'heptabao.typed-fresh-source-stage.v1','ok':True,'payloadSha256':sha(raw),'pins':expected,'providerCalled':False,'productionChanged':False,'requestsAllowed':{'managed1-r1':1,'native4-r1':1},'selectedSdkFileSha256':selectionsha}
h=put(control/'stage.public.json',report);print(json.dumps({'ok':True,'stage':str(control/'stage.public.json'),'sha256':h,'pins':len(expected),'selectedSdkFileSha256':selectionsha,'providerCalled':False}))

import subprocess
probe=root/'import-probe-r1';probe.mkdir(mode=0o700);(probe/'tmp').mkdir(mode=0o700)
nodecode="import https from 'node:https';import http from 'node:http';import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';import {pathToFileURL} from 'node:url';import{createHash}from'node:crypto';let phase='patch';const r={schema:'heptabao.sdk-usage-prerequest-diagnostic.v1',providerCalled:false,productionChanged:false,realCredentialUsed:false,networkOperations:0};function deny(){r.networkOperations++;throw Object.assign(new Error('diagnostic_operation_refused'),{safeCode:'diagnostic_operation_refused'})}try{globalThis.fetch=deny;http.request=deny;http.get=deny;https.request=deny;https.get=deny;for(const k of['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork'])cp[k]=deny;syncBuiltinESMExports();phase='import';const sdk=await import(pathToFileURL('/home/qian-qi/.npm-global/lib/node_modules/openclaw/dist/provider-usage-BxQS-VWA.js'));r.importSucceeded=true;phase='call_usage';await sdk.a('heptabao-readonly-diagnostic-not-a-token','heptabao-diagnostic-not-an-account',18000,async(input,init)=>{r.fetchReached=String(input)==='https://chatgpt.com/backend-api/wham/usage'&&init.method==='GET';r.abortSignalPresent=init.signal instanceof AbortSignal;throw Object.assign(new Error('diagnostic_fetch_reached'),{safeCode:'diagnostic_fetch_reached'})});phase='unexpected_return'}catch(e){r.phase=phase;r.errorClass=e.constructor?.name;r.safeCode=e.safeCode??null;r.errorCode=typeof e.code==='string'&&/^[A-Z_]{2,40}$/.test(e.code)?e.code:null;r.messageSha256=createHash('sha256').update(String(e.message)).digest('hex');r.frames=String(e.stack).split('\\n').slice(1,7).map(x=>x.match(/([A-Za-z0-9_.-]+\\.(?:js|mjs)):(\\d+):(\\d+)/)?.slice(1)??['native']);r.messageTerms=Object.fromEntries(['read-only','EROFS','permission','plugin','runtime','snapshot','policy','initialize','header','fetch','Proxy','SQLite','SQLiteError'].map(k=>[k,String(e.message).includes(k)]))}console.log(JSON.stringify(r))"
argv=['/usr/bin/bwrap','--ro-bind','/','/','--bind',str(probe),str(probe),'--proc','/proc','--dev','/dev','--unshare-net','--unshare-pid','--die-with-parent','--','/usr/bin/node','--input-type=module','-e',nodecode]
res=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=10,env={**os.environ,'TMPDIR':str(probe/'tmp')})
put(probe/'stdout.private',res.stdout);put(probe/'stderr.private',res.stderr)
diagnostic=json.loads(res.stdout);diagnostic['returnCode']=res.returncode;diagnostic['privateTmpdir']=str(probe/'tmp');diagnostic['kernelExternalNetworkDenied']=True;diagnostic['onlyProbeWritable']=True;ph=put(probe/'result.public.json',diagnostic)
assert res.returncode==0 and diagnostic.get('importSucceeded')is True and diagnostic.get('fetchReached')is True and diagnostic.get('abortSignalPresent')is True and diagnostic.get('safeCode')=='diagnostic_fetch_reached' and diagnostic.get('networkOperations')==0
print(json.dumps({'ok':True,'prerequestImportAndHeadersValidated':True,'providerCalled':False,'diagnosticSha256':ph}))
