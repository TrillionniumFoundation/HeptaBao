#!/usr/bin/env python3
"""Launch one current SDK preparation or one provider GET in an exact fresh owned scope."""
import os,pathlib,json,hashlib,subprocess,signal,sys,time
os.umask(0o077)
ROOT=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-managed2-61ff8bef-r1')
CASE=sys.argv[1];assert len(sys.argv)==2 and CASE in ('resolve-r1','managed2-r1')
CONTROL=ROOT/'control';WORK=ROOT/CASE;RESOLVE=CASE=='resolve-r1'
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def put(p,v):
 b=json.dumps(v,sort_keys=True,separators=(',',':')).encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
def units():
 p=subprocess.run(['/usr/bin/systemctl','--user','show','openclaw-gateway.service','--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState','--no-pager'],capture_output=True,text=True,timeout=5)
 assert p.returncode==0;return dict(line.split('=',1)for line in p.stdout.splitlines()if '='in line)
stage=json.loads((CONTROL/('resolve-stage.public.json'if RESOLVE else 'usage-stage.public.json')).read_bytes())
before={p:sha(p)for p in stage['pins']};assert before==stage['pins']
plan=CONTROL/(CASE+'.plan.json');pv=json.loads(plan.read_bytes());assert pv['work']==str(WORK)
assert not WORK.exists();WORK.mkdir(mode=0o700);(WORK/'tmp').mkdir(mode=0o700)
unitbefore=units();assert unitbefore['ActiveState']=='active'
for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NODE_OPTIONS'):assert not os.environ.get(k)
env={**os.environ,'TMPDIR':str(WORK/'tmp')}
if RESOLVE:
 (WORK/'home').mkdir(mode=0o700);state=WORK/'state'
 env.update(HOME=str(WORK/'home'),OPENCLAW_HOME=str(WORK/'home'),OPENCLAW_STATE_DIR=str(state),OPENCLAW_CONFIG_PATH=str(state/'openclaw.json'),OPENCLAW_OAUTH_DIR=str(state/'oauth'))
helper=CONTROL/('resolve_sdk.mjs'if RESOLVE else 'fresh_usage_read.mjs')
check="import os,sys; assert all(os.statvfs(p).f_flag&os.ST_RDONLY for p in sys.argv[1:4]); assert not os.statvfs(sys.argv[4]).f_flag&os.ST_RDONLY; os.execv('/usr/bin/node',['/usr/bin/node',sys.argv[5],sys.argv[6]])"
argv=['/usr/bin/bwrap','--ro-bind','/','/','--bind',str(WORK),str(WORK),'--proc','/proc','--dev','/dev']
if RESOLVE:argv+=['--unshare-net']
argv+=['--unshare-pid','--die-with-parent','--chdir',str(WORK),'--','/usr/bin/python3','-I','-S','-B','-c',check,'/home/qian-qi/.openclaw','/home/qian-qi/.codex',str(CONTROL),str(WORK),str(helper),str(plan)]
put(WORK/'intent.public.json',{'schema':'heptabao.current-managed2-isolated-intent.v1','caseId':CASE,'argv':argv,'sourcePins':before,'productionUnitBefore':unitbefore,'onlyFreshWorkWritable':True,'privatePidNamespace':True,'externalNetworkKernelDenied':RESOLVE,'oneFixedProviderGetAllowed':not RESOLVE,'automaticRetry':False,'sdkRequestAbortMs':18000 if not RESOLVE else None,'socketInactivityTimeoutMs':15000 if not RESOLVE else None,'childTimeoutSeconds':35})
start=time.monotonic();timed=False
with (WORK/'stdout.private').open('xb')as out,(WORK/'stderr.private').open('xb')as err:
 p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,start_new_session=True)
 try:rc=p.wait(timeout=35)
 except subprocess.TimeoutExpired:
  timed=True
  try:os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  rc=p.wait(timeout=5)
 finally:
  if p.poll()is None:
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   p.wait(timeout=5)
  out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
after={x:sha(x)for x in before};unitafter=units()
path=WORK/'result.public.json';core=json.loads(path.read_bytes())if path.exists()else None
r={'schema':'heptabao.current-managed2-outer.v1','ok':rc==0 and not timed and core is not None and core['ok']is True and before==after and unitbefore==unitafter,'caseId':CASE,'returnCode':rc,'timedOut':timed,'elapsedSeconds':round(time.monotonic()-start,3),'resultSha256':sha(path)if core else None,'sourcePinsUnchanged':before==after,'productionUnitBefore':unitbefore,'productionUnitAfter':unitafter,'productionUnitUnchanged':unitbefore==unitafter,'ownedNamespaceProcessExited':p.returncode is not None,'pidNamespaceTeardownEnforced':True,'automaticRetry':False,'productionChanged':False,'productionTrafficCutover':False,'providerOutcomeUnknown':core.get('providerOutcomeUnknown',False)if core else True,'requestCount':core.get('requestCount',0)if core else None,'httpStatus':core.get('httpStatus')if core else None,'stdoutSha256':sha(WORK/'stdout.private'),'stderrSha256':sha(WORK/'stderr.private')}
put(WORK/'outer-result.public.json',r)
print(json.dumps({'ok':r['ok'],'caseId':CASE,'httpStatus':r['httpStatus'],'requestCount':r['requestCount'],'result':str(WORK/'outer-result.public.json'),'resultSha256':sha(WORK/'outer-result.public.json')}))
raise SystemExit(0 if r['ok']else 1)
