#!/usr/bin/env python3
"""Run one typed read-only provider validation in one fresh private writable scope."""
import hashlib,json,os,pathlib,signal,subprocess,sys,time
os.umask(0o077)
ROOT=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-source-61ff8bef-r3')
CONTROL=ROOT/'control'
CASE=sys.argv[1]
assert CASE in ('managed1-r1','native4-r1') and len(sys.argv)==2
WORK=ROOT/CASE
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def put(p,v):
    b=json.dumps(v,sort_keys=True,separators=(',',':')).encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
def units():
    p=subprocess.run(['/usr/bin/systemctl','--user','show','openclaw-gateway.service','--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState','--no-pager'],capture_output=True,text=True,timeout=5)
    assert p.returncode==0
    return dict(s.split('=',1)for s in p.stdout.splitlines()if '='in s)
stage=json.loads((CONTROL/'stage.public.json').read_text())
before={p:sha(p)for p in stage['pins']};assert before==stage['pins']
assert not WORK.exists();WORK.mkdir(mode=0o700);(WORK/'tmp').mkdir(mode=0o700)
plan=CONTROL/(CASE+'.plan.json');planvalue=json.loads(plan.read_text());assert planvalue['work']==str(WORK)
unitbefore=units();assert unitbefore['ActiveState']=='active'
for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NODE_OPTIONS'):
    assert not os.environ.get(k),'unexpected_proxy_or_preload_configuration'
check="import os,sys; assert all(os.statvfs(p).f_flag&os.ST_RDONLY for p in sys.argv[1:4]); assert not os.statvfs(sys.argv[4]).f_flag&os.ST_RDONLY; os.execv('/usr/bin/node',['/usr/bin/node',sys.argv[5],sys.argv[6]])"
argv=['/usr/bin/bwrap','--ro-bind','/','/','--bind',str(WORK),str(WORK),'--proc','/proc','--dev','/dev',
    '--unshare-pid','--die-with-parent','--chdir',str(WORK),'--','/usr/bin/python3','-I','-S','-B','-c',check,
    '/home/qian-qi/.openclaw','/home/qian-qi/.codex',str(CONTROL),str(WORK),str(CONTROL/'fresh_usage_read.mjs'),str(plan)]
put(WORK/'intent.public.json',{'schema':'heptabao.current-source-fresh-usage-intent.v1','caseId':CASE,'sourceKind':planvalue['sourceKind'],
 'argv':argv,'sourcePins':before,'productionUnitBefore':unitbefore,'onlyFreshWorkWritable':True,'privatePidNamespace':True,
 'originalHostNetworkPreserved':True,'fixedSdkOneGetOnly':True,'requestEndpoint':'https://chatgpt.com/backend-api/wham/usage',
 'httpTimeoutMs':15000,'sdkTimeoutMs':18000,'childTimeoutSeconds':35,'automaticRetry':False,'productionChanged':False})
started=time.monotonic();timed=False
with (WORK/'stdout.private').open('xb')as out,(WORK/'stderr.private').open('xb')as err:
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,env={**os.environ,'TMPDIR':str(WORK/'tmp')})
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
path=WORK/'result.public.json';core=json.loads(path.read_text())if path.exists()else None
report={'schema':'heptabao.current-source-fresh-usage-outer.v1','ok':False,'caseId':CASE,'sourceKind':planvalue['sourceKind'],
 'returnCode':rc,'timedOut':timed,'elapsedSeconds':round(time.monotonic()-started,3),'resultSha256':sha(path)if path.exists()else None,
 'sourcePinsUnchanged':before==after,'productionUnitBefore':unitbefore,'productionUnitAfter':unitafter,'productionUnitUnchanged':unitbefore==unitafter,
 'ownedNamespaceProcessExited':p.returncode is not None,'pidNamespaceTeardownEnforced':True,'automaticRetry':False,
 'requestLedgerExists':(WORK/'request-started.public.json').exists(),'providerOutcomeUnknown':core.get('providerOutcomeUnknown',False)if core else True,
 'requestCount':core.get('requestCount')if core else None,'httpStatus':core.get('httpStatus')if core else None,
 'productionChanged':False,'productionTrafficCutover':False,'modelCalled':False,'refreshDispatched':False,
 'stdoutSha256':sha(WORK/'stdout.private'),'stderrSha256':sha(WORK/'stderr.private')}
report['ok']=rc==0 and not timed and core is not None and core['ok']is True and report['sourcePinsUnchanged']and report['productionUnitUnchanged']
put(WORK/'outer-result.public.json',report)
print(json.dumps({'ok':report['ok'],'caseId':CASE,'httpStatus':report['httpStatus'],'requestCount':report['requestCount'],'result':str(WORK/'outer-result.public.json'),'resultSha256':sha(WORK/'outer-result.public.json')}))
raise SystemExit(0 if report['ok']else 1)
