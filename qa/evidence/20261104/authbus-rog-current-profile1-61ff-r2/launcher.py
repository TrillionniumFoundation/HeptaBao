#!/usr/bin/env python3
"""Owned bwrap execution, retaining the reviewed 440/70/35/10-second budgets."""
from pathlib import Path
import hashlib,json,os,signal,subprocess,time
os.umask(0o077)
CONTROL=Path(__file__).resolve().parent
ROOT=CONTROL.parent
RUN=ROOT/'run-r2'
LIVE=Path('/home/qian-qi/.openclaw')
SDK=Path('/home/qian-qi/.npm-global/lib/node_modules/openclaw')
SOURCE=Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/ha-root-pull-response-final-source-r1')
BUILD=SOURCE.parent/'ha-root-pull-response-normal-build-rog-r1'
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def put(p,v):
    b=json.dumps(v,sort_keys=True,separators=(',',':')).encode()
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
def units():
    r=subprocess.run(['/usr/bin/systemctl','--user','show','openclaw-gateway.service','--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState','--no-pager'],capture_output=True,text=True,timeout=5)
    assert r.returncode==0
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
assert ROOT==Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-current-profile1-61ff8bef-r2')
assert not RUN.exists()
stage=json.loads((CONTROL/'stage.public.json').read_bytes())
before={p:sha(p) for p in stage['pins']};assert before==stage['pins']
protected=[LIVE/'openclaw.json',Path('/home/qian-qi/.codex/auth.json'),Path('/home/qian-qi/.codex/config.toml')]
boundaries={str(p):sha(p) for p in protected};unitbefore=units()
RUN.mkdir(mode=0o700)
parentnet=os.stat('/proc/self/ns/net').st_ino
cmd=['/usr/bin/python3','-I','-S','-B',str(CONTROL/'driver.py'),'--work-dir',str(RUN/'live'),'--control',str(CONTROL),'--parent-netns',str(parentnet)]
argv=['/usr/bin/bwrap','--ro-bind','/','/','--bind',str(RUN),str(RUN),
 '--ro-bind',str(LIVE),str(LIVE),'--ro-bind','/home/qian-qi/.codex','/home/qian-qi/.codex',
 '--ro-bind',str(SDK),str(SDK),'--ro-bind',str(SOURCE),str(SOURCE),'--ro-bind',str(BUILD),str(BUILD),
 '--ro-bind',str(CONTROL),str(CONTROL),'--proc','/proc','--dev','/dev','--unshare-net','--unshare-pid','--die-with-parent',
 '--chdir',str(RUN),'--',*cmd]
intent={'schema':'heptabao.rog-current-profile1-isolated-intent.v1','argv':argv,'pinsBefore':before,'protectedInputsBefore':boundaries,
 'productionUnitBefore':unitbefore,'budgets':{'httpSeconds':10,'consumerSeconds':70,'rollbackSeconds':35,'outerSeconds':440},
 'onlyFreshRunWritable':True,'privateNetworkNamespace':True,'privatePidNamespace':True,'providerNetworkEgress':False,'productionChanged':False,'automaticRetry':False}
put(RUN/'intent.public.json',intent)
started=time.monotonic();timed=False
with (RUN/'stdout.private').open('xb') as stdout,(RUN/'stderr.private').open('xb') as stderr:
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/home/qian-qi'},start_new_session=True)
    try:rc=p.wait(timeout=440)
    except subprocess.TimeoutExpired:
        timed=True
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        rc=p.wait(timeout=10)
    finally:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait(timeout=10)
        stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
# Exiting this private PID namespace also kills any detached descendants.
after={x:sha(x) for x in before};protectedafter={str(x):sha(x) for x in protected};unitafter=units()
result=RUN/'live/result.public.json';core=json.loads(result.read_bytes()) if result.exists() else None
report={'schema':'heptabao.rog-current-profile1-isolated-result.v1','ok':False,'returnCode':rc,'timedOut':timed,'outcomeUnknown':timed or core is None,
 'elapsedSeconds':round(time.monotonic()-started,3),'coreResultSha256':sha(result) if core else None,'intentSha256':sha(RUN/'intent.public.json'),
 'coreChecks':len(core.get('checks',[])) if core else 0,'corePassed':sum(x['passed'] is True for x in core.get('checks',[])) if core else 0,
 'ownedNamespaceProcessExited':p.returncode is not None,'pidNamespaceTeardownEnforced':True,
 'ownedServerStopped':core.get('ownedServerStopped') if core else False,'rollbackOutcomes':core.get('rollbackOutcomes') if core else None,
 'productionUnitBefore':unitbefore,'productionUnitAfter':unitafter,'productionUnitUnchanged':unitbefore==unitafter,
 'protectedInputsUnchanged':boundaries==protectedafter,'frozenInputsUnchanged':before==after,
 'productionChanged':False,'productionTrafficCutover':False,'providerCalled':False,'providerAvailabilityQualified':False,
 'productionGatewaySelectionQualified':False,'fullReplacementQualified':False,'automaticRetry':False,
 'stdoutSha256':sha(RUN/'stdout.private'),'stderrSha256':sha(RUN/'stderr.private')}
report['ok']=rc==0 and not timed and core is not None and core.get('ok') is True and report['productionUnitUnchanged'] and report['protectedInputsUnchanged'] and report['frozenInputsUnchanged'] and report['ownedServerStopped'] is True
put(RUN/'execution.result.public.json',report)
print(json.dumps({'ok':report['ok'],'result':str(RUN/'execution.result.public.json'),'sha256':sha(RUN/'execution.result.public.json'),'coreChecks':report['coreChecks'],'corePassed':report['corePassed'],'ownedServerStopped':report['ownedServerStopped'],'error':core.get('error') if core else None}))
raise SystemExit(0 if report['ok'] else 1)
