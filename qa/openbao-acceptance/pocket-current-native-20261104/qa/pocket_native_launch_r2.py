#!/usr/bin/env python3
"""One fresh isolated Pocket native scope. No automatic retry and no production mutation."""
from pathlib import Path
import argparse,os,json,hashlib,subprocess,signal,time,sys
os.umask(0o077)
P=Path('/home/alex/heptabao-installed-authbus-consumer-36076-20261104-r1')
parser=argparse.ArgumentParser()
parser.add_argument('--scenario',choices=('full-current-baseline','missing-current-ordinal5-recovery'),required=True)
parser.add_argument('--run-name',required=True)
args=parser.parse_args()
assert args.run_name in ('current-native-full-r2','current-native-missing-r2')
assert (args.scenario=='full-current-baseline')==(args.run_name=='current-native-full-r2')
R=P/args.run_name;R.mkdir(mode=0o700)
I=P/'current-native-inputs-r1';Q=P/'current-native-qa-r3';A=I/'artifacts'
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb')as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 return h.hexdigest()
def put(p,v):
 with p.open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def units():
 q=subprocess.run(['/usr/bin/systemctl','--user','show','openclaw-gateway.service',
  'openclaw-authbus-restart-when-idle.service','--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState',
  '--no-pager'],capture_output=True,text=True,timeout=5)
 assert q.returncode==0
 result=[]
 for block in q.stdout.strip().split('\n\n'):
  d={}
  for line in block.splitlines():
   k,sep,v=line.partition('=')
   if sep and k in ('Id','LoadState','ActiveState','SubState','MainPID','UnitFileState'):d[k]=v
  result.append(d)
 return sorted(result,key=lambda d:d['Id'])
protected=[
 Path('/home/alex/.openclaw/openclaw.json'),Path('/home/alex/.codex/auth.json'),Path('/home/alex/.codex/config.toml'),
 Path('/home/alex/.config/systemd/user/openclaw-gateway.service'),
 Path('/home/alex/.config/systemd/user/openclaw-gateway.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf'),
 Path('/home/alex/.config/systemd/user/openclaw-authbus-restart-when-idle.service'),
 Path('/home/alex/.config/systemd/user/openclaw-authbus-restart-when-idle.service.d/zzzz-heptabao-authbus-held-cohort-hb3-r1.conf'),
 Path('/home/alex/heptabao-authbus-persistent-guard-hb3-r1/hold-0dcbd843db6bbaf3fb0fdab97ae4775029d63660a7365b8da5b498385917c5e5.json'),
 Path('/home/alex/heptabao-authbus-persistent-guard-hb3-r1/hold-89902581f0d98cb21706f6dfdb9e879d2d6dffc7b8f4f3f4a9c654645f9624a1.json')]
before={str(p):sha(p)for p in protected};unit_before=units()
assert all(u.get('MainPID')=='0'and u.get('ActiveState')=='inactive'for u in unit_before)
prepare=I/'prepare-r2.public.json';prep=json.loads(prepare.read_bytes())
pins=json.loads((Q/'qa-pins.public.json').read_bytes())['files']
for name,pin in pins.items():assert sha(Q/name)==pin['sha256']
assert prep['consumerSha256']==pins['pocket_native_consumer_r3.mjs']['sha256']
assert prep['controllerSha256']==pins['pocket_current_native_live_r2.py']['sha256']
parent_net=os.stat('/proc/self/ns/net').st_ino
cmd=['/usr/bin/python3','-I','-S','-B',str(Q/'pocket_current_native_live_r2.py'),
 '--project-root',str(P),'--work-dir',str(R/'live'),'--binary',str(A/'heptabao-server'),
 '--build-result',str(A/'normal-build.result.public.json'),'--native-receipt',str(A/'native-build.public.json'),
 '--prepare',str(prepare),'--consumer',str(Q/'pocket_native_consumer_r3.mjs'),'--scenario',args.scenario,
 '--node','/usr/bin/node','--parent-netns-inode',str(parent_net)]
wrap=['/usr/bin/bwrap','--ro-bind','/','/','--bind',str(R),str(R),
 '--ro-bind','/home/alex/.openclaw','/home/alex/.openclaw',
 '--ro-bind','/home/alex/.codex','/home/alex/.codex',
 '--ro-bind','/home/alex/.npm-global/lib/node_modules/openclaw','/home/alex/.npm-global/lib/node_modules/openclaw',
 '--ro-bind',str(P/'source'),str(P/'source'),'--ro-bind',str(Q),str(Q),'--ro-bind',str(I),str(I),
 '--proc','/proc','--dev','/dev','--unshare-net','--unshare-pid','--die-with-parent','--chdir',str(R),'--',*cmd]
intent={'schema':'heptabao.pocket-current-native-isolated-launch-intent.v1','scenario':args.scenario,'argv':wrap,
 'sourceCommit':'33cafa4c6e29f0bde1553e041550d21b4c725d9c','sourceTree':'cdc2376e7b39c1d8bbbeb10a813d58bfe923f336',
 'binarySha256':'7dc5bc5157d62fd92e8cb10f1270f9ea776a929fde77a87eeb284509e82f1bba',
 'prepareSha256':sha(prepare),'qaPinsSha256':sha(Q/'qa-pins.public.json'),
 'launcherSha256':sha(__file__),'unitsBefore':unit_before,'protectedInputPinsBefore':before,
 'budgets':{'httpSeconds':10,'consumerSeconds':70,'rollbackSeconds':35,'outerSeconds':440},
 'kernelPrivatePidNamespace':True,'kernelPrivateNetworkNamespace':True,
 'onlyFreshRunDirectoryWritable':True,'productionChanged':False,'providerNetworkEgress':False,'automaticRetry':False}
put(R/'intent.public.json',intent)
started=time.monotonic();timed=False;rc=None
with (R/'stdout.private').open('xb')as stdout,(R/'stderr.private').open('xb')as stderr:
 process=subprocess.Popen(wrap,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
   env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/home/alex'},start_new_session=True)
 try:rc=process.wait(timeout=440)
 except subprocess.TimeoutExpired:
  timed=True
  try:os.killpg(process.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  rc=process.wait(timeout=10)
 finally:
  if process.poll()is None:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   process.wait(timeout=10)
 stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
# When the PID namespace init exits, the kernel kills remaining descendants,
# including detached native process groups. There is no retry on an unknown run.
unit_after=units();after={str(p):sha(p)for p in protected}
core_path=R/'live/result.public.json';core=json.loads(core_path.read_bytes())if core_path.exists()else None
receipt={'schema':'heptabao.pocket-current-native-isolated-launch-result.v1','scenario':args.scenario,
 'ok':rc==0 and not timed and core is not None and core.get('ok')is True,
 'returncode':rc,'outerTimeout':timed,'outcomeUnknown':timed or core is None,'automaticRetry':False,
 'elapsedSeconds':round(time.monotonic()-started,3),'intentSha256':sha(R/'intent.public.json'),
 'coreResultPath':str(core_path),'coreResultSha256':sha(core_path)if core else None,
 'coreChecks':len(core.get('checks',[]))if core else 0,
 'corePassed':sum(c.get('passed')is True for c in core.get('checks',[]))if core else 0,
 'ownedNamespaceProcessExited':process.returncode is not None,
 'pidNamespaceTeardownEnforced':True,'ownedNativeCleanupQualified':core.get('ownedNativeProcessesStopped')if core else False,
 'productionUnitsBefore':unit_before,'productionUnitsAfter':unit_after,'productionUnitsUnchanged':unit_before==unit_after,
 'protectedInputsUnchanged':before==after,'productionChanged':False,'productionTrafficCutover':False,
 'providerNetworkEgress':False,'providerAvailabilityQualified':False,
 'stdoutSha256':sha(R/'stdout.private'),'stderrSha256':sha(R/'stderr.private')}
receipt['ok']=receipt['ok']and receipt['productionUnitsUnchanged']and receipt['protectedInputsUnchanged']
put(R/'execution.result.public.json',receipt)
print(json.dumps({'path':str(R/'execution.result.public.json'),'sha256':sha(R/'execution.result.public.json'),'result':receipt}))
raise SystemExit(0 if receipt['ok']else 1)
