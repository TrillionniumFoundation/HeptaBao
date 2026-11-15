import hashlib,json,os,stat,sys,time,types,unittest
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r3/qa')
path=QA/'main3_api_controller.py'
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==32340 and hashlib.sha256(raw).hexdigest()=='74daa03bfc8edcb4d577c47dc4d664cbd5fc065adc4c79a46d2d9f822eae483f'
 assert os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
finally:os.close(fd)
module=types.ModuleType('main3_api_controller');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='18798417435d55eea5c48823162e079bfdf910d1f36dcbd91f61993106353216'
sys.path.insert(0,str(QA))

from main3_source_fence import CapsuleFence,ident
EVENTS=[["capture-r2-terminal",1793986144685],["api-r3-preparation-submit",1793986332016],["api-r3-preflight-submit",1793986687020],["namespace-diagnostic-submit",1793986788588]]
START=time.monotonic();UNTIL=START+20
r={'schema':'heptabao.main3-registry-ctime-interval-readonly.r1','ok':False,'sourceFilesModified':False,
 'sourceSqlOpened':False,'credentialValuesOrDigestsPublished':False,'privateIdentityValuesPublished':False,
 'timingBoundariesArePublicRuntimeReceipts':True,'rounds':[],'sourceFdsOpened':0,'serviceActions':[]}
fence=None
try:
 fence=CapsuleFence(UNTIL)
 rows=fence.doc['registryGeneration']['sourceIdentities']
 def interval(ns):
  previous='before-capture-r2-terminal'
  for label,ms in EVENTS:
   if ns<int(ms)*1000000:return previous+'..'+label
   previous=label
  return 'after-'+previous
 for round_number in range(2):
  observation=[]
  for name,expected in rows.items():
   fence.remaining();before=Path(name).lstat();current=ident(before)
   need_path=str(Path('/Users/qianqi/.openclaw/state/openclaw.sqlite'))
   assert name in (need_path,need_path+'-wal',need_path+'-shm')
   assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
   observation.append({'fileKind':'wal' if name.endswith('-wal') else 'shm' if name.endswith('-shm') else 'database',
    'sameFirstEightIdentityFields':list(current[:8])==list(expected[:8]),
    'expectedCtimeInterval':interval(int(expected[8])),'actualCtimeInterval':interval(before.st_ctime_ns),
    'ctimeChangedSinceCapsule':current[8]!=expected[8],
    'sameIdentityInThisRead':current==ident(Path(name).lstat())})
  r['rounds'].append({'round':round_number+1,'rows':observation})
  if round_number==0:
   observed=tuple(ident(Path(name).lstat()) for name in rows)
   time.sleep(min(2.0,fence.remaining()))
  else:r['identitiesUnchangedDuringTwoSecondQuietInterval']=observed==tuple(ident(Path(name).lstat()) for name in rows)
 r['ok']=True
except BaseException as error:r['errorType']=type(error).__name__
finally:
 r['allReturnedDescriptorsClosed']=fence is not None and fence.opened==fence.closed
 r['elapsedSeconds']=time.monotonic()-START
 r['ok']=bool(r['ok'] and r['allReturnedDescriptorsClosed'] and time.monotonic()<UNTIL)
 print(json.dumps(r,sort_keys=True),flush=True)
raise SystemExit(0 if r['ok'] else 1)
