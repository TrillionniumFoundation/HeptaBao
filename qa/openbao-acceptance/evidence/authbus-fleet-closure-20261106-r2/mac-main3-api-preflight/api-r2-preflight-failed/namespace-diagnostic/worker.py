import hashlib,json,os,stat,sys,time,types,unittest
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-authbus-main3-api-20261106-r2/qa')
path=QA/'main3_api_controller.py'
def identity(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==32340 and hashlib.sha256(raw).hexdigest()=='6bf27db160301108340d371e32c0b5384205fe26db27aea878abf493f680a722'
 assert os.read(fd,1)==b'' and identity(before)==identity(os.fstat(fd))==identity(path.lstat())
finally:os.close(fd)
module=types.ModuleType('main3_api_controller');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='e655fb1c5780ed7d1ee3fb7b5febb299f0ff7c4849ab0537dc17426cf68f2378'
sys.path.insert(0,str(QA))

from main3_source_fence import CapsuleFence,ident
started=time.monotonic();until=started+20.0
r={'schema':'heptabao.main3-capsule-namespace-difference-readonly.r1','ok':False,'sourceFilesModified':False,
 'sourceSqlOpened':False,'providerCalled':False,'serviceActions':[],'credentialValuesOrDigestsPublished':False,
 'privateGenerationValuesPublished':False,'rows':[]}
fence=None
try:
 fence=CapsuleFence(until)
 fields=('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns')
 bundles=[('agent-'+str(i+1),v) for i,v in enumerate(fence.doc['sourceGenerations'])]
 bundles.append(('registry',fence.doc['registryGeneration']))
 for category,bundle in bundles:
  for ordinal,(name,expected) in enumerate(bundle['sourceIdentities'].items(),1):
   fence.remaining()
   kind='wal' if name.endswith('-wal') else 'shm' if name.endswith('-shm') else 'journal' if name.endswith('-journal') else 'database'
   row={'category':category,'fileKind':kind,'ordinal':ordinal,'expectedPresent':True}
   try:
    actual=Path(name).lstat();current=ident(actual)
    row.update(actualPresent=True,identityEqual=tuple(expected)==current,
      changedIdentityFields=[fields[i] for i,(x,y) in enumerate(zip(expected,current,strict=True)) if x!=y],
      regularFile=stat.S_ISREG(actual.st_mode),uid501=actual.st_uid==501,nlinkOne=actual.st_nlink==1,
      privateMode=(stat.S_IMODE(actual.st_mode)&0o077)==0)
   except FileNotFoundError:row.update(actualPresent=False,identityEqual=False)
   r['rows'].append(row)
  for ordinal,name in enumerate(bundle['sourceAbsences'],1):
   fence.remaining()
   kind='wal' if name.endswith('-wal') else 'shm' if name.endswith('-shm') else 'journal' if name.endswith('-journal') else 'database'
   try:Path(name).lstat();absent=False
   except FileNotFoundError:absent=True
   r['rows'].append({'category':category,'fileKind':kind,'ordinal':ordinal,
    'expectedPresent':False,'actualPresent':not absent,'absenceEqual':absent})
 r['ok']=True
except BaseException as error:r['errorType']=type(error).__name__
finally:
 if fence is not None:
  r['allReturnedDescriptorsClosed']=fence.opened==fence.closed
 r['elapsedSeconds']=time.monotonic()-started
 r['ok']=bool(r['ok'] and r.get('allReturnedDescriptorsClosed') and time.monotonic()<until)
 print(json.dumps(r,sort_keys=True),flush=True)
raise SystemExit(0 if r['ok'] else 1)
