import hashlib,os,stat,sys,types
from pathlib import Path
QA=Path('/Volumes/T5/hepta-vnext-recovery-20261013/mac-fresh-synthetic-launchd-20261106-r2/qa')
path=QA/'fresh_synthetic_controller_r1.py'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==501 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600
 raw=os.read(fd,1048576)
 assert len(raw)==29955 and hashlib.sha256(raw).hexdigest()=='4697eb12c7af0b88fc8faec697518e0397cc8f620cf2581f301b18206f54f42c'
 assert os.read(fd,1)==b''
 assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(os.fstat(fd).st_dev,os.fstat(fd).st_ino,os.fstat(fd).st_size,os.fstat(fd).st_mtime_ns,os.fstat(fd).st_ctime_ns)
finally:os.close(fd)
module=types.ModuleType('fresh_synthetic_controller_r1');module.__file__=str(path)
sys.modules[module.__name__]=module
exec(compile(raw,str(path),'exec'),module.__dict__)
plan,pin=module.load_inputs()
assert pin=='6928becb06ea989734983c31bdd0de73cea245852f6c564a5660ff947010066c'
sys.path.insert(0,str(QA))
import test_fresh_synthetic_controller_r1 as gates
assert gates.run()==0

import test_suid_ps_tls_r2 as new_gates
assert new_gates.run()==0
import json,time
from mac_owned_commands_r1 import Signals,Commands
from mac_owned_unreaped_r1 import FIXED_PS_ARGV,FIXED_PS_SHA256,FIXED_PS_IDENTITY
signals=Signals();signals.install();commands=Commands(signals)
started=time.monotonic();qualification_until=started+30.0
qualification={'schema':'heptabao.mac-fixed-system-ps-actual-qualification.r2',
 'ok':False,'sourcePins':plan['sourcePins'],'directChildren':[],
 'serviceMutationExecuted':False,'productionChanged':False,
 'systemPsSha256':FIXED_PS_SHA256,'systemPsIdentity':list(FIXED_PS_IDENTITY),
 'libprocReadDeniedUsedAsOwnership':False,'generalRootChildAdmission':False}
try:
 for index in range(2):
  row,out,err=commands.run('fixed-ps-lifecycle-'+str(index),list(FIXED_PS_ARGV),
   until=min(qualification_until,time.monotonic()+4.0),maximum=262144)
  projection=[]
  for line in out.decode('ascii').splitlines():
   fields=line.split()
   assert len(fields)>=3 and all(x.isdecimal() for x in fields[:3])
   if fields[0]==str(row['pid']):projection.append(fields)
  qualification['directChildren'].append({'index':index,'command':row,'ownProjection':projection})
  assert row['exitCode']==0 and row['completeBeforeDeadline'] and not row['outcomeUnknown']
  assert not err and len(projection)==1 and projection[0][:4]==[str(row['pid']),str(os.getpid()),str(row['pid']),'0']
  custody=row['cleanup']['custody']
  assert custody['ps']['pid']==row['pid'] and custody['ps']['ppid']==os.getpid()
  assert custody['ps']['pgid']==row['pid'] and custody['ps']['uid']==0
  assert custody['fixedPsContract']['argv']==list(FIXED_PS_ARGV)
  assert row['cleanup']['directChildReaped'] and row['cleanup']['allGroupRowsEmptyAfterReap']
  assert not row['cleanup']['postReapSignalSent'] and row['cleanup']['signals']==[]
  assert row['cleanup']['cleanupCaps']=={'term':1,'wait':5,'group':3,'psMax':4}
 qualification['ok']=True
except BaseException as error:
 qualification['errorType']=type(error).__name__
 qualification['errorCode']=str(error)
finally:
 qualification['commands']=commands.public()
 qualification['elapsedSeconds']=time.monotonic()-started
 qualification['ok']=bool(qualification['ok'] and qualification['commands']['allOwnedCommandsStopped']
  and qualification['commands']['unknownCommandCount']==0 and time.monotonic()<qualification_until)
 print(json.dumps(qualification,sort_keys=True),flush=True)
if not qualification['ok']:raise SystemExit(1)

sys.argv=[str(path),'--mode','preflight']
raise SystemExit(module.main())
