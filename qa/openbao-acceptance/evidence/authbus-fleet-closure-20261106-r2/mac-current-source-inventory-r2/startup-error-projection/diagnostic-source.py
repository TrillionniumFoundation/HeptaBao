#!/usr/bin/env python3
"""Project fixed safe fields from one already closed private QA stderr."""
import hashlib,json,os,re,stat,sys,time
from pathlib import Path
START=time.monotonic();UNTIL=START+10
PY='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
ROOT=Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r2')
PATH=ROOT/'output/inventory.stderr.private'
PUBLIC_FILES=('capture_current_database_inventory_r2.py','authbus_current_auth_wal.py',
 'mac_guarded_current_capture_r3.py','mac_registry_readonly_wal_r1.py','mac_current_database_inventory_r1.py')
MODULES=('authbus_current_auth_wal','mac_guarded_current_capture_r3','mac_registry_readonly_wal_r1',
 'mac_current_database_inventory_r1','sqlite3','_sqlite3')
fds=[];codes=set();report={'schema':'heptabao.fixed-inventory-startup-error-projection.r1','ok':False,
 'originalJobId':'1a1b323521f-fc05-80bc','originalChildExitCode':1,
 'originalPrivateStderrExpectedBytes':308,'children':0,'databaseConnections':0,
 'providerCalls':0,'serviceActions':0,'productionSourceReads':0,
 'originalErrorMessageOrDigestPublished':False}
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def ident(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,size,private=False):
 need(time.monotonic()<UNTIL,'original_projection_deadline');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 row={'closeAttempts':0,'closed':False};fds.append(row)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==size
   and before.st_uid in (0,501) and not stat.S_IMODE(before.st_mode)&0o022,'fixed_projection_source_custody')
  if private:need(before.st_uid==501 and before.st_gid==20 and stat.S_IMODE(before.st_mode)==0o600,'fixed_private_error_custody')
  value=bytearray()
  while len(value)<=size:
   need(time.monotonic()<UNTIL,'original_projection_deadline');part=os.read(fd,min(65536,size+1-len(value)))
   if not part:break
   value.extend(part)
  need(len(value)==size and ident(before)==ident(os.fstat(fd))==ident(Path(path).lstat()),'complete_original_error_unchanged')
  return bytes(value)
 finally:
  row['closeAttempts']=1;os.close(fd);row['closed']=True
try:
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PY,'fixed_actual_projection_runtime')
 need(hashlib.sha256(read(PY,34640)).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13','fixed_projection_python_bytes')
 raw=read(PATH,308,True);text=raw.decode('utf-8','strict');lines=text.splitlines()
 safe_types=('ModuleNotFoundError','ImportError','PermissionError','FileNotFoundError','SyntaxError',
  'NameError','AttributeError','TypeError','RuntimeError','ValueError','OSError')
 error_type=next((kind for kind in safe_types if any(line.startswith(kind+':') for line in lines)),None)
 missing=next((module for module in MODULES if "ModuleNotFoundError: No module named '"+module+"'" in lines),None)
 frames=[]
 for line in lines:
  match=re.fullmatch(r'\s*File "([^"]{1,4096})", line ([0-9]{1,6}), in .{1,256}',line)
  if not match:continue
  path=Path(match.group(1));name=path.name
  frames.append({'source':name if name in PUBLIC_FILES else 'other_source_withheld','line':int(match.group(2))})
 report.update(ok=True,errorType=error_type,missingKnownModule=missing,frames=frames,
  sandboxCompilerPrefixPresent=any(line.startswith('sandbox-exec:') for line in lines),
  originalTracebackPresent=bool(lines and lines[0]=='Traceback (most recent call last):'))
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'fixed_startup_projection_refused'
finally:
 report['descriptors']=fds;report['allOriginalDescriptorsClosedOnce']=all(r['closed'] and r['closeAttempts']==1 for r in fds)
 report['elapsedSeconds']=time.monotonic()-START
 if not report['allOriginalDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
