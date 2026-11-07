#!/usr/bin/env python3
"""Read-only public-code AST representation diagnosis; no code is executed."""
import ast, hashlib, json, os, stat, sys, time
from pathlib import Path
START=time.monotonic();UNTIL=START+10
ROOT=Path('/Users/qianqi/heptabao-authbus-production-source-inventory-20261106-r1/code')
PY='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14'
SOURCES=(
 ('mac_owned_launchd_r3.py',58613,'19c131fa1952a48e99f521fee024bb9ef34ccc94901cc604b0c75c7424689031',
  ('ManagerRefused','need','parse_print','missing_service'),'8fbb583beab2a49321543b86cb9b76136f6913f0e5382cda2b27a185067cab41'),
 ('mac_native_process_observer_r1.py',13423,'cc0fa9917d05c6dc2c295594f980c1f77d089c1196e6279a14f2fdaf2d77ae9b',
  ('ObservationRefused','require','BsdInfo','ProcessReader'),'5dc4cf9b32a7fa45f4ae1fb0619a9d203d5adb20c0e84ed473915e429e45a642'))
fds=[];codes=set();report={'schema':'heptabao.public-inventory-ast-diagnosis.r1','ok':False,
 'children':0,'databaseConnections':0,'productionSourceReads':0,'serviceActions':0,
 'providerCalls':0,'applicationSourceExecuted':False,'files':[]}
def need(v,c):
 if not v:codes.add(c);raise RuntimeError(c)
def identity(s):return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,size,pin):
 need(time.monotonic()<UNTIL,'original_public_ast_deadline');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 row={'closeAttempts':0,'closed':False};fds.append(row)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,501)
   and not stat.S_IMODE(before.st_mode)&0o022 and before.st_size==size,'exact_public_ast_input_custody')
  raw=bytearray()
  while len(raw)<=size:
   need(time.monotonic()<UNTIL,'original_public_ast_deadline');part=os.read(fd,min(65536,size+1-len(raw)))
   if not part:break
   raw.extend(part)
  need(len(raw)==size and hashlib.sha256(raw).hexdigest()==pin
   and identity(before)==identity(os.fstat(fd))==identity(Path(path).lstat()),'exact_public_ast_input_bytes')
  return bytes(raw)
 finally:
  row['closeAttempts']=1;os.close(fd);row['closed']=True
try:
 need(sys.platform=='darwin' and os.getuid()==501 and os.path.realpath(sys.executable)==PY,'exact_actual_ast_runtime')
 read(PY,34640,'cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13')
 report['pythonVersion']=sys.version.split()[0]
 for name,size,pin,names,legacy in SOURCES:
  raw=read(ROOT/name,size,pin);nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
  need(len(nodes)==len(names) and {n.name for n in nodes}==set(names),'exact_four_public_definitions')
  module=ast.Module(body=nodes,type_ignores=[])
  default=ast.dump(module,include_attributes=False)
  explicit=ast.dump(module,include_attributes=False,show_empty=True)
  h=lambda text:hashlib.sha256(text.encode()).hexdigest()
  report['files'].append({'source':name,'sourceSha256':pin,'definitionCount':len(nodes),
   'defaultAstSha256':h(default),'showEmptyAstSha256':h(explicit),
   'defaultMatchesPinnedLegacy':h(default)==legacy,'showEmptyMatchesPinnedLegacy':h(explicit)==legacy,
   'defaultAndShowEmptyIdentical':default==explicit})
 report['ok']=True
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'public_ast_diagnosis_refused'
finally:
 report['descriptors']=fds;report['allOriginalDescriptorsClosedOnce']=all(r['closed'] and r['closeAttempts']==1 for r in fds)
 report['elapsedSeconds']=time.monotonic()-START
 if not report['allOriginalDescriptorsClosedOnce'] or time.monotonic()>=UNTIL:report['ok']=False
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['ok'] else 1)
