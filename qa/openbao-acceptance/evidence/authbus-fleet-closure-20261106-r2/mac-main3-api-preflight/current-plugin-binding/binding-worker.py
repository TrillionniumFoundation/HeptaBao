#!/usr/bin/env python3
"""Create-only copy and binding of exactly eight current public AuthBus files."""
import hashlib,json,os,stat,sys,time
from pathlib import Path
ROOT=Path('/Users/qianqi/heptabao-mac-authbus-main3-code-preparation-20261106-r1')
LIVE=Path('/Users/qianqi/.openclaw/extensions/openclaw-authbus')
NAMES=('index.js','bad-refresh-quarantine.js','codex-client-recycler.js','lease-assignments.js',
 'order-policy.js','provider-error-classifier.js','runtime-refresh-policy.js','package.json')
START=time.monotonic();UNTIL=START+45
report={'schema':'heptabao.current-authbus-public-code-binding.r1','ok':False,
 'credentialFilesRead':False,'currentConfigRead':False,'providerCalled':False,'serviceActions':[],
 'currentPluginModified':False,'files':[],'descriptorsClosed':False}
fds=[]
class Refused(RuntimeError):pass
def need(value,code):
 if not value:raise Refused(code)
def remaining():need(time.monotonic()<UNTIL,'original_45_second_public_code_binding')
def ident(s):return tuple(str(getattr(s,n)) for n in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def close(fd):
 os.close(fd);fds.remove(fd)
def create(name,raw):
 remaining();need('/' not in name,'fixed_flat_leaf')
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory);fds.append(fd)
 try:
  old=os.fstat(fd);need(stat.S_ISREG(old.st_mode) and old.st_uid==501 and old.st_nlink==1 and stat.S_IMODE(old.st_mode)==0o600,'new_public_file_custody')
  offset=0
  while offset<len(raw):
   remaining();count=os.write(fd,raw[offset:]);need(count>0,'finite_public_copy_progress');offset+=count
  os.fsync(fd);os.fsync(directory);after=os.fstat(fd)
  need(ident(old)[:6]==ident(after)[:6] and after.st_size==len(raw)
   and ident(after)==ident(os.stat(name,dir_fd=directory,follow_symlinks=False)),'created_public_file_identity')
  return {'path':str(ROOT/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':list(ident(after))}
 finally:close(fd)
try:
 os.umask(0o077);need(sys.platform=='darwin' and os.getuid()==501 and os.geteuid()==501,'fixed_mac_operator')
 parent=os.open('/Users/qianqi',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(parent)
 info=os.fstat(parent);need(info.st_uid==501 and not stat.S_IMODE(info.st_mode)&0o022,'owned_parent')
 os.mkdir(ROOT.name,0o700,dir_fd=parent);os.fsync(parent)
 directory=os.open(ROOT.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(directory)
 need(os.fstat(directory).st_uid==501 and stat.S_IMODE(os.fstat(directory).st_mode)==0o700,'new_owned_code_root')
 live_identity=ident(LIVE.lstat());resolved=LIVE.resolve(strict=True)
 need(resolved.is_dir(),'actual_installed_plugin_directory')
 total=0
 for name in NAMES:
  remaining();nominal=LIVE/name;actual=nominal.resolve(strict=True)
  need(actual.parent==resolved,'exact_eight_public_files_in_actual_plugin')
  fd=os.open(actual,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);fds.append(fd)
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode) and before.st_uid in (0,501) and before.st_nlink==1
    and not stat.S_IMODE(before.st_mode)&0o022 and 0<before.st_size<=1048576,'public_source_custody')
   raw=bytearray()
   while len(raw)<=1048576:
    remaining();part=os.read(fd,min(65536,1048577-len(raw)))
    if not part:break
    raw.extend(part)
   need(len(raw)==before.st_size and ident(before)==ident(os.fstat(fd))==ident(actual.lstat())
    and nominal.resolve(strict=True)==actual,'current_source_stable_whole_copy')
   total+=len(raw);need(total<=2*1048576,'eight_public_sources_total_bound')
   copy=create(name,bytes(raw))
   report['files'].append({'name':name,'sourceNominal':str(nominal),'sourcePath':str(actual),
    'sourceIdentity':list(ident(before)),'copy':copy})
  finally:close(fd)
 need(ident(LIVE.lstat())==live_identity and LIVE.resolve(strict=True)==resolved,'same_plugin_namespace')
 report.update(ok=True,sourceRoot=str(LIVE),sourceRootIdentity=list(live_identity),currentWholeBytesBound=True,
  sourceCount=len(NAMES),totalPublicCodeBytes=total)
except Refused as error:report['errorCode']=str(error)
except BaseException as error:report['errorType']=type(error).__name__
finally:
 for fd in list(reversed(fds)):
  try:close(fd)
  except BaseException:report['closeError']=True
 report['descriptorsClosed']=not fds and not report.get('closeError')
 report['ok']=bool(report['ok'] and report['descriptorsClosed'] and time.monotonic()<UNTIL)
 report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report['ok'] else 1)
