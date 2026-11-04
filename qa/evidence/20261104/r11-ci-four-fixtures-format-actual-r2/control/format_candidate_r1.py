import hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic(); LIMIT=50.0
ROOT=Path('/home/qian-qi/heptabao-ci-four-unsupported-fixtures-format-20261104-r1')
SOURCE=Path('/home/qian-qi/heptabao-native-ssh-owner-20261104-r1/r10-native-state-helper-r1/source')
SRC=SOURCE/'crates/heptabao-server/src'
FMT=Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustfmt')
FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'
EXPECTED={
 'service_native_pki_tests.rs':('cd2a36696281904076b5943e4b9cce0a9feb37d4755d0cbf4e0b70553d11ff79','c6040b9b2850b3fcf6cc1b17b9f4e8e53217f64cc6f1d26e3c33b37248e16d84'),
 'service_native_transit_tests.rs':('9a620357a6b0ef168d3291e0e36a40e8b129cb4ee10cd2b710d3ddd42d02833e','f1f6beca7cbf01ba2f1411646ec9a744d58e85e42937311d5d264780e0573299'),
 'service_native_storage_tests.rs':('4b219daf9b8ff0464dd11ce464888dace7576e70d3fce91da695928574ebe09f','bb15990f5851af63afa548c3e5cbe56911ea0332a6db3a458cb9a26ca571c7bd'),
 'service_native_v6_ha_cold_restore_tests.rs':('1ae927b441b0fccddb85f50aa0c7a4ca070e59b26de47bfffa249b015c71ae9c','8ed048c97e624d81ce3ff2478e776b461c81013173821d20ea3faf795e5345bd')}
os.umask(0o077)
def remain():
 r=LIMIT-(time.monotonic()-START)
 if r<=0: raise RuntimeError('format_total_deadline')
 return r
def sha(b): return hashlib.sha256(b).hexdigest()
def read_pin(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_nlink!=1: raise RuntimeError('input_custody')
  out=bytearray()
  while True:
   remain();part=os.read(fd,65536)
   if not part: break
   out.extend(part)
  b=os.fstat(fd);n=os.lstat(p)
  keys=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_gid,s.st_nlink)
  if keys(a)!=keys(b) or keys(a)!=keys(n): raise RuntimeError('input_changed')
  return bytes(out),{'path':str(p),'sha256':sha(out),'bytes':len(out),'identity':list(keys(a))}
 finally: os.close(fd)
def write_new(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(b)
  while view:
   remain();n=os.write(fd,view)
   if n<=0: raise RuntimeError('short_write')
   view=view[n:]
  os.fsync(fd)
 finally: os.close(fd)
def sync_dir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try: os.fsync(fd)
 finally: os.close(fd)
report={'schema':'heptabao.ci-four-native-owner-fixture-rustfmt.v1','status':'failed','productExecuted':False,
 'compileExecuted':False,'productionChanged':False,'sourceCommit':'49503322c7f446e5eb41e7744f1fdbd7f1192ecc',
 'sourceTree':'1d4211f91e1b34a2ed087a3bbef2e2884bac88e9','edition':'2024',
 'internalSeconds':50,'newRemoteSupervisorSeconds':60,'files':[],'children':[]}
created=False;before={};tool_before=None
try:
 raw=sys.stdin.buffer.read(262145)
 if len(raw)>262144: raise RuntimeError('input_size')
 data=json.loads(raw)
 if set(data)!=set(EXPECTED): raise RuntimeError('input_names')
 for name,text in data.items():
  if not isinstance(text,str) or sha(text.encode())!=EXPECTED[name][1]: raise RuntimeError('candidate_input_pin')
 report['inputCarrierSha256']=sha(raw)
 if SOURCE.resolve(strict=True)!=SOURCE or SRC.resolve(strict=True)!=SRC or FMT.resolve(strict=True)!=FMT: raise RuntimeError('parent_symlink')
 tool_bytes,tool_before=read_pin(FMT)
 if sha(tool_bytes)!=FMT_SHA: raise RuntimeError('rustfmt_pin')
 report['rustfmtBefore']=tool_before
 for name,(original_pin,_) in EXPECTED.items():
  _,v=read_pin(SRC/name)
  if v['sha256']!=original_pin: raise RuntimeError('canonical_original_pin')
  before[name]=v
 ROOT.mkdir(mode=0o700);created=True
 (ROOT/'candidate').mkdir(mode=0o700);(ROOT/'formatted').mkdir(mode=0o700)
 for name in EXPECTED:
  text=data[name];write_new(ROOT/'candidate'/name,text.encode())
  argv=[str(FMT),'--edition','2024','--emit','stdout']
  p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      cwd=str(SRC),env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},start_new_session=False)
  child={'pid':p.pid,'argv':argv,'cwd':str(SRC),'timeoutSeconds':10,'stopped':False,'newProcessGroupCreated':False}
  report['children'].append(child)
  try:
   child['pgid']=os.getpgid(p.pid)
   child['supervisorGroup']=os.getpgrp()
   if child['pgid']!=child['supervisorGroup']: raise RuntimeError('child_escaped_supervisor_group')
   out,err=p.communicate(text.encode(),timeout=min(10.0,remain()))
  except BaseException:
   if p.poll() is None:
    p.kill()
    p.wait(timeout=min(5.0,remain()))
   child.update(exitCode=p.returncode,reaped=p.returncode is not None)
   child['stopped']=child['reaped']
   raise
  child.update(exitCode=p.returncode,reaped=True)
  child['stopped']=True
  write_new(ROOT/(name+'.rustfmt.stderr'),err)
  if p.returncode!=0 or not child['stopped']: raise RuntimeError('rustfmt_failed_or_group_remaining')
  if len(out)>262144 or not out.startswith(b'use super::*;'): raise RuntimeError('formatted_output_shape')
  write_new(ROOT/'formatted'/name,out)
  report['files'].append({'name':name,'beforeSha256':sha(text.encode()),'beforeBytes':len(text.encode()),
      'afterSha256':sha(out),'afterBytes':len(out),'stderrBytes':len(err),'stderrSha256':sha(err)})
 report['canonicalBefore']=before
 report['canonicalAfter']={name:read_pin(SRC/name)[1] for name in EXPECTED}
 if report['canonicalAfter']!=before: raise RuntimeError('canonical_changed')
 report['rustfmtAfter']=read_pin(FMT)[1]
 if report['rustfmtAfter']!=tool_before: raise RuntimeError('rustfmt_changed')
 sync_dir(ROOT/'candidate');sync_dir(ROOT/'formatted');sync_dir(ROOT)
 remain();report['status']='passed'
except BaseException as e:
 report['errorType']=type(e).__name__;report['error']=str(e)
finally:
 report['elapsedSeconds']=time.monotonic()-START
 report['withinDeadline']=report['elapsedSeconds']<LIMIT
 report['allOwnedStopped']=all(x.get('stopped') is True for x in report['children'])
 if not report['withinDeadline'] or not report['allOwnedStopped']: report['status']='failed'
 if created:
  try:
   write_new(ROOT/'result.public.json',(json.dumps(report,sort_keys=True,indent=2)+'\n').encode())
   sync_dir(ROOT)
  except BaseException as e:
   report['publicationError']=type(e).__name__;report['status']='failed'
 print(json.dumps({'status':report['status'],'root':str(ROOT),'files':report['files'],
   'allOwnedStopped':report['allOwnedStopped'],'elapsedSeconds':time.monotonic()-START,
   'withinDeadline':time.monotonic()-START<LIMIT,'error':report.get('error'),'publicationError':report.get('publicationError')},sort_keys=True),flush=True)
sys.exit(0 if report['status']=='passed' and time.monotonic()-START<LIMIT else 1)
