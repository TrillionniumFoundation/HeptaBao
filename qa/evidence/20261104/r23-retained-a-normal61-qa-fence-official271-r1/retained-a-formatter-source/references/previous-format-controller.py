import hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic(); LIMIT=50.0
ROOT=Path('/home/qian-qi/heptabao-same-root-publication-format-20261105-r1')
SRC=ROOT
FMT=Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustfmt')
FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'
EXPECTED={"service_native_v6_ha_read.rs":["b241236a714862c37da2767d5f0c52214cc6395df937b4035205fd990574aabf","186c6dbc959695283a0d16471e8ac3e9598ac4393e381dd53a1c71a5e77c9477"],"service_native_v6_ha_install.rs":["ff4edb6448044625bb542ac560e4dfa7b334b8684700e87b142554fc27076426","7ca52073cce6a6a9914f6d774dde83d8b8db18a5eb6cdbe41c6816c947747607"],"service_native_v6_ha_install_tests.rs":["4ae685a3799dabca64c1866e778649480bc5fb2f9dc6afa37622807333e38c1c","32f4964cec82959269ed131ef248894802bdfc6a8b663aea258e6d1b7bf44929"],"service_native_v6_ha_same_root_republication_tests.rs":[None,"7d6828980d6fed39a95ef6afc2c624f94ba8b0e98c8ef4a1f923b601fb3a99ca"]}
FORMAT_CONFIG=b'edition = "2024"\n'
FORMAT_CONFIG_SHA='f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584'
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
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_nlink!=1 or not 0<a.st_size<=8*1024*1024: raise RuntimeError('input_custody')
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
report={'schema':'heptabao.same-root-publication-input-rustfmt.v1','status':'failed','productExecuted':False,
 'compileExecuted':False,'productionChanged':False,'sourceCommit':'6d02ceca629163e1c07480fa1f21520434407143',
 'sourceTree':'09aa45b9439741780961c2af76680c27e0773d08','sourceIdentityIsBaseOnly':True,
 'uncommittedCandidateInputs':True,'edition':'2024',
 'internalSeconds':50,'newRemoteSupervisorSeconds':60,'files':[],'children':[]}
created=False;tool_before=None;config_before=None
try:
 raw=sys.stdin.buffer.read(262145)
 if len(raw)>262144: raise RuntimeError('input_size')
 data=json.loads(raw)
 if set(data)!=set(EXPECTED): raise RuntimeError('input_names')
 for name,text in data.items():
  if not isinstance(text,str) or sha(text.encode())!=EXPECTED[name][1]: raise RuntimeError('candidate_input_pin')
 report['inputCarrierSha256']=sha(raw)
 if FMT.resolve(strict=True)!=FMT: raise RuntimeError('rustfmt_parent_symlink')
 tool_bytes,tool_before=read_pin(FMT)
 if sha(tool_bytes)!=FMT_SHA: raise RuntimeError('rustfmt_pin')
 report['rustfmtBefore']=tool_before
 report['originalSourceProvenance']='Immutable Git blobs supplied by the root; original host repository is not read or written'
 report['inputOriginalAndCandidatePins']=EXPECTED
 ROOT.mkdir(mode=0o700);created=True
 (ROOT/'candidate').mkdir(mode=0o700);(ROOT/'formatted').mkdir(mode=0o700)
 write_new(ROOT/'rustfmt.toml',FORMAT_CONFIG)
 config_bytes,config_before=read_pin(ROOT/'rustfmt.toml')
 if config_bytes!=FORMAT_CONFIG or sha(config_bytes)!=FORMAT_CONFIG_SHA: raise RuntimeError('format_config_pin')
 report['formatConfigurationBefore']=config_before
 report['repositoryRustfmtConfigPresent']=False
 report['ownedConfiguration']='Edition 2024 only; all other rustfmt defaults; explicit config path excludes ambient parent configuration'
 for name in EXPECTED:
  text=data[name];write_new(ROOT/'candidate'/name,text.encode())
  argv=[str(FMT),'--config-path',str(ROOT/'rustfmt.toml'),'--edition','2024','--emit','stdout']
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
  write_new(ROOT/(name+'.rustfmt.stdout'),out)
  if len(out)>262144 or not out.startswith(text.splitlines()[0].encode()+b'\n'): raise RuntimeError('formatted_output_shape')
  write_new(ROOT/'formatted'/name,out)
  report['files'].append({'name':name,'beforeSha256':sha(text.encode()),'beforeBytes':len(text.encode()),
      'afterSha256':sha(out),'afterBytes':len(out),'stderrBytes':len(err),'stderrSha256':sha(err)})
 sync_dir(ROOT/'candidate');sync_dir(ROOT/'formatted');sync_dir(ROOT)
 remain();report['status']='passed'
except BaseException as e:
 report['errorType']=type(e).__name__;report['error']=str(e)
finally:
 if tool_before is not None:
  try:
   report['rustfmtAfter']=read_pin(FMT)[1]
   if report['rustfmtAfter']!=tool_before: raise RuntimeError('rustfmt_changed')
  except BaseException as e:
   report['fenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 if config_before is not None:
  try:
   config_bytes,report['formatConfigurationAfter']=read_pin(ROOT/'rustfmt.toml')
   if config_bytes!=FORMAT_CONFIG or report['formatConfigurationAfter']!=config_before: raise RuntimeError('format_config_changed')
  except BaseException as e:
   report['configFenceError']=type(e).__name__+':'+str(e);report['status']='failed'
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
