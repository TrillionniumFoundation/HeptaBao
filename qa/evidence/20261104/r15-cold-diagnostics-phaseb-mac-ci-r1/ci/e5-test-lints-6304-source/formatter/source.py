import hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic(); LIMIT=50.0
ROOT=Path('/home/qian-qi/heptabao-ci-e5-test-lints-format-20261105-r1')
SRC=ROOT
FMT=Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustfmt')
FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'
EXPECTED={"kv2_native_lossless_prefetch_tests.rs":["9c7700293bdc2612135c29b1d0b7fb241106265f5996cb7cc57a94b0a82daefc","facd804e100291afb607055960e14516607a85c81a2f865fa0e995c99a47ad26"],"http_no_forward_tests.rs":["5e55cb9ddcceff2938cd50b7b36ea774a0ef455391a0b97bef656eeef588ab6f","69a74c24eddc924de3be8ecc926dc9634b6057879c2dde5ded4d760ed1a47801"],"http_snapshot_redirect_tests.rs":["8889ae597c0a8eecc61fcb061ac79f7e25dc27caf8ec4793961d9d7c66a96c22","f6488f385368f6cff35e89f058c8ee553fc997a96aa6e07aa89f4e641fd93681"],"http_response_coalescing_tests.rs":["514ac35ade150dce1f666e94b63f91529bb2ba7b49bfc4f6540b513b13d92c59","872051d35cb9b912908821cef854e9412a00beaf12719946e30a9a8426282221"],"service_native_plain_namespace.rs":["e88de0bcf6e9788046ba91aa2d7cfd26b9962626e8cc0b6a823aadbb69ec6c30","ad7ab5248140bc365587229d5cdb69b3e77737a874544c8a21171262db7c2d43"],"service_native_ssh_tests.rs":["55574d4f306d8a99011523cd2382d6edf8c93d716700c008a80b6a0c799595f8","a3918836011f112113af4308351ff46c073be4259661d500ee9949cc943064c0"],"service_native_kv1_signed_lease_tests.rs":["e39a674e7c29548f0df03f8ba6eca6747bdfba0e6ed5659b1000bb0624fa4f9e","e206b68a63cb2c098b141a2141a03e6f78865f0774ff0f209903a9bf88c5e6cb"],"service_no_forwarding_ha_tests.rs":["3c5e9b2e8f306786e1c5ce1ef1a02b5442bb1dc12e9de08bfed78e0dfcec808f","e9109b92a98bdf5742b7e32b16fc640f1d2bd8b3c161352798fc0db6d720cac8"]}
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
report={'schema':'heptabao.ci-e5-test-lints-rustfmt.v1','status':'failed','productExecuted':False,
 'compileExecuted':False,'productionChanged':False,'sourceCommit':'e5de554f5dfe99f0de30012122fe3e248fb60532',
 'sourceTree':'46b1276c237aaadd8cc3185e8228d8a791c68214','edition':'2024',
 'internalSeconds':50,'newRemoteSupervisorSeconds':60,'files':[],'children':[]}
created=False;tool_before=None
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
