import hashlib,json,os,signal,stat,subprocess,sys,time
from pathlib import Path
START=time.monotonic(); LIMIT=50.0
ROOT=Path('/home/qian-qi/heptabao-native-jwt-e3afc157-format-20261106-r1')
SRC=ROOT
SOURCE=Path('/home/qian-qi/heptabao-native-jwt-source-e3afc157-20261106-r1/source/crates/heptabao-server/src')
FMT=Path('/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustfmt')
FMT_SHA='5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'
EXPECTED={"auth.rs":["f28541658b6663ebdfed8d5fc4f019c976f2daf24bc372961e17755ebc2ad601","6fe0c3a8af3af126be3217143c85519e9b6d9abf7fcbc33f08e6b553ba5a7c97"],"auth_native_jwt.rs":[None,"d28cc6af7a1ef30fecb704ac9d3917a2c54ad8d6f8ac1cb77e6f75eca9de5042"],"auth_native_v6_routes.rs":["c5a932161eaeced8bef1c5dcd0a869ba9895bc0cafb9f4d80967cc7a21641c01","9114c08a472dfde56837f6bbccf565e471ee2b5286980efb906c3121c71d1761"],"federated_auth.rs":["177477696829aee63cf7d8fa68ebcc6f1c556f90814d877cec70a17a6981b097","8ac92cf16e18ceccb479322103228142fea413f6ce7ecbcfd9e908ed07bd1cdb"],"federated_native_jwt.rs":["d0c673be357721547d5eb1db95fbac48104e30a22420b4b1efb0635fefcaa6fa","255ec883fbb055fdfaea3d8f771fb723a4bb5b524d87f846dcc197dd5e46e92e"],"service.rs":["2545e0951051b76b6278c2678c893b98756d3164855939a811db6b22dfc31cf2","5953adcb817a2210cc2b5266ec145632e7a263d39b7c61b2811e4c9d1ece289a"],"service_native_auth.rs":["dbf07f20dc30ac077761c6ec01936c7f7cd03a3687409d60cca674d4b2ed11cf","877d158852e1e47dea0f65e3207592db1226fd92ba50d51f698f2f31d657c1a2"],"service_native_jwt_tests.rs":[None,"f7ca5c2c6e67717287887d31d5d8d40459f5ed6fb40524e5d026c95ee07fa48b"],"service_native_userpass_tests.rs":["a8eaf62664654721252a4df34400d5ecffdf836b9e23b280b38a270776e9e995","750574f862d135829036f08badaaf2fdb55bbc2790a244599e6dd4533a827fea"]}
SOURCE_SIZES={"auth.rs":397709,"auth_native_jwt.rs":17391,"auth_native_v6_routes.rs":21959,"federated_auth.rs":56677,"federated_native_jwt.rs":7709,"service.rs":519054,"service_native_auth.rs":142316,"service_native_jwt_tests.rs":33059,"service_native_userpass_tests.rs":25592}
FORMAT_OUTPUT_CAPS={"auth.rs":524288,"auth_native_jwt.rs":262144,"auth_native_v6_routes.rs":262144,"federated_auth.rs":262144,"federated_native_jwt.rs":262144,"service.rs":655360,"service_native_auth.rs":262144,"service_native_jwt_tests.rs":262144,"service_native_userpass_tests.rs":262144}
FORMAT_CONFIG=b'edition = "2024"\n'
FORMAT_CONFIG_SHA='f32d2f03b3f4b1e295c79ed49d543f1205c7dac7c3dc74f05a5a27af4fea0584'
os.umask(0o077)
def remain():
 r=LIMIT-(time.monotonic()-START)
 if r<=0: raise RuntimeError('format_total_deadline')
 return r
def sha(b): return hashlib.sha256(b).hexdigest()
def read_pin(p,expected_bytes=None):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or a.st_nlink!=1 or not 0<a.st_size<=8*1024*1024: raise RuntimeError('input_custody')
  if expected_bytes is not None and a.st_size!=expected_bytes: raise RuntimeError('source_size_pin')
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
report={'schema':'heptabao.native-jwt-input-rustfmt.v1','status':'failed','productExecuted':False,
 'compileExecuted':False,'productionChanged':False,'sourceCommit':'e3afc157447d35c861f275a761b29da3e42aff8e',
 'sourceTree':'5497775d9d473541e13e1603be8c893a3e27681b','sourceIdentityIsBaseOnly':False,
 'uncommittedCandidateInputs':False,'edition':'2024',
 'sourcePath':str(SOURCE),'sourceInputTotalBytes':1221466,
 'fixedFormattedOutputCaps':FORMAT_OUTPUT_CAPS,
 'sourceIdentityFields':['dev','ino','size','mtime_ns','ctime_ns','full_mode','uid','gid','nlink'],
 'internalSeconds':50,'newRemoteSupervisorSeconds':60,'files':[],'children':[]}
created=False;tool_before=None;config_before=None;source_before={}
try:
 raw=sys.stdin.buffer.read(262145)
 if len(raw)>262144: raise RuntimeError('input_size')
 carrier=json.loads(raw)
 if set(carrier)!=set(EXPECTED): raise RuntimeError('input_names')
 if SOURCE.resolve(strict=True)!=SOURCE: raise RuntimeError('source_parent_symlink')
 data={}
 for name in EXPECTED:
  if carrier[name]!={'bytes':SOURCE_SIZES[name],'sha256':EXPECTED[name][1]}: raise RuntimeError('source_manifest_pin')
  path=SOURCE/name
  if path.resolve(strict=True)!=path: raise RuntimeError('source_symlink')
  original,pin=read_pin(path,SOURCE_SIZES[name])
  if len(original)!=SOURCE_SIZES[name] or sha(original)!=EXPECTED[name][1]: raise RuntimeError('candidate_input_pin')
  source_before[name]=pin
  data[name]=original.decode('utf-8')
 report['sourceInputsBefore']=source_before
 report['inputCarrierSha256']=sha(raw)
 if FMT.resolve(strict=True)!=FMT: raise RuntimeError('rustfmt_parent_symlink')
 tool_bytes,tool_before=read_pin(FMT)
 if sha(tool_bytes)!=FMT_SHA: raise RuntimeError('rustfmt_pin')
 report['rustfmtBefore']=tool_before
 report['originalSourceProvenance']='Nine fixed files from exact independent e3afc157 checkout; source is only read, formatting writes owned copies'
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
  if len(err)>65536: raise RuntimeError('formatted_stderr_bound')
  write_new(ROOT/(name+'.rustfmt.stderr'),err)
  if p.returncode!=0 or not child['stopped']: raise RuntimeError('rustfmt_failed_or_group_remaining')
  write_new(ROOT/(name+'.rustfmt.stdout'),out)
  if len(out)>FORMAT_OUTPUT_CAPS[name] or not out.startswith(text.splitlines()[0].encode()+b'\n'): raise RuntimeError('formatted_output_shape')
  write_new(ROOT/'formatted'/name,out)
  report['files'].append({'name':name,'beforeSha256':sha(text.encode()),'beforeBytes':len(text.encode()),
      'afterSha256':sha(out),'afterBytes':len(out),'stderrBytes':len(err),'stderrSha256':sha(err)})
 sync_dir(ROOT/'candidate');sync_dir(ROOT/'formatted');sync_dir(ROOT)
 remain();report['status']='passed'
except BaseException as e:
 report['errorType']=type(e).__name__;report['error']=str(e)
finally:
 report['sourceInputsAfter']={}
 for name,before_pin in source_before.items():
  try:
   path=SOURCE/name
   if path.resolve(strict=True)!=path: raise RuntimeError('source_symlink')
   original,after_pin=read_pin(path,SOURCE_SIZES[name])
   report['sourceInputsAfter'][name]=after_pin
   if sha(original)!=EXPECTED[name][1] or after_pin!=before_pin: raise RuntimeError('source_changed')
  except BaseException as e:
   report['sourceFenceError']=type(e).__name__+':'+str(e);report['status']='failed'
 report['allFixedSourceInputsUnchanged']=len(source_before)==len(EXPECTED) and report['sourceInputsAfter']==source_before
 if not report['allFixedSourceInputsUnchanged']: report['status']='failed'
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
