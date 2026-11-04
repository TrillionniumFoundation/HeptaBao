from pathlib import Path
import argparse,os,json,hashlib,subprocess,shutil,time,signal
os.umask(0o077)
p=argparse.ArgumentParser()
for n in ('source','output','commit','tree','toolchain','cargo-home','target','abi'):p.add_argument('--'+n,required=True)
a=p.parse_args();source=Path(a.source);out=Path(a.output);out.mkdir(mode=0o700)
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write_json(p,v):
 with Path(p).open('x') as f:json.dump(v,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def git(*x):return subprocess.check_output(['git','-C',str(source),*x],text=True,timeout=30).strip()
def freeze():return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain')}
before=freeze();assert before=={'commit':a.commit,'tree':a.tree,'status':''}
assert shutil.disk_usage(out).free>=1024*1024*1024
env=os.environ.copy();env.update({'PATH':a.toolchain+':'+env.get('PATH',''),'CARGO_HOME':a.cargo_home,'CARGO_TARGET_DIR':a.target,'CARGO_BUILD_JOBS':'2','CARGO_PROFILE_RELEASE_OPT_LEVEL':'3','CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS':'true','CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS':'true','CARGO_PROFILE_RELEASE_DEBUG':'0','CARGO_PROFILE_RELEASE_LTO':'false','CARGO_PROFILE_RELEASE_CODEGEN_UNITS':'16','CARGO_PROFILE_RELEASE_PANIC':'unwind','RUSTFLAGS':'','CARGO_TERM_COLOR':'never'})
env.pop('CARGO_ENCODED_RUSTFLAGS',None)
rustc=subprocess.check_output([str(Path(a.toolchain)/'rustc'),'-vV'],text=True,timeout=30);assert 'host: '+a.abi in rustc
command=['cargo','build','--release','--locked','--offline','-p','heptabao-server','--bin','heptabao-server','--bin','heptabao-seed','--message-format=json']
started=time.monotonic();timed_out=False;survivors=False
with (out/'cargo.jsonl').open('xb') as so,(out/'cargo.stderr.log').open('xb') as se:
 proc=subprocess.Popen(command,cwd=source,env=env,stdout=so,stderr=se,start_new_session=True)
 try:rc=proc.wait(timeout=1800)
 except subprocess.TimeoutExpired:
  timed_out=True
  try:os.killpg(proc.pid,signal.SIGTERM)
  except ProcessLookupError:pass
  try:rc=proc.wait(timeout=5)
  except subprocess.TimeoutExpired:
   try:os.killpg(proc.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   rc=proc.wait(timeout=5)
 try:os.killpg(proc.pid,0);survivors=True
 except ProcessLookupError:pass
 so.flush();se.flush();os.fsync(so.fileno());os.fsync(se.fileno())
elapsed=time.monotonic()-started;after=freeze();events=[]
for line in (out/'cargo.jsonl').read_text().splitlines():
 try:events.append(json.loads(line))
 except json.JSONDecodeError:pass
finished=any(x.get('reason')=='build-finished' and x.get('success') is True for x in events)
features=['default','native-v6-ha','native-v6-storage']
r={'schema':'heptabao.native-default-build-result.v1','normal_default_candidate':True,'formal_qualification':False,'source_commit':a.commit,'source_tree':a.tree,'source_freeze_verified':before==after,'native_abi':a.abi,'build_exit_code':rc,'build_finished_success':finished,'timed_out':timed_out,'owned_group_survivors_after_wait':survivors,'elapsed_seconds':elapsed,'command':command,'rustc_vv':rustc,'build_driver_path':__file__,'build_driver_sha256':sha(__file__),'cargo_events_sha256':sha(out/'cargo.jsonl'),'cargo_stderr_sha256':sha(out/'cargo.stderr.log'),'requested_release_profile':{k:v for k,v in env.items() if k.startswith('CARGO_PROFILE_RELEASE_')},'artifacts':{}}
if rc!=0 or not finished or timed_out or survivors or before!=after:
 write_json(out/'result.public.json',r);raise SystemExit(1)
artifacts=out/'artifacts';artifacts.mkdir(mode=0o700)
for name in ('heptabao-server','heptabao-seed'):
 matches=[x for x in events if x.get('reason')=='compiler-artifact' and x.get('target',{}).get('name')==name and x.get('executable')];assert matches
 e=matches[-1];assert sorted(e.get('features',[]))==features
 profile=e.get('profile',{});assert str(profile.get('opt_level'))=='3' and profile.get('debug_assertions') is True and profile.get('overflow_checks') is True and profile.get('test') is False
 original=Path(e['executable']);copied=artifacts/name;shutil.copy2(original,copied);copied.chmod(0o700)
 with copied.open('rb') as f:os.fsync(f.fileno())
 digest=sha(copied);assert digest==sha(original)
 r['artifacts'][name]={'path':str(copied),'sha256':digest,'bytes':copied.stat().st_size,'compiler_executable':str(original),'features':e['features'],'profile':profile,'fresh':e.get('fresh')}
fd=os.open(str(artifacts),os.O_RDONLY)
try:os.fsync(fd)
finally:os.close(fd)
final=freeze();assert final==before==after
r['source_freeze_verified']=before==after==final
write_json(out/'result.public.json',r)
server=r['artifacts']['heptabao-server']
receipt={'schema':'heptabao.native-build.v1','source_commit':a.commit,'source_tree':a.tree,'source_freeze_verified':True,'native_abi':a.abi,'build_exit_code':0,'binary_sha256':server['sha256'],'features':server['features'],'provenance':{'result_path':str(out/'result.public.json'),'result_sha256':sha(out/'result.public.json'),'cargo_events_sha256':r['cargo_events_sha256']}}
write_json(out/'native-build.public.json',receipt)
print(json.dumps({'source_commit':a.commit,'source_tree':a.tree,'native_abi':a.abi,'server_sha256':server['sha256'],'receipt':str(out/'native-build.public.json'),'receipt_sha256':sha(out/'native-build.public.json'),'elapsed_seconds':elapsed,'normal_default_candidate':True,'owned_group_survivors_after_wait':survivors}),flush=True)
