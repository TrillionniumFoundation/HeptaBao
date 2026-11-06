from pathlib import Path,PurePosixPath
import hashlib,json,os,re,subprocess,time,tomllib
source=Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1/source-4bde9')
out=source.parent/'build-test-r1'
home=Path('/home/alex/.cargo')
toolchain=Path('/home/alex/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
env={key:os.environ[key] for key in ('HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR','TZ') if key in os.environ}
env.update(CARGO_HOME=str(home),CARGO_TARGET_DIR=str(source.parent/'target-normal'),CARGO_BUILD_JOBS='1',
           CARGO_PROFILE_RELEASE_OPT_LEVEL='3',CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
           CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',CARGO_PROFILE_RELEASE_CODEGEN_UNITS='16',CARGO_PROFILE_RELEASE_LTO='false',
           CARGO_PROFILE_RELEASE_PANIC='unwind',CARGO_TERM_COLOR='never',RUSTFLAGS='',PATH=str(toolchain)+':/usr/bin:/bin',
           RUSTC=str(toolchain/'rustc'),RUSTFMT=str(toolchain/'rustfmt'),RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='',
           CARGO_BUILD_RUSTC_WRAPPER='',CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER='')
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(ok,label):
 if not ok:raise RuntimeError(label)
r={'schema':'heptabao.pocket4-linux-offline-dependencies.v1','status':'running','source_commit':'4bde9aee03fcd27c59e13607e529b1cee594b249','source_tree':'f08493a23f8ea0637073651231865ea9607b790e','cargo_dependency_metadata_commands_executed':False,'rust_build_or_product_tests_executed':False,'production_changed':False,'formal_107_qualified':False,'steps':[],'missing_archive_source_checks':[]}
try:
 need(digest(toolchain/'cargo')=='ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24','cargo_pin')
 need(digest(source/'Cargo.lock')=='d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5','lock_pin')
 prep=json.loads((out/'preparation.result.public.json').read_bytes())
 packages={(p['name'],p['version']):p for p in tomllib.loads((source/'Cargo.lock').read_text())['package']}
 groups=[p for p in (home/'registry/src').iterdir() if p.is_dir() and not p.is_symlink()]
 for missing in prep['offline_registry']['missing_archives']:
  package=packages[(missing['name'],missing['version'])];name=missing['name']+'-'+missing['version']
  row=dict(missing,source_present=False,checksum_manifest_matches=False,all_source_files_match=False,file_count=0)
  for group in groups:
   p=group/name;checks=p/'.cargo-checksum.json'
   if not p.is_dir() or p.is_symlink():continue
   row['source_present']=True
   if not checks.is_file() or checks.is_symlink():continue
   v=json.loads(checks.read_bytes());row['checksum_manifest_matches']=v.get('package')==package['checksum']
   matches=row['checksum_manifest_matches']
   for rel,sha in v.get('files',{}).items():
    pp=PurePosixPath(rel);q=p/rel
    if pp.is_absolute() or '..' in pp.parts or not q.is_file() or q.is_symlink() or q.resolve()!=q or digest(q)!=sha:matches=False;break
   row['file_count']=len(v.get('files',{}));row['all_source_files_match']=matches
   if matches:break
  r['missing_archive_source_checks'].append(row)
 logdir=out/'offline-dependency-check-r1';os.umask(0o077);logdir.mkdir(mode=0o700)
 common=[str(toolchain/'cargo'),'tree','--locked','--offline','--target','x86_64-unknown-linux-gnu','--edges','normal,build,dev','--prefix','none']
 for label,extra in [('server',['-p','heptabao-server']),('peer',['-p','heptabao-ha-service','--features','native-v6-peer-ingress'])]:
  so=logdir/(label+'.stdout');se=logdir/(label+'.stderr');argv=common+extra;start=time.monotonic()
  with so.open('xb') as outf,se.open('xb') as errf:
   p=subprocess.run(argv,cwd=source,env=env,stdin=subprocess.DEVNULL,stdout=outf,stderr=errf,timeout=60)
   outf.flush();errf.flush();os.fsync(outf.fileno());os.fsync(errf.fileno())
  row={'label':label,'argv':argv,'exit_code':p.returncode,'seconds':round(time.monotonic()-start,6),'cap_seconds':60,'stdout_bytes':so.stat().st_size,'stdout_sha256':digest(so),'stderr_bytes':se.stat().st_size,'stderr_sha256':digest(se)}
  text=se.read_text(errors='replace');errors=re.findall(r'error: (failed to download .+|no matching package named .+|failed to get .+)',text)
  if errors:row['error_summary']=errors[0][:400]
  r['steps'].append(row);r['cargo_dependency_metadata_commands_executed']=True
 need(len(r['steps'])==2 and all(row['exit_code']==0 for row in r['steps']),'selected_linux_offline_dependency_closure_unavailable')
 clean=subprocess.check_output(['/usr/bin/git','status','--porcelain','--untracked-files=all'],cwd=source,env={'PATH':'/usr/bin:/bin','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'},timeout=15).decode().strip()
 need(not clean and digest(source/'Cargo.lock')=='d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5','source_or_lock_changed')
 r.update(status='passed',selected_linux_dependency_closures_available=True,source_and_lock_unchanged=True)
except BaseException as e:
 r['status']='failed';r['failure']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
finally:
 r['finished_at_unix']=time.time()
 result=out/'offline-dependencies.result.public.json'
 with result.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(result),'rust_build_or_product_tests_executed':False}),flush=True)
raise SystemExit(0 if r['status']=='passed' else 1)
