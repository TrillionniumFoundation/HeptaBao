from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,sys
home=Path('/home/alex')
source=home/'heptabao-replacement-unified-20261105-r5/source'
out=home/'heptabao-pocket4-normal107-readonly-preflight-20261106-r1/source-cache-inspection.public.json'
r={'schema':'heptabao.pocket4-existing-source-cache-inspection.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'running','rust_compilation_executed':False,'tools_installed':False,'production_changed':False,'source':str(source)}
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
def git(*args):
 return subprocess.run(['/usr/bin/git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(source),*args],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
try:
 head=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}');status=git('status','--porcelain','--untracked-files=all')
 assert head.returncode==tree.returncode==status.returncode==0
 r.update(source_head=head.stdout.decode().strip(),source_tree=tree.stdout.decode().strip(),source_clean=not status.stdout)
 r['source_file_pins']={name:{'bytes':(source/name).stat().st_size,'sha256':digest(source/name)} for name in ('Cargo.lock','Cargo.toml')}
 r['existing_objects']={}
 for name in ['4e808d0ecb1bcded22870a7ec960dfb2491cf6ec','09c14eae7a3b52dee8ce3af3175dad5900ac59ec','4bde9aee03fcd27c59e13607e529b1cee594b249']:
  result=git('cat-file','-e',name+'^{commit}');r['existing_objects'][name]=result.returncode==0
 r['original_path_tools']={}
 for name in ('clang','clang-21','clang-20','clang-19','clang-18','llvm-config','cc','cmake','ninja'):
  tool=shutil.which(name,path='/usr/bin:/bin')
  if not tool:continue
  path=Path(tool);resolved=path.resolve(strict=True)
  item={'path':str(path),'resolved':str(resolved),'bytes':resolved.stat().st_size,'sha256':digest(resolved)}
  if name.startswith('clang'):
   result=subprocess.run([str(path),'-print-resource-dir'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
   if result.returncode==0 and not result.stderr:
    resource=Path(result.stdout.decode().strip());item['resource_path']=str(resource);header=resource/'include/stddef.h'
    item['resource_stddef_exists']=header.is_file()
    if header.is_file():item['resource_stddef_sha256']=digest(header)
  r['original_path_tools'][name]=item
 libs=set()
 for root in (Path('/usr/lib/x86_64-linux-gnu'),Path('/usr/lib')):
  for path in root.glob('libclang-*.so*'):
   if path.is_file():libs.add(path.resolve(strict=True))
 for path in Path('/usr/lib').glob('llvm-*/lib/libclang.so*'):
  if path.is_file():libs.add(path.resolve(strict=True))
 r['existing_libclang']=[{'path':str(p),'bytes':p.stat().st_size,'sha256':digest(p)} for p in sorted(libs)]
 r['status']='observed'
except BaseException as e:r.update(status='failed',failure_type=type(e).__name__)
finally:
 with out.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(out)}),flush=True)
raise SystemExit(0 if r['status']=='observed' else 1)
