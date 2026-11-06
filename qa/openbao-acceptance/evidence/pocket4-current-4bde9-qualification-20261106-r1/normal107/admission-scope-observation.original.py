from pathlib import Path
import datetime,json,os,re,stat
root=Path('/home/alex/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
blocked=Path('/home/alex/heptabao-migration-pocket-diagnostic-20261027-r4')
s=blocked.lstat()
r={'schema':'heptabao.pocket4-admission-scope-observation.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'blocked_path':str(blocked),'blocked_metadata':{'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'is_directory':stat.S_ISDIR(s.st_mode),'is_symlink':stat.S_ISLNK(s.st_mode)},'blocked_directory_contents_opened':False,'permissions_changed':False,'current_root':str(root),'current_directories':[],'formal_paths_present':{},'compiler_processes':[],'current_commit_controllers':[],'process_observation_errors':[],'rust_build_executed':False,'production_changed':False,'normal107_qualified':False}
for p in root.iterdir():
 st=p.lstat()
 if stat.S_ISDIR(st.st_mode):r['current_directories'].append({'name':p.name,'uid':st.st_uid,'mode':stat.S_IMODE(st.st_mode)})
for name in ('launch-admission-r1.public.json','progress.public.json','result.public.json','artifacts'):
 r['formal_paths_present'][name]=os.path.lexists(root/'build-test-r1'/name)
for p in Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:
  name=(p/'comm').read_text().strip()
  if name in {'cargo','rustc','rustfmt','rust-lld'}:r['compiler_processes'].append({'pid':int(p.name),'comm':name})
  args=[os.fsdecode(x) for x in (p/'cmdline').read_bytes().split(b'\0') if x]
 except (FileNotFoundError,ProcessLookupError):continue
 except OSError as e:r['process_observation_errors'].append({'pid':int(p.name),'error_type':type(e).__name__});continue
 for arg in args:
  if not arg.startswith('/home/alex/') or not arg.endswith('controller.py'):continue
  path=Path(arg)
  try:
   st=path.stat()
   if stat.S_ISREG(st.st_mode) and st.st_size<65536 and re.search(r"(?m)^COMMIT\s*=\s*['\"]4bde9aee03fcd27c59e13607e529b1cee594b249['\"]",path.read_text()):
    r['current_commit_controllers'].append({'pid':int(p.name),'controller':str(path)})
  except OSError as e:r['process_observation_errors'].append({'pid':int(p.name),'controller':str(path),'error_type':type(e).__name__})
os.umask(0o077)
with (root/'build-test-r1/admission-scope-observation-r1.public.json').open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps(r,sort_keys=True),flush=True)
