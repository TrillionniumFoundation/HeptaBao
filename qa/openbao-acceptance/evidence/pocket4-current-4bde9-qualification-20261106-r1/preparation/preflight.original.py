from pathlib import Path
import datetime,hashlib,json,os,platform,shutil,stat
home=Path.home()
out=home/'heptabao-pocket4-normal107-readonly-preflight-20261106-r1'
os.umask(0o077);out.mkdir(mode=0o700)
r={'schema':'heptabao.configured-pocket4-linux-normal107-readonly-feasibility.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'platform':platform.system(),'machine':platform.machine(),'hostname':platform.node(),'home':str(home),'uid':os.getuid(),'status':'running','product_binary_executions':0,'rust_compilation_executed':False,'toolchain_installed':False,'production_changed':False}
pins={'cargo':'ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24','rustc':'3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2','rustfmt':'5005cdcd39ded526dca8fa6ccd716d42fc7da54469034e055dbf54649bec7877'}
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
try:
 r['resources']={'disk_free_bytes':shutil.disk_usage(home).free,'cpu_count':os.cpu_count()}
 if platform.system()=='Linux':
  mem={line.split(':')[0]:int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:','SwapFree:'))}
  r['resources'].update(mem)
  compilers=[];errors=[]
  for p in Path('/proc').iterdir():
   if not p.name.isdigit():continue
   try:
    name=(p/'comm').read_text().strip()
    if name in ('cargo','rustc','rustfmt','rust-lld'):compilers.append({'pid':int(p.name),'comm':name})
   except FileNotFoundError:pass
   except OSError as e:errors.append({'pid':int(p.name),'error_type':type(e).__name__})
  r['resources'].update(compiler_processes=compilers,process_observation_errors=errors)
 tool=home/'.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin'
 r['toolchain']={}
 for name,expected in pins.items():
  path=tool/name
  if path.is_file():
   actual=digest(path);r['toolchain'][name]={'path':str(path),'bytes':path.stat().st_size,'sha256':actual,'exact_original_pin':actual==expected}
  else:r['toolchain'][name]={'exists':False}
 cargo=home/'.cargo';r['cargo_home']=str(cargo)
 r['registry_inventory']={'archive_files':sum(1 for _ in (cargo/'registry/cache').glob('*/*.crate')),'source_directories':sum(1 for p in (cargo/'registry/src').glob('*/*') if p.is_dir()),'index_directories':sum(1 for p in (cargo/'registry/index').glob('*') if p.is_dir())}
 candidates=[]
 for base in sorted(home.glob('heptabao*')):
  if not base.is_dir() or base.is_symlink():continue
  for source in sorted(base.glob('source*')):
   if not source.is_dir() or source.is_symlink() or not (source/'.git').is_dir():continue
   head=(source/'.git/HEAD').read_text().strip()
   if len(head)==40 and all(c in '0123456789abcdef' for c in head):
    candidates.append({'source':str(source),'detached_head':head})
 r['existing_heptabao_detached_sources']=candidates
 r['platform_and_original_resource_and_tool_pins_ready']=(platform.system()=='Linux' and platform.machine()=='x86_64' and r['resources'].get('MemAvailable',0)>=12*1024**2 and r['resources']['disk_free_bytes']>=8*1024**3 and r['resources'].get('compiler_processes')==[] and r['resources'].get('process_observation_errors')==[] and all(v.get('exact_original_pin') is True for v in r['toolchain'].values()))
 r['offline_selected_closure_still_required']=True;r['status']='observed'
except BaseException as e:r.update(status='failed',failure_type=type(e).__name__)
finally:
 p=out/'result.public.json'
 with p.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(p),'normal107_qualified':False}),flush=True)
raise SystemExit(0 if r['status']=='observed' else 1)
