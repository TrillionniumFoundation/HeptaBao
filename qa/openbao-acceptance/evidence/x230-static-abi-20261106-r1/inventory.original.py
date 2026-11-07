from pathlib import Path
import datetime,hashlib,json,os,platform,re,shutil,stat,subprocess,time
root=Path('/home/qian/heptabao-current-4bde9-static-abi-20261106-r1')
os.umask(0o077);root.mkdir(mode=0o700)
started=time.monotonic();deadline=started+50
r={'schema':'heptabao.x230-existing-loader-provider-inventory.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'running','hostname':platform.node(),'platform':platform.system(),'machine':platform.machine(),'product_binary_executions':0,'candidate_abi_qualified':False,'actual_candidate_requirements_not_yet_available':True,'production_changed':False,'commands':[],'providers':{}}
def need(value,label):
 if not value:raise RuntimeError(label)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def pin(path):
 p=path.resolve(strict=True);s=p.stat()
 need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not stat.S_IMODE(s.st_mode)&0o022,'root_owned_existing_system_input')
 return {'path':str(path),'resolved':str(p),'bytes':s.st_size,'sha256':digest(p),'identity':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns]}
def run(label,argv):
 left=deadline-time.monotonic();need(left>0,'original_inventory_deadline')
 begin=time.monotonic()
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'},timeout=min(15,left))
 need(len(p.stdout)<=1048576 and len(p.stderr)<=16384,'bounded_tool_output')
 for suffix,data in [('stdout',p.stdout),('stderr',p.stderr)]:
  with (root/(label+'.'+suffix)).open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 row={'label':label,'argv':argv,'exit_code':p.returncode,'requested_cap_seconds':15,'effective_cap_seconds':min(15,left),'elapsed_seconds':time.monotonic()-begin,'timed_out':False,'stdout_bytes':len(p.stdout),'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_bytes':len(p.stderr),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest()}
 r['commands'].append(row);need(p.returncode==0 and not p.stderr,'completed_read_only_system_tool')
 return p.stdout.decode('utf-8')
try:
 need(platform.node()=='qian-ThinkPad-X230' and platform.machine()=='x86_64' and platform.system()=='Linux','exact_x230_required')
 readelf=Path(shutil.which('readelf',path='/usr/bin:/bin') or '')
 ldconfig=Path(shutil.which('ldconfig',path='/usr/sbin:/sbin:/usr/bin:/bin') or '')
 need(readelf.is_absolute() and ldconfig.is_absolute(),'existing_readelf_and_ldconfig_required')
 r['tools_before']={'readelf':pin(readelf),'ldconfig':pin(ldconfig)}
 r['readelf_version']=run('readelf-version',[str(readelf),'--version']).splitlines()[0]
 cache=run('ldconfig-cache',[str(ldconfig),'-p'])
 cachemap={}
 for line in cache.splitlines():
  m=re.fullmatch(r'\s*(\S+)\s+\(([^)]+)\)\s+=>\s+(/\S+)\s*',line)
  if m and 'x86-64' in m.group(2):cachemap.setdefault(m.group(1),[]).append(m.group(3))
 requested=Path('/lib64/ld-linux-x86-64.so.2')
 loader_pin=pin(requested)
 r['interpreter']={'requested_path':str(requested),'resolved_path':loader_pin['resolved'],'pin':loader_pin}
 names=['ld-linux-x86-64.so.2','libc.so.6','libgcc_s.so.1','libm.so.6']
 for name in names:
  candidates=cachemap.get(name,[])
  if name=='ld-linux-x86-64.so.2':candidates=list(dict.fromkeys([str(requested),*candidates]))
  need(candidates,'required_base_provider_missing_'+name)
  resolved={str(Path(p).resolve(strict=True)) for p in candidates}
  need(len(resolved)==1,'ambiguous_provider_resolution_'+name)
  actual=Path(next(iter(resolved)));before=pin(actual)
  raw=run('provider-'+name,[str(readelf),'-W','-h','-l','-d','--version-info',str(actual)])
  after=pin(actual);need(before==after,'system_provider_changed')
  versions=re.findall(r'Name:\s+(GLIBC[A-Za-z0-9_.]*|GCC_[A-Za-z0-9_.]+)',raw)
  r['providers'][name]={'lookup_candidates':candidates,'resolved_path':str(actual),'before':before,'after':after,'header_hex':actual.read_bytes()[:64].hex(),'raw_readelf_file':'provider-'+name+'.stdout','raw_readelf_sha256':hashlib.sha256(raw.encode()).hexdigest(),'version_name_union_for_inventory_only':sorted(set(versions))}
 r['tools_after']={'readelf':pin(readelf),'ldconfig':pin(ldconfig)}
 need(r['tools_before']==r['tools_after'] and pin(requested)==loader_pin,'system_tools_or_interpreter_changed')
 r['status']='passed'
except BaseException as e:r.update(status='failed',failure=str(e) if isinstance(e,RuntimeError) else type(e).__name__)
finally:
 r['elapsed_seconds']=time.monotonic()-started
 p=root/'result.public.json'
 with p.open('x') as f:json.dump(r,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(p),'candidate_abi_qualified':False,'product_binary_executions':0}),flush=True)
raise SystemExit(0 if r['status']=='passed' else 1)
