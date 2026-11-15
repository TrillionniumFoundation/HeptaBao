from pathlib import Path
import datetime,hashlib,io,json,os,re,stat,subprocess,tarfile,time,tomllib
from urllib.parse import urlsplit
root=Path('/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
source=root/'source-4bde9';prior=root/'build-test-r1';out=root/'pocket4-dependency-export-r1'
home=Path('/home/qq/.cargo')
os.umask(0o077);out.mkdir(mode=0o700)
started=time.monotonic()
result={'schema':'heptabao.closed-linux-registry-export-result.v1','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'running','rust_compilation_executed':False,'product_binary_executions':0,'source_cache_modified':False,'user_cargo_configuration_or_credentials_opened':False,'production_changed':False}
def need(ok,label):
 if not ok:raise RuntimeError(label)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path,expected=None,maximum=64*1024*1024):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=maximum,'bounded_regular_input_required')
  parts=[];total=0
  while True:
   b=os.read(fd,1024*1024)
   if not b:break
   parts.append(b);total+=len(b);need(total<=maximum,'input_grew_beyond_bound')
  data=b''.join(parts)
  ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(total==before.st_size and ident(before)==ident(os.fstat(fd))==ident(path.lstat()),'source_input_changed_during_read')
  if expected:need(digest(data)==expected,'source_input_sha256_mismatch')
  return data
 finally:os.close(fd)
def git(*args):
 return subprocess.check_output(['/usr/bin/git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',str(source),*args],env={'PATH':'/usr/bin:/bin','LC_ALL':'C','GIT_OPTIONAL_LOCKS':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'},stderr=subprocess.DEVNULL,timeout=15).decode().strip()
def index_relative(name):
 if len(name)==1:return '1/'+name
 if len(name)==2:return '2/'+name
 if len(name)==3:return '3/'+name[0]+'/'+name
 return name[:2]+'/'+name[2:4]+'/'+name
try:
 need(git('rev-parse','HEAD')=='4bde9aee03fcd27c59e13607e529b1cee594b249' and git('rev-parse','HEAD^{tree}')=='f08493a23f8ea0637073651231865ea9607b790e' and not git('status','--porcelain','--untracked-files=all'),'clean_canonical_source_required')
 lockraw=read(source/'Cargo.lock','d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5')
 packages={(p['name'],p['version']):p for p in tomllib.loads(lockraw.decode())['package']}
 receipt=json.loads(read(prior/'offline-dependencies.result.public.json','bdd3e486af56b1dfb95e93975a48711c2c9aa5de44e51e506c303063ae8c54fa'))
 need(receipt['status']=='passed' and receipt['source_and_lock_unchanged'] is True and len(receipt['steps'])==2,'original_completed_offline_closure_required')
 selected=set();tree_pins={}
 for step in receipt['steps']:
  need(step['label'] in ('server','peer') and step['exit_code']==0 and step['stderr_bytes']==0,'actual_original_tree_success')
  raw=read(prior/'offline-dependency-check-r1'/(step['label']+'.stdout'),step['stdout_sha256'])
  need(len(raw)==step['stdout_bytes'],'actual_original_tree_byte_count')
  tree_pins[step['label']]={'bytes':len(raw),'sha256':digest(raw)}
  for line in raw.decode().splitlines():
   m=re.fullmatch(r'([A-Za-z0-9_-]+) v([0-9][A-Za-z0-9.+_-]*)(?: \(.*\))?',line)
   need(m is not None,'unrecognized_original_cargo_tree_line')
   key=(m[1],m[2]);need(key in packages,'tree_package_not_in_canonical_lock');selected.add(key)
 registry={key:packages[key] for key in selected if packages[key].get('source')}
 need(registry and all(p['source']=='registry+https://github.com/rust-lang/crates.io-index' for p in registry.values()),'only_existing_public_crates_io_source')
 local=sorted([list(key) for key in selected if not packages[key].get('source')])
 cachegroups=[p for p in (home/'registry/cache').iterdir() if p.is_dir() and not p.is_symlink()]
 indexgroups=[p for p in (home/'registry/index').iterdir() if p.is_dir() and not p.is_symlink() and (p/'.cache').is_dir()]
 need(len(cachegroups)==len(indexgroups)==1 and cachegroups[0].name==indexgroups[0].name,'one_existing_consistent_sparse_registry')
 cache,index=cachegroups[0],indexgroups[0]
 entries=[];sources={}
 for (name,version),package in sorted(registry.items()):
  filename=name+'-'+version+'.crate';member='crates/'+filename
  data=read(cache/filename,package['checksum'])
  entries.append({'member':member,'kind':'linux_selected_crate','crate':name,'version':version,'bytes':len(data),'sha256':digest(data)})
  sources[member]=(cache/filename,package['checksum'])
 selected_names=sorted({name for name,version in registry})
 for name in selected_names:
  rel=index_relative(name);path=index/'.cache'/rel;data=read(path,maximum=32*1024*1024)
  records={}
  for part in data.split(b'\0'):
   if part.startswith(b'{'):
    item=json.loads(part);need(item.get('name')==name,'index_package_name_mismatch')
    need(item.get('vers') not in records,'duplicate_index_version');records[item['vers']]=item
  expected=[(version,p['checksum']) for (n,version),p in registry.items() if n==name]
  need(all(v in records and records[v].get('cksum')==sha for v,sha in expected),'index_missing_exact_locked_version_or_checksum')
  member='indexes/'+rel
  entries.append({'member':member,'kind':'selected_package_sparse_index','crate':name,'locked_versions':sorted(v for v,sha in expected),'bytes':len(data),'sha256':digest(data)})
  sources[member]=(path,digest(data))
 config=read(index/'config.json',maximum=16384);v=json.loads(config)
 need(set(v)=={'dl','api'} and all(isinstance(x,str) for x in v.values()),'public_registry_config_only')
 for value in v.values():
  u=urlsplit(value);need(u.scheme=='https' and u.hostname in ('static.crates.io','crates.io') and not u.username and not u.password and not u.query and not u.fragment,'anonymous_public_registry_metadata_required')
 entries.append({'member':'registry-config.json','kind':'public_registry_config','bytes':len(config),'sha256':digest(config)})
 sources['registry-config.json']=(index/'config.json',digest(config))
 entries.sort(key=lambda x:x['member']);need(len(entries)==len({e['member'] for e in entries}),'unique_closed_members')
 payload=out/'linux-locked-dependencies.tar'
 with payload.open('xb') as stream:
  with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
   for entry in entries:
    path,sha=sources[entry['member']];data=read(path,sha)
    need(len(data)==entry['bytes'],'source_size_changed_before_archive')
    info=tarfile.TarInfo(entry['member']);info.size=len(data);info.mode=0o600;info.uid=info.gid=0;info.mtime=0;info.uname=info.gname=''
    tar.addfile(info,io.BytesIO(data))
  stream.flush();os.fsync(stream.fileno())
 need(payload.stat().st_size<=512*1024*1024,'bounded_public_dependency_payload')
 with payload.open('rb') as stream:payloadsha=hashlib.file_digest(stream,'sha256').hexdigest()
 manifest={'schema':'heptabao.closed-linux-registry-transfer.v1','source_commit':'4bde9aee03fcd27c59e13607e529b1cee594b249','source_tree':'f08493a23f8ea0637073651231865ea9607b790e','cargo_lock_sha256':digest(lockraw),'actual_offline_receipt_sha256':'bdd3e486af56b1dfb95e93975a48711c2c9aa5de44e51e506c303063ae8c54fa','actual_cargo_tree_inputs':tree_pins,'local_workspace_packages':local,'linux_selected_registry_package_count':len(registry),'sparse_index_count':len(selected_names),'entries':entries,'payload':{'path':str(payload),'bytes':payload.stat().st_size,'sha256':payloadsha},'unselected_platform_archives_required':False,'user_cargo_config_or_credentials_included':False,'source_cache_modified':False,'rust_compilation_executed':False,'normal107_qualified':False,'production_changed':False}
 raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
 with (out/'manifest.public.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 need(read(source/'Cargo.lock')==lockraw and git('rev-parse','HEAD')==manifest['source_commit'] and not git('status','--porcelain','--untracked-files=all'),'source_unchanged_after_export')
 result.update(status='prepared',manifest={'path':str(out/'manifest.public.json'),'bytes':len(raw),'sha256':digest(raw)},payload=manifest['payload'],linux_selected_registry_package_count=len(registry),sparse_index_count=len(selected_names),entry_count=len(entries),local_workspace_packages=local)
except BaseException as e:result.update(status='failed',failure=str(e) if isinstance(e,RuntimeError) else type(e).__name__)
finally:
 result['elapsed_seconds']=time.monotonic()-started
 with (out/'result.public.json').open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 print(json.dumps(result,sort_keys=True),flush=True)
raise SystemExit(0 if result['status']=='prepared' else 1)
