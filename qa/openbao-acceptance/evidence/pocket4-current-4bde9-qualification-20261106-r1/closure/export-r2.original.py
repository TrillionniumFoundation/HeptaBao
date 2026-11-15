from pathlib import Path
import datetime,hashlib,io,json,os,re,stat,subprocess,tarfile,time,tomllib
from urllib.parse import urlsplit
root=Path('/home/qq/heptabao-kv2-ha-convergence-4bde9-authbus-20261106-r1')
source=root/'source-4bde9';prior=root/'build-test-r1';out=root/'pocket4-dependency-export-r2'
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
initial=root/'pocket4-dependency-export-r1'
cargo_home=out/'private-cargo-home'
COMMIT='4bde9aee03fcd27c59e13607e529b1cee594b249'
TREE='f08493a23f8ea0637073651231865ea9607b790e'
LOCK='d2d07ea13e42a8d4ba65fafc642ca98ae1a7de68f6cd46a69043332267f378d5'
toolchain=Path('/home/qq/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin')
expected_trees={'server':'3d112e6e8671700cd9c87b10e7c3f917b95633d469189c63cadf747ed736e707','peer':'40e70fe078077d01cb304131a61c2fa54c1dbbd9a871fe56151a321cc94c420f'}
proof={'schema':'heptabao.closed-linux-offline-resolver-proof.v1','status':'running','commands':[],'required_additional_index_names':[],'rust_build_or_product_tests_executed':False,'user_cache_modified':False,'network_downloads_allowed':False}
def write_exclusive(path,data):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 with path.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def validate_index(name,data,locked):
 records={}
 for part in data.split(b'\0'):
  if part.startswith(b'{'):
   item=json.loads(part);need(item.get('name')==name and item.get('vers') not in records,'public_sparse_index_name_or_version_mismatch');records[item['vers']]=item
 need(all(version in records and records[version].get('cksum')==sha for version,sha in locked),'index_missing_locked_version_checksum')
try:
 need(git('rev-parse','HEAD')==COMMIT and git('rev-parse','HEAD^{tree}')==TREE and not git('status','--porcelain','--untracked-files=all'),'clean_canonical_source_required')
 lockraw=read(source/'Cargo.lock',LOCK);packages=tomllib.loads(lockraw.decode())['package']
 locked={}
 for p in packages:
  if p.get('source'):
   need(p['source']=='registry+https://github.com/rust-lang/crates.io-index','public_crates_io_only')
   locked.setdefault(p['name'],[]).append((p['version'],p['checksum']))
 oldraw=read(initial/'manifest.public.json','1758c7ec1a969be00804c02dd90dddf1468dd5e8dcc4e24796c77f0f3f021f29')
 manifest=json.loads(oldraw);entries=manifest['entries'];need(len(entries)==619,'initial_closed_manifest')
 payload=read(initial/'linux-locked-dependencies.tar','8138b4e620f5d49cdd2593decf72cd2090e90eee9c620194c851b588c932cf6f',maximum=128*1024*1024)
 need(len(payload)==63508480,'initial_payload_bytes')
 groups=[p for p in (home/'registry/index').iterdir() if p.is_dir() and not p.is_symlink() and (p/'.cache').is_dir()]
 need(len(groups)==1,'one_existing_sparse_namespace');original_index=groups[0];namespace=original_index.name
 need(re.fullmatch(r'index\.crates\.io-[0-9a-f]{16}',namespace),'existing_public_sparse_namespace')
 cargo_home.mkdir(mode=0o700);copied={};index_names=set()
 with tarfile.open(fileobj=io.BytesIO(payload),mode='r:') as tar:
  members=tar.getmembers();need([m.name for m in members]==[e['member'] for e in entries],'initial_tar_closed_order')
  for info,e in zip(members,entries):
   need(info.isfile() and info.size==e['bytes'] and not info.pax_headers and not info.linkname,'initial_regular_member')
   data=tar.extractfile(info).read();need(digest(data)==e['sha256'],'initial_member_sha256')
   if e['kind']=='linux_selected_crate':
    need(e['member']=='crates/'+e['crate']+'-'+e['version']+'.crate' and (e['version'],e['sha256']) in locked[e['crate']],'initial_crate_matches_canonical_lock')
    dest=cargo_home/'registry/cache'/namespace/Path(e['member']).name
   elif e['kind']=='selected_package_sparse_index':
    need(e['member']=='indexes/'+index_relative(e['crate']),'initial_index_path')
    validate_index(e['crate'],data,[(v,s) for v,s in locked[e['crate']] if v in e['locked_versions']])
    dest=cargo_home/'registry/index'/namespace/'.cache'/index_relative(e['crate']);index_names.add(e['crate'])
   else:
    need(e['kind']=='public_registry_config' and e['member']=='registry-config.json','initial_config_only')
    dest=cargo_home/'registry/index'/namespace/'config.json'
   write_exclusive(dest,data);copied[e['member']]=dest
 env={key:os.environ[key] for key in ('HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR','TZ') if key in os.environ}
 env.update(CARGO_HOME=str(cargo_home),CARGO_TARGET_DIR=str(out/'metadata-target-unused'),CARGO_BUILD_JOBS='1',CARGO_PROFILE_RELEASE_OPT_LEVEL='3',CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',CARGO_PROFILE_RELEASE_CODEGEN_UNITS='16',CARGO_PROFILE_RELEASE_LTO='false',CARGO_PROFILE_RELEASE_PANIC='unwind',CARGO_TERM_COLOR='never',RUSTFLAGS='',PATH=str(toolchain)+':/usr/bin:/bin',RUSTC=str(toolchain/'rustc'),RUSTFMT=str(toolchain/'rustfmt'),RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='',CARGO_BUILD_RUSTC_WRAPPER='',CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER='')
 read(toolchain/'cargo','ff3022fcbd13b08434ea7afde9a0ef9d5b3f5c17b5fc7a40031be3ee000a6a24',maximum=128*1024*1024)
 common=[str(toolchain/'cargo'),'tree','--locked','--offline','--target','x86_64-unknown-linux-gnu','--edges','normal,build,dev','--prefix','none']
 for label,extra in [('server',['-p','heptabao-server']),('peer',['-p','heptabao-ha-service','--features','native-v6-peer-ingress'])]:
  for attempt in range(1,161):
   need(time.monotonic()-started<240,'bounded_offline_metadata_campaign')
   so=out/(label+'-'+str(attempt)+'.stdout');se=out/(label+'-'+str(attempt)+'.stderr')
   began=time.monotonic()
   with so.open('xb') as outf,se.open('xb') as errf:
    p=subprocess.run(common+extra,cwd=source,env=env,stdin=subprocess.DEVNULL,stdout=outf,stderr=errf,timeout=60)
    outf.flush();errf.flush();os.fsync(outf.fileno());os.fsync(errf.fileno())
   sout=read(so,maximum=1024*1024);serr=read(se,maximum=1024*1024)
   step={'label':label,'metadata_attempt':attempt,'argv':common+extra,'exit_code':p.returncode,'seconds':time.monotonic()-began,'cap_seconds':60,'stdout_bytes':len(sout),'stdout_sha256':digest(sout),'stderr_bytes':len(serr),'stderr_sha256':digest(serr)}
   proof['commands'].append(step)
   if p.returncode==0:
    need(not serr and digest(sout)==expected_trees[label],'successful_offline_tree_must_equal_original_exact_linux_closure')
    break
   errors=[line for line in serr.decode().splitlines() if line.startswith('error:')]
   need(len(errors)==1,'one_specific_missing_index_error_required')
   match=re.fullmatch(r'error: no matching package named \x60([A-Za-z0-9_-]+)\x60 found',errors[0])
   need(match is not None,'offline_error_is_not_missing_public_index')
   name=match[1];need(name in locked and name not in index_names,'missing_index_must_be_new_canonical_lock_name')
   data=read(original_index/'.cache'/index_relative(name),maximum=32*1024*1024)
   validate_index(name,data,locked[name]);member='indexes/'+index_relative(name)
   dest=cargo_home/'registry/index'/namespace/'.cache'/index_relative(name);write_exclusive(dest,data);index_names.add(name);copied[member]=dest
   entries.append({'member':member,'kind':'offline_resolver_required_sparse_index','crate':name,'locked_versions':sorted(v for v,s in locked[name]),'bytes':len(data),'sha256':digest(data),'actual_missing_index_step':{'label':label,'metadata_attempt':attempt,'stderr_sha256':digest(serr)}})
   proof['required_additional_index_names'].append(name);step['missing_public_index']=name
  else:raise RuntimeError('bounded_missing_index_attempt_count')
 need(len([s for s in proof['commands'] if s['exit_code']==0])==2,'both_original_linux_offline_trees_required')
 need(read(source/'Cargo.lock')==lockraw and git('rev-parse','HEAD')==COMMIT and not git('status','--porcelain','--untracked-files=all'),'source_unchanged_after_metadata')
 proof.update(status='passed',source_commit=COMMIT,source_tree=TREE,cargo_lock_sha256=LOCK,original_two_linux_tree_hashes_equal=True,unselected_platform_archives_added=False,additional_index_count=len(proof['required_additional_index_names']))
 proofraw=(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode();write_exclusive(out/'offline-resolver-proof.public.json',proofraw)
 entries.sort(key=lambda e:e['member']);need(len(entries)==len(set(e['member'] for e in entries)),'unique_final_closed_entries')
 finalpayload=out/'linux-locked-dependencies.tar'
 with finalpayload.open('xb') as stream:
  with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as tar:
   for e in entries:
    data=read(copied[e['member']],e['sha256']);need(len(data)==e['bytes'],'final_member_size')
    info=tarfile.TarInfo(e['member']);info.size=len(data);info.mode=0o600;info.uid=info.gid=0;info.mtime=0;info.uname=info.gname=''
    tar.addfile(info,io.BytesIO(data))
  stream.flush();os.fsync(stream.fileno())
 with finalpayload.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
 manifest.update(entries=entries,sparse_index_count=len(index_names),metadata_resolver_additional_index_count=proof['additional_index_count'],prior_export_manifest_sha256=digest(oldraw),offline_resolver_proof={'path':str(out/'offline-resolver-proof.public.json'),'bytes':len(proofraw),'sha256':digest(proofraw)},payload={'path':str(finalpayload),'bytes':finalpayload.stat().st_size,'sha256':sha},cargo_network_downloads_executed=False)
 finalraw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();write_exclusive(out/'manifest.public.json',finalraw)
 result.update(status='prepared',manifest={'path':str(out/'manifest.public.json'),'bytes':len(finalraw),'sha256':digest(finalraw)},payload=manifest['payload'],entry_count=len(entries),linux_selected_registry_package_count=321,sparse_index_count=len(index_names),metadata_resolver_additional_index_count=proof['additional_index_count'],offline_resolver_proof=manifest['offline_resolver_proof'],both_original_linux_tree_hashes_equal=True)
except BaseException as e:
 result.update(status='failed',failure=str(e) if isinstance(e,RuntimeError) else type(e).__name__)
 if not (out/'offline-resolver-proof.public.json').exists():
  proof.update(status='failed',failure=result['failure']);write_exclusive(out/'offline-resolver-proof.public.json',(json.dumps(proof,sort_keys=True,indent=2)+'\n').encode())
finally:
 result['elapsed_seconds']=time.monotonic()-started
 write_exclusive(out/'result.public.json',(json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
 print(json.dumps(result,sort_keys=True),flush=True)
raise SystemExit(0 if result['status']=='prepared' else 1)
