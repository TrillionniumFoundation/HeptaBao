#!/usr/bin/env python3
"""Bounded metadata inventory of the already selected installed public SDK.

No chmod, SDK execution, database access, service action, or network operation.
Complete metadata stays host-private; only public code paths/pins and counts are
reported. A later permission change would require its own fresh admission.
"""
import hashlib,json,os,stat,sys,time
from pathlib import Path
TARGETS={'pocket4':('/home/alex','/home/alex/.npm-global/lib/node_modules/openclaw'),
 'rog':('/home/qian-qi','/home/qian-qi/.npm-global/lib/node_modules/openclaw')}
START=time.monotonic();UNTIL=START+45;fds=[];codes=set();created=False
report={'schema':'heptabao.linux-installed-sdk-permission-inventory.r1','ok':False,
 'permissionsChanged':False,'sdkExecuted':False,'credentialDatabaseOpened':False,
 'serviceActions':0,'providerCalls':0,'childProcesses':0,'networkOpened':False,
 'productionClientQualification':False}
def need(x,code):
 if not x:codes.add(code);raise RuntimeError(code)
def remaining():need(time.monotonic()<UNTIL,'sdk_metadata_original_deadline')
def identity(s):return [str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def opened(path,flags,mode=0o777,role='public-code'):
 fd=os.open(path,flags,mode);r={'role':role,'closeAttempts':0,'closed':False};fds.append(r);return fd,r
def close(item):
 fd,r=item;need(r['closeAttempts']==0,'sdk_metadata_close_once');r['closeAttempts']=1;os.close(fd);r['closed']=True
def hash_public(path,before):
 global hashed_bytes
 need(before.st_size<=256*1048576,'bounded_writable_public_code_file')
 item=opened(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(item[0]);need(identity(s)==identity(before),'same_opened_public_code_generation')
  h=hashlib.sha256();total=0
  while True:
   remaining();part=os.read(item[0],1048576)
   if not part:break
   total+=len(part);hashed_bytes+=len(part);need(total<=before.st_size and hashed_bytes<=512*1048576,'bounded_public_code_hash_bytes');h.update(part)
  need(total==before.st_size and identity(s)==identity(os.fstat(item[0]))==identity(path.lstat()),'stable_complete_public_code_hash')
  return h.hexdigest()
 finally:close(item)
try:
 need(len(sys.argv)==2 and sys.argv[1] in TARGETS,'explicit_inventory_host');host=sys.argv[1];home_text,sdk_text=TARGETS[host]
 HOME=Path(home_text);SDK=Path(sdk_text);ROOT=HOME/f'heptabao-{host}-sdk-permissions-20261106-r1'
 need(sys.platform=='linux' and os.getuid()==1000 and Path.home()==HOME,'selected_linux_sdk_account')
 os.umask(0o077);sys.dont_write_bytecode=True
 rows=[];parents=[];candidates=[];link_rows=[];hashed_bytes=0;dir_count=0;file_count=0
 for parent in reversed(SDK.parents):
  s=parent.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid in (0,1000) and not s.st_mode&0o002,'owned_sdk_ancestor_without_world_write')
  parents.append({'path':str(parent),'identity':identity(s)})
 pending=[SDK]
 while pending:
  remaining();path=pending.pop();s=path.lstat();need(len(rows)<65536,'finite_sdk_tree_entries')
  need(s.st_uid in (0,1000),'public_sdk_tree_owner');relative=str(path.relative_to(SDK))
  row={'path':str(path),'relative':relative,'identity':identity(s)};rows.append(row)
  if stat.S_ISLNK(s.st_mode):
   target=os.readlink(path);resolved=Path(os.path.realpath(path));row['symlinkTarget']=target;row['resolvedPath']=str(resolved)
   row['targetInsideSdk']=resolved.is_relative_to(SDK);link_rows.append(row);continue
  if stat.S_ISDIR(s.st_mode):
   dir_count+=1;row['kind']='directory'
   with os.scandir(path) as stream:children=sorted([Path(entry.path) for entry in stream],reverse=True)
   need(identity(s)==identity(path.lstat()),'same_scanned_sdk_directory');pending.extend(children)
   if s.st_mode&0o022:
    need(s.st_uid==1000,'writable_sdk_directory_owned_by_caller');candidates.append({'relative':relative,'kind':'directory','mode':oct(stat.S_IMODE(s.st_mode)),'proposedMode':oct(stat.S_IMODE(s.st_mode)&~0o022)})
  elif stat.S_ISREG(s.st_mode):
   file_count+=1;row['kind']='regular';need(s.st_nlink==1,'public_sdk_tree_no_regular_hardlinks')
   if s.st_mode&0o022:
    need(s.st_uid==1000,'writable_sdk_file_owned_by_caller')
    public_code=path.suffix in ('.js','.mjs','.cjs','.json','.node','.so','.wasm','.py','.sh') or bool(s.st_mode&0o111)
    row['candidatePublicCode']=public_code
    if public_code:
     pin=hash_public(path,s);row['sha256']=pin;candidates.append({'relative':relative,'kind':'regular','bytes':s.st_size,'sha256':pin,'mode':oct(stat.S_IMODE(s.st_mode)),'proposedMode':oct(stat.S_IMODE(s.st_mode)&~0o022)})
    else:row['writableNonCodeObserved']=True
  else:need(False,'no_special_file_in_sdk_tree')
 # This public manifest is an actual separately observed plugin input, not a
 # recursive scan of live credential state.
 plugin=HOME/'.openclaw/extensions/openclaw-authbus/package.json';s=plugin.lstat()
 need(stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1,'selected_public_plugin_package')
 plugin_row={'path':str(plugin),'identity':identity(s)}
 if s.st_mode&0o022:
  plugin_row['sha256']=hash_public(plugin,s)
 for row in rows+parents+[plugin_row]:
  remaining();need(identity(Path(row['path']).lstat())==row['identity'],'complete_sdk_metadata_generations_unchanged')
  if 'symlinkTarget' in row:need(os.readlink(row['path'])==row['symlinkTarget'],'same_public_sdk_symlink_target')
 # Read-only inventory is complete even when additional paths need review;
 # unknown or external aliases explicitly block any later execute permission.
 hs=HOME.lstat();need(hs.st_uid==1000 and stat.S_ISDIR(hs.st_mode) and not hs.st_mode&0o022,'private_inventory_parent')
 ROOT.mkdir(mode=0o700,exist_ok=False);created=True
 manifest={'schema':'heptabao.linux-sdk-permission-baseline.private.r1','host':host,'sdk':str(SDK),
  'rows':rows,'ancestors':parents,'publicPluginPackage':plugin_row,'candidateChanges':candidates,
  'permissionsChanged':False,'sdkExecuted':False}
 raw=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode();need(len(raw)<=32*1048576,'bounded_private_sdk_manifest')
 item=opened(ROOT/'baseline.private.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,role='private-manifest')
 try:
  data=memoryview(raw)
  while data:
   remaining();count=os.write(item[0],data);need(count>0,'private_manifest_progress');data=data[count:]
  os.fsync(item[0])
 finally:close(item)
 item=opened(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,role='private-directory')
 try:os.fsync(item[0])
 finally:close(item)
 public_candidates=candidates if len(candidates)<=256 else []
 report.update(ok=True,host=host,publicSdkPath=str(SDK),entryCount=len(rows),directories=dir_count,regularFiles=file_count,
  symlinks=len(link_rows),externalSymlinkCount=sum(not r['targetInsideSdk'] for r in link_rows),
  writableAncestorCount=sum(bool(int(r['identity'][4])&0o022) for r in parents),
  writableNonCodeCount=sum(r.get('writableNonCodeObserved',False) for r in rows),
  candidateCount=len(candidates),candidateChanges=public_candidates,publicCandidateListComplete=len(candidates)<=256,
  pluginPackageMode=oct(stat.S_IMODE(int(plugin_row['identity'][4]))),pluginPackageWritable=bool(int(plugin_row['identity'][4])&0o022),
  pluginPackagePublicSha256=plugin_row.get('sha256'),hashBytes=hashed_bytes,allBeforeAfterMetadataIdentitiesExact=True,
  actualExecutableDependencyClosureQualified=False,permissionsChangeAuthorizedByThisReceipt=False)
except BaseException as error:
 report['errorType']=type(error).__name__;report['errorCode']=str(error) if str(error) in codes else 'public_sdk_inventory_unavailable'
finally:
 report['descriptors']=fds;report['allDescriptorsClosedOnce']=all(r['closeAttempts']==1 and r['closed'] for r in fds)
 if not report['allDescriptorsClosedOnce']:report['ok']=False
 report['createdPrivateInventory']=created;report['elapsedSeconds']=time.monotonic()-START
 print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
sys.exit(0 if report['ok'] else 1)
