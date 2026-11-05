#!/usr/bin/env python3
"""One bounded metadata-only inspection of fixed prior ROG build paths."""
import errno, hashlib, json, os, stat, time
START=time.monotonic()
UNTIL=START+15.0
TARGET='/home/qian-qi/heptabao-native-20261029-c1bd-r1/runtime/target'
NATIVE='/home/qian-qi/heptabao-native-20261029-c1bd-r1'
TOOL='/home/qian-qi/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu'
OLD='/home/qian-qi/heptabao-phaseb-fresh-ingress-observer-normal-20261104-r3'
OUTPUT=OLD+'/normal-release-tests-r1'
PATHS=(
 '/', '/home', '/home/qian-qi', NATIVE, NATIVE+'/runtime', TARGET,
 TARGET+'/release', TARGET+'/release/.cargo-lock', NATIVE+'/cargo-home',
 '/home/qian-qi/.rustup', '/home/qian-qi/.rustup/toolchains', TOOL, TOOL+'/bin',
 TOOL+'/bin/cargo', TOOL+'/bin/rustc', TOOL+'/bin/rustfmt',
 OLD, OUTPUT, OUTPUT+'/artifacts', OUTPUT+'/artifacts/heptabao-server',
 OUTPUT+'/artifacts/heptabao-seed', OUTPUT+'/retained-heptabao-server-libtest',
 OUTPUT+'/normal-release-result.public.json', OUTPUT+'/native-build.public.json',
 OUTPUT+'/result.public.json')
RECEIPTS=(
 (OUTPUT+'/normal-release-result.public.json',3200,'6313b4eaad68ac882d0891e14bd9d1632e138e635e3626b1b2b774e6be8f243f'),
 (OUTPUT+'/native-build.public.json',794,'51d0d83956a82e532b1f576a904bd1d5708ccc8991eaa6572b7435d8e57aebce'),
 (OUTPUT+'/result.public.json',35178,'8899a7acc647505c230430b35771ae1eccaf48cc5aea27a034906d513fd0b0f7'))
fds=[];total=0
report={'schema':'heptabao.cold-h2-rog-target-metadata.v1','status':'incomplete',
 'diagnostic_only':True,'paths':[],'receipts':[],'children_started':0,'files_written':0,
 'directory_entries_listed':0,'payload_directories_read':0,'production_changed':False,
 'inner_seconds':15,'outer_seconds':45,'known_prior_target':TARGET}
def remaining():
 if time.monotonic()>=UNTIL:raise TimeoutError('metadata_original_deadline')
def identity(x):
 return [x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def observe(path,kind):
 remaining()
 try:
  if kind=='lstat':value=identity(os.lstat(path))
  elif kind=='stat':value=identity(os.stat(path,follow_symlinks=True))
  else:value=os.path.realpath(path,strict=True)
  remaining()
  return {'observed':True,'value':value}
 except OSError as error:
  remaining()
  if error.errno in (errno.ENOENT,errno.ENOTDIR):
   return {'observed':True,'missing':True,'errno':error.errno}
  raise
def close(row):
 if row['attempted']:return
 row['attempted']=True
 try:os.close(row['fd']);row['closed']=True
 except OSError as error:row['close_errno']=error.errno
try:
 assert os.uname().sysname=='Linux' and os.getuid()==1000
 assert len(PATHS)==25 and len(set(PATHS))==25
 for path in PATHS:
  report['paths'].append({'path':path,**{kind:observe(path,kind) for kind in ('lstat','stat','realpath')}})
 for path,size,expected in RECEIPTS:
  remaining();row=None;item={'path':path,'expected_bytes':size,'expected_sha256':expected}
  report['receipts'].append(item)
  try:
   assert os.path.realpath(path,strict=True)==path
   named=os.lstat(path)
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   row={'fd':fd,'attempted':False,'closed':False};fds.append(row)
   before=os.fstat(fd)
   assert identity(before)==identity(named) and stat.S_ISREG(before.st_mode)
   assert before.st_uid==1000 and before.st_nlink==1 and 0<=before.st_size<=65536
   content=bytearray()
   while True:
    remaining()
    block=os.read(fd,min(16384,65537-len(content)))
    if not block:break
    content.extend(block);total+=len(block)
    assert len(content)<=65536 and total<=65536
   remaining()
   after=os.fstat(fd);final_named=os.lstat(path)
   assert identity(before)==identity(after)==identity(final_named) and len(content)==before.st_size
   digest=hashlib.sha256(content).hexdigest()
   item.update(observed=True,bytes=len(content),sha256=digest,identity=identity(before),
               matches_known_receipt=(len(content)==size and digest==expected))
   if item['matches_known_receipt']:
    value=json.loads(content)
    item['selected_public_fields']={k:value[k] for k in ('schema','source','source_commit','source_tree','target','status','test_count') if k in value}
  except OSError as error:
   if error.errno not in (errno.ENOENT,errno.ENOTDIR):raise
   item.update(observed=True,missing=True,errno=error.errno,matches_known_receipt=False)
  finally:
   if row is not None:close(row)
 remaining()
 report['status']='observed'
except BaseException as error:
 report['error_type']=type(error).__name__
 if isinstance(error,OSError):report['error_errno']=error.errno
finally:
 for row in reversed(fds):close(row)
 report['owned_descriptors']=[{'close_attempted':x['attempted'],'closed':x['closed'],'close_errno':x.get('close_errno')} for x in fds]
 report['all_opened_descriptors_closed']=all(x['closed'] for x in fds)
 report['public_receipt_bytes_read']=total
 report['elapsed_seconds']=time.monotonic()-START
 report['publication_within_original_deadline']=time.monotonic()<UNTIL
 report['complete']=bool(report['status']=='observed' and report['all_opened_descriptors_closed']
                         and report['publication_within_original_deadline'] and len(report['paths'])==25 and len(report['receipts'])==3)
 data=(json.dumps(report,sort_keys=True)+'\n').encode()
 assert len(data)<=65536
 os.write(1,data)
raise SystemExit(0 if report['complete'] and time.monotonic()<UNTIL else 1)
