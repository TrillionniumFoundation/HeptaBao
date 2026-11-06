import json,os,pathlib,stat,time,hashlib
started=time.monotonic()
root=pathlib.Path('/home/qian-qi/heptabao-kv2-ha-convergence-20261106-r1')
path=root/'build-test-r9'
result={'schema':'heptabao.rog-r9-output-collision-readonly.v1','read_only':True,'root':str(path),'controller_executed':False,'compiler_started':False,'production_changed':False,'limits':{'seconds':52,'entries':64,'proc_entries':4096}}
def identity(p):
 s=os.lstat(p)
 return {'dev':s.st_dev,'inode':s.st_ino,'mode':s.st_mode,'uid':s.st_uid,'gid':s.st_gid,'nlink':s.st_nlink,'bytes':s.st_size,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
before=identity(path)
result['before']=before
assert stat.S_ISDIR(before['mode']) and before['uid']==os.geteuid()
entries=[]
with os.scandir(path) as stream:
 for i,x in enumerate(stream):
  assert i<64 and time.monotonic()-started<52
  row={'name':x.name,**identity(x.path)}
  if x.name in ('controller.py','test-selection.public.json','result.public.json','progress.public.json','candidate.bundle') and stat.S_ISREG(row['mode']) and row['nlink']==1 and row['bytes']<=8388608:
   fd=os.open(x.path,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    st=os.fstat(fd);assert (st.st_dev,st.st_ino,st.st_size)==(row['dev'],row['inode'],row['bytes'])
    h=hashlib.sha256()
    while True:
     assert time.monotonic()-started<52
     b=os.read(fd,65536)
     if not b:break
     h.update(b)
    assert identity(x.path)=={k:v for k,v in row.items() if k!='name'}
    row['sha256']=h.hexdigest()
   finally:os.close(fd)
  entries.append(row)
result['entries']=sorted(entries,key=lambda x:x['name'])
result['after']=identity(path)
result['directory_unchanged']=result['before']==result['after']
processes=[]; errors=[]; seen=0
with os.scandir('/proc') as stream:
 for entry in stream:
  if not entry.name.isdecimal():continue
  seen+=1;assert seen<=4096 and time.monotonic()-started<52
  pp=pathlib.Path(entry.path)
  try:
   if pp.stat().st_uid!=os.geteuid():continue
   comm=(pp/'comm').read_text().strip()
   if comm not in ('cargo','rustc','rustfmt','python','python3','python3.14'):continue
   raw=(pp/'stat').read_text();tail=raw[raw.rindex(')')+2:].split()
   row={'pid':int(entry.name),'comm':comm,'state':tail[0],'ppid':int(tail[1]),'pgid':int(tail[2]),'sid':int(tail[3]),'start_ticks':int(tail[19]),'this_observer':int(entry.name)==os.getpid()}
   try:cwd=os.readlink(pp/'cwd')
   except FileNotFoundError:continue
   except PermissionError:row['cwd_observation']='permission_denied'
   else:
    row['cwd_within_convergence_root']=cwd==str(root) or cwd.startswith(str(root)+'/')
    if row['cwd_within_convergence_root']:row['cwd_relative']=str(pathlib.Path(cwd).relative_to(root))
   processes.append(row)
  except (FileNotFoundError,ProcessLookupError):continue
  except PermissionError:errors.append({'pid':int(entry.name),'type':'PermissionError'})
result['candidate_processes']=processes;result['proc_entries_seen']=seen;result['errors']=errors
result['no_cargo_rustc_rustfmt_observed']=not any(x['comm'] in ('cargo','rustc','rustfmt') for x in processes)
result['no_other_python_cwd_within_root']=not any(x.get('cwd_within_convergence_root') and not x['this_observer'] for x in processes)
result['elapsed_seconds']=time.monotonic()-started
print(json.dumps(result,sort_keys=True),flush=True)
