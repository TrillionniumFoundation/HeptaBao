from pathlib import Path
import datetime,hashlib,json,os,platform,re,stat,sys,time
start=time.monotonic();deadline=start+25
parent=Path('/home/qian/heptabao-current-4bde9-static-abi-20261106-r1')
out=parent/'runtime-prerequisites-r1'
os.umask(0o077)
def need(v,k):
 if not v:raise RuntimeError(k)
def ident(s):return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def pin(logical):
 p=Path(logical);actual=p.resolve(strict=True);s=actual.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not stat.S_IMODE(s.st_mode)&0o022 and 0<s.st_size<=32*1024*1024,'existing_root_owned_system_file')
 h=hashlib.sha256();header=b'';count=0
 with open(actual,'rb',opener=lambda x,f:os.open(x,f|os.O_NOFOLLOW)) as stream:
  need(ident(os.fstat(stream.fileno()))==ident(s),'system_open_changed')
  for block in iter(lambda:stream.read(1024*1024),b''):
   need(time.monotonic()<deadline,'metadata_deadline');count+=len(block);need(count<=s.st_size,'system_file_grew');h.update(block);header=(header+block)[:64]
  need(count==s.st_size and ident(os.fstat(stream.fileno()))==ident(s),'system_fd_changed')
 need(ident(actual.lstat())==ident(s) and p.resolve(strict=True)==actual,'system_file_changed')
 return {'path':str(actual),'requested_path':str(p),'bytes':s.st_size,'sha256':h.hexdigest(),'identity':ident(s),'mode':stat.S_IMODE(s.st_mode),'elf_header_hex':header.hex()}
def directory(path):
 p=Path(path);s=p.stat();v=os.statvfs(p)
 return {'path':str(p),'resolved_path':str(p.resolve(strict=True)),'device':s.st_dev,'uid':s.st_uid,'mode':stat.S_IMODE(s.st_mode),'available_bytes':v.f_bavail*v.f_frsize,'writable_for_current_uid':os.access(p,os.W_OK)}
need(platform.node()=='qian-ThinkPad-X230' and platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()==1000,'exact_x230')
s=parent.lstat();need(parent.resolve(strict=True)==parent and stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,'owned_existing_observation_parent')
out.mkdir(mode=0o700)
r={'schema':'heptabao.x230-runtime-tool-and-dr-filesystem-observation.v1','status':'failed','at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'hostname':platform.node(),'uid':os.geteuid(),'product_binary_executions':0,'child_processes_started':0,'network_requests':0,'production_changed':False,'normal107_or_runtime_qualification_granted':False}
try:
 r['tools']={name:pin(path) for name,path in [('readelf','/usr/bin/readelf'),('ldconfig','/sbin/ldconfig.real'),('python',sys.executable)]}
 need(all(bytes.fromhex(v['elf_header_hex'])[:4]==b'\x7fELF' for v in r['tools'].values()),'actual_native_system_tools')
 r['existing_parents']=[directory('/home/qian'),directory(parent)]
 physical={'ext4','ext3','ext2','xfs','btrfs','vfat','exfat','nfs','nfs4','zfs','fuseblk'}
 r['existing_persistent_mounts']=[]
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  left,right=line.split(' - ',1);parts=left.split();kind=right.split()[0]
  if kind not in physical:continue
  mount=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),parts[4])
  info=directory(mount);info.update(filesystem=kind,kernel_device_number=parts[2],read_only='ro' in parts[5].split(','))
  r['existing_persistent_mounts'].append(info)
 r['loader_preload_file_present']=Path('/etc/ld.so.preload').exists()
 r['memory_kib']={m[1]:int(m[2]) for line in Path('/proc/meminfo').read_text().splitlines() if (m:=re.fullmatch(r'(MemTotal|MemAvailable):\s+(\d+) kB',line))}
 need(time.monotonic()<deadline,'metadata_deadline');r['status']='passed'
except BaseException as e:r['failure']=str(e) if isinstance(e,RuntimeError) and re.fullmatch(r'[a-z0-9_]+',str(e)) else type(e).__name__
finally:
 r['elapsed_seconds']=time.monotonic()-start
 data=(json.dumps(r,sort_keys=True,indent=2)+'\n').encode()
 with (out/'result.public.json').open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 print(json.dumps({'status':r['status'],'result':str(out/'result.public.json'),'product_binary_executions':0,'child_processes_started':0}),flush=True)
raise SystemExit(0 if r['status']=='passed' else 1)
