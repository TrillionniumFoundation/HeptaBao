import ctypes,json,os,platform,socket,time
start=time.monotonic()
class Ifaddrs(ctypes.Structure):pass
Ifaddrs._fields_=[('next',ctypes.POINTER(Ifaddrs)),('name',ctypes.c_char_p),('flags',ctypes.c_uint),('addr',ctypes.c_void_p),('netmask',ctypes.c_void_p),('broad',ctypes.c_void_p),('data',ctypes.c_void_p)]
lib=ctypes.CDLL(None,use_errno=True)
lib.getifaddrs.argtypes=[ctypes.POINTER(ctypes.POINTER(Ifaddrs))];lib.getifaddrs.restype=ctypes.c_int
lib.freeifaddrs.argtypes=[ctypes.POINTER(Ifaddrs)];lib.freeifaddrs.restype=None
head=ctypes.POINTER(Ifaddrs)();assert lib.getifaddrs(ctypes.byref(head))==0
rows=[];cursor=head;count=0
try:
 while bool(cursor):
  count+=1;assert count<=1024 and time.monotonic()-start<10
  value=cursor.contents
  if value.addr:
   prefix=ctypes.string_at(value.addr,8);family=prefix[1] if platform.system()=='Darwin' else int.from_bytes(prefix[:2],byteorder='little')
   if family==socket.AF_INET:
    addr=socket.inet_ntop(socket.AF_INET,prefix[4:8]);mask=socket.inet_ntop(socket.AF_INET,ctypes.string_at(value.netmask,8)[4:8]) if value.netmask else None
    rows.append({'interface':value.name.decode('ascii'),'address':addr,'netmask':mask,'up':bool(value.flags&1),'loopback':bool(value.flags&8),'flags':value.flags})
  cursor=value.next
finally:lib.freeifaddrs(head)
print(json.dumps({'schema':'heptabao.current-lan-interface-observation.r1','host':socket.gethostname(),'system':platform.system(),'machine':platform.machine(),'uid':os.geteuid(),'interfaces':rows,'interface_records_examined':count,'elapsed_seconds':time.monotonic()-start,'children_started':0,'connections_opened':0,'network_config_changed':False,'credential_files_read':False,'production_changed':False},sort_keys=True))
from pathlib import Path
import re
observed=[];targets={731007,732656}
for path in Path('/proc').iterdir():
 if not path.name.isdigit():continue
 try:
  name=(path/'comm').read_text().strip()
  if name in {'cargo','rustc','rustfmt','rust-lld'}:observed.append({'pid':int(path.name),'comm':name});targets.add(int(path.name))
 except (FileNotFoundError,ProcessLookupError,PermissionError):pass
assert len(targets)<=128
ancestry=[]
for target in sorted(targets):
 rows=[];pid=target;seen=set()
 for _ in range(32):
  if pid<=0 or pid in seen:break
  seen.add(pid)
  try:
   p=Path('/proc')/str(pid);raw=(p/'stat').read_text();assert len(raw)<=8192
   fields=raw.rsplit(')',1)[1].split();comm=raw[raw.find('(')+1:raw.rfind(')')]
   cg=(p/'cgroup').read_text();assert len(cg)<=65536
   units=sorted(set(re.findall(r'(hepta-runtime-job-[A-Za-z0-9-]+)',cg)))
   rows.append({'pid':pid,'ppid':int(fields[1]),'pgid':int(fields[2]),'session':int(fields[3]),'state':fields[0],'start_ticks':int(fields[19]),'comm':comm,'runtime_units':units})
   pid=int(fields[1])
  except (FileNotFoundError,ProcessLookupError):rows.append({'pid':pid,'observation':'absent_during_read'});break
  except PermissionError:rows.append({'pid':pid,'observation':'permission_denied'});break
 ancestry.append({'queried_pid':target,'rows':rows})
assert time.monotonic()-start<15
print(json.dumps({'schema':'heptabao.current-compiler-owner-observation.r1','observed_compilers':observed,'original_r3_admission_pids':[731007,732656],'ancestry':ancestry,'sample_is_atomic':False,'original_pid_birth_not_assumed':True,'cmdline_or_environment_read':False,'processes_modified':False,'elapsed_seconds':time.monotonic()-start},sort_keys=True))
