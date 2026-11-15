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
