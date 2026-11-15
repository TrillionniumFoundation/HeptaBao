import ctypes,hashlib,json,os,sqlite3,stat,sys,time
P="/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
start=time.monotonic();fd=None;closed=False
assert sys.platform=="darwin" and os.getuid()==501 and os.path.realpath(sys.executable)==P
try:
 fd=os.open(P,os.O_RDONLY|os.O_NOFOLLOW)
 a=os.fstat(fd);h=hashlib.sha256();count=0
 while True:
  assert time.monotonic()-start<5
  p=os.read(fd,65536)
  if not p:break
  h.update(p);count+=len(p)
 def ident(s):return [getattr(s,k) for k in ("st_dev","st_ino","st_uid","st_gid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns")]
 assert ident(a)==ident(os.fstat(fd))==ident(os.lstat(P)) and stat.S_ISREG(a.st_mode) and count==34640
 assert h.hexdigest()=="cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13"
finally:
 if fd is not None:os.close(fd);closed=True
libc=ctypes.CDLL(None,use_errno=True)
print(json.dumps({"schema":"heptabao.mac-whole-sqlite-runtime-capabilities.r1","ok":True,"osListxattrPresent":hasattr(os,"listxattr"),"osGetxattrPresent":hasattr(os,"getxattr"),"libcFlistxattrSymbolPresent":hasattr(libc,"flistxattr"),"sqliteSerializePresent":hasattr(sqlite3.Connection,"serialize"),"sqliteSetconfigPresent":hasattr(sqlite3.Connection,"setconfig"),"sqliteNoCheckpointOnCloseConstantPresent":hasattr(sqlite3,"SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE"),"sqliteVersion":sqlite3.sqlite_version,"runtimeSourceFdClosedOnce":closed,"actualXattrCallDispatched":False,"childCount":0,"sqliteConnectionCount":0,"productionReads":0,"productionWrites":0},sort_keys=True))
