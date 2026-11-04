import hashlib,json,os,platform,stat,sys
from pathlib import Path
wanted=Path('/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
helper=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261103-ha-closure-r1/r10-normal-full128-node1-r1/native_ha_foreground_watchdog.py')
def capture(p,limit):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or not 0<a.st_size<=limit: raise RuntimeError('fixed_public_file_guard')
  h=hashlib.sha256()
  while True:
   b=os.read(fd,65536)
   if not b: break
   h.update(b)
  z=os.fstat(fd);n=p.lstat()
  keys=('st_dev','st_ino','st_mode','st_uid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  if tuple(getattr(a,k) for k in keys)!=tuple(getattr(z,k) for k in keys) or tuple(getattr(a,k) for k in keys)!=tuple(getattr(n,k) for k in keys): raise RuntimeError('changed')
  return {'path':str(p),'resolved':str(p.resolve(strict=True)),'sha256':h.hexdigest(),'bytes':a.st_size,'mode':stat.S_IMODE(a.st_mode),'uid':a.st_uid,'device':a.st_dev,'inode':a.st_ino,'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns}
 finally: os.close(fd)
i=capture(wanted,16*1024*1024);h=capture(helper,1024*1024)
expected='cbf84109626aa1013bbe408fbb9590bd0f1c1548f038b2221c6b8b87de26ca43'
features={k:hasattr(os,k) for k in ('waitid','P_PID','WEXITED','WNOHANG','WNOWAIT','CLD_EXITED','CLD_KILLED','CLD_DUMPED')}
print(json.dumps({'schema':'heptabao.r10-original-watchdog-readonly-diagnostic.v1','executed_path':sys.executable,'executed_realpath':str(Path(sys.executable).resolve(strict=True)),'same_requested_executable':Path(sys.executable).resolve(strict=True)==wanted.resolve(strict=True),'version':platform.python_version(),'system':platform.system(),'machine':platform.machine(),'interpreter':i,'original_expected_sha256':expected,'original_interpreter_pin_matches':i['sha256']==expected,'helper':h,'helper_pin_matches':h['sha256']=='74925449ae1141848c2dcbbe798ed0030fbbf9b1f599187c211d02ec03d34d61','required_os_symbols':features,'all_required_os_symbols':all(features.values()),'product_child_started':False,'network_request_sent':False,'failure_stderr_originally_retained':False,'original_failure_not_replayed':True},sort_keys=True))
