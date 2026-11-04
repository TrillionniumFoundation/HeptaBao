import hashlib,json,os,platform,signal,socket,subprocess,sys,time
from pathlib import Path
p=None
report={'schema':'heptabao.mac-waitid-preflight.v1','product_or_source_modified':False}
try:
 assert platform.system()=='Darwin' and platform.machine()=='arm64' and os.getuid()==501 and socket.gethostname()=='MacBook-Pro.local'
 assert hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()=='7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
 names=('waitid','P_PID','WEXITED','WNOHANG','WNOWAIT')
 report['available']={n:hasattr(os,n) for n in names}
 assert all(report['available'].values()) and signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL
 until=time.monotonic()+5
 p=subprocess.Popen(['/usr/bin/true'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 while True:
  observed=os.waitid(os.P_PID,p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
  if observed is not None:break
  assert time.monotonic()<until
  time.sleep(0.01)
 assert observed.si_pid==p.pid and p.returncode is None
 again=os.waitid(os.P_PID,p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
 assert again is not None and again.si_pid==p.pid
 report['same_unreaped_child_observed_twice']=True
 try:report['unreaped_child_pgid_matches']=os.getpgid(p.pid)==p.pid
 except ProcessLookupError:report['unreaped_child_pgid_matches']=None
 report['pid']=p.pid
 assert p.wait(timeout=2)==0
 report['child_reaped']=True
 report['ok']=True
except Exception as e:
 report['ok']=False;report['error_class']=type(e).__name__
finally:
 if p is not None and p.returncode is None:
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
 print(json.dumps(report,sort_keys=True),flush=True)
raise SystemExit(0 if report.get('ok') else 1)
