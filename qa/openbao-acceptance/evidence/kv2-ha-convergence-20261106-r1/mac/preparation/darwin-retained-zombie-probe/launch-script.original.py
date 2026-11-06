import os,sys,subprocess,time,json
assert sys.version_info[:2]==(3,14)
r,w=os.pipe();child=None;result={}
def row(pid):
 q=subprocess.run(['/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,state='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
 return {'exit_code':q.returncode,'columns':[x.split() for x in q.stdout.decode('ascii').splitlines()],'stderr_bytes':len(q.stderr)}
try:
 child=subprocess.Popen([sys.executable,'-I','-S','-B','-c','import os,sys;os.read(int(sys.argv[1]),1)',str(r)],pass_fds=(r,),start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 os.close(r);r=None
 result['live_birth']={'pid':child.pid,'parent':os.getpid(),'uid':os.geteuid(),'sid':os.getsid(child.pid),'pgid':os.getpgid(child.pid),'ps':row(child.pid)}
 os.write(w,b'1');os.close(w);w=None
 until=time.monotonic()+5;info=None
 while time.monotonic()<until:
  info=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
  if info is not None:break
  time.sleep(0.005)
 assert info is not None
 result['retained_waitid']={k:getattr(info,k) for k in ('si_pid','si_uid','si_code','si_status','si_signo')}
 result['after_exit_ps']=row(child.pid)
 for name in ('getsid','getpgid'):
  try:result['after_exit_'+name]={'value':getattr(os,name)(child.pid),'errno':None}
  except OSError as e:result['after_exit_'+name]={'errno':e.errno,'error_type':type(e).__name__}
 result['reap_exit_code']=child.wait(timeout=5)
 result['original_wait_completed']=True
finally:
 for fd in (r,w):
  if fd is not None:os.close(fd)
 if child is not None and child.returncode is None:
  child.kill();result['failure_cleanup_exit']=child.wait(timeout=5)
print(json.dumps(result,sort_keys=True),flush=True)
