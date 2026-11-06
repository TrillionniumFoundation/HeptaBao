import subprocess,json,os,pathlib
rows=[]
for pid in (60950,60947,60889):
 p=subprocess.run(['/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,etime=,comm='],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
 r={'pid_requested':pid,'ps_exit':p.returncode,'metadata':p.stdout.strip()}
 if p.returncode==0:
  q=subprocess.run(['/usr/sbin/lsof','-a','-p',str(pid),'-d','cwd','-F','n'],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
  r['cwd_exit']=q.returncode
  r['cwd_paths']=[x[1:] for x in q.stdout.splitlines() if x.startswith('n')]
 rows.append(r)
p=subprocess.run(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,comm='],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
active=[]
for line in p.stdout.splitlines():
 f=line.split(None,4)
 if len(f)==5 and pathlib.Path(f[4]).name in {'cargo','rustc','rustfmt','rust-lld'}:active.append({'pid':int(f[0]),'ppid':int(f[1]),'pgid':int(f[2]),'uid':int(f[3]),'comm':pathlib.Path(f[4]).name})
print(json.dumps({'schema':'heptabao.mac-compiler-metadata-only.r1','rows':rows,'active_compiler_metadata':active,'argv_read':False,'processes_changed':False},sort_keys=True))
