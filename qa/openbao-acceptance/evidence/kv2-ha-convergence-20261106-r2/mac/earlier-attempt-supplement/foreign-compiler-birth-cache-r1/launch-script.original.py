import subprocess,json,pathlib,plistlib
def call(argv):return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
def ident(pid):
 p=call(['/bin/ps','-p',str(pid),'-o','pid=,ppid=,pgid=,uid=,lstart=,comm='])
 return {'exit_code':p.returncode,'value':p.stdout.strip()}
before={str(p):ident(p) for p in (60950,60947,60889)}
f=call(['/usr/sbin/lsof','-a','-p','60950,60947','-Fpn'])
paths=[x[1:] for x in f.stdout.splitlines() if x.startswith('n') and ('/.cargo-lock' in x or '/target' in x)]
after={str(p):ident(p) for p in (60950,60947,60889)}
v=call(['/usr/sbin/diskutil','info','-plist','/Volumes/T5'])
volume=plistlib.loads(v.stdout.encode()) if v.returncode==0 else {'error':True}
print(json.dumps({'schema':'heptabao.mac-compiler-birth-cache-boundary.r1','birth_identity_before':before,'birth_identity_after':after,'stable_identity':before==after,'open_target_or_cargo_lock_paths':paths[:30],'matched_path_count':len(paths),'lsof_exit':f.returncode,'t5_mount_probe_exit':v.returncode,'t5':{k:volume.get(k) for k in ('VolumeUUID','DeviceIdentifier','MountPoint','FilesystemType')},'root_same_device_as_mount':pathlib.Path('/Volumes/T5').stat().st_dev==pathlib.Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1').stat().st_dev,'argv_read':False,'processes_changed':False},sort_keys=True))
