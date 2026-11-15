import os,sys,json,pathlib,hashlib,subprocess,plistlib
base=pathlib.Path('/Volumes/T5/hepta-vnext-recovery-20261013');root=base/'continuation-20261106-kv2-ha-convergence-r1'
assert os.getuid()==501 and base.resolve(strict=True)==base and base.stat().st_dev==16777244
p=subprocess.run(['/usr/sbin/diskutil','info','-plist','/Volumes/T5'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
v=plistlib.loads(p.stdout);assert v['VolumeUUID']=='FB804D1B-24CB-4D6E-AEA7-A9E180807758'
assert not root.exists() and not root.is_symlink(), 'owned new root must be absent'
root.mkdir(mode=0o700)
(root/'control').mkdir(mode=0o700);(root/'build-test-r1').mkdir(mode=0o700)
keys=('waitid','WNOWAIT','WEXITED','WNOHANG','P_PID','getsid','getpgid')
cap={'executable':sys.executable,'version':sys.version,'capabilities':{k:(callable(getattr(os,k,None)) if k in ('waitid','getsid','getpgid') else getattr(os,k,None)) for k in keys}}
homebrew=pathlib.Path('/opt/homebrew/bin/python3');hb={'exists':homebrew.exists()}
if homebrew.exists():
 code="import os,sys,json;keys=('waitid','WNOWAIT','WEXITED','WNOHANG','P_PID','getsid','getpgid');print(json.dumps({'executable':sys.executable,'version':sys.version,'capabilities':{k:(callable(getattr(os,k,None)) if k in ('waitid','getsid','getpgid') else getattr(os,k,None)) for k in keys}}))"
 q=subprocess.run([str(homebrew),'-I','-S','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
 hb.update(json.loads(q.stdout));hb.update(resolved_path=str(homebrew.resolve()),sha256=hashlib.sha256(homebrew.read_bytes()).hexdigest())
print(json.dumps({'schema':'heptabao.mac-owned-private-stage-capability.r1','root':str(root),'mode':oct(root.stat().st_mode & 511),'st_dev':root.stat().st_dev,'volume_uuid':v['VolumeUUID'],'usr_bin_python':cap,'homebrew_python':hb,'candidate_source_created':False,'compiler_started':False,'service_started':False,'production_changed':False}),flush=True)
