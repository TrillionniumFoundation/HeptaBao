import pathlib,hashlib,os,json,stat
os.umask(0o077)
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/fd-guards-r1")
pins=[["kv2_native_fresh_directory_dr_live.py","388f763d810e1694ce9fe3d4ce52325318aad8ec4fa4d87ebbcd6cfbe7f1f5a0",70045],["tests/test_kv2_native_fresh_directory_dr_live.py","79a837e1b3932ac409546dc6f54e24e4a73e5fe0be9293c6bcfd12de0f81c782",34985],["kv2_271_lossless_native_live.py","383176647f0670837f40f3989496c6d1c902f8503dfa006d386b75877436b581",49393]]
for relative,sha,size in pins:
 p=root/'qa/openbao-acceptance'/relative;s=p.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_uid==501 and s.st_nlink==1 and s.st_size==size
 assert hashlib.sha256(p.read_bytes()).hexdigest()==sha;p.chmod(0o600)
for p in (root,root/'qa',root/'qa/openbao-acceptance',root/'qa/openbao-acceptance/tests'):
 assert p.stat().st_uid==501 and not p.is_symlink();p.chmod(0o700)
tmp=root/'temporary';tmp.mkdir(mode=0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'fd-guards-pins-verified','expected_count':2,'outer_seconds':60,'service_started':False,'compiler_started':False}),flush=True)
env={k:os.environ[k] for k in ('HOME','USER','LOGNAME','LANG','LC_ALL','TZ') if k in os.environ};env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin',TMPDIR=str(tmp))
os.execve(python,[python,'-I','-S','-B','-c',"import sys,unittest;sys.path.insert(0,\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/fd-guards-r1/qa/openbao-acceptance/tests\");unittest.main(module=None,argv=[\"unittest\",\"-v\",\"test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_parent_fd_retirement_detects_real_open_file_directory_and_closed_boundary\",\"test_kv2_native_fresh_directory_dr_live.ControllerGuards.test_parent_fd_retirement_rejects_unclosed_stdio_and_observation_gaps\"])"],env)
