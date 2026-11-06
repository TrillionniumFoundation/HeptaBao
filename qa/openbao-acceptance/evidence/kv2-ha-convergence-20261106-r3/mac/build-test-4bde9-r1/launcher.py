import pathlib,hashlib,os,json,stat
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert os.geteuid()==501 and root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700 and root.stat().st_dev==16777244
out=root/'build-test-4bde9-r1'
assert sorted(p.name for p in out.iterdir())==['test-selection.public.json']
assert not (root/'source-4bde9-r1').exists()
pins=[(root/'control/mac_build_test_4bde9_r1.py','76ab52614563287bdfe41cb9738c6992ae9360b3e34463c3b788701132a42d7c',32288),(out/'test-selection.public.json','7da0b1e3efe257b66d31d50af7c1327a4d320c512c1c8f82df30020898c66595',46133),(root/'control/candidate-4bde9-from-09c14.bundle','9808cfef28ce90733b636e81aed122aeeaf4fe81e0f34b1b84dde7e0ab0e11cd',1393)]
for path,sha,size in pins:
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid==501 and info.st_nlink==1 and info.st_size==size
 assert path.resolve(strict=True)==path and hashlib.sha256(path.read_bytes()).hexdigest()==sha
 path.chmod(0o600)
out.chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'launch-pins-verified','source_commit':'4bde9aee03fcd27c59e13607e529b1cee594b249','expected_tests':107,'outer_seconds':8280,'controller_sha256':'76ab52614563287bdfe41cb9738c6992ae9360b3e34463c3b788701132a42d7c'}),flush=True)
os.execv(python,[python,'-I','-S','-B',str(root/'control/mac_build_test_4bde9_r1.py')])
