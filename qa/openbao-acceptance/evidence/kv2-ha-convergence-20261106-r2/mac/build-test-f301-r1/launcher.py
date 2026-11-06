import pathlib,hashlib,os,json,stat
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert os.geteuid()==501 and root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700 and root.stat().st_dev==16777244
out=root/'build-test-f301-r1'
assert sorted(p.name for p in out.iterdir())==['test-selection.public.json']
assert not (root/'source-f301-r1').exists()
pins=[(root/'control/mac_build_test_f301_r1.py','6d283c73714f2a87f4ce9259da116306c61e429a30cc23c881d841aaa0086fc0',29754),(out/'test-selection.public.json','a5079af9cfdf051b2c926cad6799b22d6bab9f6682b27e74bb7017a37424a57d',39103),(root/'control/candidate-f301-from-2b38.bundle','f2a8db0a9edf691c7ed06f3585df0ce3f45594ded9e473b061b26482063998e3',168310)]
for path,sha,size in pins:
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid==501 and info.st_nlink==1 and info.st_size==size
 assert path.resolve(strict=True)==path and hashlib.sha256(path.read_bytes()).hexdigest()==sha
 path.chmod(0o600)
out.chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'launch-pins-verified','source_commit':'f301a0f391096a2a8daf149f16bbbbd5bbf7a9e3','expected_tests':107,'outer_seconds':8280,'controller_sha256':'6d283c73714f2a87f4ce9259da116306c61e429a30cc23c881d841aaa0086fc0'}),flush=True)
os.execv(python,[python,'-I','-S','-B',str(root/'control/mac_build_test_f301_r1.py')])
