import pathlib,hashlib,os,json,stat
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert os.geteuid()==501 and root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700 and root.stat().st_dev==16777244
out=root/'build-test-2b38-r1'
assert sorted(p.name for p in out.iterdir())==['test-selection.public.json']
assert not (root/'source-2b38-r1').exists()
pins=[(root/'control/mac_build_test_2b38_r1.py','39ddbb77648443a58f2fc2b238014c59f70116873016cb241f369f0bc888ecb6',26275),(out/'test-selection.public.json','21c8eb41909568ebf1d33cf65c7a1fc1f920a5c5f7a2b9a66affe19fd66ffe76',37226),(root/'control/candidate-2b38-from-4e808.bundle','03ceec075c48d7210d22994e7cd6efbbcb9f58219dbabf4776efebe8b270752d',123258)]
for path,sha,size in pins:
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid==501 and info.st_nlink==1 and info.st_size==size
 assert path.resolve(strict=True)==path and hashlib.sha256(path.read_bytes()).hexdigest()==sha
 path.chmod(0o600)
out.chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'launch-pins-verified','source_commit':'2b38f091c2903eac74b4ed9dc32b1f1f00fd8a8a','expected_tests':107,'outer_seconds':8280,'controller_sha256':'39ddbb77648443a58f2fc2b238014c59f70116873016cb241f369f0bc888ecb6'}),flush=True)
os.execv(python,[python,'-I','-S','-B',str(root/'control/mac_build_test_2b38_r1.py')])
