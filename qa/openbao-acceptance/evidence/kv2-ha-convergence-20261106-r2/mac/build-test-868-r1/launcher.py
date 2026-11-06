import pathlib,hashlib,os,json,stat
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert os.geteuid()==501 and root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700 and root.stat().st_dev==16777244
out=root/'build-test-868-r1'
assert sorted(p.name for p in out.iterdir())==['test-selection.public.json']
assert not (root/'source-868-r1').exists()
pins=[(root/'control/mac_build_test_868_r1.py','c497c9fd40df0d2bb6776a32733d45ef3d56f2a74665ee5a01050186ef2bb499',30573),(out/'test-selection.public.json','4177229337bb7ffc7d1c81b9ea515bd48b0cbd529fd48537815cd40bbfdb53e7',41675),(root/'control/candidate-868-from-f301.bundle','51af0653f89e8ce191a8601da90bcf6f4c36d8e6a677b4ec4584e0881b2ad3a6',50809)]
for path,sha,size in pins:
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid==501 and info.st_nlink==1 and info.st_size==size
 assert path.resolve(strict=True)==path and hashlib.sha256(path.read_bytes()).hexdigest()==sha
 path.chmod(0o600)
out.chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'launch-pins-verified','source_commit':'868439e6df9f12291842898763ccba581e346bfb','expected_tests':107,'outer_seconds':8280,'controller_sha256':'c497c9fd40df0d2bb6776a32733d45ef3d56f2a74665ee5a01050186ef2bb499'}),flush=True)
os.execv(python,[python,'-I','-S','-B',str(root/'control/mac_build_test_868_r1.py')])
