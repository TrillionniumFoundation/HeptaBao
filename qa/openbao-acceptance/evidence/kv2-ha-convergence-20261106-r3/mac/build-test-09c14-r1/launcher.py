import pathlib,hashlib,os,json,stat
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert os.geteuid()==501 and root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700 and root.stat().st_dev==16777244
out=root/'build-test-09c14-r1'
assert sorted(p.name for p in out.iterdir())==['test-selection.public.json']
assert not (root/'source-09c14-r1').exists()
pins=[(root/'control/mac_build_test_09c14_r1.py','2a5973afdc515c3a4a52a1da0609734440b6d23fba98f8d599b00cd7530179ec',31441),(out/'test-selection.public.json','97c5c2ab931db0623c3c788b8cc0dbda238d0ad346144f4626aac07effd1fc25',43878),(root/'control/candidate-09c14-from-868.bundle','1343cc508548e8cad01f0ba5271d563fbf17725fd8a264f232db1ccdded0cc0d',2001)]
for path,sha,size in pins:
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid==501 and info.st_nlink==1 and info.st_size==size
 assert path.resolve(strict=True)==path and hashlib.sha256(path.read_bytes()).hexdigest()==sha
 path.chmod(0o600)
out.chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'launch-pins-verified','source_commit':'09c14eae7a3b52dee8ce3af3175dad5900ac59ec','expected_tests':107,'outer_seconds':8280,'controller_sha256':'2a5973afdc515c3a4a52a1da0609734440b6d23fba98f8d599b00cd7530179ec'}),flush=True)
os.execv(python,[python,'-I','-S','-B',str(root/'control/mac_build_test_09c14_r1.py')])
