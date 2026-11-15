import hashlib,pathlib,os
p=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/stage_source_1d63.py")
assert hashlib.sha256(p.read_bytes()).hexdigest()=="abca6cfcda6bad6cfab2a0c9b1930d3e19863605487eb98d006f3a9c048c1108"
assert p.stat().st_uid==501 and p.stat().st_nlink==1 and not p.is_symlink()
p.chmod(0o600)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
os.execv(python,[python,'-I','-S','-B',str(p)])
