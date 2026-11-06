import pathlib,hashlib,os,json,stat
os.umask(0o077)
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-raw-killpg-r1")
for relative,sha,size in [["kv2_dr_process_custody.py","669e2cd1d9ee597529c08b88f3fc21c813d4ff7b57f3792381baa44fbdbe7008",26131],["tests/test_kv2_dr_process_custody.py","41d3b0e079b2b17a0ece458f907adf380542cbdf96530213869636e81a447807",17148],["owned_process.py","0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0",28442]]:
 p=root/relative;i=p.lstat()
 assert stat.S_ISREG(i.st_mode) and i.st_uid==501 and i.st_nlink==1 and i.st_size==size and p.resolve(strict=True)==p
 assert hashlib.sha256(p.read_bytes()).hexdigest()==sha;p.chmod(0o600)
for p in (root,root/'tests'):
 assert p.stat().st_uid==501 and not p.is_symlink();p.chmod(0o700)
tmp=root/'temporary';tmp.mkdir(mode=0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'event':'legacy-killpg-guards-pins-verified','expected_count':3,'child_seconds':5,'outer_seconds':60,'production_processes_touched':False}),flush=True)
env={k:os.environ[k] for k in ('HOME','USER','LOGNAME','LANG','LC_ALL','TZ') if k in os.environ};env.update(PATH='/opt/homebrew/bin:/usr/bin:/bin',TMPDIR=str(tmp))
os.execve(python,[python,'-I','-S','-B','-c',"import sys,unittest;sys.path.insert(0,\"/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-raw-killpg-r1/tests\");unittest.main(module=None,argv=[\"unittest\",\"-v\",\"test_kv2_dr_process_custody.ProcessCustodyTests.test_legacy_raw_killpg_after_nonzero_communicate_never_signals_retired_id\",\"test_kv2_dr_process_custody.ProcessCustodyTests.test_legacy_raw_killpg_unknown_group_is_refused_without_touching_foreign_process\",\"test_kv2_dr_process_custody.ProcessCustodyTests.test_legacy_raw_killpg_live_owned_group_routes_once_and_restores_global_hook\"])"],env)
