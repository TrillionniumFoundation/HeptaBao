import pathlib,hashlib,os,json
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
for name,sha in [["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-r2/kv2_dr_process_custody.py","5b6445687c1024e6bd1b2c47c8dd83175445ce70cfbdd3637834faf4a0316d54"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-r2/tests/test_kv2_dr_process_custody.py","74ca530db853dfb7786ccb9f53a920c1581685aff68c23a7f5d19d5af63fb193"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-r2/owned_process.py","0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"]]:
 p=pathlib.Path(name);assert p.is_file() and not p.is_symlink() and p.stat().st_uid==501 and p.stat().st_nlink==1
 assert hashlib.sha256(p.read_bytes()).hexdigest()==sha;p.chmod(0o600)
(root/'control/custody-r2').chmod(0o700);(root/'control/custody-r2/tests').chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'schema':'heptabao.mac-custody-selftest-input-pins.r2','pins_verified':True,'prior_failed_job':'1a1b066d692-fc05-7043','expected_tests':13,'original_child_caps_preserved':True}),flush=True)
os.execv(python,[python,'-I','-S','-B','-m','unittest','discover','-s',str(root/'control/custody-r2/tests'),'-p','test_kv2_dr_process_custody.py','-v'])
