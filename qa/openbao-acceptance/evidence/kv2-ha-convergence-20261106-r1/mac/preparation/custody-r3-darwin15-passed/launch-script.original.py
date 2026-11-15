import pathlib,hashlib,os,json
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
for name,sha in [["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-r3/kv2_dr_process_custody.py","c3d95e975f5eec7af5f39fd76a904bdc197bfd0415a9899974adbde081e86c17"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-r3/tests/test_kv2_dr_process_custody.py","714ba53b63e482adda7bc8a4de3cac037c0330d69cfe6030f1a7a13274f66f78"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/custody-r3/owned_process.py","0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"]]:
 p=pathlib.Path(name);assert p.is_file() and not p.is_symlink() and p.stat().st_uid==501 and p.stat().st_nlink==1
 assert hashlib.sha256(p.read_bytes()).hexdigest()==sha;p.chmod(0o600)
(root/'control/custody-r3').chmod(0o700);(root/'control/custody-r3/tests').chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'schema':'heptabao.mac-custody-selftest-input-pins.r3','pins_verified':True,'prior_failed_jobs':['1a1b066d692-fc05-7043','1a1b06a4504-fc05-7060'],'expected_tests':15,'original_child_caps_preserved':True}),flush=True)
os.execv(python,[python,'-I','-S','-B','-m','unittest','discover','-s',str(root/'control/custody-r3/tests'),'-p','test_kv2_dr_process_custody.py','-v'])
