import pathlib,hashlib,os,json
root=pathlib.Path("/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1")
assert root.stat().st_uid==os.getuid()==501 and root.stat().st_dev==16777244 and (root.stat().st_mode & 511)==448
pins=[["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/kv2_dr_process_custody.py","ed9c66dc7fb56b17cffafd3ef62ac76c42db4ff4b35c6ed95b7ff8102595dd72"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/tests/test_kv2_dr_process_custody.py","69ce3d3b8161149ce57bcf0766934e8461b095f93e21b44d57adf0d0077e8f4d"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/control/owned_process.py","0ee96c9f43b50ebd57ee8f0ef95f2431c441ec02c1799992588dbf50768745d0"],["/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1/build-test-r1/test-selection.public.json","46c27a667bc06815594c344c0aee57970dc43b1eca32b849fba0fe2457888143"]]
for name,sha in pins:
 p=pathlib.Path(name);assert p.is_file() and not p.is_symlink() and p.stat().st_uid==501 and p.stat().st_nlink==1
 assert hashlib.sha256(p.read_bytes()).hexdigest()==sha
 p.chmod(0o600)
(root/'control/tests').chmod(0o700)
python='/opt/homebrew/bin/python3'
assert hashlib.sha256(pathlib.Path(python).read_bytes()).hexdigest()=='cebfcc4ac431ff7a2179bc6eff7e5c6bdae48b564eeab2d504bef6173a2cfc13'
print(json.dumps({'schema':'heptabao.mac-custody-selftest-input-pins.r1','pins_verified':True,'source_candidate_built':False}),flush=True)
os.execv(python,[python,'-I','-S','-B','-m','unittest','discover','-s',str(root/'control/tests'),'-p','test_kv2_dr_process_custody.py','-v'])
