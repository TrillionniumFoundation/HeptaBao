import pathlib,hashlib,subprocess,json,time,os
base=pathlib.Path("/home/qq/heptabao-passkey-r5-input-20261106-r1")
binary=pathlib.Path("/home/qq/heptabao-personal-credentials-20261106-r1-build-a1b6ff4/bin-final/heptabao-vault")
build=pathlib.Path("/home/qq/heptabao-personal-credentials-20261106-r1-build-a1b6ff4/receipt.final.json")
script=base/"passkey_prepare.py";peer=base/"peer-public.pem"
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(binary)=="b0cccc3c204d6be5e2e20ee5830e34cb1242d3ac03ea42cd3b7e26a3ea416358"
assert sha(build)=="fa166952072d99490164cb355e1b9784e14791faf39cb48a2f226aed627ccdd4"
assert sha(script)=="01d18f09db37a06876f02b193bb5a961bebdbfa203893ff58d2fbd8b3a7c995f" and sha(peer)=="8cfb95be3707303b5f2a9bfc2ddc090d75c97b2a5960cc6dbfbfc59a331efe53"
root=pathlib.Path("/home/qq/heptabao-passkey-r5-seed-20261106-r1")
r=subprocess.run(["/usr/bin/python3",str(script),"--vault-bin",str(binary),"--peer-public-key",str(peer),"--peer-key-sha256",sha(peer),"--output",str(root)],capture_output=True)
assert r.returncode==0,"synthetic_prepare_failed"
assert sha(binary)=="b0cccc3c204d6be5e2e20ee5830e34cb1242d3ac03ea42cd3b7e26a3ea416358"
receipt=json.loads((root/"receipt.public.json").read_bytes())
assert receipt["vault_binary_sha256"]==sha(binary)
bound={"schema":1,"ok":True,"scope":"new_r5_synthetic_seed_fixed_producer","producer_binary_path":str(binary),"producer_binary_sha256":sha(binary),"producer_source_commit":"a1b6ff4506f52082a0893b7167fafb4ff95610be","producer_source_tree":"5f685c1aaf647f016afed0555a6710cd4a76c317","producer_toolchain":"rustc 1.98.0","producer_build_receipt_path":str(build),"producer_build_receipt_sha256":sha(build),"prepare_script_sha256":sha(script),"prepare_receipt_sha256":sha(root/"receipt.public.json"),"ciphertext_sha256":receipt["ciphertext_sha256"],"capsule_sha256":receipt["capsule_sha256"],"peer_public_key_sha256":receipt["peer_public_key_sha256"],"vault_id":receipt["vault_id"],"prior_r4_seed_reused":False,"created_unix_ns":time.time_ns(),"plaintext_credentials_returned":False,"qa_enrollment_not_product_pairing":True}
os.umask(0o077)
with (root/"producer.public.json").open("x") as f:json.dump(bound,f,sort_keys=True,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({"ok":True,"root":str(root),"producer_receipt_sha256":sha(root/"producer.public.json"),"seed_receipt_sha256":sha(root/"receipt.public.json"),"ciphertext_sha256":receipt["ciphertext_sha256"],"capsule_sha256":receipt["capsule_sha256"],"producer_binary_sha256":sha(binary)}))
