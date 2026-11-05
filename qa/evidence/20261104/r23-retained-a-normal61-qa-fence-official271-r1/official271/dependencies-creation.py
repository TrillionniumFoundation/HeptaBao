from pathlib import Path
import io,tarfile,gzip,base64,hashlib,json
p=Path("/workspace/scratch/f86faac821c4/official271-matrix-review-r1")
names=["official271-source-contract-declarations-v2.public.json","product-corpus.json","official-tree.original.json","extract_contract_declarations_v2.py"]
buf=io.BytesIO(); rows=[]
with tarfile.open(fileobj=buf,mode="w",format=tarfile.USTAR_FORMAT) as tar:
 for name in names:
  body=(p/name).read_bytes()
  info=tarfile.TarInfo(name);info.size=len(body);info.mode=0o644;info.mtime=0;info.uid=0;info.gid=0;info.uname="";info.gname=""
  tar.addfile(info,io.BytesIO(body))
  rows.append({"name":name,"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()})
tarraw=buf.getvalue(); compressed=gzip.compress(tarraw,compresslevel=9,mtime=0); encoded=base64.b64encode(compressed)+b"\n"
archive="root-review-v3-dependencies.tar.gz.base64";(p/archive).write_bytes(encoded)
manifest={"schema":"heptabao.official271.root-review-dependencies.v1","files":rows,"archive":{"name":archive,"base64_bytes":len(encoded),"base64_sha256":hashlib.sha256(encoded).hexdigest(),"gzip_bytes":len(compressed),"gzip_sha256":hashlib.sha256(compressed).hexdigest(),"tar_bytes":len(tarraw),"tar_sha256":hashlib.sha256(tarraw).hexdigest()},"contains_private_data":False,"scope":"Original public inputs for root_review_v3.py. Source corpus r3 is separately complete in source-corpus-r3.gzip.base64. All raw input failures and source refinement limits remain distinct."}
name="root-review-v3-dependencies.manifest.public.json"; raw=(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode();(p/name).write_bytes(raw)
print(json.dumps({"archive":{"name":archive,"bytes":len(encoded),"sha256":hashlib.sha256(encoded).hexdigest()},"manifest":{"name":name,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},"files":rows},indent=2))
