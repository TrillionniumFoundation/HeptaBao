import os,stat,pathlib,json,hashlib,zlib,base64
root=pathlib.Path('/home/qian-qi/heptabao-ha-closure-20261103-r1/authbus-fresh-managed2-61ff8bef-r1')
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p,limit=1048576):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb')as f:
  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and s.st_nlink==1 and s.st_mode&0o077==0 and s.st_size<=limit;b=f.read();t=os.fstat(f.fileno());u=p.lstat()
  assert len(b)==s.st_size and all((v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)==(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)for v in [t,u])
 return b
files=[]
for rel in ['managed2-r1/result.public.json','managed2-r1/outer-result.public.json','managed2-r1/request-started.public.json','managed2-r1/intent.public.json']:
 b=read(root/rel);json.loads(b)
 if rel.endswith('outer-result.public.json'):assert sha(b)=='9d00efa408fe1592aefa718f6c8ebd30d7c82dd11479682fe1f7a717931e0dd4'
 files.append({'relative':rel,'bytes':len(b),'sha256':sha(b),'text':b.decode()})
core=json.loads(files[0]['text']);body=read(root/'managed2-r1/response.private');assert sha(body)==core['responseSha256']and len(body)==core['responseBytes']
raw=json.dumps({'schema':'heptabao.current-managed2-fresh-provider-receipt-export.v1','providerCalled':False,'productionChanged':False,'providerBodyRetainedPrivate':True,'responseFileHashIndependentlyVerified':True,'files':files},sort_keys=True,separators=(',',':')).encode();z=zlib.compress(raw,9)
print(json.dumps({'bytes':len(raw),'sha256':sha(raw),'zlibSha256':sha(z),'dataBase64':base64.b64encode(z).decode()},separators=(',',':')))
