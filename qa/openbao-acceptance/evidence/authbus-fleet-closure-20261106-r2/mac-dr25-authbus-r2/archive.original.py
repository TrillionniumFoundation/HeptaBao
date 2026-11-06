import gzip,hashlib,json,os,stat,time
from pathlib import Path
start=time.monotonic()
root=Path('/Volumes/T5/hepta-vnext-recovery-20261013/continuation-20261106-kv2-ha-convergence-r1')
work=root/'full34-dr25-authbus-r2'
out=root/'dr25-execution-authbus-r2'
def need(v,n):
 if not v:raise RuntimeError(n)
def shape(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,version=None):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_uid==501 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and a.st_size<=8*1024*1024,'private_regular_public_receipt')
  if version:need(':'.join(str(x) for x in (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns))==version,'exact_observed_summary_version')
  data=b''
  while len(data)<=8*1024*1024:
   chunk=os.read(fd,65536)
   if not chunk:break
   data+=chunk
  need(len(data)==a.st_size and shape(a)==shape(os.fstat(fd))==shape(path.lstat()),'stable_receipt_source')
  return data,shape(a)
 finally:os.close(fd)
def publish(name,data):
 path=out/name
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  p=memoryview(data)
  while p:
   n=os.write(fd,p);need(n>0,'short_write');p=p[n:]
  os.fsync(fd)
 finally:os.close(fd)
 reread,_=read(path);need(reread==data,'gzip_readback')
 return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
need(os.geteuid()==501 and out.resolve()==out and stat.S_IMODE(out.stat().st_mode)==0o700,'owned_completed_output')
raw,first=read(work/'dr25-summary.json','16777244:72739313:2148370:1793978126371627247:1793978126371627247')
v=json.loads(raw)
need(v['status']=='passed' and v['fresh_directory_same_seal_v6_recovery_verified'] is True and v['baseline']['qualified'] is True,'actual_dr_completed')
need(len(v['checks'])==25 and len({x['case'] for x in v['checks']})==25 and all(x['passed'] is True for x in v['checks']),'exact_dr25')
baseline=work/'quarantine/original-closure/summary.json'
need(v['baseline']['summary']==str(baseline),'exact_quarantined_baseline_path')
b,before=read(baseline)
need(hashlib.sha256(b).hexdigest()==v['baseline']['sha256'],'baseline_original_binding')
z=json.loads(b)
need(z['status']=='passed' and z['profile']=='full34' and z['full34_qualified'] is True and len(z['checks'])==31 and len({x['case'] for x in z['checks']})==31 and all(x['passed'] is True for x in z['checks']),'exact_original_baseline31')
files=[]
for name,data in [('dr25-summary.original.json.gz',raw),('baseline31-summary.original.json.gz',b)]:
 compressed=gzip.compress(data,compresslevel=9,mtime=0)
 need(gzip.decompress(compressed)==data,'lossless_compression')
 row=publish(name,compressed);row.update(original_bytes=len(data),original_sha256=hashlib.sha256(data).hexdigest());files.append(row)
need(read(work/'dr25-summary.json')[1]==first and read(baseline)[1]==before,'original_receipts_unchanged')
need(time.monotonic()-start<45,'original_archival_budget')
print(json.dumps({'schema':'heptabao.mac-dr25-completed-receipt-lossless-archive.v1','original_receipts_unchanged':True,'baseline31_passed':True,'dr25_passed':True,'files':files,'elapsed_seconds':time.monotonic()-start,'service_actions':0,'private_credential_files_opened':False},sort_keys=True))
