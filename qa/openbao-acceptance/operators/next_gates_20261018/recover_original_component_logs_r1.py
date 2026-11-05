import base64,hashlib,json,os,pathlib,stat,subprocess
root=pathlib.Path("/home/qian-qi/heptabao-next-gates-20261017/r8-archive-logs-recovered-20261018-01")
assert not root.exists();root.mkdir(mode=0o700)
entries=[
("r8f-mac-34mib-component.log","/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017/r8f-server-native-ha-34mib-pinned-mtls.log","6b2f36d9aed91c0da49826c927bc54d955857f33b5bf2cf56fcb8d9274f2ae1d"),
("r8k-mac-archive34.log","/Volumes/T5/hepta-vnext-recovery-20261013/v6-next-gates-20261017/r8k-server-native-ha-archive.log","eed6bd8187854c3780a867b57983c5e515c207021d0d06b4bdf6530d7ccc39a2")]
worker="""import base64,hashlib,json,os,pathlib,stat,sys
entries=json.loads(sys.stdin.read())
rows=[]
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
for name,path,digest in entries:
 p=pathlib.Path(path);assert p.resolve(strict=True)==p
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,"rb") as f:
  before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and before.st_size<=65536
  data=f.read(65537);assert len(data)==before.st_size and identity(before)==identity(os.fstat(f.fileno()))==identity(p.lstat())
 assert hashlib.sha256(data).hexdigest()==digest
 rows.append({"name":name,"source":path,"bytes":len(data),"sha256":digest,"content_base64":base64.b64encode(data).decode()})
print(json.dumps(rows))
"""
import shlex
p=subprocess.run(["ssh","-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","ConnectTimeout=10","macbook-pro","python3 -c "+shlex.quote(worker)],input=json.dumps(entries).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
assert p.returncode==0 and len(p.stdout)<196608,("readonly_original_log_fetch_failed",p.returncode)
rows=json.loads(p.stdout);assert len(rows)==2
public=[]
for row in rows:
 b=base64.b64decode(row.pop("content_base64"),validate=True);assert len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"]
 with (root/row["name"]).open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
 public.append(row)
with (root/"public-receipt.json").open("x") as f:json.dump({"schema":"heptabao.original-public-log-recovery.v1","files":public,"tests_rerun":False},f,indent=2);f.write("\n");f.flush();os.fsync(f.fileno())
print(json.dumps({"ok":True,"files":public,"tests_rerun":False}))
