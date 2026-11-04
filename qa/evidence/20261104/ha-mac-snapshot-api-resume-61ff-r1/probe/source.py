import socket,fcntl,os,json,hashlib,sys,stat,time
P='/opt/homebrew/Cellar/python@3.14/3.14.3_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python'
fd=os.open(P,os.O_RDONLY|os.O_NOFOLLOW)
try:
 st=os.fstat(fd); raw=b''
 while True:
  part=os.read(fd,1048576)
  if not part: break
  raw+=part
 assert stat.S_ISREG(st.st_mode) and hashlib.sha256(raw).hexdigest()=='7ecc1ecbf9daa9303c4bf502ff62ffdd9010ed5c08729d470ae9380c10ce1211'
finally: os.close(fd)
assert os.getuid()==501 and socket.gethostname()=='MacBook-Pro.local'
start=time.monotonic()
with socket.socket() as l:
 l.bind(('127.0.0.1',0));l.listen(1);l.setblocking(False)
 with socket.socket() as c:
  c.settimeout(2);c.connect(l.getsockname())
  s,peer=l.accept()
  with s:
   before=fcntl.fcntl(s.fileno(),fcntl.F_GETFL)
   s.setblocking(True)
   after=fcntl.fcntl(s.fileno(),fcntl.F_GETFL)
   print(json.dumps({'listener_nonblock':bool(fcntl.fcntl(l.fileno(),fcntl.F_GETFL)&os.O_NONBLOCK),'accepted_nonblock_before':bool(before&os.O_NONBLOCK),'accepted_nonblock_after':bool(after&os.O_NONBLOCK),'owned_loopback':peer[0]=='127.0.0.1','elapsed_seconds':time.monotonic()-start,'test_scope':'actual Darwin socket flags only; no Rust TLS or product qualification'}),flush=True)
