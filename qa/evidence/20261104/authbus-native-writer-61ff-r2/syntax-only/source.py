import ast,sys,json,hashlib,subprocess,os
assert os.statvfs('/home/qian-qi/.openclaw').f_flag & os.ST_RDONLY
x=json.loads(sys.stdin.buffer.read(1048577));out=[]
for n,s in x.items():
 if n.endswith('.py'):ast.parse(s,filename=n)
 elif n.endswith('.mjs'):
  p=subprocess.run(['/usr/bin/node','--input-type=module','--check'],input=s.encode(),capture_output=True,timeout=10)
  if p.returncode:raise RuntimeError(n+': '+p.stderr.decode())
 else:raise AssertionError('only reviewed syntax sources')
 out.append({'name':n,'sha256':hashlib.sha256(s.encode()).hexdigest(),'bytes':len(s.encode()),'syntaxOk':True})
print(json.dumps({'schema':'heptabao.native-control-syntax-only.v1','providerCalled':False,'nativeStarted':False,'productionChanged':False,'files':out},sort_keys=True))
