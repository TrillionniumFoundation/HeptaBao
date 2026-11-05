import ast,hashlib,json,re
from pathlib import Path
root=Path('/tmp/authbus-mac-manager-source-r3-20261105-01')
checks=[]
for name in ('mac_current_phase_owner_r2.py','mac_current_server_owner_r1.py','mac_owned_launchd_r3.py'):
 raw=(root/name).read_bytes();source=raw.decode();tree=ast.parse(source,filename=name);compile(tree,name,'exec')
 checks.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'ast_compile_only':True})
deltas=[]
for name,after in (('phase','mac_current_phase_owner_r2.py'),('server','mac_current_server_owner_r1.py')):
 a=(root/(name+'.before.py')).read_text().splitlines(keepends=True)
 lines=(root/(name+'.review.diff')).read_text().splitlines(keepends=True);out=[];position=0;i=0;hunks=0
 while i<len(lines):
  if not lines[i].startswith('@@ '):i+=1;continue
  m=re.fullmatch(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n',lines[i]);assert m
  start,nold,newstart,nnew=map(int,m.groups());assert start-1>=position
  out.extend(a[position:start-1]);position=start-1;i+=1;oc=nc=0
  assert len(out)==newstart-1
  while i<len(lines) and not lines[i].startswith('@@ '):
   line=lines[i];assert line[:1] in (' ','+','-')
   if line[0] in ' -':assert a[position]==line[1:];position+=1;oc+=1
   if line[0] in ' +':out.append(line[1:]);nc+=1
   i+=1
  assert (oc,nc)==(nold,nnew);hunks+=1
 out.extend(a[position:]);assert ''.join(out)==(root/after).read_text()
 deltas.append({'name':name,'hunks':hunks,'strict_whole_apply':True})
print(json.dumps({'schema':'heptabao.mac-manager-r3.local-source-check.v1','sources':checks,'deltas':deltas,'whole_module_executed':False,'host_or_sqlite_or_product_child_operation':False,'scope':'local scratch source AST/compile and strict diff only'},sort_keys=True))