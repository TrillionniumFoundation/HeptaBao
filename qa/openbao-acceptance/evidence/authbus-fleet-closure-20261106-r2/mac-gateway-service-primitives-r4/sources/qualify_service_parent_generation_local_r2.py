#!/usr/bin/env python3
"""Own-mkdir metadata regression, using exact new launcher function AST."""
import ast,hashlib,json,os,stat,tempfile
from pathlib import Path
BASE=Path(__file__).resolve().parent
source=(BASE/'launch_gateway_service_primitives_r2.template.py').read_bytes()
tree=ast.parse(source)
names={'parent_after_owned_mkdir','ident'}
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
assert len(nodes)==2
def need(value,code):
 if not value:raise RuntimeError(code)
scope={'stat':stat,'need':need}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'exact-launcher-parent-excerpt','exec'),scope)
parent=scope['parent_after_owned_mkdir'];ident=scope['ident']
cases=[]
def case(name,fn):fn();cases.append({'case':name,'passed':True})
def reject(fn):
 try:fn()
 except RuntimeError as e:assert str(e)=='only_owned_mkdir_parent_link_generation';return
 raise AssertionError('expected_refusal')
before=(1,2,501,20,stat.S_IFDIR|0o700,5,100,11,12)
def changed(index,value):
 row=list(before);row[index]=value;return tuple(row)
case('N01_unchanged_link_count_allowed',lambda:need(parent(before,before)==before,'unchanged'))
case('N02_single_owned_child_link_allowed',lambda:need(parent(before,changed(5,6))==changed(5,6),'single'))
case('N03_two_extra_links_refused',lambda:reject(lambda:parent(before,changed(5,7))))
case('N04_replaced_directory_inode_refused',lambda:reject(lambda:parent(before,changed(1,3))))
case('N05_parent_owner_change_refused',lambda:reject(lambda:parent(before,changed(2,502))))
case('N06_parent_mode_change_refused',lambda:reject(lambda:parent(before,changed(4,stat.S_IFDIR|0o755))))
observed={}
def actual_local_mkdir():
 with tempfile.TemporaryDirectory(prefix='gateway-parent-case-',dir=BASE) as name:
  p=Path(name);fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   first=ident(os.fstat(fd));os.mkdir('owned-child',0o700,dir_fd=fd);second=ident(os.fstat(fd))
   assert first[:5]==second[:5] and second[5]==first[5]+1
   assert first[:6]!=second[:6]  # Exact old launcher comparison rejects its own mkdir.
   assert parent(first,second)==second
   observed.update(originalFirstSixComparisonRejected=True,heldParentFirstFiveUnchanged=True,
    onlyOwnMkdirLinkCountIncreasedOnce=True,originalDescriptorClosedOnce=True)
  finally:os.close(fd)
case('N07_actual_local_own_mkdir_reproduces_old_guard',actual_local_mkdir)
report={'schema':'heptabao.service-parent-generation-local.r2','ok':True,'passed':len(cases),
 'actualMacRun':False,'cases':cases,'localFilesystemObservation':observed,
 'templateSha256':hashlib.sha256(source).hexdigest(),'productionActions':0}
(BASE/'service-parent-generation-local-r2.result.public.json').write_text(json.dumps(report,sort_keys=True)+'\n')
print(json.dumps(report,sort_keys=True))
