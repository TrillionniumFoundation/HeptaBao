#!/usr/bin/env python3
"""Real filesystem negative cases for the exact scoped reader with fixture paths.

Only the three /Users path literals and owner UID are remapped into a new local
synthetic root and the executor's unprivileged UID.
No Mac runtime or current source observation is claimed by this qualification.
"""
import ast,hashlib,json,os,shutil,stat,tempfile,time
from pathlib import Path
BASE=Path(__file__).resolve().parent
raw=(BASE/'launch_current_refresh_flags_r1.template.py').read_bytes()
tree=ast.parse(raw)
original=next(x for x in tree.body if isinstance(x,ast.ClassDef) and x.name=='StateInputs')
report={'schema':'heptabao.refresh-state-inputs-local-filesystem-qualification.r1','ok':False,
 'actualMacExecuted':False,'syntheticStateOnly':True,'productionFilesRead':False,
 'sourceTemplateSha256':hashlib.sha256(raw).hexdigest(),'namespaceAndOwnerLiteralRemappingOnly':True,'cases':[]}
deadline=time.monotonic()+10
def need(value,code):
 if not value:raise RuntimeError(code)
def remaining():need(time.monotonic()<deadline,'local_fixture_original_deadline')
def ident(s):return tuple(str(getattr(s,k)) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
temp=Path(tempfile.mkdtemp(prefix='refresh-state-local-',dir=BASE))
def one(name,action):
 root=temp/name;root.mkdir(mode=0o700)
 live=root/'Users/qianqi/.openclaw';live.mkdir(mode=0o700,parents=True)
 current=ast.parse(ast.unparse(original)).body[0]
 class ChangePaths(ast.NodeTransformer):
  def visit_Constant(self,node):
   replacements={'/':str(root),'/Users':str(root/'Users'),'/Users/qianqi':str(root/'Users/qianqi')}
   if isinstance(node.value,str) and node.value in replacements:return ast.copy_location(ast.Constant(replacements[node.value]),node)
   if type(node.value) is int and node.value==501:return ast.copy_location(ast.Constant(os.getuid()),node)
   return node
 module=ast.Module(body=[ChangePaths().visit(current)],type_ignores=[]);ast.fix_missing_locations(module)
 env={'os':os,'stat':stat,'Path':Path,'LIVE':live,'STATES':('bad-refresh-quarantine.json','refresh-backoff.json'),
  'need':need,'remaining':remaining,'ident':ident}
 exec(compile(module,'source-bound-state-inputs','exec'),env)
 guard=env['StateInputs']();folder=live/'authbus';file=folder/'refresh-backoff.json'
 def create(data=b'{"profiles":{}}',mode=0o600):
  folder.mkdir(mode=0o700,exist_ok=True);file.write_bytes(data);os.chmod(file,mode)
  need(file.stat().st_uid==os.getuid(),'synthetic_leaf_owner_required')
 def rejected(call):
  try:call()
  except (OSError,RuntimeError):return
  raise AssertionError('expected_closed_refusal')
 try:action(guard,folder,file,create,rejected);report['cases'].append({'case':name,'passed':True})
 finally:guard.close()
 return guard
try:
 def positive(g,d,f,c,r):
  c();need(g.get('refresh-backoff.json')==b'{"profiles":{}}','exact_synthetic_bytes');g.verify();g.close();g.verify();need(g.public()['allOwnedDescriptorsClosed'],'closed_once')
 one('S01_read_verify_close_verify',positive)
 one('S02_absent_directory',lambda g,d,f,c,r:(need(g.get('refresh-backoff.json') is None,'absent_directory'),g.verify()))
 def missing_file(g,d,f,c,r):d.mkdir(mode=0o700);need(g.get('refresh-backoff.json') is None,'absent_file');g.verify()
 one('S03_absent_file',missing_file)
 def replacement(g,d,f,c,r):
  c();g.get('refresh-backoff.json');f.rename(d/'original');c();r(g.verify)
 one('S04_inode_replacement_refused',replacement)
 def changed(g,d,f,c,r):c();g.get('refresh-backoff.json');f.write_bytes(b'{"profiles":{},"changed":true}');r(g.verify)
 one('S05_byte_change_refused',changed)
 def mode_change(g,d,f,c,r):c();g.get('refresh-backoff.json');os.chmod(f,0o640);r(g.verify)
 one('S06_mode_change_refused',mode_change)
 def linked(g,d,f,c,r):c();os.link(f,d/'extra-link');r(lambda:g.get('refresh-backoff.json'))
 one('S07_hardlink_refused',linked)
 def symlink(g,d,f,c,r):c();f.rename(d/'real');f.symlink_to(d/'real');r(lambda:g.get('refresh-backoff.json'))
 one('S08_leaf_symlink_refused',symlink)
 def parent_link(g,d,f,c,r):c();d.rename(d.with_name('real-authbus'));d.symlink_to(d.with_name('real-authbus'));r(lambda:g.get('refresh-backoff.json'))
 one('S09_parent_symlink_refused',parent_link)
 one('S10_empty_file_refused',lambda g,d,f,c,r:(c(b''),r(lambda:g.get('refresh-backoff.json'))))
 one('S11_oversize_file_refused',lambda g,d,f,c,r:(c(b'x'*1048577),r(lambda:g.get('refresh-backoff.json'))))
 one('S12_unselected_path_refused',lambda g,d,f,c,r:r(lambda:g.get('status.json')))
 def absent_changed(g,d,f,c,r):d.mkdir(mode=0o700);g.get('refresh-backoff.json');c();r(g.verify)
 one('S13_absent_name_created_refused',absent_changed)
 def parent_created(g,d,f,c,r):g.get('refresh-backoff.json');d.mkdir(mode=0o700);r(g.verify)
 one('S14_absent_parent_created_refused',parent_created)
 def close_fault(g,d,f,c,r):
  c();g.get('refresh-backoff.json');os.close(g.rows[-1]['fd']);g.close();need(not g.public()['allOwnedDescriptorsClosed'] and len(g.close_errors)==1,'unknown_close_refused');before=g.closed;g.close();need(g.closed==before,'no_close_replay')
 one('S15_unknown_close_not_replayed',close_fault)
 report['ok']=len(report['cases'])==15
except BaseException as error:report['errorType']=type(error).__name__;report['errorCode']='local_state_guard_qualification_failed'
finally:report['elapsedSeconds']=round(10-(deadline-time.monotonic()),6)
print(json.dumps(report,sort_keys=True));raise SystemExit(0 if report['ok'] else 1)
