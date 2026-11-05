import ast,hashlib,json,stat,sys,types
d=json.loads(sys.argv[1]);old=d["before"];new=d["after"];tree=ast.parse(new);checks=[]
names={"verify_receipts","bundle_header","directory_key","check_input_directories"}
for name in names:
 def segment(s):
  t=ast.parse(s);n=next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name==name)
  return ast.get_source_segment(s,n)
 assert segment(old)==segment(new),name
checks.append("prior29_selected_component_definitions_byte_identical")
selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in {"Cancelled","on_signal","directory_key","create_source_directory","check_source_directory"}]
assert len(selected)==5
g={"stat":stat};exec(compile(ast.Module(body=selected,type_ignores=[]),"<source-directory-selected-definitions>","exec"),g)
class S:
 st_dev=2050;st_ino=201;st_uid=1000;st_gid=1000;st_mode=stat.S_IFDIR|0o700
class Source:
 name="normal-phaseb-ingress-observer-source-r1"
 def mkdir(self,mode):
  assert mode==0o700;calls.append("mkdir")
  if mode_case=="exists":raise FileExistsError()
 def __str__(self):return "/synthetic/"+self.name
calls=[];mode_case=None;fdstat=None;named=None
def setup(mode):
 global mode_case,fdstat,named
 calls.clear();mode_case=mode;fdstat=S();named=S()
 g.update(protected=0,pending_signal=None,source_directory=None,BASE="/synthetic",SOURCE=Source(),input_directories=[{"fd":10}],remaining=lambda:1,fsync_dir=lambda p:calls.append("fsync"))
 def open_(path,flags):
  calls.append("open")
  if mode=="open_failure":raise PermissionError()
  if mode=="cancel_open":g["on_signal"](15,None)
  return 11
 def st(name,dir_fd,follow_symlinks):
  assert name==Source.name and dir_fd==10 and follow_symlinks is False
  calls.append("named");return named
 g["os"]=types.SimpleNamespace(O_RDONLY=0,O_DIRECTORY=65536,O_NOFOLLOW=32,open=open_,fstat=lambda fd:fdstat,stat=st)
setup("exists")
try:g["create_source_directory"]()
except FileExistsError:
 assert calls==["mkdir"] and g["source_directory"] is None
 checks.append("existing_source_rejected_before_open_or_git")
else:raise AssertionError("existing")
setup("ok");g["create_source_directory"]()
assert g["source_directory"]["fd"]==11 and g["source_directory"]["key"]==[2050,201,1000,1000,16832] and calls[-1]=="fsync"
checks.append("exclusive_new_directory_registered_and_named_checked")
named.st_ino=202
try:g["check_source_directory"]()
except AssertionError:checks.append("renamed_source_directory_rejected")
else:raise AssertionError("rename")
setup("ok");g["create_source_directory"]();fdstat.st_ino=202
try:g["check_source_directory"]()
except AssertionError:checks.append("changed_held_source_fd_rejected")
else:raise AssertionError("fd")
setup("cancel_open")
try:g["create_source_directory"]()
except g["Cancelled"]:
 assert g["protected"]==0 and g["source_directory"]["fd"]==11 and g["pending_signal"]==15 and "fsync" not in calls
 checks.append("cancel_during_open_registered_before_propagation")
else:raise AssertionError("cancel")
setup("open_failure")
try:g["create_source_directory"]()
except PermissionError:
 assert g["protected"]==0 and g["source_directory"] is None and calls==["mkdir","open"]
 checks.append("open_failure_no_untracked_returned_fd")
else:raise AssertionError("open")
setup("ok")
def expired():raise AssertionError("expired")
g["remaining"]=expired
try:g["create_source_directory"]()
except AssertionError:
 assert not calls
 checks.append("expired_original_budget_before_directory_creation")
else:raise AssertionError("expired")
print(json.dumps({"schema":"heptabao.phaseb3cb.importer-owned-source-directory-components.v1","status":"passed","checks_passed":len(checks),"checks":checks,"candidate_bytes":len(new.encode()),"candidate_sha256":hashlib.sha256(new.encode()).hexdigest(),"prior29_cases_selected_definitions_unchanged":True,"all_resource_objects_synthetic":True,"candidate_top_level_executed":False,"filesystem_operations":0,"network_operations":0,"child_processes":0,"actual_import_executed":False},sort_keys=True))
