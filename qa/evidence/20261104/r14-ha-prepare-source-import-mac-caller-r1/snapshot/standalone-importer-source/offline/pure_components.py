import ast,copy,hashlib,json,re,sys,types
from pathlib import PurePosixPath
d=json.loads(sys.argv[1]);src=d["source"];tree=ast.parse(src);checks=[]
def definitions(names):
 nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
 assert {n.name for n in nodes}==set(names)
 return compile(ast.Module(body=nodes,type_ignores=[]),"<selected-importer-definitions>","exec")
def literal(name):
 return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id==name for v in n.targets)))
files=literal("FILES");sourcefiles=literal("SOURCE_FILES");head=literal("CANONICAL");treesha=literal("TREE")
g={"json":json,"FILES":files,"SOURCE_FILES":sourcefiles,"CANONICAL":head,"TREE":treesha,"PARENT":literal("PARENT"),"ROOT_COMMIT":literal("ROOT_COMMIT"),"CANONICAL_COUNT":literal("CANONICAL_COUNT"),"CARRIER":PurePosixPath("/home/qian-qi/heptabao-ha-closure-20261103-r1/normal-phaseb-ingress-observer-source-carrier-r1")}
exec(definitions(["verify_receipts","bundle_header"]),g)
g["digest"]=lambda b:hashlib.sha256(b).hexdigest()
exported=json.loads(d["export"])
transported=json.loads(d["prior_transport"])
transported.update(schema="heptabao.phaseb3cb.public-source-carrier-relay.v1",destination_root=str(g["CARRIER"]),files=sourcefiles)
transported["controller"].update(bytes=15395,sha256="f98ef18f25583506e7ff6072b8f383115ea826a399286f22bff1517b6eeb4432")
transported["helpers"]["sender.py"]["sha256"]="8681201f587a3c5d2da07f01404e4b74e1db2e3ada2614f3482915c6543fb650"
transported["helpers"]["receiver.py"]["sha256"]="2280d96c79b5e8fe8a0b3a9b601196cc61dbc43c11f4ded31780617f0533a6e5"
transported["sender"]["files"]=[];transported["receiver"]["files"]=[]
transported["receiver"]["source_export_provenance_verified"]=True
held=[]
for i,(item,source) in enumerate(zip(files,sourcefiles,strict=True)):
 identity=[2050,100+i,1000,1000,33024,1,item["bytes"],1000+i,1000+i]
 summary={"bytes":item["bytes"],"sha256":item["sha256"]}
 transported["sender"]["files"].append({"name":item["name"],"source":source["path"],"source_version":source["version"],"source_identity_before":[i],"source_identity_after":[i],"initial_file":summary,"stream":summary})
 transported["receiver"]["files"].append({"name":item["name"],"path":item["path"],"bytes":item["bytes"],"sha256":item["sha256"],"identity":identity,"mode":256,"create_only":True,"fsynced":True,"same_fd_readback":summary})
 held.append({"name":item["name"],"identity":identity,"same_fd_readback":summary})
def run_receipts(e,t,rows):
 g["result"]={}
 raw={"source-export.result.public.json":json.dumps(e).encode(),"source-carrier.result.public.json":json.dumps(t).encode()}
 g["verify_receipts"](raw,rows)
 assert g["result"]=={"export_receipt_verified":True,"transport_receipt_verified":True,"raw_input_receipts_unchanged":True}
run_receipts(exported,transported,held);checks.append("actual_export_plus_synthetic_two_file_carrier_accepted")
mutations=[
 ("wrong_export_count",lambda e,t,r:e["canonical_proof"].__setitem__("commit_count",3754)),
 ("wrong_carrier_schema",lambda e,t,r:t.__setitem__("schema","wrong")),
 ("failed_carrier",lambda e,t,r:t.__setitem__("status","failed")),
 ("unknown_carrier_cleanup",lambda e,t,r:t.__setitem__("remote_cleanup_unknown",True)),
 ("wrong_carrier_source",lambda e,t,r:t.__setitem__("source_commit","0"*40)),
 ("at_parent_deadline",lambda e,t,r:t.__setitem__("elapsed_seconds",300)),
 ("wrong_carrier_controller",lambda e,t,r:t["controller"].__setitem__("sha256","0"*64)),
 ("wrong_sender_source_version",lambda e,t,r:t["sender"]["files"][0].__setitem__("source_version","0:0:0:0:0")),
 ("changed_target_inode",lambda e,t,r:r[0].__setitem__("identity",[0]*9)),
 ("unexpected_target_file",lambda e,t,r:t["receiver"]["files"].append({})),
 ("unreaped_carrier_child",lambda e,t,r:t["cleanup"][0].__setitem__("direct_child_reaped",False)),
 ("wrong_bundle_digest",lambda e,t,r:e["bundle"].__setitem__("sha256","0"*64)),
]
for name,mutate in mutations:
 e,t,r=copy.deepcopy((exported,transported,held));mutate(e,t,r)
 try:run_receipts(e,t,r)
 except (AssertionError,KeyError,TypeError,ValueError):checks.append(name+"_rejected")
 else:raise AssertionError(name+" was accepted")
prefix=b"# v2 git bundle\n"+head.encode()+b" HEAD\n\nPACK"
assert g["bundle_header"](prefix)["prerequisites"]==[];checks.append("exact_header_accepted")
for name,b in [("prerequisite",b"# v2 git bundle\n-"+b"0"*40+b" prerequisite\n"+head.encode()+b" HEAD\n\nPACK"),("wrong_head",prefix.replace(head.encode(),b"0"*40)),("missing_pack",prefix[:-4])]:
 try:g["bundle_header"](b)
 except (AssertionError,ValueError):checks.append(name+"_rejected")
 else:raise AssertionError(name)
top=next(n for n in reversed(tree.body) if isinstance(n,ast.Try))
start=next(i for i,n in enumerate(top.body) if isinstance(n,ast.Assert) and "ACTUAL_INPUTS_READY" in ast.get_source_segment(src,n))
stop=next(i for i,n in enumerate(top.body) if isinstance(n,ast.Assert) and "platform.system()" in ast.get_source_segment(src,n))
gate=compile(ast.Module(body=top.body[start:stop],type_ignores=[]),"<selected-pure-readiness-guard>","exec")
def run_gate(ready,f,t):
 exec(gate,{"ACTUAL_INPUTS_READY":ready,"FILES":f,"TRANSFER":t,"MAX_BUNDLE":64*1024*1024,"re":re})
f=copy.deepcopy(files);t=literal("TRANSFER")
for item in f:item["version"]="1:2:3:4:5"
t.update(bytes=123,sha256="a"*64,version="1:2:3:4:5")
run_gate(True,f,t);checks.append("synthetic_complete_metadata_guard_accepted")
for name,ready,f1,t1 in [
 ("unresolved_ready_flag",False,f,t),
 ("unresolved_input_version",True,files,t),
 ("unresolved_transfer_fields",True,f,literal("TRANSFER")),
 ("at_cap_transfer",True,f,{**t,"bytes":262145}),
]:
 try:run_gate(ready,f1,t1)
 except (AssertionError,TypeError):checks.append(name+"_rejected_before_fs")
 else:raise AssertionError(name)
exec(definitions(["directory_key","check_input_directories"]),g)
class S:
 def __init__(self,ino,mode=16832):self.st_dev=2050;self.st_ino=ino;self.st_uid=1000;self.st_gid=1000;self.st_mode=mode
class P:
 def lstat(self):return named["base"]
named={};fds={}
def setup():
 named.clear();fds.clear()
 for i in range(4):fds[10+i]=S(100+i)
 named.update(base=copy.copy(fds[10]),carrier=copy.copy(fds[11]),incoming=copy.copy(fds[12]),control=copy.copy(fds[13]))
 g["input_directories"]=[{"path":P(),"parent_index":None,"name":None,"fd":10,"key":g["directory_key"](fds[10])}]
 for i,(parent,name) in enumerate([(0,"carrier"),(1,"incoming"),(1,"control")],1):
  g["input_directories"].append({"path":None,"parent_index":parent,"name":name,"fd":10+i,"key":g["directory_key"](fds[10+i])})
 g["remaining"]=lambda:1
 def lstat(name,dir_fd,follow_symlinks):
  assert follow_symlinks is False and dir_fd in fds
  return named[name]
 g["os"]=types.SimpleNamespace(fstat=lambda fd:fds[fd],stat=lstat)
setup();g["check_input_directories"]();checks.append("synthetic_held_named_chain_accepted")
for name,mutate in [("base_renamed",lambda:named["base"].__setattr__("st_ino",999)),("carrier_renamed",lambda:named["carrier"].__setattr__("st_ino",999)),("incoming_renamed",lambda:named["incoming"].__setattr__("st_ino",999)),("control_symlink",lambda:named["control"].__setattr__("st_mode",41471)),("held_fd_replaced",lambda:fds[12].__setattr__("st_ino",999))]:
 setup();mutate()
 try:g["check_input_directories"]()
 except AssertionError:checks.append(name+"_rejected")
 else:raise AssertionError(name)
setup()
def expired():raise AssertionError("expired")
g["remaining"]=expired
try:g["check_input_directories"]()
except AssertionError:checks.append("expired_directory_check_rejected")
else:raise AssertionError("expired")
print(json.dumps({"schema":"heptabao.phaseb3cb.local-importer-pure-components.v1","status":"passed","checks_passed":len(checks),"checks":checks,"actual_export_receipt_used":True,"new_carrier_receipt":"synthetic_not_actual","metadata_and_fd_cases":"synthetic_in_memory_only","candidate_top_level_executed":False,"actual_import_executed":False,"filesystem_operations":0,"network_operations":0,"child_processes":0},sort_keys=True))
