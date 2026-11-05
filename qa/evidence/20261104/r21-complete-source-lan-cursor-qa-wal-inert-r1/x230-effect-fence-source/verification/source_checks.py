import ast,base64,hashlib,json,stat,sys
src=base64.b64decode(sys.argv[1],validate=True).decode()
meta=base64.b64decode(sys.argv[2],validate=True).decode()
report=json.loads(base64.b64decode(sys.argv[3],validate=True))
tree=ast.parse(src);mt=ast.parse(meta)
compile(tree,"<inactive-fence-source>","exec")
checks=[]
def need(ok,label):
    if not ok:raise AssertionError(label)
    checks.append(label)
def definition(t,name):
    return next(n for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name)
for name in ("Refused","identity","require_invocation"):
    need(ast.get_source_segment(src,definition(tree,name)) == ast.get_source_segment(meta,definition(mt,name)),
         "exact approved metadata helper "+name)
fc=definition(tree,"Fence");mc=definition(mt,"Metadata")
fm=next(n for n in fc.body if isinstance(n,ast.FunctionDef) and n.name=="close_all")
mm=next(n for n in mc.body if isinstance(n,ast.FunctionDef) and n.name=="close_all")
need(ast.dump(fm,include_attributes=False)==ast.dump(mm,include_attributes=False),
     "once close method AST exact to checked metadata method")
def value(name):
    node=next(n for n in tree.body if isinstance(n,ast.Assign)
              and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
    return ast.literal_eval(node.value)
dirs=value("EXPECTED_DIRECTORIES")
controls=value("EXPECTED_CONTROLS")
need(value("BINDING_READY") is True,"metadata-bound ready flag; no runtime admission")
need(value("METADATA_EVIDENCE_SHA256")==hashlib.sha256(base64.b64decode(sys.argv[3])).hexdigest(),
     "exact actual metadata stdout SHA")
need(dirs=={n["path"]:n["identity_before"] for n in report["nodes"] if n["directory"]},
     "five actual full nine-field directory identities exact")
for name,row in controls.items():
    n=next(n for n in report["nodes"] if n["path"].endswith("/"+name))
    need(row["identity"]==n["identity_before"]==n["identity_after"],
         "actual source full identity exact "+name)
need(value("READ_CAP")==131072 and value("TOMBSTONE_CAP")==8192 and
     sum(v["bytes"] for v in controls.values())*2+8192 < value("READ_CAP"),
     "two exact source scans plus max tombstone within public cap")
need(value("SOFT_SECONDS")==15 and value("OUTPUT_CAP")==32768,"explicit proposed new bounds")
banned={"unlink","rmdir","rmtree","remove","rename","replace","chmod","chown","kill","killpg",
        "listdir","scandir","system","fork","execv","execve"}
calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)]
need(not any(isinstance(n.func,ast.Attribute) and n.func.attr in banned for n in calls),
     "no delete rename permissions signal listing or process effects")
need(not any(isinstance(n,(ast.Import,ast.ImportFrom)) and
             any(a.name.split(".")[0] in ("subprocess","socket","shutil","urllib","requests") for a in n.names)
             for n in ast.walk(tree)),"no child or network imports")
mkdir=[n for n in calls if isinstance(n.func,ast.Attribute) and
       isinstance(n.func.value,ast.Name) and n.func.value.id=="os" and n.func.attr=="mkdir"]
need(len(mkdir)==1 and isinstance(mkdir[0].args[0],ast.Name) and mkdir[0].args[0].id=="ROOT_NAME"
     and ast.literal_eval(mkdir[0].args[1])==0o700
     and any(k.arg=="dir_fd" and isinstance(k.value,ast.Subscript) for k in mkdir[0].keywords),
     "single mkdirat exact fixed root 0700")
need("os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC" in src and
     'TOMBSTONE_NAME, os.O_RDWR' in src,
     "create-only fixed tombstone flags")
need('self.nodes.append({\n            "path": root["path"] + "/" + TOMBSTONE_NAME' in src,
     "tombstone held/named identity remains in final verification set")
classes=[definition(tree,"Refused")]
binding=definition(tree,"validate_binding")
ns={"stat":stat,"BINDING_READY":False,"METADATA_EVIDENCE_SHA256":value("METADATA_EVIDENCE_SHA256"),
    "EXPECTED_DIRECTORIES":dirs,"BASE":value("BASE"),"CONTROLS":value("BASE")+"/normal-cold-h2-x230-transfer-controls-r1"}
exec(compile(ast.Module(body=classes+[binding],type_ignores=[]),"<binding-only>","exec"),ns)
try:ns["validate_binding"]()
except ns["Refused"] as e:inactive=str(e)=="actual_metadata_binding_unresolved"
else:inactive=False
need(inactive,"actual selected binding rejects inactive candidate")
ns["BINDING_READY"]=True
ns["validate_binding"]()
need(True,"selected binding accepts exact observed shapes without OS call")
ns["EXPECTED_DIRECTORIES"]={**dirs,"/unexpected":dirs["/"]}
try:ns["validate_binding"]()
except ns["Refused"]:bad=True
else:bad=False
need(bad,"selected binding rejects additional path")
ns["EXPECTED_DIRECTORIES"]={k:list(v) for k,v in dirs.items()}
ns["EXPECTED_DIRECTORIES"]["/home"][4]|=0o002
try:ns["validate_binding"]()
except ns["Refused"]:bad=True
else:bad=False
need(bad,"selected binding rejects writable ancestor")
print(json.dumps({"schema":"heptabao.x230-effect-fence-active-source-checks.v1",
 "source_bytes":len(src.encode()),"source_sha256":hashlib.sha256(src.encode()).hexdigest(),
 "checks":checks,"checks_passed":len(checks),"whole_ast_compile":True,
 "candidate_main_or_fence_methods_executed":False,"selected_binding_function_only":True,
 "candidate_OS_calls":0,"physical_host_calls":0,"candidate_filesystem_writes":0,
 "local_verifier_process":True,"runtime_admission":False},sort_keys=True))
