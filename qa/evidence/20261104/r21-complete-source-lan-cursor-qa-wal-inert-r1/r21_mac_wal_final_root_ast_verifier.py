import ast,hashlib,json,sys,argparse
from pathlib import Path
m=json.loads(sys.argv[1]);inert,parent,reader,library=sys.argv[2:6]
for label,source in (("inert",inert),("parent",parent),("reader",reader),("library",library)):compile(source,label,"exec")
tree=ast.parse(inert)
values={}
for n in tree.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
  try:values[n.targets[0].id]=ast.literal_eval(n.value)
  except (ValueError,TypeError):pass
assert values["PINS"]==m["source_pins"] and values["DOCUMENT_PINS"]==m["document_pins"]
assert values["PAYLOAD_BYTES"]==m["carrier_bytes"] and values["PAYLOAD_SHA"]==m["carrier_sha256"]
pt=ast.parse(parent);main=next(n for n in pt.body if isinstance(n,ast.FunctionDef) and n.name=="main")
imports={n.module for n in ast.walk(main) if isinstance(n,ast.ImportFrom)}
assert {"mac_darwin_owned_projection_r1","mac_native_owned_commands_r1","mac_native_owned_unreaped_r1"}<=imports
assert not ({"mac_owned_commands_r1","mac_owned_unreaped_r1"}&imports)
calls=[n for n in ast.walk(main) if isinstance(n,ast.Call)]
bind=[n for n in calls if isinstance(n.func,ast.Name) and n.func.id=="bind_projection"]
qual=[n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=="qualify_self"]
assert len(bind)==1 and len(qual)==2
readers=[n for n in calls if isinstance(n.func,ast.Name) and n.func.id=="run_reader"]
assert len(readers)==1 and min(x.lineno for x in qual)<bind[0].lineno<readers[0].lineno<max(x.lineno for x in qual)
nodes=[n for n in main.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="parser" for t in n.targets)) or (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=="parser" and n.value.func.attr=="add_argument")]
assert len(nodes)==2
env={"argparse":argparse};exec(compile(ast.Module(body=nodes,type_ignores=[]),"pure-original-parser","exec"),env)
actual=env["parser"].parse_args(m["synthetic_args"][4:])
assert actual.candidate_sha256==m["candidate_sha256"]
assert "START=time.monotonic();UNTIL=START+45.0" in parent
assert "URI_OPTIONS='mode=ro&cache=private&vfs=unix-posix&readonly_shm=1'" in library
assert "WAL_MAXIMUM=5969912" in library
assert "import mac_guarded_current_capture_r3 as base" in library
assert "documents=[base.auth_rows(inputs,agent) for agent in base.AGENTS]" in library
print(json.dumps({"ok":True,"compiled_without_execution":4,"source_pins":len(values["PINS"]),"public_documents":len(values["DOCUMENT_PINS"]),"native_runtime_owner_imports":True,"one_native_bind":True,"self_before_and_after_reader_calls":True,"original_candidate_argparse_statements":2,"synthetic_argv_exact":True,"no_host_or_main_execution":True},sort_keys=True))
