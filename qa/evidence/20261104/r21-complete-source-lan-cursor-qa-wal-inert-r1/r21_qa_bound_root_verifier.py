import ast,json,sys,argparse
from pathlib import Path
d=json.loads(sys.argv[1])
for k in ("publisher","unbound","builder"): compile(d[k],k,"exec")
def definitions(s):
 return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(s).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
assert definitions(d["publisher"])==definitions(d["unbound"])
assert len(definitions(d["publisher"]))==5
mod=ast.parse(d["publisher"])
pins=next(ast.literal_eval(n.value) for n in mod.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="PINS" for t in n.targets))
assert pins==d["pins"]
main=next(n for n in ast.parse(d["builder"]).body if isinstance(n,ast.FunctionDef) and n.name=="main")
nodes=[n for n in main.body if (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="parser" for t in n.targets)) or (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=="parser" and n.value.func.attr=="add_argument")]
assert len(nodes)==4
scope={"argparse":argparse,"Path":Path}
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),"selected-original-argparse","exec"),scope)
args=vars(scope["parser"].parse_args(d["build_args"][4:]))
assert str(args["binding"])==d["binding_path"]
assert args["binding_sha256"]==d["binding_sha256"] and args["self_sha256"]==d["builder_sha256"]
print(json.dumps({"ok":True,"publisher_definitions_exact":5,"carrier_pins":len(pins),"original_parser_statements":4,"main_executed":False,"host_calls":0,"argv_contract":{k:str(v) for k,v in args.items()}},sort_keys=True))
