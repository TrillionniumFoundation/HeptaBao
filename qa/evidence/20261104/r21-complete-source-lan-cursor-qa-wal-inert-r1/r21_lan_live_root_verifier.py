import ast,json,sys,argparse
d=json.loads(sys.argv[1]);tree=ast.parse(d["source"]);nodes=[]
for n in tree.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ("parser","action"):nodes.append(n)
 elif isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id in ("parser","action") and n.value.func.attr=="add_argument":nodes.append(n)
assert len(nodes)==5
env={"argparse":argparse};exec(compile(ast.Module(body=nodes,type_ignores=[]),"original-argument-contract","exec"),env)
a=env["parser"].parse_args(d["args"][4:])
assert a.run_once is True and a.prepare_only is False and a.prepared_sha256==d["actual_sha"]
assert d["args"][:4]==["-I","-S","-B",d["launcher_path"]]
print(json.dumps({"ok":True,"original_parser_statements":5,"live_action":True,"actual_prepared_sha":a.prepared_sha256,"host_calls":0,"source_main_executed":False},sort_keys=True))
