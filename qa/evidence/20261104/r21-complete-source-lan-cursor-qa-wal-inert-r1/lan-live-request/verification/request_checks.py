import argparse,ast,base64,contextlib,hashlib,io,json,sys,types
source=base64.b64decode(sys.argv[1],validate=True).decode()
req=json.loads(base64.b64decode(sys.argv[2],validate=True))
tree=ast.parse(source);compile(tree,"<exact-lan-launcher>","exec")
start=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="parser" for t in n.targets))
end=next(i for i,n in enumerate(tree.body[start:],start) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="option" for t in n.targets))
nodes=tree.body[start:end]
ns={"argparse":argparse}
exec(compile(ast.Module(body=nodes,type_ignores=[]),"<parser-only>","exec"),ns)
args=req["args"][4:]
parsed=ns["parser"].parse_args(args)
assert parsed.run_once is True and parsed.prepare_only is False
assert parsed.prepared_sha256=="89418a152b5b23db976cc88de4d8eabca3f53aeb66ed632534bf057672bc58bb"
guard=next(n for n in tree.body if isinstance(n,ast.Assert) and isinstance(n.test,ast.BoolOp) and ast.unparse(n.test).startswith("option.prepared_sha256 and "))
env={"option":parsed,"sha":lambda ignored:"89418a152b5b23db976cc88de4d8eabca3f53aeb66ed632534bf057672bc58bb","prepared_path":object()}
exec(compile(ast.Module(body=[guard],type_ignores=[]),"<prepared-guard-only>","exec"),env)
checks=["whole AST compile without importing module","actual parser declarations selected unchanged","exact new request accepted as run-once","actual prepared guard accepts whole-SHA binding"]
for value in (None,"0"*64):
    env["option"]=types.SimpleNamespace(prepared_sha256=value)
    try:exec(compile(ast.Module(body=[guard],type_ignores=[]),"<prepared-guard-only>","exec"),env)
    except AssertionError:pass
    else:raise AssertionError("guard did not reject")
    checks.append("actual prepared guard rejects "+("missing" if value is None else "wrong SHA"))
with contextlib.redirect_stderr(io.StringIO()):
    try:ns["parser"].parse_args(["--prepare-only","--run-once","--prepared-sha256","89418a152b5b23db976cc88de4d8eabca3f53aeb66ed632534bf057672bc58bb"])
    except SystemExit as e:assert e.code==2
    else:raise AssertionError("mutual exclusion missing")
checks.append("actual parser refuses both actions")
print(json.dumps({"schema":"heptabao.df026-lan-live-request-source-checks.v1","checks":checks,"checks_passed":len(checks),"source_sha256":hashlib.sha256(source.encode()).hexdigest(),"main_executed":False,"physical_host_calls":0,"candidate_filesystem_calls":0,"runtime_admission":False},sort_keys=True))
