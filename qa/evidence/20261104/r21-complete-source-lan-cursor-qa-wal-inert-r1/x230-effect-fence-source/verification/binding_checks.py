import ast,base64,difflib,hashlib,json,sys,types
before=base64.b64decode(sys.argv[1],validate=True).decode()
after=base64.b64decode(sys.argv[2],validate=True).decode()
request=json.loads(base64.b64decode(sys.argv[3],validate=True))
checks=[]
def need(value,label):
    if not value: raise AssertionError(label)
    checks.append(label)
changes=[
('"""Inactive, source-only proposal: reserve one exact old relay name; never replay."""',
 '"""Reviewable source proposal: reserve one exact old relay name; never replay."""'),
("BINDING_READY = False\n","BINDING_READY = True\n")]
made=before
for old,new in changes:
    need(made.count(old)==1,"unique replacement "+str(len(checks)))
    made=made.replace(old,new,1)
need(made==after,"two literal replacements reconstruct whole active source")
back=after
for old,new in reversed(changes):
    need(back.count(new)==1,"unique inverse "+str(len(checks)))
    back=back.replace(new,old,1)
need(back==before,"inverse returns whole reviewed inactive source")
ta=ast.parse(after);tb=ast.parse(before)
compile(ta,"<active-source>","exec");compile(tb,"<inactive-source>","exec")
def normalized(tree):
    nodes=[n for n in tree.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)) and not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="BINDING_READY" for t in n.targets))]
    return ast.dump(ast.Module(body=nodes,type_ignores=[]),include_attributes=False)
need(normalized(ta)==normalized(tb),"every other AST node identical")
need(set(request)=={"host","executable","args","cwd","timeout_seconds","idempotency_key"},"exact request six keys")
sha=hashlib.sha256(after.encode()).hexdigest()
need(request["host"]=="desktop" and request["executable"]=="/usr/bin/python3" and request["cwd"]=="/home/qian-qi/heptabao-ha-closure-20261103-r1" and request["timeout_seconds"]==60,"fixed host cwd interpreter outer")
need(request["args"]==["-I","-S","-B","-c",after,sha],"whole code and self SHA exact")
need(request["idempotency_key"]=="heptabao-x230-original-relay-effect-fence-r1-"+sha[:8],"new fixed key derived from exact source")
defs=[n for n in ta.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ("Refused","require_invocation")]
need(len(defs)==2,"selected entry definitions exact")
fake=types.SimpleNamespace(argv=["-c",sha],orig_argv=[request["executable"]]+request["args"])
ns={"sys":fake,"hashlib":hashlib}
exec(compile(ast.Module(body=defs,type_ignores=[]),"<entry-only>","exec"),ns)
need(ns["require_invocation"]()==sha,"actual selected entry accepts exact request")
for label,argv,original in [
("missing self SHA",["-c"],[request["executable"]]+request["args"][:-1]),
("wrong self SHA",["-c","0"*64],[request["executable"]]+request["args"][:-1]+["0"*64]),
("extra arg",["-c",sha,"extra"],[request["executable"]]+request["args"]+["extra"]),
("code byte drift",["-c",sha],[request["executable"]]+request["args"][:-2]+[after+"\n",sha])]:
    fake.argv=argv;fake.orig_argv=original
    try: ns["require_invocation"]()
    except ns["Refused"]: refused=True
    else: refused=False
    need(refused,"actual selected entry refuses "+label)
diff="".join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile="effect_fence_inactive.py",tofile="effect_fence_active.py"))
print(json.dumps({"schema":"heptabao.x230-effect-fence-active-binding-checks.v1","checks":checks,"checks_passed":len(checks),"source_sha256":sha,"diff":diff,"diff_hunks":sum(line.startswith("@@ ") for line in diff.splitlines()),"whole_AST_compile":True,"main_or_fence_methods_executed":False,"selected_entry_only":True,"physical_host_calls":0,"candidate_OS_calls":0,"candidate_filesystem_writes":0,"runtime_admission":False},sort_keys=True))
