import ast, base64, hashlib, json, sys, types
source = base64.b64decode(sys.argv[1], validate=True).decode("utf-8")
relay = base64.b64decode(sys.argv[2], validate=True).decode("utf-8")
tree = ast.parse(source)
compile(tree, "<metadata-source>", "exec")
old = ast.parse(relay)
checks = []
def check(ok, label):
    if not ok:
        raise AssertionError(label)
    checks.append(label)
check(not any(isinstance(n, (ast.Import, ast.ImportFrom)) and
              any(a.name.split(".")[0] in ("subprocess", "socket", "urllib", "requests", "pathlib") for a in n.names)
              for n in ast.walk(tree)), "metadata imports no child/network/path helper")
for n in ast.walk(tree):
    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
        if isinstance(n.func.value, ast.Name) and n.func.value.id == "os":
            check(n.func.attr not in {"read","pread","write","pwrite","mkdir","makedirs",
                                     "unlink","rmdir","rename","replace","listdir","scandir",
                                     "system","fork","execv","execve","kill","killpg"},
                  "metadata os call readonly: " + n.func.attr)
main_try = next(n for n in old.body if isinstance(n, ast.Try))
def is_named_call(node, owner, method):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
           and isinstance(node.func.value, ast.Name) and node.func.value.id == owner \
           and node.func.attr == method
root_positions = [i for i,n in enumerate(main_try.body)
                  if isinstance(n, ast.Expr) and is_named_call(n.value,"ROOT","mkdir")]
control_positions = [i for i,n in enumerate(main_try.body)
                     if isinstance(n, ast.Expr) and is_named_call(n.value,"CONTROL","mkdir")]
check(len(root_positions) == len(control_positions) == 1, "original exactly one root/control mkdir")
ri, ci = root_positions[0], control_positions[0]
check(ri < ci, "original root mkdir dominates control mkdir")
root_call = main_try.body[ri].value
check(all(k.arg != "exist_ok" for k in root_call.keywords), "original mkdir retains default exist_ok false")
before = ast.Module(body=main_try.body[:ri], type_ignores=[])
check(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and
              n.func.id in ("start_child","inspect_config","snapshot") for n in ast.walk(before)),
      "no child or snapshot dispatch before original root mkdir")
calls = [(i,n) for i,node in enumerate(main_try.body) for n in ast.walk(node)
         if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
         and n.func.id in ("start_child","inspect_config")]
check(bool(calls) and all(i > ci for i,n in calls), "all transport/config dispatch after root/control mkdir")
check(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
              and n.func.attr in ("unlink","rmdir","rmtree","remove","rename","replace")
              for n in ast.walk(old)), "original has no root deletion or rename")
check(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
          and n.func.id == "snapshot" for node in main_try.finalbody for n in ast.walk(node)),
      "original finally snapshot remains possible")
selected = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Refused"
            or isinstance(n, ast.FunctionDef) and n.name == "require_invocation"]
scope = {"hashlib":hashlib}
exec(compile(ast.Module(body=selected,type_ignores=[]),"<entry-only>","exec"), scope)
digest = hashlib.sha256(source.encode()).hexdigest()
argv = ["-c",digest]
orig = ["/usr/bin/python3","-I","-S","-B","-c",source,digest]
for label, args, original, expected in [
    ("exact",argv,orig,True),
    ("missing",["-c"],orig,False),
    ("wrong",["-c","0"*64],orig[:-1]+["0"*64],False),
    ("extra",argv+["extra"],orig+["extra"],False),
]:
    scope["sys"] = types.SimpleNamespace(argv=args,orig_argv=original)
    try:
        value=scope["require_invocation"]()
        actual = value == digest
    except scope["Refused"]:
        actual=False
    check(actual == expected, "selected entry " + label)
metadata_class=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="Metadata")
close_fn=next(n for n in metadata_class.body if isinstance(n,ast.FunctionDef) and n.name=="close_all")
called=[]
def fake_close(fd):
    called.append(fd)
    if fd == 12:
        raise OSError(5,"synthetic")
close_scope={"os":types.SimpleNamespace(close=fake_close)}
exec(compile(ast.Module(body=[close_fn],type_ignores=[]),"<close-only>","exec"),close_scope)
rows=[dict(fd=x,opened=True,close_attempted=False,closed=False,
           close_error_type=None,close_errno=None) for x in (11,12)]
state=types.SimpleNamespace(phase="",ledger=rows)
check(close_scope["close_all"](state) is False and called==[12,11],
      "close failure stays false while remaining descriptor closes")
check(rows[0]["closed"] and not rows[1]["closed"] and rows[1]["close_attempted"],
      "failed close consumes once marker")
check(close_scope["close_all"](state) is False and called==[12,11],
      "failed close not repeated")
check_fn=next(n for n in metadata_class.body if isinstance(n,ast.FunctionDef) and n.name=="check")
check_scope={"Refused":scope["Refused"]}
exec(compile(ast.Module(body=[check_fn],type_ignores=[]),"<deadline-only>","exec"),check_scope)
for label,now,pending,expected in [("before",999,None,True),("at",1000,None,False),
                                   ("signal",999,15,False)]:
    check_scope["time"]=types.SimpleNamespace(monotonic_ns=lambda now=now:now)
    state=types.SimpleNamespace(pending_signal=pending,until_ns=1000)
    try:
        check_scope["check"](state)
        result=True
    except scope["Refused"]:
        result=False
    check(result==expected,"selected unchanged deadline "+label)
print(json.dumps({"schema":"heptabao.x230-fence-metadata-source-checks.v1",
 "source_sha256":digest,"source_bytes":len(source.encode()),
 "relay_sha256":hashlib.sha256(relay.encode()).hexdigest(),
 "whole_ast_compile":True,"actual_metadata_main_executed":False,
 "actual_relay_module_executed":False,"physical_host_calls":0,
 "filesystem_reads_or_writes":0,"native_descriptors":0,"actual_children":0,
 "checks":checks,"checks_passed":len(checks)},sort_keys=True))
